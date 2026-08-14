import hashlib
import json
import secrets
import time
from typing import Any, Dict
from urllib.parse import quote, urlencode

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from redis.exceptions import RedisError

from config import Settings, get_settings
from redis_client import add_key_value_redis, get_and_delete_value_redis


HUBSPOT_AUTHORIZATION_URL = 'https://app.hubspot.com/oauth/authorize'
HUBSPOT_TOKEN_URL = 'https://api.hubspot.com/oauth/2026-03/token'
HUBSPOT_SCOPES = (
    'oauth',
    'crm.objects.contacts.read',
    'crm.objects.companies.read',
    'crm.objects.deals.read',
)
OAUTH_STATE_TTL_SECONDS = 600
CREDENTIAL_HANDOFF_TTL_SECONDS = 600
TOKEN_REQUEST_TIMEOUT_SECONDS = 10.0


def _get_hubspot_settings() -> Settings:
    settings = get_settings()
    missing_settings = []
    if not settings.hubspot_client_id:
        missing_settings.append('HUBSPOT_CLIENT_ID')
    if not settings.hubspot_client_secret:
        missing_settings.append('HUBSPOT_CLIENT_SECRET')
    if not settings.hubspot_redirect_uri:
        missing_settings.append('HUBSPOT_REDIRECT_URI')

    if missing_settings:
        raise HTTPException(
            status_code=500,
            detail=(
                'HubSpot OAuth is not configured. Set '
                f'{", ".join(missing_settings)}.'
            ),
        )

    return settings


def _normalize_identifier(value: str, field_name: str) -> str:
    normalized_value = value.strip() if isinstance(value, str) else ''
    if not normalized_value:
        raise HTTPException(status_code=400, detail=f'{field_name} is required.')

    return normalized_value


def _state_key(state: str) -> str:
    return f'oauth:hubspot:state:{state}'


def _credentials_key(user_id: str, org_id: str) -> str:
    identity = f'{org_id}\0{user_id}'.encode('utf-8')
    identity_hash = hashlib.sha256(identity).hexdigest()
    return f'oauth:hubspot:credentials:{identity_hash}'


def _decode_redis_object(value: bytes, object_name: str) -> Dict[str, Any]:
    try:
        decoded_value = json.loads(value)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f'Stored HubSpot {object_name} data is invalid.',
        ) from exc

    if not isinstance(decoded_value, dict):
        raise HTTPException(
            status_code=500,
            detail=f'Stored HubSpot {object_name} data is invalid.',
        )

    return decoded_value


def _token_exchange_error(response: httpx.Response) -> HTTPException:
    error_code = None
    correlation_id = None
    try:
        response_data = response.json()
        if isinstance(response_data, dict):
            error_code = (
                response_data.get('error')
                or response_data.get('status')
                or response_data.get('category')
            )
            correlation_id = response_data.get('correlationId')
    except ValueError:
        pass

    detail = 'HubSpot rejected the authorization code. Please reconnect.'
    if error_code:
        detail = f'{detail} Error: {error_code}.'
    if correlation_id:
        detail = f'{detail} Correlation ID: {correlation_id}.'

    if response.status_code == 429:
        status_code = 503
    elif 400 <= response.status_code < 500:
        status_code = 400
    else:
        status_code = 502

    return HTTPException(status_code=status_code, detail=detail)


async def authorize_hubspot(user_id: str, org_id: str) -> str:
    settings = _get_hubspot_settings()
    normalized_user_id = _normalize_identifier(user_id, 'user_id')
    normalized_org_id = _normalize_identifier(org_id, 'org_id')
    state = secrets.token_urlsafe(32)
    state_data = {
        'user_id': normalized_user_id,
        'org_id': normalized_org_id,
    }

    try:
        await add_key_value_redis(
            _state_key(state),
            json.dumps(state_data),
            expire=OAUTH_STATE_TTL_SECONDS,
        )
    except RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail='OAuth state storage is temporarily unavailable.',
        ) from exc

    authorization_params = {
        'client_id': settings.hubspot_client_id,
        'redirect_uri': settings.hubspot_redirect_uri,
        'scope': ' '.join(HUBSPOT_SCOPES),
        'state': state,
    }
    return (
        f'{HUBSPOT_AUTHORIZATION_URL}?'
        f'{urlencode(authorization_params, quote_via=quote)}'
    )


async def oauth2callback_hubspot(request: Request) -> HTMLResponse:
    provider_error = request.query_params.get('error')
    if provider_error:
        error_description = request.query_params.get('error_description')
        raise HTTPException(
            status_code=400,
            detail=error_description or f'HubSpot authorization failed: {provider_error}.',
        )

    code = request.query_params.get('code')
    state = request.query_params.get('state')
    if not code:
        raise HTTPException(status_code=400, detail='Missing HubSpot authorization code.')
    if not state:
        raise HTTPException(status_code=400, detail='Missing HubSpot OAuth state.')

    try:
        stored_state = await get_and_delete_value_redis(_state_key(state))
    except RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail='OAuth state storage is temporarily unavailable.',
        ) from exc

    if not stored_state:
        raise HTTPException(
            status_code=400,
            detail='HubSpot OAuth state is invalid or has expired.',
        )

    state_data = _decode_redis_object(stored_state, 'state')
    user_id = _normalize_identifier(state_data.get('user_id'), 'user_id')
    org_id = _normalize_identifier(state_data.get('org_id'), 'org_id')
    settings = _get_hubspot_settings()

    token_request_data = {
        'grant_type': 'authorization_code',
        'client_id': settings.hubspot_client_id,
        'client_secret': settings.hubspot_client_secret,
        'redirect_uri': settings.hubspot_redirect_uri,
        'code': code,
    }

    try:
        async with httpx.AsyncClient(
            timeout=TOKEN_REQUEST_TIMEOUT_SECONDS
        ) as client:
            response = await client.post(
                HUBSPOT_TOKEN_URL,
                data=token_request_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail='HubSpot token exchange timed out. Please reconnect.',
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail='Unable to reach HubSpot for the token exchange.',
        ) from exc

    if response.is_error:
        raise _token_exchange_error(response)

    try:
        credentials = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an invalid token response.',
        ) from exc

    if not isinstance(credentials, dict):
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an invalid token response.',
        )

    required_fields = ('access_token', 'refresh_token', 'expires_in')
    if any(not credentials.get(field) for field in required_fields):
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an incomplete token response.',
        )

    try:
        expires_in = int(credentials['expires_in'])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an invalid token lifetime.',
        ) from exc

    if expires_in <= 0:
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an invalid token lifetime.',
        )

    credentials['expires_in'] = expires_in
    credentials['expires_at'] = int(time.time()) + expires_in

    try:
        await add_key_value_redis(
            _credentials_key(user_id, org_id),
            json.dumps(credentials),
            expire=CREDENTIAL_HANDOFF_TTL_SECONDS,
        )
    except RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail='OAuth credential storage is temporarily unavailable.',
        ) from exc

    close_window_script = '''
    <!doctype html>
    <html>
        <head><title>HubSpot connected</title></head>
        <body>
            <script>window.close();</script>
        </body>
    </html>
    '''
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id: str, org_id: str) -> Dict[str, Any]:
    normalized_user_id = _normalize_identifier(user_id, 'user_id')
    normalized_org_id = _normalize_identifier(org_id, 'org_id')

    try:
        stored_credentials = await get_and_delete_value_redis(
            _credentials_key(normalized_user_id, normalized_org_id)
        )
    except RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail='OAuth credential storage is temporarily unavailable.',
        ) from exc

    if not stored_credentials:
        raise HTTPException(status_code=400, detail='No HubSpot credentials found.')

    return _decode_redis_object(stored_credentials, 'credential')


async def create_integration_item_metadata_object(response_json):
    # Implemented in Phase 3.
    pass


async def get_items_hubspot(credentials):
    # Implemented in Phase 3.
    pass
