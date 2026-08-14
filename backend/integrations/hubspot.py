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
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_and_delete_value_redis


HUBSPOT_AUTHORIZATION_URL = 'https://app.hubspot.com/oauth/authorize'
HUBSPOT_TOKEN_URL = 'https://api.hubspot.com/oauth/2026-03/token'
HUBSPOT_OBJECTS_URL = 'https://api.hubapi.com/crm/objects/2026-03'
HUBSPOT_SCOPES = (
    'oauth',
    'crm.objects.contacts.read',
    'crm.objects.companies.read',
    'crm.objects.deals.read',
)
OAUTH_STATE_TTL_SECONDS = 600
CREDENTIAL_HANDOFF_TTL_SECONDS = 600
TOKEN_REQUEST_TIMEOUT_SECONDS = 10.0
TOKEN_REFRESH_BUFFER_SECONDS = 60
HUBSPOT_PAGE_LIMIT = 100

HUBSPOT_OBJECT_CONFIG = {
    'contacts': {
        'label': 'Contact',
        'record_type_id': '0-1',
        'properties': ['firstname', 'lastname', 'email'],
    },
    'companies': {
        'label': 'Company',
        'record_type_id': '0-2',
        'properties': ['name', 'domain'],
    },
    'deals': {
        'label': 'Deal',
        'record_type_id': '0-3',
        'properties': ['dealname', 'amount', 'dealstage', 'pipeline'],
    },
}


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


def _decode_credentials_payload(credentials: Any) -> Dict[str, Any]:
    if isinstance(credentials, str):
        try:
            credentials = json.loads(credentials)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail='HubSpot credentials payload is invalid JSON.',
            ) from exc

    if not isinstance(credentials, dict):
        raise HTTPException(
            status_code=400,
            detail='HubSpot credentials payload is invalid.',
        )

    access_token = credentials.get('access_token')
    if not isinstance(access_token, str) or not access_token.strip():
        raise HTTPException(
            status_code=400,
            detail='HubSpot credentials are missing an access token.',
        )

    normalized_credentials = dict(credentials)
    normalized_credentials['access_token'] = access_token.strip()
    refresh_token = normalized_credentials.get('refresh_token')
    if isinstance(refresh_token, str):
        normalized_credentials['refresh_token'] = refresh_token.strip()

    return normalized_credentials


def _coerce_timestamp(value: Any) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _hubspot_request_error(response: httpx.Response, object_name: str) -> HTTPException:
    error_code = None
    correlation_id = None
    message = None

    try:
        response_data = response.json()
        if isinstance(response_data, dict):
            error_code = (
                response_data.get('category')
                or response_data.get('status')
                or response_data.get('error')
            )
            correlation_id = response_data.get('correlationId')
            message = response_data.get('message')
    except ValueError:
        pass

    if response.status_code == 401:
        detail = 'HubSpot credentials expired or are invalid. Please reconnect.'
        return HTTPException(status_code=401, detail=detail)

    detail = f'Unable to load HubSpot {object_name}.'
    if message:
        detail = f'{detail} {message}'
    elif error_code:
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


def _build_hubspot_item_name(
    object_name: str,
    object_id: str,
    properties: Dict[str, Any],
) -> str:
    if object_name == 'contacts':
        first_name = (properties.get('firstname') or '').strip()
        last_name = (properties.get('lastname') or '').strip()
        full_name = ' '.join(part for part in (first_name, last_name) if part)
        email = (properties.get('email') or '').strip()
        return full_name or email or f'Contact {object_id}'

    if object_name == 'companies':
        company_name = (properties.get('name') or '').strip()
        domain = (properties.get('domain') or '').strip()
        return company_name or domain or f'Company {object_id}'

    if object_name == 'deals':
        deal_name = (properties.get('dealname') or '').strip()
        return deal_name or f'Deal {object_id}'

    return object_id


def _build_hubspot_record_url(
    credentials: Dict[str, Any],
    record_type_id: str,
    object_id: str,
) -> str | None:
    hub_id = credentials.get('hub_id') or credentials.get('hubId') or credentials.get('portal_id')
    if not hub_id:
        return None

    return f'https://app.hubspot.com/contacts/{hub_id}/record/{record_type_id}/{object_id}'


def create_integration_item_metadata_object(
    response_json: Dict[str, Any],
    object_name: str,
    credentials: Dict[str, Any],
) -> IntegrationItem:
    object_id = str(response_json.get('id', '')).strip()
    properties = response_json.get('properties') or {}
    object_config = HUBSPOT_OBJECT_CONFIG[object_name]

    return IntegrationItem(
        id=f'{object_name}:{object_id}',
        type=object_config['label'],
        name=_build_hubspot_item_name(object_name, object_id, properties),
        creation_time=response_json.get('createdAt'),
        last_modified_time=response_json.get('updatedAt'),
        url=_build_hubspot_record_url(
            credentials,
            object_config['record_type_id'],
            object_id,
        ),
    )


async def _refresh_hubspot_access_token(
    credentials: Dict[str, Any],
) -> Dict[str, Any]:
    refresh_token = credentials.get('refresh_token')
    if not isinstance(refresh_token, str) or not refresh_token:
        raise HTTPException(
            status_code=401,
            detail='HubSpot credentials expired and no refresh token is available. Please reconnect.',
        )

    settings = _get_hubspot_settings()
    token_request_data = {
        'grant_type': 'refresh_token',
        'client_id': settings.hubspot_client_id,
        'client_secret': settings.hubspot_client_secret,
        'refresh_token': refresh_token,
    }

    try:
        async with httpx.AsyncClient(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(
                HUBSPOT_TOKEN_URL,
                data=token_request_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail='HubSpot token refresh timed out. Please reconnect.',
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail='Unable to reach HubSpot while refreshing credentials.',
        ) from exc

    if response.is_error:
        raise _token_exchange_error(response)

    try:
        refreshed_credentials = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an invalid token response.',
        ) from exc

    if not isinstance(refreshed_credentials, dict):
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an invalid token response.',
        )

    access_token = refreshed_credentials.get('access_token')
    expires_in = refreshed_credentials.get('expires_in')
    if not access_token or expires_in is None:
        raise HTTPException(
            status_code=502,
            detail='HubSpot returned an incomplete token response.',
        )

    try:
        expires_in = int(expires_in)
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

    updated_credentials = dict(credentials)
    updated_credentials.update(refreshed_credentials)
    updated_credentials['access_token'] = access_token
    updated_credentials['expires_in'] = expires_in
    updated_credentials['expires_at'] = int(time.time()) + expires_in
    updated_credentials['refresh_token'] = (
        refreshed_credentials.get('refresh_token') or refresh_token
    )

    return updated_credentials


async def _ensure_active_credentials(credentials: Dict[str, Any]) -> Dict[str, Any]:
    expires_at = _coerce_timestamp(credentials.get('expires_at'))
    if expires_at is None:
        return credentials

    if expires_at <= int(time.time()) + TOKEN_REFRESH_BUFFER_SECONDS:
        return await _refresh_hubspot_access_token(credentials)

    return credentials


async def _fetch_hubspot_object_items(
    client: httpx.AsyncClient,
    credentials: Dict[str, Any],
    object_name: str,
) -> tuple[list[IntegrationItem], Dict[str, Any]]:
    object_config = HUBSPOT_OBJECT_CONFIG[object_name]
    access_credentials = await _ensure_active_credentials(credentials)
    items: list[IntegrationItem] = []
    after: str | None = None
    seen_cursors: set[str] = set()
    refreshed_after_401 = False

    while True:
        params = {
            'limit': HUBSPOT_PAGE_LIMIT,
            'properties': ','.join(object_config['properties']),
            'archived': 'false',
        }
        if after:
            params['after'] = after

        response = await client.get(
            f'{HUBSPOT_OBJECTS_URL}/{object_name}',
            params=params,
            headers={
                'Authorization': f'Bearer {access_credentials["access_token"]}',
                'Accept': 'application/json',
            },
        )

        if response.status_code == 401 and not refreshed_after_401:
            access_credentials = await _refresh_hubspot_access_token(access_credentials)
            refreshed_after_401 = True
            continue

        if response.is_error:
            raise _hubspot_request_error(response, object_name)

        refreshed_after_401 = False

        try:
            response_data = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=502,
                detail=f'HubSpot returned an invalid {object_name} response.',
            ) from exc

        if not isinstance(response_data, dict):
            raise HTTPException(
                status_code=502,
                detail=f'HubSpot returned an invalid {object_name} response.',
            )

        results = response_data.get('results') or []
        if not isinstance(results, list):
            raise HTTPException(
                status_code=502,
                detail=f'HubSpot returned an invalid {object_name} response.',
            )

        for result in results:
            if isinstance(result, dict) and result.get('id') is not None:
                items.append(
                    create_integration_item_metadata_object(
                        result,
                        object_name,
                        access_credentials,
                    )
                )

        paging = response_data.get('paging') or {}
        next_page = paging.get('next') or {}
        next_after = next_page.get('after')
        if not next_after:
            break

        next_after = str(next_after)
        if next_after in seen_cursors:
            raise HTTPException(
                status_code=502,
                detail=f'HubSpot pagination for {object_name} returned a duplicate cursor.',
            )

        seen_cursors.add(next_after)
        after = next_after

    return items, access_credentials


async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    parsed_credentials = _decode_credentials_payload(credentials)

    try:
        async with httpx.AsyncClient(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as client:
            list_of_integration_item_metadata: list[IntegrationItem] = []
            active_credentials = parsed_credentials
            for object_name in ('contacts', 'companies', 'deals'):
                object_items, active_credentials = await _fetch_hubspot_object_items(
                    client,
                    active_credentials,
                    object_name,
                )
                list_of_integration_item_metadata.extend(object_items)
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail='HubSpot item loading timed out.',
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail='Unable to reach HubSpot while loading items.',
        ) from exc

    return list_of_integration_item_metadata
