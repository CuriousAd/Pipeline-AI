import asyncio
import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode

import httpx
import requests
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

from config import get_settings
from integrations.integration_item import IntegrationItem
from redis_client import (
    add_key_value_redis,
    delete_key_redis,
    get_value_redis,
)

AIRTABLE_AUTHORIZATION_URL = 'https://airtable.com/oauth2/v1/authorize'
AIRTABLE_SCOPE = (
    'data.records:read data.records:write '
    'data.recordComments:read data.recordComments:write '
    'schema.bases:read schema.bases:write'
)


def _get_airtable_settings():
    settings = get_settings()
    if not settings.airtable_client_id or not settings.airtable_client_secret:
        raise HTTPException(
            status_code=500,
            detail=(
                'Airtable OAuth is not configured. Set AIRTABLE_CLIENT_ID '
                'and AIRTABLE_CLIENT_SECRET.'
            ),
        )

    return settings


async def authorize_airtable(user_id, org_id):
    settings = _get_airtable_settings()
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')

    authorization_params = {
        'client_id': settings.airtable_client_id,
        'response_type': 'code',
        'owner': 'user',
        'redirect_uri': settings.airtable_redirect_uri,
        'state': encoded_state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'scope': AIRTABLE_SCOPE,
    }
    auth_url = f'{AIRTABLE_AUTHORIZATION_URL}?{urlencode(authorization_params)}'
    await asyncio.gather(
        add_key_value_redis(f'airtable_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'airtable_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )

    return auth_url

async def oauth2callback_airtable(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'airtable_state:{org_id}:{user_id}'),
        get_value_redis(f'airtable_verifier:{org_id}:{user_id}'),
    )

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    settings = _get_airtable_settings()
    encoded_client_id_secret = base64.b64encode(
        f'{settings.airtable_client_id}:{settings.airtable_client_secret}'.encode()
    ).decode()

    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://airtable.com/oauth2/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': settings.airtable_redirect_uri,
                    'client_id': settings.airtable_client_id,
                    'code_verifier': code_verifier.decode('utf-8'),
                },
                headers={
                    'Authorization': f'Basic {encoded_client_id_secret}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'airtable_state:{org_id}:{user_id}'),
            delete_key_redis(f'airtable_verifier:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'airtable_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_airtable_credentials(user_id, org_id):
    credentials = await get_value_redis(f'airtable_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'airtable_credentials:{org_id}:{user_id}')

    return credentials

def create_integration_item_metadata_object(
    response_json: str, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    parent_id = None if parent_id is None else parent_id + '_Base'
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None) + '_' + item_type,
        name=response_json.get('name', None),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )

    return integration_item_metadata


def fetch_items(
    access_token: str, url: str, aggregated_response: list, offset=None
) -> dict:
    """Fetching the list of bases"""
    params = {'offset': offset} if offset is not None else {}
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        results = response.json().get('bases', {})
        offset = response.json().get('offset', None)

        for item in results:
            aggregated_response.append(item)

        if offset is not None:
            fetch_items(access_token, url, aggregated_response, offset)
        else:
            return


async def get_items_airtable(credentials) -> list[IntegrationItem]:
    credentials = json.loads(credentials)
    url = 'https://api.airtable.com/v0/meta/bases'
    list_of_integration_item_metadata = []
    list_of_responses = []

    fetch_items(credentials.get('access_token'), url, list_of_responses)
    for response in list_of_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'Base')
        )
        tables_response = requests.get(
            f'https://api.airtable.com/v0/meta/bases/{response.get("id")}/tables',
            headers={'Authorization': f'Bearer {credentials.get("access_token")}'},
        )
        if tables_response.status_code == 200:
            tables_response = tables_response.json()
            for table in tables_response['tables']:
                list_of_integration_item_metadata.append(
                    create_integration_item_metadata_object(
                        table,
                        'Table',
                        response.get('id', None),
                        response.get('name', None),
                    )
                )

    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata
