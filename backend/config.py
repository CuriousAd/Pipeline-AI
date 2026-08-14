import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / '.env')


def _optional_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None

    value = value.strip()
    return value or None


def _redis_port() -> int:
    raw_port = os.getenv('REDIS_PORT', '6379')
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError('REDIS_PORT must be an integer.') from exc

    if not 1 <= port <= 65535:
        raise ValueError('REDIS_PORT must be between 1 and 65535.')

    return port


@dataclass(frozen=True)
class Settings:
    hubspot_client_id: Optional[str]
    hubspot_client_secret: Optional[str]
    hubspot_redirect_uri: str
    airtable_client_id: Optional[str]
    airtable_client_secret: Optional[str]
    airtable_redirect_uri: str
    redis_host: str
    redis_port: int
    frontend_origin: str


@lru_cache
def get_settings() -> Settings:
    return Settings(
        hubspot_client_id=_optional_env('HUBSPOT_CLIENT_ID'),
        hubspot_client_secret=_optional_env('HUBSPOT_CLIENT_SECRET'),
        hubspot_redirect_uri=os.getenv(
            'HUBSPOT_REDIRECT_URI',
            'http://localhost:8000/integrations/hubspot/oauth2callback',
        ),
        airtable_client_id=_optional_env('AIRTABLE_CLIENT_ID'),
        airtable_client_secret=_optional_env('AIRTABLE_CLIENT_SECRET'),
        airtable_redirect_uri=os.getenv(
            'AIRTABLE_REDIRECT_URI',
            'http://localhost:8000/integrations/airtable/oauth2callback',
        ),
        redis_host=os.getenv('REDIS_HOST', 'localhost'),
        redis_port=_redis_port(),
        frontend_origin=os.getenv('FRONTEND_ORIGIN', 'http://localhost:3000'),
    )
