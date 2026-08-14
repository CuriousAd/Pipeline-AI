import redis.asyncio as redis

from config import get_settings


settings = get_settings()
redis_client = redis.Redis(
    host=settings.redis_host,
    port=settings.redis_port,
    db=0,
)


async def add_key_value_redis(key, value, expire=None):
    await redis_client.set(key, value, ex=expire)


async def get_value_redis(key):
    return await redis_client.get(key)


async def get_and_delete_value_redis(key):
    return await redis_client.getdel(key)


async def delete_key_redis(key):
    await redis_client.delete(key)
