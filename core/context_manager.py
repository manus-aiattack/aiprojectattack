import json
from typing import Any, Dict, Optional
import asyncio
from core.logger import log
from core.redis_client import get_redis_client # Use the new lazy-initialized client

class ContextManager:
    """
    Manages shared context data using Redis, providing concurrency control and real-time updates.
    This replaces the in-memory SharedDataContext.
    """
    def __init__(self, context_key: str = "global_context"):
        self.context_key = context_key
        self.redis = None # Initialize to None

    async def setup(self):
        """Asynchronously sets up the Redis client connection."""
        try:
            self.redis = await get_redis_client()
        except ConnectionError as e:
            log.critical(f"ContextManager failed to connect to Redis: {e}")
            raise

    async def get_context(self, field: Optional[str] = None) -> Any:
        """
        Retrieves the entire context or a specific field from Redis.
        """
        try:
            if field:
                value = await self.redis.hget(self.context_key, field)
                if value is None:
                    return None
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                return json.loads(value)
            else:
                full_context = await self.redis.hgetall(self.context_key)
                return {(k.decode('utf-8') if isinstance(k, bytes) else k): json.loads(v.decode('utf-8') if isinstance(v, bytes) else v) for k, v in full_context.items()}
        except Exception as e:
            log.error(f"Error getting context from Redis (field: {field}): {e}")
            return None

    async def set_context(self, field: str, value: Any):
        """
        Sets a specific field in the context with a new value.
        """
        try:
            await self.redis.hset(self.context_key, field, json.dumps(value))
            log.debug(f"Context field '{field}' set in Redis.")
        except Exception as e:
            log.error(f"Error setting context in Redis (field: {field}): {e}")

    async def update_context(self, updates: Dict[str, Any]):
        """
        Updates multiple fields in the context.
        """
        try:
            # Use a mapping dictionary for hmset
            mapping = {field: json.dumps(value) for field, value in updates.items()}
            await self.redis.hmset(self.context_key, mapping)
            log.debug(f"Context updated with fields: {list(updates.keys())}")
        except Exception as e:
            log.error(f"Error updating context in Redis: {e}")

    async def delete_context_field(self, field: str):
        """
        Deletes a specific field from the context.
        """
        try:
            await self.redis.hdel(self.context_key, field)
            log.debug(f"Context field '{field}' deleted from Redis.")
        except Exception as e:
            log.error(f"Error deleting context field '{field}' from Redis: {e}")

    async def clear_context(self):
        """
        Clears all fields from the context.
        """
        try:
            await self.redis.delete(self.context_key)
            log.debug(f"Context '{self.context_key}' cleared from Redis.")
        except Exception as e:
            log.error(f"Error clearing context '{self.context_key}' from Redis: {e}")

    # --- Event Publishing/Subscription (Optional, for real-time notifications) ---
    async def publish_event(self, channel: str, message: Dict[str, Any]):
        """
        Publishes a message to a Redis Pub/Sub channel.
        """
        try:
            await self.redis.publish(channel, json.dumps(message))
            log.debug(f"Published event to channel '{channel}'.")
        except Exception as e:
            log.error(f"Error publishing event to channel '{channel}': {e}")

    async def subscribe_to_channel(self, channel: str, handler_func):
        """
        Subscribes to a Redis Pub/Sub channel and calls handler_func for each message.
        Note: This is a blocking operation for the current coroutine.
        """
        try:
            pubsub = self.redis.pubsub()
            await pubsub.subscribe(channel)
            log.info(f"Subscribed to Redis channel '{channel}'.")
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    data = json.loads(message['data'])
                    await handler_func(data)
        except Exception as e:
            log.error(f"Error subscribing to channel '{channel}': {e}")


    async def cleanup(self):
        """
        Cleanup resources (Redis connection is managed globally, so nothing to do here)
        """
        log.debug("ContextManager cleanup called (no action needed)")
        pass

