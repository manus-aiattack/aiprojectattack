import asyncio
import secrets
import os
from dotenv import load_dotenv

# Assuming redis_config is in a reachable path
from database.redis_config import RedisManager

# Load environment variables
load_dotenv()

# Session configuration
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", 3600)) # 1 hour default

class SessionManager:
    """Manages user sessions using Redis."""

    @staticmethod
    async def create_session(user_id: str) -> str:
        """
        Creates a new session for a user and returns the session ID.

        Args:
            user_id: The unique identifier for the user.

        Returns:
            The generated session ID.
        """
        session_id = secrets.token_urlsafe(32)
        redis_conn = await RedisManager.get_connection()
        try:
            session_key = f"session:{session_id}"
            await redis_conn.set(session_key, user_id, ex=SESSION_TTL_SECONDS)
            print(f"Created session {session_id} for user {user_id}")
            return session_id
        finally:
            await redis_conn.close()

    @staticmethod
    async def validate_session(session_id: str) -> str | None:
        """
        Validates a session ID and returns the user ID if valid.

        Args:
            session_id: The session ID to validate.

        Returns:
            The user ID if the session is valid, otherwise None.
        """
        redis_conn = await RedisManager.get_connection()
        try:
            session_key = f"session:{session_id}"
            user_id = await redis_conn.get(session_key)
            if user_id:
                # Refresh the session TTL on activity
                await redis_conn.expire(session_key, SESSION_TTL_SECONDS)
            return user_id
        finally:
            await redis_conn.close()

    @staticmethod
    async def terminate_session(session_id: str):
        """
        Terminates a user session.

        Args:
            session_id: The session ID to terminate.
        """
        redis_conn = await RedisManager.get_connection()
        try:
            session_key = f"session:{session_id}"
            await redis_conn.delete(session_key)
            print(f"Terminated session {session_id}")
        finally:
            await redis_conn.close()

# Example Usage
async def main():
    test_user_id = "user-abc-123"
    print(f"Testing session management for user: {test_user_id}")

    # Create a session
    session_id = await SessionManager.create_session(test_user_id)
    print(f"  - Session created with ID: {session_id}")

    # Validate the session
    validated_user_id = await SessionManager.validate_session(session_id)
    print(f"  - Validating session... User ID is: {validated_user_id}")
    assert validated_user_id == test_user_id

    # Terminate the session
    await SessionManager.terminate_session(session_id)
    print(f"  - Session terminated.")

    # Try to validate again
    validated_user_id_after_termination = await SessionManager.validate_session(session_id)
    print(f"  - Validating after termination... User ID is: {validated_user_id_after_termination}")
    assert validated_user_id_after_termination is None

    print("\nSession management test completed successfully.")
    await RedisManager.close_pool()

if __name__ == "__main__":
    # Ensure Redis is running and accessible
    # asyncio.run(main())
    print("Run this module within an async context to test.")