"""
Utility functions for reverse engineering services
"""

import asyncio
import functools
import logging
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)


def async_retry(
    max_attempts: int = 3,
    delay_seconds: float = 1.0,
    backoff_multiplier: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    Async retry decorator with exponential backoff.

    Usage:
        @async_retry(max_attempts=5, delay_seconds=2.0)
        async def call_api():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            delay = delay_seconds
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        await asyncio.sleep(delay)
                        delay *= backoff_multiplier
                    else:
                        logger.error(
                            f"All {max_attempts} attempts failed for {func.__name__}: {e}"
                        )

            if last_exception:
                raise last_exception

        return wrapper
    return decorator


def gemini_retry(max_attempts: int = 3, delay_seconds: float = 2.0):
    """
    Specialized retry decorator for Gemini API calls.
    Handles rate limiting and transient errors.
    """
    return async_retry(
        max_attempts=max_attempts,
        delay_seconds=delay_seconds,
        backoff_multiplier=2.0,
        exceptions=(
            Exception,  # Catch all for now
            # genai.types.BlockedPromptException,  # Add specific exceptions as needed
        )
    )


__all__ = [
    'async_retry',
    'gemini_retry',
]
