"""HTTP client utilities for CVElk services."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from loguru import logger
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)


class RateLimiter:
    """Simple rate limiter for API requests.

    Implements a sliding window rate limiter to comply with API rate limits.
    """

    def __init__(self, requests_per_window: int, window_seconds: int = 30):
        """Initialize rate limiter.

        Args:
            requests_per_window: Maximum requests allowed per window.
            window_seconds: Window duration in seconds.
        """
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._request_times: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request, waiting if necessary."""
        async with self._lock:
            now = asyncio.get_event_loop().time()

            # Remove requests outside the current window
            self._request_times = [t for t in self._request_times if now - t < self.window_seconds]

            # If at limit, wait until oldest request expires
            if len(self._request_times) >= self.requests_per_window:
                oldest = self._request_times[0]
                wait_time = self.window_seconds - (now - oldest) + 0.1
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.1f}s")
                    await asyncio.sleep(wait_time)
                    # Re-acquire current time after sleeping
                    now = asyncio.get_event_loop().time()
                    self._request_times = [
                        t for t in self._request_times if now - t < self.window_seconds
                    ]

            self._request_times.append(now)


class HTTPClientError(Exception):
    """Base exception for HTTP client errors."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class RetryableHTTPError(HTTPClientError):
    """HTTP error that can be retried."""


class NonRetryableHTTPError(HTTPClientError):
    """HTTP error that should not be retried."""


@asynccontextmanager
async def create_http_client(
    timeout: int = 30,
    **kwargs: Any,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an async HTTP client with sensible defaults.

    Args:
        timeout: Request timeout in seconds.
        **kwargs: Additional arguments passed to httpx.AsyncClient.

    Yields:
        Configured httpx.AsyncClient instance.
    """
    # Remove timeout from kwargs if accidentally passed there too
    kwargs.pop("timeout", None)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        **kwargs,
    ) as client:
        yield client


def create_retry_decorator(
    max_attempts: int = 3,
    min_wait: int = 4,
    max_wait: int = 60,
) -> Any:
    """Create a tenacity retry decorator for HTTP requests.

    Args:
        max_attempts: Maximum number of retry attempts.
        min_wait: Minimum wait time between retries (seconds).
        max_wait: Maximum wait time between retries (seconds).

    Returns:
        Configured retry decorator.
    """
    return retry(
        retry=retry_if_exception_type(
            (RetryableHTTPError, httpx.TimeoutException, httpx.NetworkError)
        ),
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        before_sleep=lambda retry_state: logger.warning(
            f"Retrying request (attempt {retry_state.attempt_number}): "
            f"{retry_state.outcome.exception() if retry_state.outcome else 'unknown error'}"
        ),
    )


async def handle_response(response: httpx.Response) -> dict[str, Any]:
    """Handle HTTP response and raise appropriate exceptions.

    Args:
        response: httpx Response object.

    Returns:
        Parsed JSON response data.

    Raises:
        RetryableHTTPError: For 5xx errors and rate limiting.
        NonRetryableHTTPError: For 4xx errors (except 429).
    """
    if response.status_code == 200:
        result: dict[str, Any] = response.json()
        return result

    error_msg = f"HTTP {response.status_code}: {response.text[:200]}"

    # Rate limiting - retryable
    if response.status_code == 429:
        logger.warning("Rate limited by server")
        raise RetryableHTTPError(error_msg, response.status_code)

    # Server errors - retryable
    if response.status_code >= 500:
        logger.warning(f"Server error: {error_msg}")
        raise RetryableHTTPError(error_msg, response.status_code)

    # Client errors - not retryable
    if response.status_code >= 400:
        logger.error(f"Client error: {error_msg}")
        raise NonRetryableHTTPError(error_msg, response.status_code)

    final_result: dict[str, Any] = response.json()
    return final_result
