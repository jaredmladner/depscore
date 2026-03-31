import asyncio
import random
from abc import ABC
from typing import Any, TypeVar

import httpx

from depscore.exceptions import (
    AuthenticationError,
    NetworkError,
    NotFoundError,
    RateLimitError,
)

T = TypeVar("T")


class BaseEnricher(ABC):
    def __init__(self, timeout: float = 30.0, max_retries: int = 3) -> None:
        self.timeout = timeout
        self.max_retries = max_retries

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = await client.get(url, headers=headers or {}, params=params or {})
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    await asyncio.sleep(retry_after)
                    raise RateLimitError(
                        f"Rate limited by {url}", retry_after=retry_after
                    )
                if resp.status_code == 401 or resp.status_code == 403:
                    raise AuthenticationError(
                        f"Auth error {resp.status_code} from {url}"
                    )
                if resp.status_code == 404:
                    raise NotFoundError(f"Not found: {url}")
                if resp.status_code >= 500:
                    resp.raise_for_status()
                resp.raise_for_status()
                return resp.json()
            except (RateLimitError, NotFoundError, AuthenticationError):
                raise
            except httpx.TimeoutException as exc:
                last_exc = NetworkError(f"Timeout fetching {url}: {exc}")
            except httpx.HTTPStatusError as exc:
                last_exc = exc
            except Exception as exc:
                last_exc = exc

            wait = (2**attempt) + random.uniform(0, 1)
            await asyncio.sleep(wait)

        raise NetworkError(
            f"Failed after {self.max_retries} retries: {url}"
        ) from last_exc

    async def _post(
        self,
        client: httpx.AsyncClient,
        url: str,
        json_body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = await client.post(url, json=json_body, headers=headers or {})
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    await asyncio.sleep(retry_after)
                    raise RateLimitError(
                        f"Rate limited by {url}", retry_after=retry_after
                    )
                if resp.status_code >= 500:
                    resp.raise_for_status()
                resp.raise_for_status()
                return resp.json()
            except (RateLimitError,):
                raise
            except httpx.TimeoutException as exc:
                last_exc = NetworkError(f"Timeout posting to {url}: {exc}")
            except httpx.HTTPStatusError as exc:
                last_exc = exc
            except Exception as exc:
                last_exc = exc

            wait = (2**attempt) + random.uniform(0, 1)
            await asyncio.sleep(wait)

        raise NetworkError(
            f"POST failed after {self.max_retries} retries: {url}"
        ) from last_exc
