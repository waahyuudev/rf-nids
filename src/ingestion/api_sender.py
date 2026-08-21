"""Bounded-retry HTTP delivery to the existing classification API."""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable, Sequence
from typing import Any

import requests

from .models import AdaptedFlow

logger = logging.getLogger(__name__)


class ApiSendError(RuntimeError):
    pass


class ApiSender:
    def __init__(
        self,
        base_url: str,
        *,
        max_retries: int = 3,
        retry_delay_seconds: float = 2,
        timeout_seconds: float = 10,
        post: Callable[..., Any] = requests.post,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = f"{base_url.rstrip('/')}/api/predict/batch"
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds
        self.timeout_seconds = timeout_seconds
        self._post = post
        self._sleep = sleep

    def send(self, flows: Sequence[AdaptedFlow]) -> list[dict[str, Any]]:
        if not flows:
            return []
        payload = {
            "flows": [
                {"features": flow.features, "metadata": flow.metadata or None}
                for flow in flows
            ]
        }
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._post(self.url, json=payload, timeout=self.timeout_seconds)
                response.raise_for_status()
                predictions = response.json()["predictions"]
                if not isinstance(predictions, list) or len(predictions) != len(flows):
                    raise ValueError(
                        "API response prediction count does not match submitted flow count"
                    )
                for prediction in predictions:
                    if not isinstance(prediction, dict) or prediction.get("prediction") not in {
                        "Normal", "DDoS", "PortScan"
                    }:
                        raise ValueError(
                            f"API returned invalid prediction result {prediction!r}"
                        )
                counts = Counter(item["prediction"] for item in predictions)
                logger.info(
                    "API batch success flows=%d Normal=%d DDoS=%d PortScan=%d",
                    len(predictions), counts["Normal"], counts["DDoS"], counts["PortScan"],
                )
                return predictions
            except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
                last_error = exc
                logger.warning(
                    "API request failed attempt=%d/%d error=%s",
                    attempt + 1, self.max_retries + 1, exc,
                )
                if attempt < self.max_retries:
                    self._sleep(self.retry_delay_seconds * (2**attempt))
        raise ApiSendError(f"API batch failed after {self.max_retries + 1} attempts") from last_error
