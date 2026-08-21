from __future__ import annotations

import requests

import pytest

from src.ingestion.api_sender import ApiSendError, ApiSender
from src.ingestion.models import AdaptedFlow


class FakeResponse:
    def __init__(self, payload=None, error: Exception | None = None):
        self.payload = payload
        self.error = error

    def raise_for_status(self):
        if self.error:
            raise self.error

    def json(self):
        return self.payload


def flow() -> AdaptedFlow:
    return AdaptedFlow(features={"a": 1.0}, metadata={"source_ip": "10.0.0.1"})


def test_sender_posts_batch_contract() -> None:
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({"predictions": [{"prediction": "Normal"}]})

    result = ApiSender("http://api:8000/", post=post).send([flow()])
    assert result[0]["prediction"] == "Normal"
    assert calls[0][0] == "http://api:8000/api/predict/batch"
    assert calls[0][1]["json"]["flows"][0]["features"] == {"a": 1.0}


def test_sender_retries_with_bound_and_delay() -> None:
    attempts = 0
    delays = []

    def post(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return FakeResponse(error=requests.ConnectionError("offline"))
        return FakeResponse({"predictions": [{"prediction": "DDoS"}]})

    sender = ApiSender(
        "http://api", max_retries=2, retry_delay_seconds=0.25,
        post=post, sleep=delays.append,
    )
    assert sender.send([flow()])[0]["prediction"] == "DDoS"
    assert attempts == 3
    assert delays == [0.25, 0.5]


def test_sender_raises_after_retry_limit() -> None:
    def post(*args, **kwargs):
        return FakeResponse(error=requests.ConnectionError("offline"))

    with pytest.raises(ApiSendError, match="2 attempts"):
        ApiSender("http://api", max_retries=1, post=post, sleep=lambda _: None).send([flow()])
