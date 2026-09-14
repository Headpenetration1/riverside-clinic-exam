"""Thin client for the Cerebras chat completions API (OpenAI-compatible).

Design points:
- The API key is read at call time from a getter, is only ever placed in the
  Authorization header, and is never logged or returned.
- Every failure mode (network, non-200, malformed JSON, unexpected shape)
  becomes one exception type with a short generic message. The controller
  turns that into a 502 without leaking upstream details to the client.
- A hard timeout so a slow upstream cannot pin our worker.
"""
import logging

import requests

log = logging.getLogger(__name__)


class ChatUpstreamError(Exception):
    """Raised for any problem talking to the model provider."""


class CerebrasClient:
    def __init__(self, api_key_getter, model: str, url: str, timeout: int = 20):
        self._get_key = api_key_getter
        self.model = model
        self.url = url
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self._get_key())

    def chat(self, messages: list[dict], max_tokens: int = 400) -> str:
        key = self._get_key()
        if not key:
            raise ChatUpstreamError("assistant not configured")

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(self.url, json=payload, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            # exc may contain the URL; it never contains the header, but keep it out of the message anyway
            log.warning("cerebras request failed: %s", type(exc).__name__)
            raise ChatUpstreamError("upstream request failed") from None

        if resp.status_code != 200:
            log.warning("cerebras returned HTTP %s", resp.status_code)
            raise ChatUpstreamError(f"upstream returned HTTP {resp.status_code}")

        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            log.warning("cerebras returned a response we could not parse")
            raise ChatUpstreamError("malformed upstream response") from None

        if not isinstance(content, str):
            raise ChatUpstreamError("malformed upstream response")
        return content
