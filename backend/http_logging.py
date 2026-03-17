"""Helpers to log outbound HTTP calls and payloads."""
from __future__ import annotations

import json
from typing import Any, Mapping, Optional

import requests

from logging_utils import get_user_logger


_LOGGER = get_user_logger()
_INSTALLED = False
_ORIGINAL_SESSION_REQUEST = requests.sessions.Session.request


def _format_payload(payload: Any) -> str:
    try:
        return json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        return repr(payload)


def _extract_sent_payload(kwargs: Mapping[str, Any]) -> Optional[Any]:
    if "json" in kwargs:
        return kwargs.get("json")
    if "data" in kwargs:
        return kwargs.get("data")
    return None


def install_http_logging() -> None:
    """Install a requests hook that logs method/endpoint and key payloads."""
    global _INSTALLED
    if _INSTALLED:
        return

    def _logged_request(self: requests.sessions.Session, method: str, url: str, **kwargs: Any):
        method_upper = (method or "").upper()
        _LOGGER.info("HTTP %s %s", method_upper, url)

        sent_payload = _extract_sent_payload(kwargs)
        if method_upper != "GET" and sent_payload is not None:
            _LOGGER.info("HTTP %s %s payload_sent=%s", method_upper, url, _format_payload(sent_payload))

        response = _ORIGINAL_SESSION_REQUEST(self, method, url, **kwargs)

        if method_upper == "GET":
            try:
                response_payload = response.json()
            except Exception:
                response_payload = response.text
            _LOGGER.info("HTTP %s %s payload_received=%s", method_upper, url, _format_payload(response_payload))

        return response

    requests.sessions.Session.request = _logged_request
    _INSTALLED = True


__all__ = ["install_http_logging"]
