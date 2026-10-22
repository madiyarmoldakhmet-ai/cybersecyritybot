"""
Centralized Logging for Aegis / Commit Guardian.
One configuration for the API server, the Telegram bot and the webhook pipeline:
human-readable or JSON output (for SIEM ingestion) and automatic masking of secrets.
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import List, Optional

from aegis.core.config import settings

_CONFIGURED = False

# Credentials embedded in clone URLs, e.g. https://x-access-token:<token>@github.com/...
_URL_CREDENTIALS = re.compile(r"(https?://[^/\s:@]+:)[^@\s]+@")
# Well-known token formats: GitHub, OpenRouter/OpenAI, Telegram bot tokens
_TOKEN_PATTERNS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
]
_NOISY_LOGGERS = ("httpx", "httpcore", "aiogram.event", "multipart", "openai._base_client")


def _configured_secrets() -> List[str]:
    values = [
        settings.telegram_bot_token,
        settings.github_token,
        settings.github_client_secret,
        settings.github_webhook_secret,
        settings.openrouter_api_key,
        settings.gemini_api_key,
    ]
    return [v for v in values if v and len(v) >= 8]


def redact(text: str) -> str:
    """Mask secrets in a log message."""
    for secret in _configured_secrets():
        text = text.replace(secret, "***")
    text = _URL_CREDENTIALS.sub(r"\1***@", text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub("***", text)
    return text


class SecretRedactionFilter(logging.Filter):
    """Masks tokens and passwords before a record reaches any handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg = redact(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


class JSONFormatter(logging.Formatter):
    """One JSON object per line, ready for ELK / Splunk / any SIEM."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_text:
            payload["exception"] = record.exc_text
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: Optional[str] = None, fmt: Optional[str] = None) -> None:
    """Configure the root logger once; safe to call from every entrypoint."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(SecretRedactionFilter())
    if (fmt or settings.log_format).lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s"))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, (level or settings.log_level).upper(), logging.INFO))

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    # Uvicorn installs its own handlers; route them through ours so redaction and format apply
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv = logging.getLogger(name)
        uv.handlers = []
        uv.propagate = True

    _CONFIGURED = True
