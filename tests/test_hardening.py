"""
Security hardening tests: local-only LLM policy, log redaction, webhook and API hardening.
"""

import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core.config import LLMProvider, Settings, settings
from aegis.core.logging_config import JSONFormatter, SecretRedactionFilter, redact

CLOUD_ENV = ("LLM_PROVIDER", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "ALLOW_CLOUD_LLM", "USE_LOCAL_LLM")


@pytest.fixture
def clean_env(monkeypatch):
    for name in CLOUD_ENV:
        monkeypatch.delenv(name, raising=False)


def test_defaults_are_local_only(clean_env):
    s = Settings(_env_file=None)
    assert s.llm_provider == LLMProvider.OLLAMA
    assert s.allow_cloud_llm is False
    assert s.air_gapped is True
    assert s.llm_policy_notices == []


def test_cloud_provider_is_ignored_without_explicit_opt_in(clean_env):
    s = Settings(_env_file=None, llm_provider="openrouter", openrouter_api_key="sk-or-v1-abcdef1234567890",
                 gemini_api_key="gemini-key-123456")
    assert s.llm_provider == LLMProvider.OLLAMA
    assert s.openrouter_api_key is None
    assert s.gemini_api_key is None
    assert s.air_gapped is True
    assert any("ALLOW_CLOUD_LLM" in n for n in s.llm_policy_notices)


def test_cloud_provider_requires_and_honours_opt_in(clean_env):
    s = Settings(_env_file=None, allow_cloud_llm=True, llm_provider="openrouter", openrouter_api_key="sk-or-v1-abcdef1234567890")
    assert s.llm_provider == LLMProvider.OPENROUTER
    assert s.openrouter_api_key == "sk-or-v1-abcdef1234567890"
    assert s.air_gapped is False
    assert any("ENABLED" in n for n in s.llm_policy_notices)


def test_ai_components_target_local_ollama_by_default(monkeypatch):
    from aegis.scanners.ai_filter import AIFalsePositiveFilter

    monkeypatch.setattr(settings, "llm_provider", LLMProvider.OLLAMA)
    monkeypatch.setattr(settings, "openrouter_api_key", None)
    ai_filter = AIFalsePositiveFilter()
    assert ai_filter.enabled
    assert str(ai_filter.client.base_url).startswith(settings.ollama_base_url)


def test_redact_masks_tokens_and_url_credentials(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", "my-configured-telegram-secret")
    text = (
        "clone https://x-access-token:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/gov/portal.git "
        "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 key=sk-or-v1-0123456789abcdef0123 "
        "bot=my-configured-telegram-secret"
    )
    out = redact(text)
    assert "ghp_" not in out
    assert "sk-or-v1" not in out
    assert "my-configured-telegram-secret" not in out
    assert "https://x-access-token:***@github.com/gov/portal.git" in out


def test_log_records_are_redacted_and_json_formatted():
    record = logging.LogRecord(
        "aegis.test", logging.INFO, __file__, 1,
        "cloning %s", ("https://x-access-token:supersecret123@github.com/a/b.git",), None,
    )
    assert SecretRedactionFilter().filter(record) is True
    line = JSONFormatter().format(record)
    payload = json.loads(line)
    assert payload["level"] == "INFO" and payload["logger"] == "aegis.test"
    assert "supersecret123" not in line
    assert payload["message"] == "cloning https://x-access-token:***@github.com/a/b.git"


def test_unsigned_webhooks_rejected_in_production(monkeypatch):
    from web.webhook import verify_github_signature

    monkeypatch.setattr(settings, "github_webhook_secret", None)
    monkeypatch.setattr(settings, "environment", "production")
    assert verify_github_signature(b"{}", None) is False

    monkeypatch.setattr(settings, "environment", "development")
    assert verify_github_signature(b"{}", None) is True


def test_cors_never_uses_wildcard(clean_env):
    s = Settings(_env_file=None, web_app_url="https://guardian.gov.kz/", cors_allow_origins="*, https://admin.gov.kz")
    assert s.cors_origins == ["https://guardian.gov.kz", "https://admin.gov.kz"]


@pytest.mark.asyncio
async def test_server_errors_do_not_leak_details():
    from starlette.requests import Request

    from aegis_server.main import global_error

    request = Request({"type": "http", "method": "GET", "path": "/boom", "headers": [], "query_string": b""})
    response = await global_error(request, RuntimeError("/etc/aegis/secret.key not readable"))
    body = json.loads(response.body)
    assert response.status_code == 500
    assert body["error"] == "Internal server error"
    assert "secret.key" not in response.body.decode()
    assert len(body["error_id"]) == 12


def test_env_example_loads_and_is_local_only(clean_env, monkeypatch):
    for name in ("ALLOWED_TELEGRAM_USERS", "CORS_ALLOW_ORIGINS", "DEFAULT_TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(name, raising=False)
    env_example = Path(__file__).resolve().parent.parent / ".env.example"
    s = Settings(_env_file=env_example)
    assert s.allowed_telegram_users == [12345678, 87654321]
    assert s.default_telegram_chat_id is None
    assert s.llm_provider == LLMProvider.OLLAMA and s.air_gapped


def test_sanitizer_drops_short_literal_secret_false_positives():
    from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding
    from aegis.scanners.sanitizer import FalsePositiveSanitizer

    def secret_finding(snippet: str) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            id="generic-api-key", scanner=ScannerType.SECRET, title="Hardcoded Generic API Key",
            description="", severity=Severity.CRITICAL, file_path="aegis/ai/client.py", code_snippet=snippet,
        )

    sanitizer = FalsePositiveSanitizer()
    assert sanitizer.sanitize_finding(secret_finding('api_key="ollama",')) is None
    assert sanitizer.sanitize_finding(secret_finding('SECRET = "secret"')) is None
    real = secret_finding('api_key = "sk_live_9fA2xQ7mZ4LwP1vR8tYc3K"')
    assert sanitizer.sanitize_finding(real) is real


def test_dast_verifies_tls_by_default(clean_env):
    from aegis.scanners.http_dast import HTTPSecurityScanner

    assert HTTPSecurityScanner().verify_tls is True
    assert HTTPSecurityScanner(verify_tls=False).verify_tls is False
