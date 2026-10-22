"""
Configuration module for Aegis.
Uses Pydantic Settings for strictly typed, environment-driven configuration.
"""

from enum import Enum
from pathlib import Path
from typing import Annotated, List, Optional
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        env_ignore_empty=True,  # "KEY=" in .env means "not set", not an empty value
    )

    # Policy messages produced while loading settings, logged at startup (always computed, never read from env)
    llm_policy_notices: List[str] = Field(default_factory=list, exclude=True)

    # General App Settings
    app_name: str = Field(default="Aegis", description="Application name")
    environment: str = Field(default="development", description="Runtime environment")
    debug: bool = Field(default=False, description="Enable debug logging and detailed errors")
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="text", description="Log output format: 'text' or 'json' (for SIEM ingestion)")

    # Telegram Bot Settings
    telegram_bot_token: Optional[str] = Field(
        default=None,
        description="Telegram Bot API Token (from @BotFather)"
    )
    # NoDecode: accept "123,456" from env instead of requiring a JSON list
    allowed_telegram_users: Annotated[List[int], NoDecode] = Field(
        default_factory=list,
        description="List of allowed Telegram User IDs for access control"
    )
    default_telegram_chat_id: Optional[int] = Field(
        default=None,
        description="Default Telegram Chat ID for Webhook Commit Guardian alerts"
    )
    web_app_url: str = Field(
        default="http://localhost:3000",
        description="URL of the frontend Next.js application for Telegram Web App integration"
    )
    cors_allow_origins: Annotated[List[str], NoDecode] = Field(
        default_factory=list,
        description="Extra origins allowed to call the API from a browser (comma-separated); web_app_url is always allowed"
    )

    # GitHub OAuth & Integration
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub Personal Access Token for PR creation & scanning"
    )
    github_client_id: Optional[str] = Field(
        default=None,
        description="GitHub OAuth App Client ID"
    )
    github_client_secret: Optional[str] = Field(
        default=None,
        description="GitHub OAuth App Client Secret"
    )
    github_webhook_secret: Optional[str] = Field(
        default=None,
        description="GitHub Webhook HMAC Secret for signature validation"
    )

    # Concurrency & Queue Settings
    max_concurrent_llm_jobs: int = Field(
        default=1,
        description="Maximum concurrent inference requests to local Ollama model to protect host resources"
    )

    # AI / LLM Engine Settings
    # Privacy by default: source code is only ever sent to the local Ollama model.
    # Cloud providers stay disabled unless ALLOW_CLOUD_LLM=true is set explicitly.
    allow_cloud_llm: bool = Field(
        default=False,
        description="Opt-in to cloud LLM providers (OpenRouter/Gemini). When false, all AI runs on local Ollama"
    )
    use_local_llm: bool = Field(
        default=True,
        description="Force use of local Ollama for all AI operations"
    )
    llm_provider: LLMProvider = Field(
        default=LLMProvider.OLLAMA,
        description="Active LLM provider: 'ollama', 'gemini' or 'openrouter' (cloud ones need ALLOW_CLOUD_LLM=true)"
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL"
    )
    ollama_model: str = Field(
        default="qwen2.5-coder:14b",
        description="Local Ollama model name"
    )
    gemini_api_key: Optional[str] = Field(
        default=None,
        description="Google Gemini API key for fallback/cloud inference"
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        description="Gemini model identifier"
    )
    openrouter_api_key: Optional[str] = Field(
        default=None,
        description="OpenRouter API key for Claude 3.5/GPT-4o cloud inference"
    )
    openrouter_model: str = Field(
        default="anthropic/claude-sonnet-5",
        description="OpenRouter model identifier"
    )

    # Aegis Deep Agentic Pentest Engine Settings (Apache-2.0)
    aegis_enabled: bool = Field(
        default=True,
        description="Enable Aegis Deep AI Pentest Engine"
    )
    aegis_ollama_base_url: str = Field(
        default="http://localhost:11434/v1",
        description="Ollama OpenAI-compatible API base URL for Aegis"
    )
    aegis_model: str = Field(
        default="qwen2.5-coder:14b",
        description="Local LLM model for Aegis Engine (qwen2.5-coder:14b or 7b)"
    )

    # Scanner Settings
    semgrep_config: str = Field(
        default="auto",
        description="Semgrep ruleset config (e.g. 'auto', 'p/ci', 'p/security-audit')"
    )
    scan_timeout_seconds: int = Field(
        default=300,
        description="Maximum execution time for each scanner subprocess"
    )
    scan_output_dir: Path = Field(
        default=Path("./reports"),
        description="Directory to save generated scan reports"
    )
    dast_verify_tls: bool = Field(
        default=True,
        description="Validate TLS certificates during DAST scans (disable only for self-signed staging hosts)"
    )
    temp_clone_dir: Path = Field(
        default=Path("./temp_scans"),
        description="Directory for temporary repository clones during audit"
    )

    # Compliance Reporting Settings
    report_pdf_enabled: bool = Field(
        default=True,
        description="Render a PDF copy next to every Markdown audit report"
    )
    report_font_path: Optional[Path] = Field(
        default=None,
        description="TTF font with Cyrillic coverage for PDF reports (auto-detected when unset)"
    )
    ai_summary_timeout_seconds: int = Field(
        default=90,
        description="Timeout for the local Ollama audit summary request"
    )

    # Observability
    metrics_db_path: Path = Field(
        default=Path("./data/commit_guardian.db"),
        description="SQLite database that stores audit metrics for the /dashboard page"
    )

    @field_validator("allowed_telegram_users", mode="before")
    @classmethod
    def parse_allowed_telegram_users(cls, v):
        if isinstance(v, str):
            if not v.strip():
                return []
            return [int(uid.strip()) for uid in v.split(",") if uid.strip().isdigit()]
        if isinstance(v, (int, float)):
            return [int(v)]
        return v or []

    @model_validator(mode="after")
    def enforce_local_llm_policy(self) -> "Settings":
        """
        Air-gap guarantee: unless cloud inference is explicitly allowed, force the local
        provider and drop cloud credentials, so no code path can reach OpenRouter or Gemini
        even if a key is present in the environment.
        """
        if self.allow_cloud_llm:
            self.llm_policy_notices = [
                f"Cloud LLM inference is ENABLED (provider: {self.llm_provider.value}); "
                "source code may be sent to a third-party API."
            ] if self.llm_provider != LLMProvider.OLLAMA else []
            return self

        notices = []
        if self.llm_provider != LLMProvider.OLLAMA:
            notices.append(
                f"LLM_PROVIDER={self.llm_provider.value} ignored: cloud inference is disabled "
                "(set ALLOW_CLOUD_LLM=true to opt in). Using local Ollama."
            )
        if self.openrouter_api_key or self.gemini_api_key:
            notices.append("Cloud API keys found in the environment were ignored (ALLOW_CLOUD_LLM=false).")

        self.llm_provider = LLMProvider.OLLAMA
        self.use_local_llm = True
        self.openrouter_api_key = None
        self.gemini_api_key = None
        self.llm_policy_notices = notices
        return self

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def parse_cors_allow_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v or []

    @property
    def cors_origins(self) -> List[str]:
        """Explicit browser origins for CORS; never a wildcard, since credentials are allowed."""
        origins = [self.web_app_url.rstrip("/")] + [o.rstrip("/") for o in self.cors_allow_origins]
        return [o for o in dict.fromkeys(origins) if o and o != "*"]

    @property
    def air_gapped(self) -> bool:
        """True when every AI call is guaranteed to stay on the local Ollama host."""
        return not self.allow_cloud_llm or self.llm_provider == LLMProvider.OLLAMA

    def ensure_directories(self) -> None:
        """Ensure necessary output and temporary folders exist."""
        self.scan_output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_clone_dir.mkdir(parents=True, exist_ok=True)


# Singleton settings instance
settings = Settings()
settings.ensure_directories()
