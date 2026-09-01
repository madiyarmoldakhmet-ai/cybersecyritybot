"""
Configuration module for Aegis.
Uses Pydantic Settings for strictly typed, environment-driven configuration.
"""

from enum import Enum
from pathlib import Path
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # General App Settings
    app_name: str = Field(default="Aegis", description="Application name")
    environment: str = Field(default="development", description="Runtime environment")
    debug: bool = Field(default=False, description="Enable debug logging and detailed errors")
    log_level: str = Field(default="INFO", description="Logging level")

    # Telegram Bot Settings
    telegram_bot_token: Optional[str] = Field(
        default=None,
        description="Telegram Bot API Token (from @BotFather)"
    )
    allowed_telegram_users: List[int] = Field(
        default_factory=list,
        description="List of allowed Telegram User IDs for access control"
    )
    default_telegram_chat_id: Optional[int] = Field(
        default=None,
        description="Default Telegram Chat ID for Webhook Commit Guardian alerts"
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
    use_local_llm: bool = Field(
        default=False,
        description="Force use of local Ollama for all AI operations"
    )
    llm_provider: LLMProvider = Field(
        default=LLMProvider.OPENROUTER,
        description="Active LLM provider: 'ollama', 'gemini' or 'openrouter'"
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
    temp_clone_dir: Path = Field(
        default=Path("./temp_scans"),
        description="Directory for temporary repository clones during audit"
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

    def ensure_directories(self) -> None:
        """Ensure necessary output and temporary folders exist."""
        self.scan_output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_clone_dir.mkdir(parents=True, exist_ok=True)


# Singleton settings instance
settings = Settings()
settings.ensure_directories()
