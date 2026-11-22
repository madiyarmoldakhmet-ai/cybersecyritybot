"""
Unified Runtime LLM Provider & Smart Model Resolver for Commit Guardian.

- Privacy-first default: 100% local Ollama (0 bytes leave the host).
- Smart Ollama model resolution: automatically inspects `/api/tags` and selects the best
  installed coding model (preferring `qwen2.5-coder:7b` / `14b`, falling back cleanly to any
  installed local model so scans never fail on a missing default tag).
- Optional session-only BYOK (Bring Your Own Key) switching in memory for OpenRouter,
  Anthropic Claude, Google Gemini, or OpenAI when the user explicitly opts in. Keys are
  NEVER persisted to disk or returned to clients.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx
from openai import AsyncOpenAI

from aegis.core.config import LLMProvider, settings
from aegis.core.queue_manager import ollama_limiter

logger = logging.getLogger("aegis.llm_runtime")

# Priority order when auto-selecting an installed local Ollama model
_PREFERRED_OLLAMA_MODELS: Tuple[str, ...] = (
    "qwen2.5-coder:7b",
    "qwen2.5-coder:14b",
    "qwen2.5-coder:latest",
    "qwen2.5-coder:3b",
    "qwen2.5-coder:1.5b",
    "deepseek-coder-v2:latest",
    "deepseek-coder:6.7b",
    "codellama:latest",
    "qwen2.5:7b",
    "qwen:latest",
    "gemma4:e2b",
)

DEFAULT_BYOK_MODELS: Dict[str, str] = {
    "openrouter": "anthropic/claude-3.5-sonnet",
    "anthropic": "claude-sonnet-4-20250514",
    "gemini": "gemini-3.8-flash",
    "openai": "gpt-4o-mini",
}


@dataclass
class RuntimeLLMOverride:
    provider: LLMProvider = LLMProvider.OLLAMA
    model: Optional[str] = None
    api_key: Optional[str] = None  # Memory-only BYOK secret, never written to disk


_runtime_override: Optional[RuntimeLLMOverride] = None
_ollama_tags_cache: Tuple[str, float, List[str]] = ("", 0.0, [])
_OLLAMA_CACHE_TTL = 15.0
_resolved_gemini_model: Optional[str] = None


async def list_ollama_models(force_refresh: bool = False) -> List[str]:
    """Query local Ollama `/api/tags` with a short URL-keyed cache & fast timeout."""
    global _ollama_tags_cache
    base = settings.ollama_base_url.rstrip("/")
    now = time.monotonic()
    cached_base, cached_ts, cached_models = _ollama_tags_cache
    if not force_refresh and cached_base == base and (now - cached_ts) < _OLLAMA_CACHE_TTL and cached_models:
        return list(cached_models)

    try:
        async with httpx.AsyncClient(timeout=1.8) as client:
            resp = await client.get(f"{base}/api/tags")
            if resp.status_code == 200:
                raw_models = resp.json().get("models") or []
                names = [str(m.get("name")) for m in raw_models if m.get("name")]
                _ollama_tags_cache = (base, now, names)
                return list(names)
    except Exception as exc:
        logger.debug(f"Ollama tag discovery skipped ({base}): {exc}")

    _ollama_tags_cache = (base, now, [])
    return []


def _pick_best_ollama_model(installed: List[str], requested: Optional[str] = None) -> str:
    """Pick requested model if installed, otherwise highest-priority installed coding model."""
    if not installed:
        return requested or settings.ollama_model or "qwen2.5-coder:7b"

    installed_set = set(installed)
    if requested and requested in installed_set:
        return requested
    if settings.ollama_model and settings.ollama_model in installed_set:
        return settings.ollama_model

    for pref in _PREFERRED_OLLAMA_MODELS:
        if pref in installed_set:
            return pref

    # Prefix match for any qwen2.5-coder or coder model
    for name in installed:
        if "coder" in name.lower():
            return name
    return installed[0]


def set_runtime_override(
    provider: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Update the in-memory runtime LLM configuration (BYOK or local Ollama)."""
    global _runtime_override
    clean_provider = (provider or "ollama").strip().lower()
    try:
        prov_enum = LLMProvider(clean_provider)
    except ValueError as exc:
        raise ValueError(
            f"Неизвестный провайдер '{provider}'. Доступны: ollama, openrouter, anthropic, gemini, openai."
        ) from exc

    clean_model = (model or "").strip() or None
    clean_key = (api_key or "").strip() or None

    if prov_enum == LLMProvider.OLLAMA:
        _runtime_override = RuntimeLLMOverride(provider=LLMProvider.OLLAMA, model=clean_model, api_key=None)
    else:
        # Preserve existing in-memory key for same provider if user only changes model name
        if not clean_key and _runtime_override and _runtime_override.provider == prov_enum:
            clean_key = _runtime_override.api_key
        if not clean_key:
            raise ValueError(f"Для облачного режима ({prov_enum.value}) нужен API-ключ (BYOK).")
        _runtime_override = RuntimeLLMOverride(
            provider=prov_enum,
            model=clean_model or DEFAULT_BYOK_MODELS.get(prov_enum.value),
            api_key=clean_key,
        )

    return {
        "provider": _runtime_override.provider.value,
        "model": _runtime_override.model,
        "is_cloud": _runtime_override.provider != LLMProvider.OLLAMA,
        "has_api_key": bool(_runtime_override.api_key),
    }


def reset_runtime_override() -> None:
    """Restore default strict local Ollama mode and purge any in-memory BYOK key."""
    global _runtime_override
    _runtime_override = None


async def resolve_active_llm(
    per_request_override: Optional[Dict[str, Any]] = None,
) -> Tuple[LLMProvider, str, Optional[str], bool]:
    """
    Resolve active `(provider, model, api_key, is_local)` tuple.

    Precedence:
    1. Explicit per-request override (if provided with key or local ollama model)
    2. Session runtime override set via `/api/ai/config`
    3. Environment `settings` (strict local Ollama unless `ALLOW_CLOUD_LLM=true`)
    """
    if per_request_override and per_request_override.get("provider"):
        p_raw = str(per_request_override["provider"]).strip().lower()
        try:
            prov = LLMProvider(p_raw)
        except ValueError:
            prov = LLMProvider.OLLAMA
        req_model = (per_request_override.get("model") or "").strip() or None
        req_key = (per_request_override.get("api_key") or "").strip() or None
        if prov == LLMProvider.OLLAMA:
            installed = await list_ollama_models()
            return LLMProvider.OLLAMA, _pick_best_ollama_model(installed, req_model), None, True
        if req_key:
            return prov, req_model or DEFAULT_BYOK_MODELS.get(prov.value, ""), req_key, False

    if _runtime_override is not None:
        if _runtime_override.provider == LLMProvider.OLLAMA:
            installed = await list_ollama_models()
            return (
                LLMProvider.OLLAMA,
                _pick_best_ollama_model(installed, _runtime_override.model),
                None,
                True,
            )
        if _runtime_override.api_key:
            return (
                _runtime_override.provider,
                _runtime_override.model or DEFAULT_BYOK_MODELS.get(_runtime_override.provider.value, ""),
                _runtime_override.api_key,
                False,
            )

    if not settings.air_gapped:
        if settings.llm_provider == LLMProvider.OPENROUTER and settings.openrouter_api_key:
            return LLMProvider.OPENROUTER, settings.openrouter_model, settings.openrouter_api_key, False
        if settings.llm_provider == LLMProvider.GEMINI and settings.gemini_api_key:
            eff_model = _resolved_gemini_model or (
                "gemini-3.8-flash" if settings.gemini_model == "gemini-2.5-flash" else settings.gemini_model
            )
            return LLMProvider.GEMINI, eff_model, settings.gemini_api_key, False

    installed = await list_ollama_models()
    return LLMProvider.OLLAMA, _pick_best_ollama_model(installed), None, True


async def get_runtime_status() -> Dict[str, Any]:
    """Return safe public AI engine status (never exposes API keys)."""
    installed = await list_ollama_models(force_refresh=True)
    provider, model, api_key, is_local = await resolve_active_llm()
    ollama_reachable = len(installed) > 0
    return {
        "provider": provider.value,
        "model": model,
        "is_local": is_local,
        "air_gapped": is_local,
        "has_api_key": bool(api_key),
        "ollama_reachable": ollama_reachable,
        "ollama_models": installed,
        "recommended_local_model": "qwen2.5-coder:7b",
        "default_byok_models": DEFAULT_BYOK_MODELS,
    }


def build_openai_client(provider: LLMProvider, api_key: Optional[str], timeout: float = 30.0) -> AsyncOpenAI:
    """Build an AsyncOpenAI-compatible client for Ollama, OpenRouter, Gemini, or OpenAI."""
    if provider == LLMProvider.OPENROUTER and api_key:
        return AsyncOpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key, timeout=timeout, max_retries=1)
    if provider == LLMProvider.GEMINI and api_key:
        return AsyncOpenAI(
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            api_key=api_key,
            timeout=timeout,
            max_retries=1,
        )
    if provider == LLMProvider.OPENAI and api_key:
        return AsyncOpenAI(base_url="https://api.openai.com/v1", api_key=api_key, timeout=timeout, max_retries=1)
    return AsyncOpenAI(
        base_url=settings.ollama_base_url.rstrip("/") + "/v1",
        api_key="ollama",
        timeout=timeout,
        max_retries=1,
    )


async def chat_completion(
    system_prompt: str,
    user_prompt: str,
    *,
    temperature: float = 0.1,
    max_tokens: int = 1600,
    timeout: float = 40.0,
    task_label: str = "LLM",
    override: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Execute a single-turn chat completion across whichever provider is active
    (Local Ollama, OpenRouter, Anthropic Claude, Gemini, or OpenAI).
    Returns None cleanly if the provider is unreachable or fails.
    """
    provider, model, api_key, is_local = await resolve_active_llm(override)

    if is_local:
        installed = await list_ollama_models()
        if not installed:
            logger.debug(f"{task_label}: local Ollama unavailable, skipping LLM call.")
            return None

    try:
        if provider == LLMProvider.GEMINI and api_key:
            global _resolved_gemini_model

            def _gemini_payload(target_model: str) -> Dict[str, Any]:
                gen_cfg: Dict[str, Any] = {
                    "temperature": temperature,
                    "maxOutputTokens": max(max_tokens, 1400),
                }
                # Gemini 3.x defaults to medium thinking (15-25s latency); LOW keeps real-time chat ~1-3s
                if "gemini-3" in target_model.lower():
                    gen_cfg["thinkingConfig"] = {"thinkingLevel": "LOW"}
                return {
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                    "generationConfig": gen_cfg,
                }

            base_candidates = (
                [_resolved_gemini_model]
                if _resolved_gemini_model
                else [
                    "gemini-3.8-flash" if model == "gemini-2.5-flash" else model,
                    "gemini-3.8-flash",
                    "gemini-flash-latest",
                    "gemini-2.5-flash-lite",
                ]
            )
            candidate_models = list(dict.fromkeys(m for m in base_candidates if m))
            hdrs = {"Content-Type": "application/json", "x-goog-api-key": api_key}
            async with httpx.AsyncClient(timeout=max(timeout, 35.0)) as client:
                for cand_model in candidate_models:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{cand_model}:generateContent"
                    resp = await client.post(url, headers=hdrs, json=_gemini_payload(cand_model))
                    if resp.status_code == 200:
                        cands = resp.json().get("candidates") or []
                        if cands:
                            parts = (cands[0].get("content") or {}).get("parts") or []
                            txt = "\n".join(
                                str(p.get("text", ""))
                                for p in parts
                                if p.get("text") and not p.get("thought")
                            ).strip()
                            if txt:
                                _resolved_gemini_model = cand_model
                                return txt
                    elif resp.status_code == 404:
                        logger.warning(f"{task_label}: Gemini model '{cand_model}' returned 404, trying fallback...")
                        continue
                    else:
                        logger.warning(
                            f"{task_label}: Gemini ({cand_model}) HTTP {resp.status_code}: {resp.text[:220]}"
                        )
                        break

                # Last-resort dynamic discovery from /v1beta/models if all static model IDs returned 404
                list_resp = await client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    headers={"x-goog-api-key": api_key},
                )
                if list_resp.status_code == 200:
                    models_list = list_resp.json().get("models") or []
                    flash_models = [
                        str(m.get("name", "")).replace("models/", "")
                        for m in models_list
                        if "generateContent" in (m.get("supportedGenerationMethods") or [])
                        and "flash" in str(m.get("name", "")).lower()
                        and "image" not in str(m.get("name", "")).lower()
                        and "tts" not in str(m.get("name", "")).lower()
                    ]
                    if flash_models:
                        dyn_model = flash_models[-1]
                        logger.info(f"{task_label}: Auto-discovered live Gemini model '{dyn_model}'")
                        resp2 = await client.post(
                            f"https://generativelanguage.googleapis.com/v1beta/models/{dyn_model}:generateContent",
                            headers=hdrs,
                            json=_gemini_payload(dyn_model),
                        )
                        if resp2.status_code == 200:
                            cands = resp2.json().get("candidates") or []
                            if cands:
                                parts = (cands[0].get("content") or {}).get("parts") or []
                                txt = "\n".join(
                                    str(p.get("text", ""))
                                    for p in parts
                                    if p.get("text") and not p.get("thought")
                                ).strip()
                                if txt:
                                    _resolved_gemini_model = dyn_model
                                    return txt
            return None

        if provider == LLMProvider.ANTHROPIC and api_key:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                        "system": system_prompt,
                        "messages": [{"role": "user", "content": user_prompt}],
                    },
                )
                if resp.status_code != 200:
                    logger.warning(f"{task_label}: Anthropic API HTTP {resp.status_code}")
                    return None
                blocks = resp.json().get("content") or []
                text_parts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
                return "\n".join(text_parts).strip() or None

        client = build_openai_client(provider, api_key, timeout=timeout)

        async def _invoke() -> str:
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return (resp.choices[0].message.content or "").strip()

        if is_local:
            async with ollama_limiter.acquire_slot(task_label):
                return await _invoke() or None
        return await _invoke() or None
    except Exception as exc:
        logger.warning(f"{task_label} ({provider.value}/{model}) failed: {type(exc).__name__}: {exc}")
        return None
