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

import asyncio
import hashlib
import logging
import re
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
    "gemini": "gemini-3.1-pro-preview",
    "openai": "gpt-4o-mini",
}

_GEMINI_FALLBACK_PRO_ORDER: Tuple[str, ...] = (
    "gemini-3.1-pro-preview",
    "gemini-3-pro-preview",
    "gemini-pro-latest",
    "gemini-2.5-pro",
    "gemini-3.8-flash",
    "gemini-3-flash-preview",
    "gemini-flash-latest",
)

_GEMINI_SKIP_TOKENS: Tuple[str, ...] = (
    "image",
    "tts",
    "audio",
    "embedding",
    "embed",
    "live",
    "vision",
    "veo",
    "imagen",
    "gemma",
    "learnlm",
    "aqa",
    "bison",
    "gecko",
    "robotics",
    "computer-use",
    "deep-research",
)

_GEMINI_VER_RE = re.compile(r"gemini-(\d+)(?:\.(\d+))?", re.IGNORECASE)


@dataclass
class RuntimeLLMOverride:
    provider: LLMProvider = LLMProvider.OLLAMA
    model: Optional[str] = None
    api_key: Optional[str] = None  # Memory-only BYOK secret, never written to disk


_runtime_override: Optional[RuntimeLLMOverride] = None
_ollama_tags_cache: Tuple[str, float, List[str]] = ("", 0.0, [])
_OLLAMA_CACHE_TTL = 15.0
_gemini_models_cache: Tuple[str, float, List[str]] = ("", 0.0, [])
_GEMINI_MODELS_CACHE_TTL = 600.0
_resolved_gemini_model: Optional[str] = None
_resolved_gemini_expires_at: float = 0.0
_last_gemini_model_used: Optional[str] = None
_last_gemini_fallbacks: List[str] = []
_gemini_cooldown: Dict[str, float] = {}
_gemini_warmup_task: Optional[asyncio.Task] = None


def _get_resolved_gemini() -> Optional[str]:
    global _resolved_gemini_model, _resolved_gemini_expires_at
    if _resolved_gemini_model and _resolved_gemini_expires_at > 0 and time.monotonic() > _resolved_gemini_expires_at:
        _resolved_gemini_model = None
        _resolved_gemini_expires_at = 0.0
    return _resolved_gemini_model


def _set_resolved_gemini(model_name: str) -> None:
    global _resolved_gemini_model, _resolved_gemini_expires_at
    _resolved_gemini_model = model_name
    # Non-lite Pro/Flash stays active until it fails; lite emergency fallback auto-re-promotes after 3m
    _resolved_gemini_expires_at = (time.monotonic() + 180.0) if "lite" in model_name.lower() else 0.0


def _clear_resolved_gemini(expected: Optional[str] = None) -> None:
    global _resolved_gemini_model, _resolved_gemini_expires_at
    if expected is None or _resolved_gemini_model == expected:
        _resolved_gemini_model = None
        _resolved_gemini_expires_at = 0.0


def _mark_gemini_cooldown(model_name: str, seconds: float) -> None:
    _gemini_cooldown[model_name] = time.monotonic() + seconds


def _is_gemini_cooled_down(model_name: str) -> bool:
    until = _gemini_cooldown.get(model_name, 0.0)
    return until > time.monotonic()


async def warmup_gemini_model() -> Optional[str]:
    """
    Probe top ranked Gemini models (Pro first, then full Flash, then emergency Lite) IN PARALLEL
    at server startup so the very first user chat turn responds in ~2-4s without serial 429/404/503s.
    """
    global _last_gemini_fallbacks
    if settings.air_gapped or settings.llm_provider != LLMProvider.GEMINI or not settings.gemini_api_key:
        return None

    api_key = settings.gemini_api_key
    ranked = await list_gemini_models(api_key)
    candidates = (ranked[:14] if ranked else list(_GEMINI_FALLBACK_PRO_ORDER))
    if not candidates:
        return None

    hdrs = {"Content-Type": "application/json", "x-goog-api-key": api_key}

    async def _probe(cand: str) -> Tuple[str, str]:
        low = cand.lower()
        gen_cfg: Dict[str, Any] = {"maxOutputTokens": 16}
        if "gemini-3" in low:
            gen_cfg["thinkingConfig"] = {"thinkingLevel": "low"}
        elif "gemini-2.5-pro" in low:
            gen_cfg["thinkingConfig"] = {"thinkingBudget": 128}
        payload = {
            "contents": [{"role": "user", "parts": [{"text": "ok"}]}],
            "generationConfig": gen_cfg,
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{cand}:generateContent"
        try:
            async with httpx.AsyncClient(timeout=7.5) as client:
                resp = await client.post(url, headers=hdrs, json=payload)
                if resp.status_code == 400 and "thinking" in resp.text.lower():
                    resp = await client.post(
                        url,
                        headers=hdrs,
                        json={"contents": payload["contents"], "generationConfig": {"maxOutputTokens": 16}},
                    )
                if resp.status_code == 200:
                    return cand, "OK"
                return cand, f"HTTP{resp.status_code}"
        except httpx.TimeoutException:
            return cand, "timeout"
        except Exception as exc:
            return cand, type(exc).__name__

    results = await asyncio.gather(*(_probe(c) for c in candidates))
    winner: Optional[str] = None
    notes: List[str] = []
    for cand, status in results:
        if status == "OK":
            if winner is None:
                winner = cand
        else:
            if winner is None:
                notes.append(f"{cand}:{status}")
            if status in ("HTTP404", "HTTP429"):
                _mark_gemini_cooldown(cand, 1800.0)
            else:
                _mark_gemini_cooldown(cand, 120.0)

    if winner:
        _set_resolved_gemini(winner)
        _last_gemini_fallbacks = notes
        logger.info(f"Gemini startup warmup locked onto '{winner}' (skipped: {notes[:5]})")
    else:
        _last_gemini_fallbacks = notes
        logger.warning(f"Gemini startup warmup found no ready candidate: {notes[:6]}")
    return winner


def start_gemini_warmup() -> None:
    """Kick off non-blocking parallel Gemini warmup once at FastAPI startup."""
    global _gemini_warmup_task
    if settings.air_gapped or settings.llm_provider != LLMProvider.GEMINI or not settings.gemini_api_key:
        return
    if _gemini_warmup_task is None or _gemini_warmup_task.done():
        _gemini_warmup_task = asyncio.create_task(warmup_gemini_model())


def rank_gemini_models(model_names: List[str]) -> List[str]:
    """
    Filter and rank Gemini generateContent models strictly by security reasoning quality:
      Tier 0: Flagship Pro models (highest version descending, e.g. 3.8-pro > 3.1-pro > 3-pro > pro-latest > 2.5-pro)
      Tier 1: Full non-lite Flash models (highest version descending) — automatic failover if Pro hits 404/429/timeout
      Tier 2: Flash-Lite models — emergency last-resort fallback ONLY if both Pro and full Flash fail
    """
    cleaned: List[str] = []
    seen = set()
    for raw in model_names:
        name = str(raw or "").strip()
        if name.startswith("models/"):
            name = name[len("models/") :]
        low = name.lower()
        if not name or name in seen:
            continue
        if "gemini" not in low:
            continue
        if any(tok in low for tok in _GEMINI_SKIP_TOKENS):
            continue
        seen.add(name)
        cleaned.append(name)

    def _sort_key(name: str) -> Tuple[int, int, int, int, int, str]:
        low = name.lower()
        is_lite = "lite" in low
        is_pro = "pro" in low and not is_lite
        is_flash = "flash" in low and not is_lite
        if is_pro:
            tier = 0
        elif is_flash:
            tier = 1
        elif is_lite:
            tier = 2
        else:
            tier = 3

        m = _GEMINI_VER_RE.search(low)
        if m:
            major = int(m.group(1))
            minor = int(m.group(2) or 0)
        elif "latest" in low:
            # Place `gemini-pro-latest` right after explicit 3.x Pro and ahead of 2.5-pro
            major, minor = 2, 99
        else:
            major, minor = 0, 0

        is_exp = 1 if ("exp" in low or "001" in low) else 0
        is_customtools = 1 if "customtools" in low else 0
        return (tier, -major, -minor, is_customtools, is_exp, low)

    return sorted(cleaned, key=_sort_key)


async def list_gemini_models(api_key: str, force_refresh: bool = False) -> List[str]:
    """Query Google AI Studio `/v1beta/models` (cached 10m) and return Pro-first ranked model IDs."""
    global _gemini_models_cache
    if not api_key:
        return []
    key_fp = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    now = time.monotonic()
    cached_fp, cached_ts, cached_models = _gemini_models_cache
    if not force_refresh and cached_fp == key_fp and (now - cached_ts) < _GEMINI_MODELS_CACHE_TTL and cached_models:
        return list(cached_models)

    try:
        async with httpx.AsyncClient(timeout=4.5) as client:
            resp = await client.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": api_key},
            )
            if resp.status_code == 200:
                raw_models = resp.json().get("models") or []
                gen_names = [
                    str(m.get("name", "")).replace("models/", "")
                    for m in raw_models
                    if "generateContent" in (m.get("supportedGenerationMethods") or [])
                ]
                ranked = rank_gemini_models(gen_names)
                _gemini_models_cache = (key_fp, now, ranked)
                logger.info(f"Discovered Gemini models (Pro-first): {ranked[:8]}")
                return list(ranked)
            logger.warning(f"Gemini /v1beta/models HTTP {resp.status_code}: {resp.text[:160]}")
    except Exception as exc:
        logger.debug(f"Gemini model discovery failed: {type(exc).__name__}: {exc}")

    return list(cached_models) if cached_fp == key_fp else []


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
    global _runtime_override, _resolved_gemini_model
    clean_provider = (provider or "ollama").strip().lower()
    try:
        prov_enum = LLMProvider(clean_provider)
    except ValueError as exc:
        raise ValueError(
            f"Неизвестный провайдер '{provider}'. Доступны: ollama, openrouter, anthropic, gemini, openai."
        ) from exc

    clean_model = (model or "").strip() or None
    clean_key = (api_key or "").strip() or None
    _resolved_gemini_model = None

    if prov_enum == LLMProvider.OLLAMA:
        _runtime_override = RuntimeLLMOverride(provider=LLMProvider.OLLAMA, model=clean_model, api_key=None)
    else:
        # Preserve existing in-memory or server-env key for same provider if user only changes model name
        if not clean_key and _runtime_override and _runtime_override.provider == prov_enum:
            clean_key = _runtime_override.api_key
        if not clean_key and not settings.air_gapped:
            if prov_enum == LLMProvider.GEMINI and settings.gemini_api_key:
                clean_key = settings.gemini_api_key
            elif prov_enum == LLMProvider.OPENROUTER and settings.openrouter_api_key:
                clean_key = settings.openrouter_api_key
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
    global _runtime_override, _resolved_gemini_model
    _runtime_override = None
    _resolved_gemini_model = None
    _gemini_cooldown.clear()


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
            eff_model = _get_resolved_gemini()
            if not eff_model:
                discovered = await list_gemini_models(settings.gemini_api_key)
                healthy = [m for m in discovered if not _is_gemini_cooled_down(m)]
                pool = healthy or discovered
                cfg_model = (settings.gemini_model or "").strip()
                cfg_is_weak = (not cfg_model) or cfg_model == "gemini-2.5-flash" or ("lite" in cfg_model.lower())
                if pool:
                    if not cfg_is_weak and cfg_model in pool:
                        eff_model = cfg_model
                    else:
                        eff_model = pool[0]
                else:
                    eff_model = "gemini-3.1-pro-preview" if cfg_is_weak else cfg_model
            return LLMProvider.GEMINI, eff_model, settings.gemini_api_key, False

    installed = await list_ollama_models()
    return LLMProvider.OLLAMA, _pick_best_ollama_model(installed), None, True


async def get_runtime_status() -> Dict[str, Any]:
    """Return safe public AI engine status (never exposes API keys)."""
    installed = await list_ollama_models(force_refresh=True)
    provider, model, api_key, is_local = await resolve_active_llm()
    gemini_models = await list_gemini_models(api_key) if (provider == LLMProvider.GEMINI and api_key) else []
    ollama_reachable = len(installed) > 0
    return {
        "provider": provider.value,
        "model": model,
        "last_used_model": _last_gemini_model_used if provider == LLMProvider.GEMINI else model,
        "is_local": is_local,
        "air_gapped": is_local,
        "has_api_key": bool(api_key),
        "ollama_reachable": ollama_reachable,
        "ollama_models": installed,
        "gemini_models": gemini_models[:12],
        "gemini_fallbacks": list(_last_gemini_fallbacks[:5]) if provider == LLMProvider.GEMINI else [],
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
    deep_reasoning: bool = False,
    task_label: str = "LLM",
    override: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Execute a single-turn chat completion across whichever provider is active
    (Local Ollama, OpenRouter, Anthropic Claude, Gemini, or OpenAI).
    When `deep_reasoning=True`, uses stronger reasoning budgets (e.g. Gemini Pro
    with medium thinking) for backdoor/business-logic auditing and auto-fix patches.
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
            global _resolved_gemini_model, _last_gemini_model_used, _last_gemini_fallbacks
            attempt_notes: List[str] = []

            # If startup parallel warmup is currently probing models, await it briefly (<= 7s)
            # instead of duplicating serial 429/404/503 retries on the user's first message.
            if _resolved_gemini_model is None and _gemini_warmup_task is not None and not _gemini_warmup_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(_gemini_warmup_task), timeout=7.5)
                except Exception:
                    pass

            def _gemini_payload(target_model: str, include_thinking: bool = True) -> Dict[str, Any]:
                low_name = target_model.lower()
                if "gemini-3" in low_name:
                    gen_cfg: Dict[str, Any] = {
                        "maxOutputTokens": max(max_tokens, 2600 if deep_reasoning else 1600),
                    }
                    if include_thinking:
                        gen_cfg["thinkingConfig"] = {"thinkingLevel": "medium" if deep_reasoning else "low"}
                elif "gemini-2.5-pro" in low_name:
                    gen_cfg = {
                        "maxOutputTokens": max(max_tokens, 2400 if deep_reasoning else 1400),
                    }
                    if include_thinking:
                        gen_cfg["thinkingConfig"] = {"thinkingBudget": 2048 if deep_reasoning else 512}
                else:
                    gen_cfg = {
                        "temperature": temperature,
                        "maxOutputTokens": max(max_tokens, 1400),
                    }
                return {
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                    "generationConfig": gen_cfg,
                }

            def _extract_gemini_text(payload: Dict[str, Any]) -> str:
                cands = payload.get("candidates") or []
                if not cands:
                    return ""
                parts = (cands[0].get("content") or {}).get("parts") or []
                return "\n".join(
                    str(p.get("text", ""))
                    for p in parts
                    if p.get("text") and not p.get("thought")
                ).strip()

            discovered = await list_gemini_models(api_key)
            explicit_user_model = (
                (override or {}).get("model")
                or (_runtime_override.model if _runtime_override and _runtime_override.provider == LLMProvider.GEMINI else None)
            )
            base_candidates: List[str] = []
            if explicit_user_model:
                base_candidates.append(explicit_user_model)
            resolved_now = _get_resolved_gemini()
            if resolved_now:
                base_candidates.append(resolved_now)
            if discovered:
                base_candidates.extend(discovered)
            else:
                if model and model != "gemini-2.5-flash" and "lite" not in model.lower():
                    base_candidates.append(model)
                base_candidates.extend(_GEMINI_FALLBACK_PRO_ORDER)

            candidate_models = list(dict.fromkeys(m for m in base_candidates if m))
            # Skip models that recently returned 404/429/503 unless explicitly requested or all cooled down
            active_candidates = [
                m for m in candidate_models
                if m == explicit_user_model or not _is_gemini_cooled_down(m)
            ]
            if not active_candidates:
                active_candidates = candidate_models
            hdrs = {"Content-Type": "application/json", "x-goog-api-key": api_key}
            deadline = time.monotonic() + (max(timeout, 32.0) if deep_reasoning else min(max(timeout, 16.0), 19.0))

            for cand_model in active_candidates[:16]:
                remaining = deadline - time.monotonic()
                if remaining < 2.5:
                    break
                is_pro = "pro" in cand_model.lower() and "lite" not in cand_model.lower()
                is_verified = cand_model == resolved_now
                if deep_reasoning:
                    wanted_t = max(timeout, 30.0) if is_pro else min(max(timeout, 18.0), 24.0)
                elif is_verified:
                    wanted_t = 11.0
                else:
                    wanted_t = 8.5
                per_model_timeout = max(3.0, min(wanted_t, remaining))

                url = f"https://generativelanguage.googleapis.com/v1beta/models/{cand_model}:generateContent"
                async with httpx.AsyncClient(timeout=per_model_timeout) as client:
                    try:
                        resp = await client.post(url, headers=hdrs, json=_gemini_payload(cand_model, True))
                    except httpx.TimeoutException:
                        attempt_notes.append(f"{cand_model}:timeout({per_model_timeout:.0f}s)")
                        _mark_gemini_cooldown(cand_model, 120.0)
                        logger.warning(
                            f"{task_label}: Gemini '{cand_model}' timed out after {per_model_timeout:.0f}s, trying next..."
                        )
                        _clear_resolved_gemini(cand_model)
                        continue

                    # If a preview Pro/Flash variant rejects thinkingConfig with HTTP 400, retry once without it
                    if resp.status_code == 400 and "thinking" in resp.text.lower():
                        try:
                            resp = await client.post(url, headers=hdrs, json=_gemini_payload(cand_model, False))
                        except httpx.TimeoutException:
                            attempt_notes.append(f"{cand_model}:timeout-nothink")
                            _mark_gemini_cooldown(cand_model, 120.0)
                            continue

                    if resp.status_code == 200:
                        txt = _extract_gemini_text(resp.json())
                        if txt:
                            _last_gemini_model_used = cand_model
                            if attempt_notes:
                                _last_gemini_fallbacks = attempt_notes
                            _set_resolved_gemini(cand_model)
                            logger.info(
                                f"{task_label}: Gemini responded via {cand_model} (deep_reasoning={deep_reasoning})"
                            )
                            return txt
                        attempt_notes.append(f"{cand_model}:empty")
                    elif resp.status_code in (404, 429, 503):
                        attempt_notes.append(f"{cand_model}:HTTP{resp.status_code}")
                        _mark_gemini_cooldown(cand_model, 1800.0 if resp.status_code in (404, 429) else 120.0)
                        logger.warning(
                            f"{task_label}: Gemini '{cand_model}' HTTP {resp.status_code} ({resp.text[:160]}), trying next..."
                        )
                        _clear_resolved_gemini(cand_model)
                        continue
                    else:
                        attempt_notes.append(f"{cand_model}:HTTP{resp.status_code}")
                        _mark_gemini_cooldown(cand_model, 120.0)
                        logger.warning(
                            f"{task_label}: Gemini ({cand_model}) HTTP {resp.status_code}: {resp.text[:220]}"
                        )
                        continue
            _last_gemini_fallbacks = attempt_notes
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
