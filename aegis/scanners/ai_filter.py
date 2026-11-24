import asyncio
import json
import logging
from typing import Dict, List

from aegis.core.config import LLMProvider, settings
from aegis.core.llm_runtime import build_openai_client, chat_completion
from aegis.scanners.models import ScannerType, VulnerabilityFinding

logger = logging.getLogger("aegis.ai_filter")

# Deterministic scanners never need LLM false-positive filtering
_SKIP_AI_FILTER_SCANNERS = {
    ScannerType.SCA,
    ScannerType.PIP_AUDIT,
    ScannerType.GIT_HISTORY,
    ScannerType.AI_LOGIC,  # Already verified by structural rules or anti-hallucination gate
    ScannerType.BACKDOOR,  # High-precision backdoor / reverse-shell / Trojan Source signatures
    ScannerType.SYSTEM_ANALYST,  # Deterministic architecture / trust-boundary checks
}

AI_BATCH_FILTER_SYSTEM_PROMPT = """\
You are an expert Application Security Engineer triaging static analysis (SAST) alerts.
For each numbered finding, determine whether it is a REAL threat (`true`) or a FALSE POSITIVE (`false`),
such as dummy placeholders ('replace_me', 'change_me', 'example', mock tokens) or sanitized code.

Respond ONLY with a valid JSON object mapping each finding index (as string) to a boolean:
{"0": true, "1": false}
"""


class AIFalsePositiveFilter:
    """
    Fast Batched AI-Assisted SAST Filter.

    Only inspects ambiguous SAST/Secret findings (skipping deterministic CVE/SCA & already-verified
    scanners) and batches up to 6 findings into a single bounded LLM request (<12s total) so scans
    stay fast (~10-15s) even on large repositories.
    """

    def __init__(self, timeout_seconds: int = 12, max_candidates: int = 6) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_candidates = max_candidates
        self.enabled = True
        provider = LLMProvider.OLLAMA if settings.air_gapped else settings.llm_provider
        api_key = None if settings.air_gapped else (settings.openrouter_api_key or settings.gemini_api_key)
        self.client = build_openai_client(provider, api_key, timeout=float(timeout_seconds))

    async def filter_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Batch-filter ambiguous findings in one fast LLM call with strict timeout."""
        if not self.enabled or not findings:
            return findings

        candidate_indices: List[int] = []
        for idx, f in enumerate(findings):
            if f.scanner in _SKIP_AI_FILTER_SCANNERS:
                continue
            candidate_indices.append(idx)
            if len(candidate_indices) >= self.max_candidates:
                break

        if not candidate_indices:
            return findings

        blocks: List[str] = []
        for batch_pos, orig_idx in enumerate(candidate_indices):
            f = findings[orig_idx]
            snippet = (f.code_snippet or "").strip()[:260]
            blocks.append(
                f"[{batch_pos}] {f.title} | {f.file_path}:{f.line_start or 1} | CWE: {f.cwe}\n"
                f"Snippet:\n{snippet}"
            )

        user_prompt = (
            "Classify each numbered SAST alert below as true (real vulnerability) or false (false positive / placeholder):\n\n"
            + "\n\n".join(blocks)
            + '\n\nReturn ONLY JSON like {"0": true, "1": false}.'
        )

        try:
            raw_text = await asyncio.wait_for(
                chat_completion(
                    AI_BATCH_FILTER_SYSTEM_PROMPT,
                    user_prompt,
                    temperature=0.05,
                    max_tokens=160,
                    timeout=float(self.timeout_seconds),
                    task_label=f"AIFilterBatch({len(candidate_indices)})",
                ),
                timeout=float(self.timeout_seconds) + 1.0,
            )
        except Exception as exc:
            logger.debug(f"AI batch filter skipped (timeout/error): {exc}")
            return findings

        if not raw_text:
            return findings

        verdicts: Dict[int, bool] = {}
        try:
            text = raw_text.strip()
            if "```json" in text:
                text = text.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in text:
                text = text.split("```", 1)[1].split("```", 1)[0].strip()
            lo, hi = text.find("{"), text.rfind("}")
            if lo != -1 and hi != -1:
                parsed = json.loads(text[lo : hi + 1])
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        if str(k).isdigit() and isinstance(v, bool):
                            pos = int(k)
                            if 0 <= pos < len(candidate_indices):
                                verdicts[candidate_indices[pos]] = v
        except Exception as exc:
            logger.debug(f"AI batch filter JSON parse skipped: {exc}")
            return findings

        kept: List[VulnerabilityFinding] = []
        for idx, f in enumerate(findings):
            if verdicts.get(idx, True) is False:
                logger.info(f"AI Filter dropped False Positive '{f.title}' in {f.file_path}")
                continue
            kept.append(f)
        return kept
