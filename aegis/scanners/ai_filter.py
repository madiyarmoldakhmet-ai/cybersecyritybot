import asyncio
import json
import logging
from typing import List

from aegis.core.llm_runtime import chat_completion, resolve_active_llm
from aegis.scanners.models import VulnerabilityFinding

logger = logging.getLogger("aegis.ai_filter")

AI_FILTER_SYSTEM_PROMPT = """\
You are an expert Application Security Engineer. Your job is to review a potential vulnerability finding produced by a static analysis tool (SAST) and determine if it is a REAL threat or a FALSE POSITIVE.
You must consider local data flow, variable sanitization, and context.

CRITICAL RULE FOR SECRETS:
If the finding is related to a hardcoded secret, token, or password, analyze the string value. If it is obviously a placeholder, mock token, or dummy string (e.g. 'YOUR_API_KEY_HERE', 'test-token', '123456', 'example_key'), you MUST classify it as a FALSE POSITIVE (is_real: false).

Respond ONLY with a valid JSON object in this format:
{
  "is_real": true_or_false,
  "reason": "Brief explanation of why it is real or false positive."
}
"""


class AIFalsePositiveFilter:
    """
    AI-Assisted SAST Filter: Uses the active runtime LLM (Local Ollama or BYOK)
    to semantically analyze findings and drop false positives that AST/regex couldn't resolve.
    """

    def __init__(self, timeout_seconds: int = 25) -> None:
        self.timeout_seconds = timeout_seconds
        self.enabled = True

    async def _check_finding(self, finding: VulnerabilityFinding) -> bool:
        """Asks the active LLM if the finding is real. Returns True if real, False if false positive."""
        if not self.enabled:
            return True

        prompt = (
            f"Vulnerability Title: {finding.title}\n"
            f"CWE: {finding.cwe}\n"
            f"Description: {finding.description}\n"
            f"File Path: {finding.file_path}\n\n"
            f"### CODE SNIPPET:\n```\n{finding.code_snippet or ''}\n```\n\n"
            "Analyze the data flow and context. Is this a true positive vulnerability or a false positive?\n"
            "Respond strictly in JSON format with 'is_real' (boolean) and 'reason'."
        )

        raw_text = await chat_completion(
            AI_FILTER_SYSTEM_PROMPT,
            prompt,
            temperature=0.1,
            max_tokens=200,
            timeout=float(self.timeout_seconds),
            task_label=f"AIFilter:{finding.file_path}",
        )
        if not raw_text:
            return True

        try:
            if "```json" in raw_text:
                raw_text = raw_text.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in raw_text:
                raw_text = raw_text.split("```", 1)[1].split("```", 1)[0].strip()

            start_idx = raw_text.find("{")
            end_idx = raw_text.rfind("}")
            if start_idx != -1 and end_idx != -1:
                data = json.loads(raw_text[start_idx : end_idx + 1])
                is_real = bool(data.get("is_real", True))
                reason = str(data.get("reason", ""))
                if not is_real:
                    logger.info(
                        f"AI Filter dropped False Positive '{finding.title}' in {finding.file_path}. Reason: {reason}"
                    )
                return is_real
        except Exception as exc:
            logger.debug(f"AI Filter parse skipped for '{finding.title}': {exc}")
        return True

    async def filter_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Run findings through the AI filter concurrently with provider-aware rate limits."""
        if not self.enabled or not findings:
            return findings

        provider, _, _, is_local = await resolve_active_llm()
        concurrency = 2 if (not is_local and provider.value == "openrouter") else 4
        sem = asyncio.Semaphore(concurrency)

        async def bounded_check(f: VulnerabilityFinding) -> bool:
            async with sem:
                res = await self._check_finding(f)
                if not is_local and provider.value == "openrouter":
                    await asyncio.sleep(0.8)
                return res

        results = await asyncio.gather(*(bounded_check(f) for f in findings), return_exceptions=True)

        filtered: List[VulnerabilityFinding] = []
        for finding, is_real in zip(findings, results):
            if isinstance(is_real, Exception) or is_real is True:
                filtered.append(finding)
        return filtered
