import asyncio
import json
import logging
from typing import List, Optional

from openai import AsyncOpenAI

from strix.core.config import settings
from strix.scanners.models import VulnerabilityFinding, Severity

logger = logging.getLogger("cybersecuritybot.ai_filter")

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
    AI-Assisted SAST Filter: Uses LLM to semantically analyze findings 
    and drop false positives that AST or regex couldn't resolve.
    """
    def __init__(self, timeout_seconds: int = 30) -> None:
        self.client: Optional[AsyncOpenAI] = None
        self.model_name = ""
        self.enabled = False

        if settings.use_local_llm or settings.llm_provider == "ollama":
            self.model_name = settings.ollama_model or "qwen2.5-coder:14b"
            self.client = AsyncOpenAI(
                base_url=settings.ollama_base_url + "/v1",
                api_key="ollama", # Ollama doesn't require an API key
                timeout=float(timeout_seconds),
                max_retries=1,
            )
            self.enabled = True
        elif settings.llm_provider == "openrouter" and settings.openrouter_api_key:
            self.model_name = settings.openrouter_model or "anthropic/claude-sonnet-5"
            self.client = AsyncOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=settings.openrouter_api_key,
                timeout=float(timeout_seconds),
                max_retries=1,
            )
            self.enabled = True
        elif settings.llm_provider == "gemini" and settings.gemini_api_key:
            self.model_name = settings.gemini_model or "gemini-2.5-flash"
            self.client = AsyncOpenAI(
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=settings.gemini_api_key,
                timeout=float(timeout_seconds),
                max_retries=1,
            )
            self.enabled = True

    async def _check_finding(self, finding: VulnerabilityFinding) -> bool:
        """Asks the LLM if the finding is real. Returns True if real, False if false positive."""
        if not self.enabled or not self.client:
            return True  # If LLM is not configured, keep the finding to be safe

        prompt = (
            f"Vulnerability Title: {finding.title}\n"
            f"CWE: {finding.cwe}\n"
            f"Description: {finding.description}\n"
            f"File Path: {finding.file_path}\n\n"
            f"### CODE SNIPPET:\n```\n{finding.code_snippet}\n```\n\n"
            "Analyze the data flow and context. Is this a true positive vulnerability or a false positive?\n"
            "Respond strictly in JSON format with 'is_real' (boolean) and 'reason'."
        )

        try:
            resp = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": AI_FILTER_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=200,
            )
            raw_text = resp.choices[0].message.content or ""
            
            # Extract JSON block
            if "```json" in raw_text:
                raw_text = raw_text.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_text:
                raw_text = raw_text.split("```")[1].strip()

            start_idx = raw_text.find("{")
            end_idx = raw_text.rfind("}")
            if start_idx != -1 and end_idx != -1:
                json_str = raw_text[start_idx:end_idx+1]
                data = json.loads(json_str)
                is_real = data.get("is_real", True)
                reason = data.get("reason", "")
                
                if not is_real:
                    logger.info(f"AI Filter dropped False Positive '{finding.title}' in {finding.file_path}. Reason: {reason}")
                
                return is_real

        except Exception as e:
            logger.debug(f"AI Filter failed for finding '{finding.title}': {e}")
            return True  # Fallback: keep the finding if LLM fails

        return True

    async def filter_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Runs all findings through the AI filter concurrently, respecting API rate limits."""
        if not self.enabled or not findings:
            return findings

        is_openrouter = settings.llm_provider == "openrouter"
        concurrency = 2 if is_openrouter else 10
        sem = asyncio.Semaphore(concurrency)

        async def bounded_check(f):
            async with sem:
                res = await self._check_finding(f)
                if is_openrouter:
                    await asyncio.sleep(1.5) # Rate limit: prevent bursting 429
                return res

        # Run concurrently with bounds
        tasks = [bounded_check(f) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        filtered_findings = []
        for finding, is_real in zip(findings, results):
            if isinstance(is_real, Exception):
                logger.debug(f"AI Filter task exception: {is_real}")
                filtered_findings.append(finding) # Keep on failure
            elif is_real is True:
                filtered_findings.append(finding)
                
        return filtered_findings
