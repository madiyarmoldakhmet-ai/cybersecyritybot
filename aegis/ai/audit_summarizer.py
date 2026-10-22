"""
Local AI Audit Summarizer for Commit Guardian.
Turns the merged SAST findings of a single commit into a short executive summary
using the local Ollama model, so source code and findings never leave the host.
"""

import logging
import time
from dataclasses import dataclass
from typing import List, Optional

from openai import AsyncOpenAI

from aegis.core.config import settings
from aegis.core.queue_manager import ollama_limiter
from aegis.scanners.models import SASTScanResult, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.audit_summarizer")

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# Keep the prompt bounded so a noisy commit cannot exhaust the local model's context window
MAX_FINDINGS_IN_PROMPT = 25
MAX_SNIPPET_CHARS = 240

SUMMARY_SYSTEM_PROMPT = """\
Ты — ведущий инженер по безопасности приложений, который готовит заключение аудита кода для государственной организации.
На вход ты получаешь список находок статического анализа (SAST) по одному коммиту.

Напиши краткое заключение на русском языке (5–8 предложений, без Markdown-заголовков):
1. Общая оценка риска коммита (критический / высокий / средний / низкий) и почему.
2. Самые опасные уязвимости: что именно и где.
3. Приоритетные шаги по устранению, по порядку.

Пиши только по фактам из списка находок. Не придумывай уязвимости, файлы или цифры, которых нет во входных данных.
"""


@dataclass
class AuditSummary:
    """Executive summary of a commit audit and how it was produced."""

    text: str
    model: str
    duration_seconds: float
    ai_generated: bool


def sort_findings(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    """Order findings from most to least severe."""
    rank = {sev: idx for idx, sev in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: rank.get(f.severity, len(SEVERITY_ORDER)))


class AuditSummarizer:
    """
    Produces the AI vulnerability summary for compliance reports.
    Always talks to the local Ollama endpoint: no cloud provider is ever used here.
    """

    def __init__(
        self,
        client: Optional[AsyncOpenAI] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.model = model or settings.ollama_model
        self.client = client or AsyncOpenAI(
            base_url=settings.ollama_base_url.rstrip("/") + "/v1",
            api_key="ollama",  # Ollama ignores the key, the SDK requires one
            timeout=float(timeout_seconds or settings.ai_summary_timeout_seconds),
            max_retries=0,
        )

    async def summarize(self, scan_result: SASTScanResult, repo_name: str, commit_sha: str) -> AuditSummary:
        """Summarize a scan result. Falls back to a deterministic summary if Ollama is unavailable."""
        if not scan_result.findings:
            return AuditSummary(
                text="Уязвимостей не обнаружено: SAST-сканеры не выявили проблем безопасности в этом коммите.",
                model="—",
                duration_seconds=0.0,
                ai_generated=False,
            )

        prompt = self._build_prompt(scan_result, repo_name, commit_sha)
        try:
            async with ollama_limiter.acquire_slot(f"AuditSummary:{repo_name}:{commit_sha[:8]}"):
                # Time only the inference itself, not the wait for a free Ollama slot
                started = time.perf_counter()
                resp = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                    max_tokens=600,
                )
            text = (resp.choices[0].message.content or "").strip()
            if not text:
                raise ValueError("Empty response from local model")

            duration = round(time.perf_counter() - started, 2)
            logger.info(f"Local AI summary for {repo_name}@{commit_sha[:8]} generated in {duration}s ({self.model})")
            return AuditSummary(text=text, model=self.model, duration_seconds=duration, ai_generated=True)

        except Exception as e:
            logger.warning(f"Local AI summary unavailable for {repo_name}@{commit_sha[:8]}, using rule-based summary: {e}")
            return AuditSummary(
                text=self.fallback_summary(scan_result),
                model="rule-based (Ollama недоступна)",
                duration_seconds=0.0,
                ai_generated=False,
            )

    def _build_prompt(self, scan_result: SASTScanResult, repo_name: str, commit_sha: str) -> str:
        counts = ", ".join(
            f"{sev.value}: {scan_result.findings_by_severity.get(sev, 0)}" for sev in SEVERITY_ORDER
        )
        lines = [
            f"Репозиторий: {repo_name}",
            f"Коммит: {commit_sha}",
            f"Всего находок: {scan_result.total_findings} ({counts})",
            "",
            "Находки:",
        ]
        ordered = sort_findings(scan_result.findings)
        for f in ordered[:MAX_FINDINGS_IN_PROMPT]:
            location = f"{f.file_path}:{f.line_start or 1}"
            cwe = f" [{', '.join(f.cwe)}]" if f.cwe else ""
            lines.append(f"- [{f.severity.value}] {f.title} ({f.id}, {f.scanner.value}) — {location}{cwe}")
            if f.code_snippet:
                snippet = " ".join(f.code_snippet.split())[:MAX_SNIPPET_CHARS]
                lines.append(f"  код: {snippet}")
        if len(ordered) > MAX_FINDINGS_IN_PROMPT:
            lines.append(f"... и ещё {len(ordered) - MAX_FINDINGS_IN_PROMPT} находок меньшей важности")
        return "\n".join(lines)

    @staticmethod
    def fallback_summary(scan_result: SASTScanResult) -> str:
        """Deterministic summary used when the local model cannot be reached."""
        crit = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
        high = scan_result.findings_by_severity.get(Severity.HIGH, 0)
        med = scan_result.findings_by_severity.get(Severity.MEDIUM, 0)

        if crit:
            risk = "критический"
        elif high:
            risk = "высокий"
        elif med:
            risk = "средний"
        else:
            risk = "низкий"

        parts = [
            f"Уровень риска коммита: {risk}. Обнаружено находок: {scan_result.total_findings} "
            f"(CRITICAL: {crit}, HIGH: {high}, MEDIUM: {med})."
        ]
        top = [f for f in sort_findings(scan_result.findings) if f.severity in (Severity.CRITICAL, Severity.HIGH)][:3]
        if top:
            listed = "; ".join(f"{f.title} ({f.file_path}:{f.line_start or 1})" for f in top)
            parts.append(f"Устранить в первую очередь: {listed}.")
        parts.append("Сводка сформирована по правилам, так как локальная модель Ollama была недоступна.")
        return " ".join(parts)
