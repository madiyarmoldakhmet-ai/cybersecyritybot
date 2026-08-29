"""
AI Remediation Engine for CyberSecurityBot.
Performs root-cause vulnerability analysis and generates secure code patches.
Supports local Ollama (e.g. Qwen2.5-Coder / DeepSeek-R1) and Google Gemini fallback.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from openai import AsyncOpenAI

from core.config import LLMProvider, settings
from scanners.models import VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.ai_engine")


class RemediationResult(BaseModel):
    finding_id: str = Field(..., description="ID of the addressed vulnerability")
    vuln_name: str = Field(..., description="Name/title of the vulnerability")
    severity: str = Field(..., description="Severity level")
    explanation_ru: str = Field(
        ..., description="Detailed explanation of the vulnerability in Russian"
    )
    impact_analysis: str = Field(
        ..., description="Potential security risk and impact analysis"
    )
    remediation_steps: List[str] = Field(
        default_factory=list, description="Step-by-step fix guide"
    )
    fixed_code: str = Field(
        ..., description="Complete, secure, drop-in replacement code for the vulnerable section"
    )
    diff_patch: Optional[str] = Field(
        default=None, description="Unified diff or summary of changed lines"
    )
    confidence_score: float = Field(
        default=0.9, ge=0.0, le=1.0, description="AI confidence score for the proposed patch"
    )


class RemediationEngine:
    """Orchestrates AI analysis and automated patch generation."""

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        model_name: Optional[str] = None,
    ) -> None:
        self.provider = provider or settings.llm_provider
        self.model_name = model_name or (
            settings.ollama_model
            if self.provider == LLMProvider.OLLAMA
            else settings.gemini_model
        )

        # Initialize OpenAI-compatible client for Ollama
        self.ollama_client = AsyncOpenAI(
            base_url=f"{settings.ollama_base_url.rstrip('/')}/v1",
            api_key="ollama",  # Ollama does not require a real key
            timeout=5.0,
            max_retries=1,
        )

    def _build_system_prompt(self) -> str:
        return (
            "Ты — ведущий эксперт по информационной безопасности и Senior DevSecOps инженер. "
            "Твоя задача — проанализировать отчет об уязвимости SAST/Bandit/Semgrep и предоставить "
            "детальный анализ и полностью рабочий, безопасный патч (исправленный код). "
            "Ответ ДОЛЖЕН быть строго в формате JSON со следующей структурой ключей:\n"
            "{\n"
            '  "explanation_ru": "Подробное и понятное объяснение уязвимости и первопричины на русском языке",\n'
            '  "impact_analysis": "К чему может привести эксплуатация данной уязвимости (анализ рисков)",\n'
            '  "remediation_steps": ["Шаг 1: ...", "Шаг 2: ..."],\n'
            '  "fixed_code": "Полный исправленный и безопасный блок кода без уязвимости",\n'
            '  "diff_patch": "Краткое описание того, что было изменено (diff)",\n'
            '  "confidence_score": 0.95\n'
            "}\n"
            "Не добавляй markdown ```json ... ``` вокруг ответа, верни только чистый JSON."
        )

    def _build_user_prompt(
        self, finding: VulnerabilityFinding, code_context: str
    ) -> str:
        return (
            f"Найденная уязвимость:\n"
            f"- ID: {finding.id}\n"
            f"- Сканер: {finding.scanner.value}\n"
            f"- Название: {finding.title}\n"
            f"- Описание: {finding.description}\n"
            f"- Уровень: {finding.severity.value}\n"
            f"- Файл: {finding.file_path}\n"
            f"- Строки: {finding.line_start}-{finding.line_end}\n"
            f"- CWE: {', '.join(finding.cwe) if finding.cwe else 'N/A'}\n"
            f"- CVE: {', '.join(finding.cve) if finding.cve else 'N/A'}\n"
            f"- Рекомендация сканера: {finding.recommendation or 'N/A'}\n\n"
            f"Фрагмент уязвимого исходного кода:\n"
            f"```python\n{code_context}\n```\n\n"
            f"Проанализируй уязвимость и верни JSON со структурированным решением и исправленным кодом (fixed_code)."
        )

    async def _query_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """Execute chat completion via local Ollama API."""
        try:
            response = await self.ollama_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content or ""
            return content.strip()
        except Exception as e:
            logger.warning(f"Ollama inference error: {e}. Attempting fallback...")
            raise e

    async def _query_gemini(self, system_prompt: str, user_prompt: str) -> str:
        """Execute chat completion via Google Gemini API."""
        if not settings.gemini_api_key:
            raise ValueError("GEMINI_API_KEY is not set in environment or settings.")

        import google.generativeai as genai

        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel(
            model_name=settings.gemini_model,
            system_instruction=system_prompt,
            generation_config={"response_mime_type": "application/json", "temperature": 0.2},
        )
        response = await model.generate_content_async(user_prompt)
        return response.text.strip()

    def _parse_llm_json_response(
        self, raw_text: str, finding: VulnerabilityFinding
    ) -> RemediationResult:
        """Clean and validate LLM JSON output."""
        cleaned = raw_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback if model returned partially malformed JSON
            logger.error(f"Failed to parse LLM JSON: {raw_text[:200]}")
            return RemediationResult(
                finding_id=finding.id,
                vuln_name=finding.title,
                severity=finding.severity.value,
                explanation_ru=raw_text[:500],
                impact_analysis="Требуется ручная проверка уязвимости.",
                remediation_steps=["Примените безопасные паттерны кодирования."],
                fixed_code=finding.code_snippet or "# Код требует ручного исправления",
                diff_patch="Не удалось автоматически распарсить структурированный патч",
                confidence_score=0.5,
            )

        return RemediationResult(
            finding_id=finding.id,
            vuln_name=finding.title,
            severity=finding.severity.value,
            explanation_ru=data.get("explanation_ru", finding.description),
            impact_analysis=data.get("impact_analysis", "Высокий риск безопасности"),
            remediation_steps=data.get("remediation_steps", []),
            fixed_code=data.get("fixed_code", finding.code_snippet or ""),
            diff_patch=data.get("diff_patch", None),
            confidence_score=float(data.get("confidence_score", 0.9)),
        )

    async def analyze_and_remediate(
        self,
        finding: VulnerabilityFinding,
        code_context: Optional[str] = None,
    ) -> RemediationResult:
        """
        Analyze a vulnerability finding and generate structured remediation with secure code.
        """
        context = code_context or finding.code_snippet or "Фрагмент кода не предоставлен."
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(finding, context)

        raw_output = ""
        # 1. Try primary provider
        if self.provider == LLMProvider.OLLAMA:
            try:
                raw_output = await self._query_ollama(system_prompt, user_prompt)
            except Exception as e:
                logger.warning(f"Ollama failed ({e}), checking Gemini fallback...")
                if settings.gemini_api_key:
                    raw_output = await self._query_gemini(system_prompt, user_prompt)
                else:
                    return RemediationResult(
                        finding_id=finding.id,
                        vuln_name=finding.title,
                        severity=finding.severity.value,
                        explanation_ru=(
                            f"Локальная модель Ollama недоступна ({e}), и GEMINI_API_KEY не задан. "
                            f"Рекомендация сканера: {finding.recommendation or finding.description}"
                        ),
                        impact_analysis="Определяется типом уязвимости.",
                        remediation_steps=["Запустите локально `ollama serve` или укажите GEMINI_API_KEY."],
                        fixed_code=context,
                        diff_patch=None,
                        confidence_score=0.0,
                    )
        else:
            try:
                raw_output = await self._query_gemini(system_prompt, user_prompt)
            except Exception as e:
                logger.warning(f"Gemini failed ({e}), checking Ollama fallback...")
                try:
                    raw_output = await self._query_ollama(system_prompt, user_prompt)
                except Exception:
                    raise RuntimeError(f"All LLM providers failed. Last error: {e}")

        return self._parse_llm_json_response(raw_output, finding)
