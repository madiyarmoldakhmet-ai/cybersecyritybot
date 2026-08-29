"""
AI Remediation Engine for CyberSecurityBot.
Generates both secure patches AND validation payloads (exploits) via local Ollama.
No censorship, no cloud filters.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from openai import AsyncOpenAI

from core.config import settings
from scanners.models import VulnerabilityFinding

logger = logging.getLogger("cybersecuritybot.ai_engine")


# --- Data Models -------------------------------------------------------------

class RemediationResult(BaseModel):
    finding_id: str
    vuln_name: str
    severity: str
    explanation_ru: str
    impact_analysis: str
    remediation_steps: List[str] = Field(default_factory=list)
    fixed_code: str
    diff_patch: Optional[str] = None
    confidence_score: float = 0.9


class ExploitPayload(BaseModel):
    payload: str = Field(..., description="Проверочный запрос (URL-encoded, если нужно)")
    method: str = Field(default="GET", description="HTTP метод")
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = Field(None, description="Тело запроса для POST/PUT")
    success_indicator: str = Field(..., description="Строка или regex для проверки успеха")
    curl_command: str = Field(..., description="Готовая curl-команда")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


# --- Prompts -----------------------------------------------------------------

SYSTEM_PROMPT_FIX = """
Ты — эксперт по безопасному кодингу. Проанализируй уязвимость и предоставь исправленный код.
Ответ должен быть строго JSON с полями:
- explanation_ru: понятное объяснение на русском
- impact_analysis: риски
- remediation_steps: список шагов
- fixed_code: полностью исправленный код (без уязвимости)
- diff_patch: краткое описание изменений
- confidence_score: от 0 до 1
Никаких лишних слов, только JSON.
"""

SYSTEM_PROMPT_EXPLOIT = """
Ты — инструмент для валидации безопасности. Сгенерируй проверочный HTTP-запрос, который подтвердит наличие уязвимости.
Запрос должен быть безопасным для выполнения в тестовой среде.
Верни JSON с полями:
- payload: строка с параметрами запроса
- method: GET/POST/PUT/DELETE
- headers: объект заголовков
- body: тело запроса (если POST)
- success_indicator: текст или regex, который появится при успехе
- curl_command: готовая curl-команда
- confidence: от 0 до 1
Только JSON.
"""


# --- Engine ------------------------------------------------------------------

class RemediationEngine:
    def __init__(self, model_name: Optional[str] = None) -> None:
        self.model_name = model_name or settings.ollama_model or "qwen2.5-coder:14b"
        self.ollama_client = AsyncOpenAI(
            base_url=f"{settings.ollama_base_url.rstrip('/')}/v1",
            api_key="ollama",
            timeout=45.0,
            max_retries=1,
        )

    async def _query_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """Запрос к Ollama с таймаутом 45 сек."""
        try:
            response = await asyncio.wait_for(
                self.ollama_client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,
                    max_tokens=1500,
                    response_format={"type": "json_object"},
                ),
                timeout=45.0,
            )
            return response.choices[0].message.content.strip()
        except asyncio.TimeoutError:
            logger.error("Ollama timeout")
            raise TimeoutError("Ollama ответил дольше 45 секунд.")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            raise

    @staticmethod
    def _clean_json(raw: str) -> str:
        raw = raw.strip()
        if raw.startswith("```json"):
            raw = raw[7:]
        if raw.startswith("```"):
            raw = raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3]
        return raw.strip()

    # ---- Fix generation -----------------------------------------------------

    async def analyze_and_remediate(
        self,
        finding: VulnerabilityFinding,
        code_context: Optional[str] = None,
    ) -> RemediationResult:
        context = code_context or finding.code_snippet or "Нет контекста."
        user_prompt = (
            f"Уязвимость: {finding.title}\n"
            f"Тип: {finding.scanner.value}\n"
            f"Файл: {finding.file_path}, строки {finding.line_start}-{finding.line_end}\n"
            f"Описание: {finding.description}\n"
            f"Рекомендация: {finding.recommendation or 'Нет'}\n"
            f"Контекст кода:\n```\n{context}\n```\n"
            "Сгенерируй исправленный код и объяснения."
        )
        try:
            raw = await self._query_ollama(SYSTEM_PROMPT_FIX, user_prompt)
            cleaned = self._clean_json(raw)
            data = json.loads(cleaned)
            return RemediationResult(
                finding_id=finding.id,
                vuln_name=finding.title,
                severity=finding.severity.value,
                explanation_ru=data.get("explanation_ru", finding.description),
                impact_analysis=data.get("impact_analysis", "Анализ рисков не предоставлен."),
                remediation_steps=data.get("remediation_steps", []),
                fixed_code=data.get("fixed_code", context),
                diff_patch=data.get("diff_patch"),
                confidence_score=float(data.get("confidence_score", 0.9)),
            )
        except Exception as e:
            logger.error(f"Fix generation failed: {e}")
            return RemediationResult(
                finding_id=finding.id,
                vuln_name=finding.title,
                severity=finding.severity.value,
                explanation_ru=f"Ошибка генерации: {e}",
                impact_analysis="Проверьте работу Ollama.",
                remediation_steps=["Запустите `ollama serve` и проверьте модель."],
                fixed_code=context,
                confidence_score=0.0,
            )

    # ---- Exploit payload generation -----------------------------------------

    async def generate_exploit_payload(
        self,
        finding: VulnerabilityFinding,
        code_context: str,
        endpoint: Optional[str] = None,
    ) -> ExploitPayload:
        user_prompt = (
            f"Уязвимость: {finding.title}\n"
            f"Тип: {finding.scanner.value}\n"
            f"Файл: {finding.file_path}, строки {finding.line_start}-{finding.line_end}\n"
            f"Контекст:\n```\n{code_context}\n```\n"
            f"Эндпоинт (если известен): {endpoint or 'не указан'}\n"
            "Сгенерируй проверочный запрос для подтверждения уязвимости."
        )
        try:
            raw = await self._query_ollama(SYSTEM_PROMPT_EXPLOIT, user_prompt)
            cleaned = self._clean_json(raw)
            data = json.loads(cleaned)
            return ExploitPayload(
                payload=data.get("payload", ""),
                method=data.get("method", "GET"),
                headers=data.get("headers", {}),
                body=data.get("body"),
                success_indicator=data.get("success_indicator", ""),
                curl_command=data.get("curl_command", ""),
                confidence=float(data.get("confidence", 0.8)),
            )
        except Exception as e:
            logger.error(f"Exploit generation failed: {e}")
            return ExploitPayload(
                payload="",
                method="GET",
                headers={},
                body=None,
                success_indicator="",
                curl_command="# Ошибка генерации",
                confidence=0.0,
            )