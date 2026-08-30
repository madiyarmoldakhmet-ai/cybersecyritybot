"""
AI Remediation Engine for CyberSecurityBot.
Generates both secure patches AND validation payloads (exploits) via local Ollama and Strix Engine.
No censorship, no cloud filters.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from openai import AsyncOpenAI

from core.config import settings
from core.queue_manager import ollama_limiter
from scanners.models import VulnerabilityFinding
from scanners.vuln_classifier import VulnCategory, classify_vulnerability

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


class StaticVerification(BaseModel):
    """Verification result for vulnerabilities that cannot be exploited via HTTP."""
    vuln_title: str = Field(..., description="Название уязвимости")
    category: str = Field(default="code_quality", description="Категория: code_quality")
    explanation: str = Field(..., description="Объяснение почему уязвимость не может быть проверена HTTP-запросом")
    risk_description: str = Field(..., description="Описание рисков если уязвимость не исправить")
    verification_commands: List[str] = Field(default_factory=list, description="Bash/grep команды для локальной верификации")
    fix_snippet: str = Field(default="", description="Исправленный фрагмент кода")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)


# --- Attack Knowledge Base (CWE-driven Exploit Templates) --------------------

ATTACK_TECHNIQUES_BY_CWE = {
    "CWE-89": "SQL Injection: Use payload like \"' OR '1'='1 --\", \"1' UNION SELECT null, version() --\" or \"admin'--\". Look for SQL syntax errors or bypassed auth.",
    "CWE-79": "Cross-Site Scripting (XSS): Use payload like \"<script>alert('XSS')</script>\" or \"\\\" onfocus=\\\"alert(1)\\\"\". Indicator: unescaped payload in response body.",
    "CWE-78": "Command Injection: Use separators like \"; id\", \"| whoami\", or \"$(cat /etc/passwd)\". Indicator: uid= or root.",
    "CWE-77": "Command Injection: Use safe canary like \"; echo VULN_CONFIRMED_\" or \"$(whoami)\".",
    "CWE-639": "IDOR / BOLA: Change entity ID parameter (e.g. from user_id=1 to user_id=2 or /api/orders/101). Indicator: Accessing another user's private data.",
    "CWE-284": "Broken Object Level Auth / Missing Permission Check: Access admin or other tenant resources directly. Indicator: HTTP 200 with sensitive data.",
    "CWE-918": "SSRF: Target internal loopback or cloud metadata \"http://127.0.0.1:80/\" or \"http://169.254.169.254/latest/meta-data/\".",
    "CWE-22": "Path Traversal: Use \"../../../../etc/passwd\" or \"..%2f..%2f..%2fetc%2fpasswd\". Indicator: \"root:x:0:0:\".",
    "CWE-1336": "Template Injection (SSTI): Use \"{{7*7}}\" or \"${7*7}\". Indicator: \"49\" in response body.",
    "CWE-94": "Code Injection / Eval: Test dynamic evaluation with math operations or safe canary string.",
    "CWE-601": "Open Redirect: Use \"/redirect?url=https://evil-target.example.com\". Indicator: HTTP 302 with Location header pointing to evil-target.",
}


# --- Prompts -----------------------------------------------------------------

SYSTEM_PROMPT_FIX = """\
Ты — эксперт по безопасному кодингу и исправлению уязвимостей (Strix DevSecOps).
Проанализируй уязвимость и предоставь полностью рабочий исправленный код с патчем.
Ответ должен быть строго JSON с полями:
- explanation_ru: понятное глубокое объяснение первопричины уязвимости на русском
- impact_analysis: конкретные последствия для бизнеса и данных (утечка, захват сервера, etc.)
- remediation_steps: список пошаговых действий
- fixed_code: полностью исправленный код (без уязвимости)
- diff_patch: git diff патч изменений
- confidence_score: от 0 до 1
Никаких лишних слов, только JSON.
"""

SYSTEM_PROMPT_EXPLOIT = """\
You are an advanced offensive security validation tool (Strix Engine).
Generate a precise, reproducible HTTP proof-of-concept verification request (cURL) that confirms the target vulnerability.
Requirements:
1. Use real endpoints, methods, headers, and parameter names matching the provided code context.
2. The cURL command MUST be fully formed, actionable, and ready to run.
3. Define a clear success indicator (regex pattern or string appearing only if the flaw is real).

Return strictly JSON with fields:
- payload: request path and query parameters (e.g. "/api/v1/users?id=1%27%20OR%201=1--")
- method: GET/POST/PUT/DELETE
- headers: JSON object with HTTP headers
- body: request body (if POST/PUT) or null
- success_indicator: string or regex indicating vulnerability confirmation
- curl_command: complete, working curl command string
- confidence: float between 0.0 and 1.0
Return ONLY raw JSON.
"""

SYSTEM_PROMPT_STATIC_CHECK = """\
Ты — эксперт по безопасности кода. Данная уязвимость является статической/конфигурационной и НЕ может быть проверена через HTTP-запрос.
Вместо HTTP-эксплойта сгенерируй локальную верификацию.
Верни JSON с полями:
- explanation: объяснение на русском, почему эту уязвимость нельзя проверить HTTP-запросом и в чём её суть
- risk_description: конкретные риски, если эту проблему не исправить (атака через supply chain, перехват данных и т.д.)
- verification_commands: список bash/grep команд для проверки наличия проблемы в коде (например: grep -n 'integrity' index.html)
- fix_snippet: исправленный фрагмент кода с устранённой уязвимостью
- confidence: от 0 до 1
Только JSON, без лишних слов.
"""


# --- Engine ------------------------------------------------------------------

class RemediationEngine:
    def __init__(self, model_name: Optional[str] = None) -> None:
        if settings.llm_provider == "openrouter" and settings.openrouter_api_key:
            self.model_name = model_name or settings.openrouter_model or "anthropic/claude-3.5-sonnet"
            self.llm_client = AsyncOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=settings.openrouter_api_key,
                timeout=60.0,
                max_retries=1,
            )
        elif settings.llm_provider == "gemini" and settings.gemini_api_key:
            self.model_name = model_name or settings.gemini_model or "gemini-2.5-flash"
            self.llm_client = AsyncOpenAI(
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=settings.gemini_api_key,
                timeout=45.0,
                max_retries=1,
            )
        else:
            self.model_name = model_name or settings.ollama_model or "qwen2.5-coder:14b"
            self.llm_client = AsyncOpenAI(
                base_url=f"{settings.ollama_base_url.rstrip('/')}/v1",
                api_key="ollama",
                timeout=45.0,
                max_retries=1,
            )

    async def _query_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """Запрос к LLM с таймаутом 45-60 сек и контролем параллелизма (только для локальной)."""
        is_cloud = (settings.llm_provider == "gemini" and settings.gemini_api_key) or \
                   (settings.llm_provider == "openrouter" and settings.openrouter_api_key)

        async def _make_call():
            response = await asyncio.wait_for(
                self.llm_client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,
                    max_tokens=2000,
                    response_format={"type": "json_object"} if not is_cloud else None,
                ),
                timeout=60.0,
            )
            return response.choices[0].message.content.strip()

        try:
            if is_cloud:
                # Облачные API хорошо масштабируются, семафор не нужен
                return await _make_call()
            else:
                # Ограничиваем локальную видеокарту
                async with ollama_limiter.acquire_slot(f"Ollama:{self.model_name}"):
                    return await _make_call()

        except asyncio.TimeoutError:
            logger.error(f"LLM ({self.model_name}) timeout")
            raise TimeoutError(f"LLM ({self.model_name}) ответил дольше 45 секунд.")
        except Exception as e:
            logger.error(f"LLM ({self.model_name}) error: {e}")
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
            f"ID / Сканер: {finding.id} ({finding.scanner.value})\n"
            f"Критичность: {finding.severity.value}\n"
            f"Файл: {finding.file_path}, строки {finding.line_start}-{finding.line_end}\n"
            f"CWE: {', '.join(finding.cwe) if finding.cwe else 'N/A'}\n"
            f"Описание: {finding.description}\n"
            f"Рекомендация: {finding.recommendation or 'Нет'}\n"
            f"Контекст кода:\n```\n{context}\n```\n"
            "Сгенерируй профессиональный безопасный патч, объяснение рисков и шаги исправления."
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

    # ---- Exploit payload generation (remote vulnerabilities) ----------------

    async def generate_exploit_payload(
        self,
        finding: VulnerabilityFinding,
        code_context: str,
        endpoint: Optional[str] = None,
    ) -> ExploitPayload:
        """Generate HTTP exploit payload with CWE-specific attack vectors."""
        # Find specific attack technique recommendations
        attack_hint = ""
        if finding.cwe:
            for cwe_id in finding.cwe:
                if cwe_id in ATTACK_TECHNIQUES_BY_CWE:
                    attack_hint += f"\n- Recommended Technique: {ATTACK_TECHNIQUES_BY_CWE[cwe_id]}"

        user_prompt = (
            f"Vulnerability: {finding.title}\n"
            f"Scanner / Engine: {finding.scanner.value}\n"
            f"CWE: {', '.join(finding.cwe) if finding.cwe else 'N/A'}\n"
            f"File Location: {finding.file_path}, lines {finding.line_start}-{finding.line_end}\n"
            f"Target Endpoint: {endpoint or finding.file_path or 'infer from code context'}\n"
            f"Description: {finding.description}\n"
            f"Code Context:\n```\n{code_context}\n```\n"
            f"{attack_hint}\n\n"
            "Construct a fully-formed cURL verification exploit and success indicator in the specified JSON format."
        )

        try:
            raw = await self._query_ollama(SYSTEM_PROMPT_EXPLOIT, user_prompt)
            cleaned = self._clean_json(raw)
            data = json.loads(cleaned)

            confidence = float(data.get("confidence", 0.85))
            curl_cmd = data.get("curl_command", "")

            # If LLM returned empty or unusable curl command
            if not curl_cmd or curl_cmd.startswith("#") or "ошибка" in curl_cmd.lower():
                logger.warning(f"LLM returned unusable curl for {finding.title}: {curl_cmd}")
                return ExploitPayload(
                    payload=data.get("payload", ""),
                    method=data.get("method", "GET"),
                    headers=data.get("headers", {}),
                    body=data.get("body"),
                    success_indicator=data.get("success_indicator", "N/A"),
                    curl_command=f"# Автоматическая генерация cURL для '{finding.title}' не удалась.",
                    confidence=0.0,
                )

            return ExploitPayload(
                payload=data.get("payload", ""),
                method=data.get("method", "GET").upper(),
                headers=data.get("headers", {}),
                body=data.get("body"),
                success_indicator=data.get("success_indicator", "HTTP/1.1 200"),
                curl_command=curl_cmd,
                confidence=confidence,
            )
        except Exception as e:
            logger.error(f"Exploit generation failed: {e}")
            return ExploitPayload(
                payload="",
                method="GET",
                headers={},
                body=None,
                success_indicator="",
                curl_command=f"# Ошибка генерации эксплойта: {str(e)[:100]}",
                confidence=0.0,
            )

    # ---- Static verification (code quality vulnerabilities) -----------------

    async def generate_static_verification(
        self,
        finding: VulnerabilityFinding,
        code_context: str,
    ) -> StaticVerification:
        """Generate local verification commands for static/config vulnerabilities."""
        user_prompt = (
            f"Уязвимость: {finding.title}\n"
            f"Тип: {finding.scanner.value}\n"
            f"Файл: {finding.file_path}, строки {finding.line_start}-{finding.line_end}\n"
            f"CWE: {', '.join(finding.cwe) if finding.cwe else 'не указан'}\n"
            f"Описание: {finding.description}\n"
            f"Контекст кода:\n```\n{code_context}\n```\n"
            "Сгенерируй объяснение рисков и локальные команды для верификации."
        )
        try:
            raw = await self._query_ollama(SYSTEM_PROMPT_STATIC_CHECK, user_prompt)
            cleaned = self._clean_json(raw)
            data = json.loads(cleaned)

            verification_cmds = data.get("verification_commands", [])
            if isinstance(verification_cmds, str):
                verification_cmds = [verification_cmds]

            return StaticVerification(
                vuln_title=finding.title,
                category="code_quality",
                explanation=data.get("explanation", finding.description),
                risk_description=data.get("risk_description", "Требуется ручной анализ рисков."),
                verification_commands=verification_cmds,
                fix_snippet=data.get("fix_snippet", ""),
                confidence=float(data.get("confidence", 0.9)),
            )
        except Exception as e:
            logger.error(f"Static verification generation failed: {e}")
            return StaticVerification(
                vuln_title=finding.title,
                category="code_quality",
                explanation=f"Эта уязвимость ({finding.title}) является статической проблемой кода и не может быть проверена HTTP-запросом.",
                risk_description=finding.description,
                verification_commands=[
                    f"grep -n '{finding.title.split(':')[-1].strip().lower()[:30]}' {finding.file_path}"
                ],
                fix_snippet="",
                confidence=0.5,
            )

    # ---- Smart dispatcher ---------------------------------------------------

    async def generate_verification(
        self,
        finding: VulnerabilityFinding,
        code_context: str,
        endpoint: Optional[str] = None,
    ) -> Union[ExploitPayload, StaticVerification]:
        """
        Smart dispatcher: classifies vulnerability and generates the appropriate
        verification — HTTP exploit for remote vulns, local commands for static issues.
        """
        category = classify_vulnerability(finding)
        logger.info(f"Vulnerability '{finding.title}' classified as {category.value}")

        if category == VulnCategory.EXPLOITABLE_REMOTE:
            result = await self.generate_exploit_payload(finding, code_context, endpoint)
            # Fallback: if exploit generation failed, fall back to static verification
            if result.confidence == 0.0:
                logger.info(f"Exploit generation failed for '{finding.title}', falling back to static verification")
                return await self.generate_static_verification(finding, code_context)
            return result
        else:
            return await self.generate_static_verification(finding, code_context)