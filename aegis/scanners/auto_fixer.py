import logging
import os
from typing import Optional
from openai import AsyncOpenAI

from aegis.core.config import settings
from aegis.scanners.models import VulnerabilityFinding

logger = logging.getLogger("aegis.auto_fixer")

AUTO_FIXER_PROMPT = """\
Ты AI Security Engineer. Вот уязвимый код. 
Напиши безопасную версию этого кода. Выведи ТОЛЬКО безопасный код, без объяснений. 
Если это XSS — добавь санитизацию. 
Если это хардкод секрета — замени его на os.getenv("..."), process.env.YOUR_SECRET, или аналогичный механизм для текущего языка. 
Если это SQLi — используй параметризованные запросы. 

Код ДОЛЖЕН быть обрамлен в markdown (например, ```python ... ```). Никаких слов, приветствий или описаний.
"""

class AIAutoFixer:
    """
    Auto-Remediation module to generate secure code patches for vulnerabilities.
    """
    
    def __init__(self, timeout_seconds: int = 45) -> None:
        self.client: Optional[AsyncOpenAI] = None
        self.model_name = ""
        self.enabled = False

        if settings.use_local_llm or settings.llm_provider == "ollama":
            self.model_name = settings.ollama_model or "qwen2.5-coder:14b"
            self.client = AsyncOpenAI(
                base_url=settings.ollama_base_url + "/v1",
                api_key="ollama", # Ollama doesn't require an API key
                timeout=float(timeout_seconds),
                max_retries=3,
            )
            self.enabled = True
        elif settings.llm_provider == "openrouter" and settings.openrouter_api_key:
            self.model_name = settings.openrouter_model or "anthropic/claude-sonnet-5"
            self.client = AsyncOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=settings.openrouter_api_key,
                timeout=float(timeout_seconds),
                max_retries=3,
            )
            self.enabled = True
        elif settings.llm_provider == "gemini" and settings.gemini_api_key:
            self.model_name = settings.gemini_model or "gemini-2.5-flash"
            self.client = AsyncOpenAI(
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=settings.gemini_api_key,
                timeout=float(timeout_seconds),
                max_retries=3,
            )
            self.enabled = True

    async def generate_fix(self, finding: VulnerabilityFinding) -> Optional[str]:
        """
        Generates a secure version of the code snippet.
        """
        if not self.enabled or not self.client:
            logger.warning("AI Auto-Fixer is not configured.")
            return None
            
        if not finding.code_snippet:
            return None

        prompt = (
            f"Vulnerability Title: {finding.title}\n"
            f"File: {finding.file_path}\n"
            f"Vulnerable Code:\n\n{finding.code_snippet}\n"
        )

        try:
            resp = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": AUTO_FIXER_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=800,
            )
            
            raw_text = resp.choices[0].message.content or ""
            
            if "```" in raw_text:
                blocks = raw_text.split("```")
                if len(blocks) >= 3:
                    code = blocks[1]
                    if "\n" in code:
                        first_line, rest = code.split("\n", 1)
                        if not any(char.isspace() for char in first_line):
                            return rest.strip()
                    return code.strip()
                    
            return raw_text.strip()
            
        except Exception as e:
            logger.error(f"Auto-fix generation failed: {e}")
            return None
