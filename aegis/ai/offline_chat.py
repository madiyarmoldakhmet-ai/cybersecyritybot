"""
Context-aware offline AppSec chat responder for Commit Guardian.
Provides deterministic vulnerability explanations, CWE remediation patches, policy
guidance, and authorship-verification help when local Ollama or cloud LLMs are offline.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

import httpx

from aegis.core.config import settings


def is_configured_model_available(tags_payload: Any, target_model: str) -> bool:
    """Return True only when the configured Ollama model is actually present in /api/tags."""
    if not isinstance(tags_payload, dict):
        return False
    models = tags_payload.get("models")
    if not isinstance(models, list):
        return False
    wanted = (target_model or "").strip().lower()
    if not wanted:
        return len(models) > 0
    wanted_variants = {wanted}
    if ":" not in wanted:
        wanted_variants.add(f"{wanted}:latest")
    for entry in models:
        if not isinstance(entry, dict):
            continue
        for key in ("name", "model"):
            candidate = str(entry.get(key) or "").strip().lower()
            if candidate in wanted_variants:
                return True
    return False


async def probe_ai_status(timeout_seconds: float = 0.8) -> Tuple[str, bool, str]:
    """Probe effective AI runtime status (mode label, online flag, and UI hint)."""
    from aegis.core.llm_runtime import list_ollama_models, resolve_active_llm

    provider, model, _, is_local = await resolve_active_llm()
    if not is_local:
        return f"{provider.value} · {model} (BYOK)", True, "облачный BYOK-провайдер (сессионный ключ)"

    installed = await list_ollama_models(force_refresh=True)
    if installed:
        return f"Ollama · {model} (online)", True, "локальная модель, 0 байт в облако"
    return f"Ollama · {model} (standby)", False, "rule-based AppSec движок, без облака"


def format_scan_context_note(ctx: Optional[Dict[str, Any]]) -> str:
    """Format an active scan context dictionary into a concise summary block."""
    if not isinstance(ctx, dict) or not ctx.get("repo_name"):
        return ""

    findings = ctx.get("findings") or []
    top_lines = []
    for item in findings[:8]:
        if isinstance(item, dict):
            sev = item.get("severity", "INFO")
            title = item.get("title", "Vulnerability")
            loc = f"{item.get('file_path', '?')}:{item.get('line_start') or 1}"
            cwe = ", ".join(item.get("cwe") or [])
            top_lines.append(f"- [{sev}] {title} ({loc}" + (f", {cwe}" if cwe else "") + ")")

    note = (
        f"[Контекст текущего аудита в консоли] Репозиторий: {ctx.get('repo_name')}; "
        f"Score: {ctx.get('security_score', '-')}/100 ({ctx.get('grade', '-')}); "
        f"Всего находок: {ctx.get('total_findings', len(findings))}."
    )
    if top_lines:
        note += "\nКлючевые уязвимости:\n" + "\n".join(top_lines)
    return note


def parse_chat_payload(raw_data: str) -> Tuple[bool, str, str, Optional[Dict[str, Any]]]:
    """Parse plain text or JSON chat payload into (reset, text, summary_note, scan_ctx)."""
    stripped = raw_data.strip()
    if not stripped.startswith("{"):
        return False, stripped, "", None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return False, stripped, "", None
    if not isinstance(payload, dict):
        return False, stripped, "", None
    if payload.get("reset"):
        return True, "", "", None

    user_text = str(payload.get("message") or "").strip()
    ctx = payload.get("scan_context")
    valid_ctx = ctx if isinstance(ctx, dict) and ctx.get("repo_name") else None
    return False, user_text, format_scan_context_note(valid_ctx), valid_ctx


def _short_cwe(item: Dict[str, Any]) -> str:
    cwes = item.get("cwe") or []
    return ", ".join(str(c) for c in cwes[:2]) if cwes else str(item.get("scanner", "SAST")).upper()


def _quick_fix_hint(item: Dict[str, Any]) -> str:
    haystack = " ".join(
        str(item.get(k) or "") for k in ("title", "description", "recommendation")
    ).lower() + " " + " ".join(str(c).lower() for c in (item.get("cwe") or []))
    if "sql" in haystack or "cwe-89" in haystack or "b608" in haystack:
        return "Замени конкатенацию строк на параметризованный запрос (`cursor.execute('... WHERE id = ?', (user_id,))`)."
    if "shell" in haystack or "subprocess" in haystack or "cwe-78" in haystack or "b602" in haystack:
        return "Передай аргументы списком и выставь `shell=False`."
    if "ssl" in haystack or "tls" in haystack or "certificate" in haystack or "cwe-295" in haystack:
        return "Убери `badCertificateCallback => true` / отключение проверки SSL и включи TLS-пиннинг."
    if "eval" in haystack or "cwe-95" in haystack or "cwe-94" in haystack or "b307" in haystack:
        return "Замени динамический парсинг на `ast.literal_eval()` или `json.loads()`."
    if "secret" in haystack or "token" in haystack or "key" in haystack or "password" in haystack or "cwe-798" in haystack:
        return "Убери секрет из кода в переменные окружения и срочно перевыпусти ключ."
    if "иин" in haystack or "iin" in haystack or "pii" in haystack:
        return "Маскируй ИИН перед записью в логи (`mask_iin(value)` -> `******123456`)."
    return str(item.get("recommendation") or "Открой строку в таблице находок и нажми «Патч» для готового diff.")


def _find_matching_findings(findings: List[Dict[str, Any]], keywords: Tuple[str, ...]) -> List[Dict[str, Any]]:
    matched = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        blob = " ".join([
            str(item.get("title") or ""),
            str(item.get("description") or ""),
            str(item.get("file_path") or ""),
            " ".join(str(c) for c in (item.get("cwe") or [])),
        ]).lower()
        if any(kw in blob for kw in keywords):
            matched.append(item)
    return matched


def _reply_policy_and_iin(scan_context: Optional[Dict[str, Any]]) -> str:
    findings = (scan_context or {}).get("findings") or []
    pii_hits = _find_matching_findings(findings, ("иин", "iin", "pii", "персонал", "unmasked"))
    hit_block = ""
    if pii_hits:
        lines = [
            f"- `{f.get('file_path', '?')}:{f.get('line_start') or 1}` — {f.get('title')}"
            for f in pii_hits[:3]
        ]
        hit_block = "**Найдено в текущем аудите:**\n" + "\n".join(lines) + "\n\n"

    return (
        "### Политика `.aegis.yml` и защита персональных данных (ИИН)\n\n"
        f"{hit_block}"
        "Commit Guardian автоматически читает файл `.aegis.yml` в корне проверяемого репозитория:\n"
        "- `ignore_paths` — исключает тестовые и сборочные папки (`.venv`, `tests`, `fixtures`);\n"
        "- `severity_threshold` — задаёт порог провала CI/webhook (`CRITICAL` / `HIGH`);\n"
        "- `custom_rules` — проверяет утечки **12-значного казахстанского ИИН** и чувствительных полей в логах (`log.info` / `print`).\n\n"
        "```yaml\n"
        "severity_threshold: HIGH\n"
        "ignore_paths:\n"
        "  - tests/**\n"
        "custom_rules:\n"
        "  - id: kz-iin-in-logs\n"
        "    pattern: '\\\\b\\\\d{12}\\\\b'\n"
        "    severity: CRITICAL\n"
        "    message: 'Unmasked 12-digit KZ IIN detected'\n"
        "```"
    )


def _reply_authorship() -> str:
    return (
        "### Проверка авторства (Strict Ownership Gate)\n\n"
        "Перед сканированием закрытых репозиториев, активным DAST или созданием Pull Request открой вкладку **«Авторство»** и выбери один из 3 способов:\n\n"
        "1. **GitHub PAT (`token`)** — проверяет через GitHub API реальные права `push` / `admin` / `maintain` на репозиторий (обычного read-доступа недостаточно).\n"
        "2. **Commit / `verify.txt` Challenge** — сервер выдаёт одноразовый код `cybersec-verify-...` (TTL 30 мин); размести его в сообщении коммита или в `.well-known/aegis-verify.txt`.\n"
        "3. **DNS TXT (`_aegis-challenge.<domain>`)** — подтверждение владения доменом перед активным DAST.\n\n"
        "После проверки сервер выпускает подписанный **HMAC `proof_token`**, который разблокирует строгий режим аудита и авто-PR."
    )


def _reply_patch_guidance(q: str, scan_context: Optional[Dict[str, Any]]) -> str:
    findings = (scan_context or {}).get("findings") or []

    if any(k in q for k in ("shell", "command", "subprocess", "rce", "cmd")):
        hits = _find_matching_findings(findings, ("shell", "subprocess", "cwe-78", "b602"))
        loc = f" (в текущем аудите: `{hits[0].get('file_path')}:{hits[0].get('line_start') or 1}`)" if hits else ""
        return (
            f"### Патч от Command Injection (`CWE-78`){loc}\n\n"
            "Никогда не передавай пользовательскую строку в `shell=True`. Разбивай команду на список аргументов:\n\n"
            "```python\n"
            "# Опасно:\n"
            "subprocess.run(f\"ping -c 1 {host}\", shell=True)\n\n"
            "# Безопасно:\n"
            "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, check=True)\n"
            "```"
        )

    if any(k in q for k in ("ssl", "tls", "cert", "https", "flutter", "pinning")):
        hits = _find_matching_findings(findings, ("ssl", "tls", "295", "badcertificate"))
        loc = f" (в текущем аудите: `{hits[0].get('file_path')}:{hits[0].get('line_start') or 1}`)" if hits else ""
        return (
            f"### Патч SSL/TLS Validation (`CWE-295`){loc}\n\n"
            "Отключение проверки сертификатов открывает MITM-атаки на платёжные запросы. Удали обход `badCertificateCallback`:\n\n"
            "```dart\n"
            "// Опасно:\n"
            "client.badCertificateCallback = (cert, host, port) => true;\n\n"
            "// Безопасно: проверяем стандартным системным trust store + pinned SHA-256\n"
            "final context = SecurityContext(withTrustedRoots: true);\n"
            "```"
        )

    sqli_hits = _find_matching_findings(findings, ("sql", "cwe-89", "b608"))
    hit_note = ""
    if sqli_hits:
        first = sqli_hits[0]
        hit_note = f"Найдено в текущем скане: `{first.get('file_path', '?')}:{first.get('line_start') or 1}` ({first.get('title')}).\n\n"

    parts = [
        "### Патч от SQL-инъекции (`CWE-89`)",
        hit_note.strip(),
        "Не склеивай переменные пользователя в SQL-строки. Используй bind-параметры:\n\n"
        "```python\n"
        "# Опасно: подстановка пользовательского ввода в строку SQL-запроса\n"
        "cursor.execute(untrusted_sql_query)\n\n"
        "# Безопасно: параметризованный запрос\n"
        "cursor.execute(\"SELECT id, role FROM users WHERE iin = ?\", (user_iin,))\n"
        "```",
        "Нажми **«Патч»** напротив строки в таблице **Находки**, чтобы увидеть полный diff и при необходимости открыть Auto-PR.",
    ]
    return "\n\n".join(part for part in parts if part)


def _reply_findings_breakdown(scan_context: Optional[Dict[str, Any]]) -> str:
    if not scan_context or not scan_context.get("findings"):
        return (
            "Активного отчёта пока нет, поэтому разбирать нечего. "
            "Нажми **«Демо-аудит»** вверху справа (11–12 сек на тестовом KZ Fintech-приложении), "
            "прикрепи `.zip` скрепкой или вставь ссылку `github.com/owner/repo` — я разберу каждую критичную находку."
        )

    findings: List[Dict[str, Any]] = [f for f in (scan_context.get("findings") or []) if isinstance(f, dict)]
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranked = sorted(findings, key=lambda item: sev_order.get(str(item.get("severity", "INFO")).upper(), 9))

    repo = scan_context.get("repo_name", "workspace")
    score = scan_context.get("security_score", "-")
    grade = scan_context.get("grade", "-")
    total = scan_context.get("total_findings", len(findings))

    lines = [
        f"### Разбор аудита `{repo}` — Score **{score}/100 ({grade})**, находок: **{total}**",
        "",
        "**Приоритетные уязвимости для исправления:**",
    ]
    for idx, item in enumerate(ranked[:5], 1):
        sev = item.get("severity", "INFO")
        title = item.get("title", "Vulnerability")
        loc = f"{item.get('file_path', '?')}:{item.get('line_start') or 1}"
        cwe = _short_cwe(item)
        fix = _quick_fix_hint(item)
        lines.append(f"{idx}. **[`{sev}`] {title}** (`{loc}`, `{cwe}`) — {fix}")

    lines.append("")
    lines.append("Жми **«Патч»** рядом с нужной уязвимостью справа, чтобы получить готовый code-diff или открыть PR.")
    return "\n".join(lines)


def _reply_financial_risk(scan_context: Optional[Dict[str, Any]]) -> str:
    risk = (scan_context or {}).get("financial_risk") or {}
    total_kzt = risk.get("total_kzt")
    reg_kzt = risk.get("regulatory_kzt")
    inc_kzt = risk.get("incident_kzt")
    if total_kzt:
        fmt = lambda n: f"{int(n):,}".replace(",", " ") + " ₸"
        extra = f" + инцидент `{fmt(inc_kzt)}`" if inc_kzt else ""
        return (
            f"### Финансовый риск по ст. 79 КоАП РК: до **{fmt(total_kzt)}**\n\n"
            f"- **Расчёт:** штраф регулятора `{fmt(reg_kzt)}` (до 2 000 МРП × 4 325 ₸){extra}.\n"
            "- **Экономика (ROI):** тариф `Team On-Prem` стоит **190 000 ₸/мес** против **800 000+ ₸/мес** за штатного AppSec-инженера (~4.2× экономии).\n"
            "- Нажми **«Исцелить автоматически»** справа — система перепишет уязвимый код в песочнице, пересканирует и докажет снижение риска в тенге."
        )
    return (
        "### Финансовый риск и экономика (ст. 79 КоАП РК)\n\n"
        "- За утечку персональных данных (ИИН/ПДн) ст. 79 КоАП РК предусматривает штраф до **2 000 МРП (8 650 000 ₸)**, плюс внутреннюю стоимость инцидента из `.aegis.yml` (`records_at_risk × cost_per_record_kzt`).\n"
        "- Запусти **«Демо-аудит»**, чтобы увидеть расчёт по каждой строке кода и интерактивный ROI-калькулятор для твоей команды."
    )


def _reply_git_history_and_heal() -> str:
    return (
        "### Машина времени Git и Самоисцеление с доказательством\n\n"
        "1. **Машина времени Git (`git-history`)** — проигрывает историю коммитов и находит *ghost secrets* (токены и ключи, которые удалили из `HEAD`, но любой может восстановить через `git log -p`), с автором и окном утечки в днях.\n"
        "2. **Самоисцеление (`POST /api/scan/demo/heal` · `aegis heal`)** — правит копию кода через AST, проверяет синтаксис (`ast.parse`), **пересканирует** и оставляет только подтверждённые фиксы (плохие патчи откатываются автоматически).\n"
        "3. **Human-in-the-Loop апелляции** — любую ложную находку можно оспорить кнопкой **«FP»** с моментальным пересчётом `Security Score` и записью в аудит-лог `/dashboard`."
    )


def build_offline_appsec_reply(
    question: str,
    scan_context: Optional[Dict[str, Any]],
    ollama_model: str,
) -> str:
    """Return a context-aware deterministic AppSec response when live LLM streaming is unavailable."""
    q = (question or "").strip().lower()

    if any(k in q for k in ("тенге", "коап", "штраф", "roi", "деньг", "эконом", "финанс", "мрп")):
        return _reply_financial_risk(scan_context)

    if any(k in q for k in ("машина времени", "истор", "ghost", "самоисцел", "heal", "апелляц", "оспор", "false positive")):
        return _reply_git_history_and_heal()

    if any(k in q for k in ("aegis.yml", "иин", "iin", "pii", "персонал", "политик", "правил")):
        return _reply_policy_and_iin(scan_context)

    if any(k in q for k in ("автор", "владен", "verify", "challenge", "dns", "подтвер", "домен")):
        return _reply_authorship()

    if any(k in q for k in ("патч", "sql", "инъекц", "fix", "исправ", "shell", "command", "cmd", "ssl", "tls", "cert", "pinning")):
        return _reply_patch_guidance(q, scan_context)

    if any(k in q for k in ("критич", "баг", "уязв", "найден", "объясн", "разбер", "риск", "скан", "отчет", "отчёт", "score")):
        return _reply_findings_breakdown(scan_context)

    active_note = ""
    if scan_context and scan_context.get("repo_name"):
        active_note = (
            f"\n\nСейчас открыт отчёт по `{scan_context.get('repo_name')}` "
            f"(**{scan_context.get('security_score', '-')}/100 · {scan_context.get('grade', '-')}**, "
            f"находок: **{scan_context.get('total_findings', 0)}**) — спроси *«Объясни критичные баги»* или *«Патч от SQL-инъекции»*."
        )

    return (
        f"Готов к работе в режиме AppSec Engine (GPU-модель `{ollama_model}` сейчас в standby, "
        "поэтому весь анализ и рекомендации идут полностью детерминированно на сервере без утечки кода наружу):\n\n"
        "- **Аудит репозитория или `.zip`:** вставь ссылку `github.com/owner/repo`, загрузи `.zip` или нажми **«Демо-аудит»** (Semgrep + Bandit + pip-audit + AST Taint + Secrets + KZ ИИН).\n"
        "- **Проверка авторства:** во вкладке **«Авторство»** подтверди права через GitHub PAT, commit-челлендж или DNS TXT.\n"
        "- **Патчи и отчёты:** готовые фиксы по кнопке **«Патч»**, экспорт в **PDF/Markdown** и метрики на `/dashboard`."
        f"{active_note}"
    )
