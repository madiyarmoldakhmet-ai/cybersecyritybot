"""
Observability Dashboard for Commit Guardian.
Serves `/dashboard`: a self-contained HTML page (inline CSS, no CDN or web fonts, so it
works in air-gapped networks) plus the JSON metrics endpoint that refreshes it.
"""

import html
import logging
import secrets
from typing import Any, Dict, Optional

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from aegis.ai.offline_chat import probe_ai_status
from aegis.core.audit_pipeline import report_urls_for
from aegis.core.config import settings
from aegis.core.metrics_store import DashboardMetrics, get_metrics_store
from aegis.core.traffic_guard import traffic_telemetry

logger = logging.getLogger("aegis.dashboard")
router = APIRouter(tags=["Observability"])

REFRESH_SECONDS = 10


@router.get("/api/v1/dashboard/metrics")
async def dashboard_metrics() -> Dict[str, Any]:
    """Aggregated audit metrics backing the dashboard."""
    data = get_metrics_store().summary().to_dict()
    llm_mode, llm_online, llm_hint = await probe_ai_status(timeout_seconds=0.4)
    data["llm_mode"] = llm_mode
    data["llm_online"] = llm_online
    data["llm_hint"] = llm_hint
    data["live_traffic"] = traffic_telemetry.snapshot()
    return data


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> HTMLResponse:
    """Render the observability dashboard."""
    metrics = get_metrics_store().summary()
    llm_mode, llm_online, llm_hint = await probe_ai_status(timeout_seconds=0.4)
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return HTMLResponse(
        _render(metrics, nonce, llm_mode=llm_mode, llm_online=llm_online, llm_hint=llm_hint),
        headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )


def _llm_mode() -> str:
    return f"Ollama · {settings.ollama_model}"


def _fmt_seconds(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.1f} с"


def _fmt_time(iso: str) -> str:
    return iso.replace("T", " ")[:16]


def _row(audit: Dict[str, Any]) -> str:
    e = html.escape
    if audit["status"] == "failed":
        status = '<span class="pill pill-fail">ошибка</span>'
    elif audit["critical"] or audit["high"]:
        status = '<span class="pill pill-risk">риск</span>'
    else:
        status = '<span class="pill pill-ok">чисто</span>'
    ai = _fmt_seconds(audit["ai_seconds"]) if audit["ai_generated"] else "—"
    pdf_url, md_url = report_urls_for(audit["repo_name"], audit.get("report_name"))
    if pdf_url and md_url and audit["status"] != "failed":
        report_links = (
            f'<a class="link" href="{e(pdf_url)}" target="_blank">PDF</a> · '
            f'<a class="link" href="{e(md_url)}" target="_blank">MD</a>'
        )
    else:
        report_links = '<span class="muted">—</span>'
    return (
        "<tr>"
        f'<td class="mono muted">{e(_fmt_time(audit["created_at"]))}</td>'
        f"<td>{e(audit['repo_name'])}<div class=\"mono muted small\">{e(audit['branch'])}</div></td>"
        f'<td class="mono">{e(audit["commit_sha"][:8])}</td>'
        f'<td class="num {"crit" if audit["critical"] else "muted"}">{audit["critical"]}</td>'
        f'<td class="num {"high" if audit["high"] else "muted"}">{audit["high"]}</td>'
        f'<td class="num {"" if audit["medium"] else "muted"}">{audit["medium"]}</td>'
        f'<td class="num {"" if audit["low"] else "muted"}">{audit["low"]}</td>'
        f'<td class="num mono">{e(ai)}</td>'
        f"<td>{status}</td>"
        f'<td class="mono small">{report_links}</td>'
        "</tr>"
    )


def _appeal_row(item: Dict[str, Any]) -> str:
    e = html.escape
    badge = "FP" if item.get("status") == "false_positive" else "ACCEPTED"
    return (
        "<tr>"
        f'<td class="mono muted">{e(_fmt_time(item["created_at"]))}</td>'
        f'<td class="mono">{e(item["repo_name"])}</td>'
        f'<td>{e(item["finding_title"])}<div class="mono muted small">{e(item["finding_key"])}</div></td>'
        f'<td class="mono">{e(item["severity"])}</td>'
        f'<td><span class="pill pill-ok">{badge}</span></td>'
        f'<td class="small muted">{e(item["reason"] or "—")}</td>'
        "</tr>"
    )


def _render(
    m: DashboardMetrics,
    nonce: str,
    llm_mode: Optional[str] = None,
    llm_online: bool = False,
    llm_hint: str = "локальная модель, без облака",
) -> str:
    e = html.escape
    effective_mode = llm_mode or _llm_mode()
    dot_cls = "dot" if llm_online else "dot dot-standby"
    rows = "".join(_row(a) for a in m.recent) or (
        '<tr><td colspan="10" class="empty">Пока нет проверок. Отправьте push в подключённый репозиторий или запустите демо.</td></tr>'
    )
    appeal_rows = "".join(_appeal_row(a) for a in m.recent_appeals) or (
        '<tr><td colspan="6" class="empty">Оспоренных находок (False Positive) пока нет.</td></tr>'
    )
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Commit Guardian — мониторинг</title>
<style>
  :root {{
    color-scheme: dark;
    --bg: #0b0e18; --panel: #121829; --panel-2: #19223a;
    --line: #324670; --line-strong: #5270ab; --shadow: #05070e;
    --text: #eef6ff; --body: #c9e4ff; --muted: #93add1;
    --accent: #56d4b2; --violet: #8e7ef0; --moon: #ffe79e;
    --ok: #47d18c; --crit: #ff6b57; --high: #f0b541;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", "Courier New", monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; border-radius: 0 !important; }}
  body {{
    background-color: var(--bg);
    background-image:
      linear-gradient(180deg, rgba(45,168,144,.14) 0px, rgba(94,76,168,.09) 72px, transparent 150px),
      radial-gradient(rgba(201,228,255,.16) 1px, transparent 0);
    background-size: 100% 100%, 28px 28px;
    color: var(--text);
    font: 14px/1.55 var(--mono);
    padding: 0 24px 40px;
  }}
  .aurora-bar {{
    height: 4px; margin: 0 -24px 32px;
    background-image: repeating-linear-gradient(
      90deg,
      #1f6e6c 0px, #1f6e6c 24px, #2da890 24px, #2da890 48px,
      #56d4b2 48px, #56d4b2 64px, #5e4ca8 64px, #5e4ca8 96px,
      #3d3572 96px, #3d3572 120px, #ffe79e 120px, #ffe79e 132px,
      #e94a32 132px, #e94a32 148px
    );
  }}
  .wrap {{ max-width: 1180px; margin: 0 auto; }}
  header {{ display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: flex-end; margin-bottom: 28px; }}
  .eyebrow {{ font: 12px var(--mono); color: var(--accent); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }}
  h1 {{ font-size: 26px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; text-shadow: 3px 3px 0 var(--shadow); }}
  .status {{ display: flex; gap: 10px; flex-wrap: wrap; }}
  .chip {{
    font: 12px var(--mono); color: var(--body); background: var(--panel);
    border: 2px solid var(--line-strong); padding: 6px 12px;
    box-shadow: 3px 3px 0 var(--shadow);
  }}
  .chip b {{ color: var(--moon); font-weight: 600; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; background: var(--ok); margin-right: 8px; }}
  .dot-standby {{ background: var(--high); }}
  .kpis {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
  .kpi {{
    background: var(--panel); border: 2px solid var(--line-strong); padding: 20px;
    box-shadow: 4px 4px 0 var(--shadow);
  }}
  .kpi .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .6px; }}
  .kpi .value {{ font-size: 46px; font-weight: 700; letter-spacing: -1px; line-height: 1.1; margin-top: 8px; font-variant-numeric: tabular-nums; text-shadow: 3px 3px 0 var(--shadow); }}
  .kpi .hint {{ color: var(--muted); font-size: 11.5px; margin-top: 8px; }}
  .kpi.crit .value {{ color: var(--crit); }}
  .kpi.ai .value {{ color: var(--accent); }}
  .secondary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0 24px; }}
  .stat {{
    background: var(--panel-2); border: 2px solid var(--line); padding: 12px 14px;
    box-shadow: 3px 3px 0 var(--shadow);
  }}
  .stat .label {{ color: var(--muted); font-size: 11.5px; text-transform: uppercase; }}
  .stat .value {{ font-size: 22px; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; color: var(--text); }}
  h2 {{ font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: .8px; color: var(--moon); margin-bottom: 12px; }}
  .table-wrap {{
    background: var(--panel); border: 2px solid var(--line-strong); overflow-x: auto;
    box-shadow: 4px 4px 0 var(--shadow);
  }}
  table {{ width: 100%; border-collapse: collapse; min-width: 760px; }}
  th, td {{ padding: 11px 14px; text-align: left; border-bottom: 2px solid var(--line); vertical-align: top; }}
  th {{ color: var(--accent); background: var(--panel-2); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
  tr:last-child td {{ border-bottom: none; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  th.num {{ text-align: right; }}
  .mono {{ font-family: var(--mono); font-size: 12.5px; }}
  .muted {{ color: var(--muted); }}
  .small {{ font-size: 11.5px; }}
  .crit {{ color: var(--crit); font-weight: 700; }}
  .high {{ color: var(--high); font-weight: 700; }}
  .pill {{ font: 11px var(--mono); padding: 2px 8px; border: 2px solid; white-space: nowrap; text-transform: uppercase; }}
  .pill-ok {{ color: var(--ok); border-color: var(--ok); background: rgba(71,209,140,.14); }}
  .pill-risk {{ color: var(--crit); border-color: #e94a32; background: rgba(233,74,50,.18); }}
  .pill-fail {{ color: var(--muted); border-color: var(--line); background: rgba(255,255,255,.05); }}
  .link {{ color: var(--accent); text-decoration: none; }}
  .link:hover {{ text-decoration: underline; color: var(--moon); }}
  .nav-link {{ color: var(--text); text-decoration: none; background: #e94a32; border-color: #ff8c78; }}
  .nav-link:hover {{ background: #ff5b42; }}
  .empty {{ color: var(--muted); text-align: center; padding: 36px; }}
  footer {{ color: var(--muted); font-size: 12px; margin-top: 24px; }}
  @media (forced-colors: active) {{
    .chip, .kpi, .stat, .table-wrap {{ box-shadow: none; border: 2px solid CanvasText; }}
  }}
  @media (max-width: 760px) {{
    .kpis {{ grid-template-columns: 1fr; }}
    .secondary {{ grid-template-columns: repeat(2, 1fr); }}
    .kpi .value {{ font-size: 38px; }}
  }}
</style>
</head>
<body>
<div class="aurora-bar" aria-hidden="true"></div>
<div class="wrap">
  <header>
    <div>
      <div class="eyebrow">// commit-guardian</div>
      <h1>Мониторинг безопасности</h1>
    </div>
    <div class="status">
      <a class="chip nav-link" href="/">← Консоль сканера</a>
      <span class="chip"><span class="{dot_cls}" id="ai_chip_dot"></span>AI: <b id="ai_chip_label">{e(effective_mode)}</b></span>
      <span class="chip">данные не покидают сервер</span>
    </div>
  </header>

  <section class="kpis">
    <div class="kpi">
      <div class="label">Всего проверок</div>
      <div class="value" id="total_scans">{m.total_scans}</div>
      <div class="hint">коммитов проверено автоматически</div>
    </div>
    <div class="kpi crit">
      <div class="label">Критических уязвимостей</div>
      <div class="value" id="critical_found">{m.critical_found}</div>
      <div class="hint">найдено до продакшена</div>
    </div>
    <div class="kpi ai">
      <div class="label">Среднее время AI-анализа</div>
      <div class="value" id="avg_ai_seconds">{e(_fmt_seconds(m.avg_ai_seconds))}</div>
      <div class="hint" id="ai_kpi_hint">{e(llm_hint)}</div>
    </div>
  </section>

  <section class="secondary">
    <div class="stat"><div class="label">Уязвимостей HIGH</div><div class="value" id="high_found">{m.high_found}</div></div>
    <div class="stat"><div class="label">Всего находок</div><div class="value" id="total_findings">{m.total_findings}</div></div>
    <div class="stat"><div class="label">Репозиториев</div><div class="value" id="repos_monitored">{m.repos_monitored}</div></div>
    <div class="stat"><div class="label">Среднее время сканирования</div><div class="value" id="avg_scan_seconds">{e(_fmt_seconds(m.avg_scan_seconds))}</div></div>
    <div class="stat"><div class="label">Оспорено (FP)</div><div class="value" id="appeals_count">{m.appeals_count}</div></div>
  </section>

  <section class="secondary" aria-label="Живая активность сайта">
    <div class="stat"><div class="label">Онлайн сейчас (WS)</div><div class="value" id="live_active_online">{traffic_telemetry.active_ws_users}</div></div>
    <div class="stat"><div class="label">Уникальных гостей</div><div class="value" id="live_unique_visitors">{traffic_telemetry.snapshot()["unique_visitors"]}</div></div>
    <div class="stat"><div class="label">Всего HTTP-запросов</div><div class="value" id="live_total_requests">{traffic_telemetry.total_requests}</div></div>
    <div class="stat"><div class="label">Кэш Демо-скана</div><div class="value" id="live_demo_cache_hits">{traffic_telemetry.demo_cache_hits}</div></div>
    <div class="stat"><div class="label">Заблокировано (429)</div><div class="value" id="live_rate_limited_429">{traffic_telemetry.rate_limited_429}</div></div>
  </section>

  <h2>Последние проверки</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Время (UTC)</th><th>Репозиторий</th><th>Коммит</th>
        <th class="num">CRIT</th><th class="num">HIGH</th><th class="num">MED</th><th class="num">LOW</th>
        <th class="num">AI</th><th>Статус</th><th>Отчёт</th>
      </tr></thead>
      <tbody id="recent">{rows}</tbody>
    </table>
  </div>

  <h2 style="margin-top:28px;">Журнал апелляций (Human-in-the-Loop)</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Время (UTC)</th><th>Репозиторий</th><th>Находка</th><th>Уровень</th><th>Статус</th><th>Комментарий</th>
      </tr></thead>
      <tbody id="recent_appeals">{appeal_rows}</tbody>
    </table>
  </div>
  <footer>Обновляется каждые {REFRESH_SECONDS} с · неудачных проверок: <span id="failed_scans">{m.failed_scans}</span></footer>
</div>
<script nonce="{nonce}">
(function () {{
  var REFRESH_MS = {REFRESH_SECONDS * 1000};
  function secs(v) {{ return v === null || v === undefined ? "—" : v.toFixed(1) + " с"; }}
  function cell(text, cls) {{ var td = document.createElement("td"); if (cls) td.className = cls; td.textContent = text; return td; }}
  function row(a) {{
    var tr = document.createElement("tr");
    tr.appendChild(cell(a.created_at.replace("T", " ").slice(0, 16), "mono muted"));
    var repo = cell(a.repo_name);
    var branch = document.createElement("div"); branch.className = "mono muted small"; branch.textContent = a.branch;
    repo.appendChild(branch); tr.appendChild(repo);
    tr.appendChild(cell(a.commit_sha.slice(0, 8), "mono"));
    tr.appendChild(cell(String(a.critical), "num " + (a.critical ? "crit" : "muted")));
    tr.appendChild(cell(String(a.high), "num " + (a.high ? "high" : "muted")));
    tr.appendChild(cell(String(a.medium), "num " + (a.medium ? "" : "muted")));
    tr.appendChild(cell(String(a.low), "num " + (a.low ? "" : "muted")));
    tr.appendChild(cell(a.ai_generated ? secs(a.ai_seconds) : "—", "num mono"));
    var st = document.createElement("td"), pill = document.createElement("span");
    if (a.status === "failed") {{ pill.className = "pill pill-fail"; pill.textContent = "ошибка"; }}
    else if (a.critical || a.high) {{ pill.className = "pill pill-risk"; pill.textContent = "риск"; }}
    else {{ pill.className = "pill pill-ok"; pill.textContent = "чисто"; }}
    st.appendChild(pill); tr.appendChild(st);
    var repCell = document.createElement("td"); repCell.className = "mono small";
    if (a.report_name && a.status !== "failed") {{
      var slug = (a.repo_name || "unknown").replace(/\\//g, "__").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "").slice(0, 100) || "unknown-repo";
      var cleanFile = String(a.report_name).replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "").slice(0, 100);
      var base = cleanFile.replace(/\\.[^.]+$/, "");
      var aPdf = document.createElement("a"); aPdf.className = "link"; aPdf.href = "/api/v1/reports/" + slug + "/" + base + ".pdf"; aPdf.target = "_blank"; aPdf.textContent = "PDF";
      var sep = document.createTextNode(" · ");
      var aMd = document.createElement("a"); aMd.className = "link"; aMd.href = "/api/v1/reports/" + slug + "/" + base + ".md"; aMd.target = "_blank"; aMd.textContent = "MD";
      repCell.appendChild(aPdf); repCell.appendChild(sep); repCell.appendChild(aMd);
    }} else {{
      repCell.className = "muted"; repCell.textContent = "—";
    }}
    tr.appendChild(repCell);
    return tr;
  }}
  function appealRow(a) {{
    var tr = document.createElement("tr");
    tr.appendChild(cell(a.created_at.replace("T", " ").slice(0, 16), "mono muted"));
    tr.appendChild(cell(a.repo_name, "mono"));
    var titleCell = cell(a.finding_title);
    var keyDiv = document.createElement("div"); keyDiv.className = "mono muted small"; keyDiv.textContent = a.finding_key;
    titleCell.appendChild(keyDiv); tr.appendChild(titleCell);
    tr.appendChild(cell(a.severity, "mono"));
    var st = document.createElement("td"), pill = document.createElement("span");
    pill.className = "pill pill-ok"; pill.textContent = a.status === "false_positive" ? "FP" : "ACCEPTED";
    st.appendChild(pill); tr.appendChild(st);
    tr.appendChild(cell(a.reason || "—", "small muted"));
    return tr;
  }}
  function refresh() {{
    fetch("/api/v1/dashboard/metrics", {{ cache: "no-store" }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (m) {{
        if (!m) return;
        ["total_scans", "critical_found", "high_found", "total_findings", "repos_monitored", "failed_scans", "appeals_count"]
          .forEach(function (k) {{ var el = document.getElementById(k); if (el && m[k] !== undefined) el.textContent = m[k]; }});
        document.getElementById("avg_ai_seconds").textContent = secs(m.avg_ai_seconds);
        document.getElementById("avg_scan_seconds").textContent = secs(m.avg_scan_seconds);
        if (m.llm_mode) {{ document.getElementById("ai_chip_label").textContent = m.llm_mode; }}
        if (m.llm_hint) {{ document.getElementById("ai_kpi_hint").textContent = m.llm_hint; }}
        if (m.live_traffic) {{
          ["active_online", "unique_visitors", "total_requests", "demo_cache_hits", "rate_limited_429"]
            .forEach(function (k) {{ var el = document.getElementById("live_" + k); if (el && m.live_traffic[k] !== undefined) el.textContent = m.live_traffic[k]; }});
        }}
        var dot = document.getElementById("ai_chip_dot");
        if (dot) {{ dot.className = m.llm_online ? "dot" : "dot dot-standby"; }}
        if (m.recent && m.recent.length) {{
          var body = document.getElementById("recent");
          body.replaceChildren.apply(body, m.recent.map(row));
        }}
        if (m.recent_appeals && m.recent_appeals.length) {{
          var abody = document.getElementById("recent_appeals");
          if (abody) abody.replaceChildren.apply(abody, m.recent_appeals.map(appealRow));
        }}
      }})
      .catch(function () {{}});
  }}
  setInterval(refresh, REFRESH_MS);
}})();
</script>
</body>
</html>"""
