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

from aegis.core.config import settings
from aegis.core.metrics_store import DashboardMetrics, get_metrics_store

logger = logging.getLogger("aegis.dashboard")
router = APIRouter(tags=["Observability"])

REFRESH_SECONDS = 10


@router.get("/api/v1/dashboard/metrics")
async def dashboard_metrics() -> Dict[str, Any]:
    """Aggregated audit metrics backing the dashboard."""
    data = get_metrics_store().summary().to_dict()
    data["llm_mode"] = _llm_mode()
    return data


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> HTMLResponse:
    """Render the observability dashboard."""
    metrics = get_metrics_store().summary()
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return HTMLResponse(
        _render(metrics, nonce),
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
        "</tr>"
    )


def _render(m: DashboardMetrics, nonce: str) -> str:
    e = html.escape
    rows = "".join(_row(a) for a in m.recent) or (
        '<tr><td colspan="9" class="empty">Пока нет проверок. Отправьте push в подключённый репозиторий.</td></tr>'
    )
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Commit Guardian — мониторинг</title>
<style>
  :root {{
    --bg: #0A0B0D; --panel: #111317; --line: rgba(255,255,255,.08); --text: #ECEDEE; --muted: #8A8F98;
    --accent: #C6F432; --crit: #FF5C5C; --high: #FF9F0A;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; }}
  body {{ background: var(--bg); color: var(--text); font: 15px/1.5 var(--sans); padding: 40px 24px; }}
  .wrap {{ max-width: 1180px; margin: 0 auto; }}
  header {{ display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: flex-end; margin-bottom: 32px; }}
  .eyebrow {{ font: 13px var(--mono); color: var(--accent); margin-bottom: 6px; }}
  h1 {{ font-size: 32px; font-weight: 700; letter-spacing: -.5px; }}
  .status {{ display: flex; gap: 10px; flex-wrap: wrap; }}
  .chip {{ font: 13px var(--mono); color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 6px 12px; }}
  .chip b {{ color: var(--text); font-weight: 500; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--accent); margin-right: 8px; box-shadow: 0 0 10px var(--accent); }}
  .kpis {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
  .kpi {{ background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 24px; }}
  .kpi .label {{ color: var(--muted); font-size: 14px; }}
  .kpi .value {{ font-size: 56px; font-weight: 700; letter-spacing: -2px; line-height: 1.1; margin-top: 8px; font-variant-numeric: tabular-nums; }}
  .kpi .hint {{ color: var(--muted); font: 12px var(--mono); margin-top: 8px; }}
  .kpi.crit .value {{ color: var(--crit); }}
  .kpi.ai .value {{ color: var(--accent); }}
  .secondary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 16px 0 32px; }}
  .stat {{ border-top: 1px solid var(--line); padding-top: 12px; }}
  .stat .label {{ color: var(--muted); font-size: 13px; }}
  .stat .value {{ font-size: 24px; font-weight: 600; font-variant-numeric: tabular-nums; }}
  h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 12px; }}
  .table-wrap {{ background: var(--panel); border: 1px solid var(--line); border-radius: 16px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; min-width: 760px; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 500; font-size: 13px; }}
  tr:last-child td {{ border-bottom: none; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  th.num {{ text-align: right; }}
  .mono {{ font-family: var(--mono); font-size: 13px; }}
  .muted {{ color: var(--muted); }}
  .small {{ font-size: 12px; }}
  .crit {{ color: var(--crit); }}
  .high {{ color: var(--high); }}
  .pill {{ font: 12px var(--mono); padding: 3px 10px; border-radius: 999px; white-space: nowrap; }}
  .pill-ok {{ color: var(--accent); background: rgba(198,244,50,.1); }}
  .pill-risk {{ color: var(--crit); background: rgba(255,92,92,.12); }}
  .pill-fail {{ color: var(--muted); background: rgba(255,255,255,.06); }}
  .empty {{ color: var(--muted); text-align: center; padding: 40px; }}
  footer {{ color: var(--muted); font: 12px var(--mono); margin-top: 24px; }}
  @media (max-width: 760px) {{
    .kpis {{ grid-template-columns: 1fr; }}
    .secondary {{ grid-template-columns: repeat(2, 1fr); }}
    .kpi .value {{ font-size: 44px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="eyebrow">// commit-guardian</div>
      <h1>Мониторинг безопасности</h1>
    </div>
    <div class="status">
      <span class="chip"><span class="dot"></span>AI: <b>{e(_llm_mode())}</b></span>
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
      <div class="hint">локальная модель, без облака</div>
    </div>
  </section>

  <section class="secondary">
    <div class="stat"><div class="label">Уязвимостей HIGH</div><div class="value" id="high_found">{m.high_found}</div></div>
    <div class="stat"><div class="label">Всего находок</div><div class="value" id="total_findings">{m.total_findings}</div></div>
    <div class="stat"><div class="label">Репозиториев</div><div class="value" id="repos_monitored">{m.repos_monitored}</div></div>
    <div class="stat"><div class="label">Среднее время сканирования</div><div class="value" id="avg_scan_seconds">{e(_fmt_seconds(m.avg_scan_seconds))}</div></div>
  </section>

  <h2>Последние проверки</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Время (UTC)</th><th>Репозиторий</th><th>Коммит</th>
        <th class="num">CRIT</th><th class="num">HIGH</th><th class="num">MED</th><th class="num">LOW</th>
        <th class="num">AI</th><th>Статус</th>
      </tr></thead>
      <tbody id="recent">{rows}</tbody>
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
    return tr;
  }}
  function refresh() {{
    fetch("/api/v1/dashboard/metrics", {{ cache: "no-store" }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (m) {{
        if (!m) return;
        ["total_scans", "critical_found", "high_found", "total_findings", "repos_monitored", "failed_scans"]
          .forEach(function (k) {{ document.getElementById(k).textContent = m[k]; }});
        document.getElementById("avg_ai_seconds").textContent = secs(m.avg_ai_seconds);
        document.getElementById("avg_scan_seconds").textContent = secs(m.avg_scan_seconds);
        if (m.recent.length) {{
          var body = document.getElementById("recent");
          body.replaceChildren.apply(body, m.recent.map(row));
        }}
      }})
      .catch(function () {{}});
  }}
  setInterval(refresh, REFRESH_MS);
}})();
</script>
</body>
</html>"""
