"""
Compliance Audit Reports for Commit Guardian.
Every audited commit produces a formal Markdown report (and a PDF copy) under
`settings.scan_output_dir`, giving auditors a durable record of what was scanned,
which SAST rules fired, and the local AI's assessment.
"""

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from xml.sax.saxutils import escape

from pydantic import BaseModel, Field

from aegis.ai.audit_summarizer import SEVERITY_ORDER, AuditSummary, sort_findings
from aegis.core.config import settings
from aegis.scanners.models import SASTScanResult

logger = logging.getLogger("aegis.audit_report")

MAX_RULES_IN_REPORT = 500

# TrueType fonts with Cyrillic coverage, tried in order (Docker image, macOS, Windows)
_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "C:/Windows/Fonts/arial.ttf",
]
_BOLD_SIBLINGS = {
    "DejaVuSans.ttf": "DejaVuSans-Bold.ttf",
    "arial.ttf": "arialbd.ttf",
}


class TriggeredRule(BaseModel):
    rule_id: str
    scanner: str
    severity: str
    title: str
    location: str
    cwe: List[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    report_id: str
    generated_at: datetime
    repo_name: str
    commit_sha: str
    branch: str
    author: str
    commit_url: Optional[str] = None
    scan_duration_seconds: float
    scanners_run: List[str] = Field(default_factory=list)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
    triggered_rules: List[TriggeredRule] = Field(default_factory=list)
    ai_summary: str
    ai_model: str
    ai_generated: bool
    ai_duration_seconds: float
    scan_errors: List[str] = Field(default_factory=list)

    @classmethod
    def from_scan(
        cls,
        scan_result: SASTScanResult,
        summary: AuditSummary,
        repo_name: str,
        commit_sha: str,
        branch: str,
        author: str,
        commit_url: Optional[str] = None,
    ) -> "AuditReport":
        rules = [
            TriggeredRule(
                rule_id=f.id,
                scanner=f.scanner.value,
                severity=f.severity.value,
                title=f.title,
                location=f"{f.file_path}:{f.line_start or 1}",
                cwe=list(f.cwe),
            )
            for f in sort_findings(scan_result.findings)
        ]
        return cls(
            report_id=uuid.uuid4().hex[:12],
            generated_at=datetime.now(timezone.utc),
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            author=author,
            commit_url=commit_url,
            scan_duration_seconds=scan_result.duration_seconds,
            scanners_run=[s.value for s in scan_result.scanners_run],
            severity_counts={sev.value: scan_result.findings_by_severity.get(sev, 0) for sev in SEVERITY_ORDER},
            total_findings=scan_result.total_findings,
            triggered_rules=rules,
            ai_summary=summary.text,
            ai_model=summary.model,
            ai_generated=summary.ai_generated,
            ai_duration_seconds=summary.duration_seconds,
            scan_errors=list(scan_result.errors),
        )

    @property
    def timestamp_utc(self) -> str:
        return self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def risk_level(self) -> str:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if self.severity_counts.get(sev, 0):
                return sev
        return "NONE"


@dataclass
class ReportPaths:
    markdown: Path
    pdf: Optional[Path] = None


def _md_cell(value: str) -> str:
    """Make a value safe for a single Markdown table cell."""
    return " ".join(str(value).split()).replace("|", "\\|")


def _safe_component(value: str, fallback: str) -> str:
    """Reduce untrusted webhook input to a filesystem-safe name (no separators, no '..')."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned[:100] or fallback


def render_markdown(report: AuditReport) -> str:
    """Render the compliance report as Markdown."""
    commit = f"[`{report.commit_sha}`]({report.commit_url})" if report.commit_url else f"`{report.commit_sha}`"
    ai_source = (
        f"{report.ai_model} (локально, {report.ai_duration_seconds} c)"
        if report.ai_generated
        else report.ai_model
    )
    lines = [
        "# Commit Guardian — отчёт аудита безопасности кода",
        "",
        "| Поле | Значение |",
        "|---|---|",
        f"| Идентификатор отчёта | `{report.report_id}` |",
        f"| Дата и время | {report.timestamp_utc} |",
        f"| Репозиторий | `{_md_cell(report.repo_name)}` |",
        f"| Ветка | `{_md_cell(report.branch)}` |",
        f"| Коммит | {commit} |",
        f"| Автор | {_md_cell(report.author)} |",
        f"| Сканеры | {_md_cell(', '.join(report.scanners_run) or '—')} |",
        f"| Длительность сканирования | {report.scan_duration_seconds} c |",
        f"| Итоговый уровень риска | **{report.risk_level}** |",
        "",
        "## Сводка по критичности",
        "",
        "| CRITICAL | HIGH | MEDIUM | LOW | INFO | Всего |",
        "|---:|---:|---:|---:|---:|---:|",
        "| " + " | ".join(str(report.severity_counts.get(s.value, 0)) for s in SEVERITY_ORDER)
        + f" | {report.total_findings} |",
        "",
        "## Заключение AI",
        "",
        f"_Модель: {_md_cell(ai_source)}_",
        "",
        report.ai_summary.strip(),
        "",
        "## Сработавшие SAST-правила",
        "",
    ]

    if report.triggered_rules:
        lines += [
            "| # | Критичность | Правило | Сканер | Описание | Расположение | CWE |",
            "|---:|---|---|---|---|---|---|",
        ]
        for idx, rule in enumerate(report.triggered_rules[:MAX_RULES_IN_REPORT], 1):
            lines.append(
                f"| {idx} | {rule.severity} | `{_md_cell(rule.rule_id)}` | {_md_cell(rule.scanner)} | "
                f"{_md_cell(rule.title)} | `{_md_cell(rule.location)}` | {_md_cell(', '.join(rule.cwe) or '—')} |"
            )
        if len(report.triggered_rules) > MAX_RULES_IN_REPORT:
            lines.append("")
            lines.append(f"_Показаны первые {MAX_RULES_IN_REPORT} из {len(report.triggered_rules)} находок._")
    else:
        lines.append("Ни одно правило не сработало.")

    if report.scan_errors:
        lines += ["", "## Предупреждения сканеров", ""]
        lines += [f"- {_md_cell(err)}" for err in report.scan_errors]

    lines += [
        "",
        "---",
        "_Отчёт сформирован автоматически Commit Guardian. Исходный код и результаты анализа "
        "обрабатывались локально и не передавались внешним сервисам._",
        "",
    ]
    return "\n".join(lines)


def _register_fonts() -> tuple:
    """Register a Unicode TTF font for the PDF; returns (regular, bold) font names."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    candidates = ([str(settings.report_font_path)] if settings.report_font_path else []) + _FONT_CANDIDATES
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            if "CG-Regular" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("CG-Regular", str(path)))
                bold_path = path.with_name(_BOLD_SIBLINGS.get(path.name, path.name))
                pdfmetrics.registerFont(TTFont("CG-Bold", str(bold_path if bold_path.is_file() else path)))
            return "CG-Regular", "CG-Bold"
        except Exception as e:
            logger.debug(f"Could not register PDF font {path}: {e}")

    logger.warning("No Unicode TTF font found for PDF reports; Cyrillic text may not render. Set REPORT_FONT_PATH.")
    return "Helvetica", "Helvetica-Bold"


def render_pdf(report: AuditReport, output_path: Path) -> None:
    """Render the compliance report as an A4 PDF."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    regular, bold = _register_fonts()
    ink, muted, line = colors.HexColor("#0F172A"), colors.HexColor("#64748B"), colors.HexColor("#CBD5E1")
    sev_colors = {
        "CRITICAL": colors.HexColor("#B91C1C"),
        "HIGH": colors.HexColor("#C2410C"),
        "MEDIUM": colors.HexColor("#A16207"),
        "LOW": colors.HexColor("#1D4ED8"),
        "INFO": colors.HexColor("#475569"),
    }

    title = ParagraphStyle("CGTitle", fontName=bold, fontSize=18, leading=22, textColor=ink, spaceAfter=4)
    subtitle = ParagraphStyle("CGSub", fontName=regular, fontSize=9.5, leading=13, textColor=muted, spaceAfter=10)
    h2 = ParagraphStyle("CGH2", fontName=bold, fontSize=12.5, leading=16, textColor=ink, spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("CGBody", fontName=regular, fontSize=9.5, leading=13.5, textColor=ink)
    cell = ParagraphStyle("CGCell", fontName=regular, fontSize=8, leading=10, textColor=ink)
    cell_bold = ParagraphStyle("CGCellBold", parent=cell, fontName=bold)

    def p(text: str, style=body) -> Paragraph:
        return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)

    story = [
        p("Commit Guardian — отчёт аудита безопасности кода", title),
        p(f"Отчёт {report.report_id} · {report.timestamp_utc} · обработка выполнена локально", subtitle),
    ]

    meta = [
        ("Репозиторий", report.repo_name),
        ("Ветка", report.branch),
        ("Коммит", report.commit_sha),
        ("Автор", report.author),
        ("Сканеры", ", ".join(report.scanners_run) or "—"),
        ("Длительность сканирования", f"{report.scan_duration_seconds} c"),
        ("Итоговый уровень риска", report.risk_level),
    ]
    meta_table = Table([[p(k, cell_bold), p(v, cell)] for k, v in meta], colWidths=[48 * mm, 122 * mm])
    meta_table.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, line),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story += [meta_table, p("Сводка по критичности", h2)]

    sev_header = [p(s.value, cell_bold) for s in SEVERITY_ORDER] + [p("Всего", cell_bold)]
    sev_values = [p(str(report.severity_counts.get(s.value, 0)), cell) for s in SEVERITY_ORDER]
    sev_values.append(p(str(report.total_findings), cell_bold))
    sev_table = Table([sev_header, sev_values], colWidths=[28 * mm] * 5 + [30 * mm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("GRID", (0, 0), (-1, -1), 0.4, line),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [sev_table, p("Заключение AI", h2)]

    ai_source = (
        f"Модель: {report.ai_model} (локально, {report.ai_duration_seconds} c)"
        if report.ai_generated
        else f"Модель: {report.ai_model}"
    )
    story += [p(ai_source, subtitle), p(report.ai_summary.strip()), p("Сработавшие SAST-правила", h2)]

    if report.triggered_rules:
        rows = [[p(h, cell_bold) for h in ("#", "Критичность", "Правило / описание", "Расположение", "CWE")]]
        styles = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("GRID", (0, 0), (-1, -1), 0.4, line),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for idx, rule in enumerate(report.triggered_rules[:MAX_RULES_IN_REPORT], 1):
            sev_style = ParagraphStyle(f"sev{idx}", parent=cell_bold, textColor=sev_colors.get(rule.severity, ink))
            rows.append([
                p(str(idx), cell),
                p(rule.severity, sev_style),
                p(f"{rule.rule_id} ({rule.scanner})\n{rule.title}", cell),
                p(rule.location, cell),
                p(", ".join(rule.cwe) or "—", cell),
            ])
        rules_table = Table(rows, colWidths=[8 * mm, 22 * mm, 72 * mm, 48 * mm, 20 * mm], repeatRows=1)
        rules_table.setStyle(TableStyle(styles))
        story.append(rules_table)
    else:
        story.append(p("Ни одно правило не сработало."))

    if report.scan_errors:
        story.append(p("Предупреждения сканеров", h2))
        story += [p(f"• {err}") for err in report.scan_errors]

    def footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont(regular, 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(20 * mm, 10 * mm, f"Commit Guardian · {report.repo_name} · {report.commit_sha[:12]}")
        canvas.drawRightString(190 * mm, 10 * mm, f"Стр. {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Commit Guardian audit {report.repo_name}@{report.commit_sha[:12]}",
        author="Commit Guardian",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


class AuditReportWriter:
    """Persists audit reports as `<output_dir>/<repo>/<timestamp>_<commit>.md` (+ `.pdf`)."""

    def __init__(self, output_dir: Optional[Path] = None, pdf_enabled: Optional[bool] = None) -> None:
        self.output_dir = Path(output_dir or settings.scan_output_dir)
        self.pdf_enabled = settings.report_pdf_enabled if pdf_enabled is None else pdf_enabled

    def path_for(self, report: AuditReport) -> Path:
        repo_dir = _safe_component(report.repo_name.replace("/", "__"), "unknown-repo")
        commit = re.sub(r"[^0-9a-fA-F]", "", report.commit_sha)[:12] or "unknown"
        stamp = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
        return self.output_dir / repo_dir / f"{stamp}_{commit}.md"

    def write(self, report: AuditReport) -> ReportPaths:
        md_path = self.path_for(report)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(report), encoding="utf-8")
        paths = ReportPaths(markdown=md_path)

        if self.pdf_enabled:
            pdf_path = md_path.with_suffix(".pdf")
            try:
                render_pdf(report, pdf_path)
                paths.pdf = pdf_path
            except Exception as e:
                # The Markdown report is the record of truth; a PDF failure must not lose the audit
                logger.exception(f"PDF rendering failed for report {report.report_id}: {e}")

        logger.info(f"Audit report {report.report_id} saved to {md_path}" + (" (+ PDF)" if paths.pdf else ""))
        return paths
