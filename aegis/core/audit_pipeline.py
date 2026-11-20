"""
Shared post-scan audit pipeline for Commit Guardian.
Computes security score, produces local AI / fallback executive summary,
writes Markdown + PDF compliance reports, and records observability metrics.
"""

import logging
from dataclasses import dataclass
from typing import Optional, Type

from aegis.ai.audit_summarizer import AuditSummarizer, AuditSummary
from aegis.core.metrics_store import get_metrics_store
from aegis.reporting.audit_report import AuditReport, AuditReportWriter, _safe_component
from aegis.scanners.models import SASTScanResult
from aegis.core.project_config import load_config
from aegis.scanners.risk_model import RiskAssessment, assess_risk
from aegis.scanners.security_score import calculate_score, get_grade

logger = logging.getLogger("aegis.audit_pipeline")


@dataclass
class AuditArtifacts:
    """Computed security score, compliance report paths/URLs, and summary metadata."""

    score: int
    grade: str
    recommendation: str
    summary: Optional[AuditSummary]
    report_name: Optional[str]
    repo_slug: str
    report_pdf_path: Optional[str] = None
    report_md_path: Optional[str] = None
    report_pdf_url: Optional[str] = None
    report_md_url: Optional[str] = None
    risk: Optional[RiskAssessment] = None


def report_urls_for(repo_name: str, report_name: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Build relative download URLs for PDF and Markdown siblings if present."""
    if not report_name:
        return None, None
    repo_slug = _safe_component(repo_name.replace("/", "__"), "unknown-repo")
    safe_file = _safe_component(report_name, "report.md")
    base = safe_file.rsplit(".", 1)[0]
    return f"/api/v1/reports/{repo_slug}/{base}.pdf", f"/api/v1/reports/{repo_slug}/{base}.md"


async def finalize_scan_audit(
    scan_result: SASTScanResult,
    repo_name: str,
    commit_sha: str,
    branch: str = "main",
    author: str = "system",
    commit_url: Optional[str] = None,
    summarizer_cls: Type[AuditSummarizer] = AuditSummarizer,
    writer_cls: Type[AuditReportWriter] = AuditReportWriter,
) -> AuditArtifacts:
    """Compute score, generate compliance report, and persist metrics without failing the scan."""
    score = calculate_score(scan_result.findings)
    grade, _, recommendation = get_grade(score)
    repo_slug = _safe_component(repo_name.replace("/", "__"), "unknown-repo")

    risk: Optional[RiskAssessment] = None
    try:
        risk = assess_risk(scan_result.findings, load_config(scan_result.target_path).risk)
    except Exception as e:
        logger.warning(f"Financial risk assessment skipped for {repo_name}: {e}")

    report_name: Optional[str] = None
    report_pdf_path: Optional[str] = None
    report_md_path: Optional[str] = None
    report_pdf_url: Optional[str] = None
    report_md_url: Optional[str] = None
    summary: Optional[AuditSummary] = None

    try:
        summary = await summarizer_cls().summarize(
            scan_result, repo_name=repo_name, commit_sha=commit_sha
        )
        report = AuditReport.from_scan(
            scan_result,
            summary,
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            author=author,
            commit_url=commit_url,
            risk=risk,
        )
        paths = writer_cls().write(report)
        primary = paths.pdf or paths.markdown
        report_name = primary.name
        report_md_path = str(paths.markdown)
        report_md_url = f"/api/v1/reports/{repo_slug}/{paths.markdown.name}"
        if paths.pdf:
            report_pdf_path = str(paths.pdf)
            report_pdf_url = f"/api/v1/reports/{repo_slug}/{paths.pdf.name}"
    except Exception as e:
        logger.exception(f"Failed to generate audit report for {repo_name}@{commit_sha[:8]}: {e}")

    try:
        get_metrics_store().record_audit(
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            severity_counts={sev.value: count for sev, count in scan_result.findings_by_severity.items()},
            total_findings=scan_result.total_findings,
            scan_seconds=scan_result.duration_seconds,
            ai_seconds=summary.duration_seconds if summary else 0.0,
            ai_generated=bool(summary and summary.ai_generated),
            report_name=report_name,
        )
    except Exception as e:
        logger.exception(f"Failed to record audit metrics for {repo_name}@{commit_sha[:8]}: {e}")

    return AuditArtifacts(
        score=score,
        grade=grade,
        recommendation=recommendation,
        summary=summary,
        report_name=report_name,
        repo_slug=repo_slug,
        report_pdf_path=report_pdf_path,
        report_md_path=report_md_path,
        report_pdf_url=report_pdf_url,
        report_md_url=report_md_url,
        risk=risk,
    )
