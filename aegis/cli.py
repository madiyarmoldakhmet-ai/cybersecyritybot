import asyncio
import os
import sys
import json
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import print as rprint

from aegis.scanners.sast_scanner import SASTScanner
from aegis.scanners.models import SASTScanResult, Severity, VulnerabilityFinding
from aegis.scanners.pdf_generator import PDFReportGenerator
from aegis.scanners.auto_fixer import AIAutoFixer
from aegis.scanners.aegis_runner import AegisEngine
from aegis.scanners.security_score import render_score_card
from aegis.core.config import settings

app = typer.Typer(help="Aegis Engine - Security Scanner")
console = Console()

@app.callback()
def main_callback():
    """Aegis Engine - Security Scanner"""
    pass

def print_banner():
    banner = r"""
    ___               _     
   /   |  ___  ____ _(_)____
  / /| | / _ \/ __ `/ / ___/
 / ___ |/  __/ /_/ / (__  ) 
/_/  |_|\___/\__, /_/____/  
            /____/          
    """
    console.print(Panel(Text(banner, style="bold cyan", justify="center"), title="Aegis CLI"))

def export_sarif(findings: List[VulnerabilityFinding], target_path: str, output_path: str = "results.sarif"):
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Aegis Security Scanner",
                    "version": "2.0.0"
                }
            },
            "results": []
        }]
    }

    for finding in findings:
        level = "warning"
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            level = "error"
        elif finding.severity == Severity.INFO:
            level = "note"

        result = {
            "ruleId": finding.cwe[0] if finding.cwe else "AEGIS-001",
            "level": level,
            "message": {
                "text": finding.title
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(finding.file_path)
                    },
                    "region": {
                        "startLine": finding.line_start or 1
                    }
                }
            }]
        }
        sarif["runs"][0]["results"].append(result)

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)
    console.print(f"✅ [bold green]SARIF report saved to:[/] {output_path}")

@app.command()
def scan(
    target: Path = typer.Argument(..., help="Path to the repository to scan"),
    export_pdf: bool = typer.Option(False, "--export-pdf", help="Generate an Enterprise PDF report"),
    autofix: bool = typer.Option(False, "--autofix", help="Generate AI-based fixes for discovered vulnerabilities"),
    deep: bool = typer.Option(False, "--deep", help="Run Deep scan instead of fast AST scan"),
    format_out: str = typer.Option("table", "--format", help="Output format: sarif, json, or table")
):
    """
    Scan a repository for vulnerabilities using Aegis Engine.
    """
    print_banner()

    if not target.exists():
        console.print(f"[bold red]Error:[/] Target path '{target}' does not exist.")
        raise typer.Exit(code=1)

    scan_result = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task_sast = progress.add_task("🔍 SAST Scanning...", total=100)
        task_sca = progress.add_task("📦 SCA Dependencies...", total=100)
        task_secrets = progress.add_task("🔑 Secret Detection...", total=100)
        task_ai = progress.add_task("🧠 AI Filtering...", total=100)

        # In a real async environment we would advance these tasks accurately based on runner callbacks.
        # Since AegisEngine encapsulates the scan, we will just simulate progress while it runs.
        
        async def run_scan():
            if deep:
                engine = AegisEngine()
                return await engine.scan(target)
            else:
                scanner = SASTScanner()
                return await scanner.scan(target)

        # Simulating progress updates
        async def fake_progress():
            for i in range(100):
                await asyncio.sleep(0.05)
                progress.update(task_sast, advance=1)
                if i > 25: progress.update(task_sca, advance=1.3)
                if i > 50: progress.update(task_secrets, advance=2)
                if i > 75: progress.update(task_ai, advance=4)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        scan_task = loop.create_task(run_scan())
        progress_task = loop.create_task(fake_progress())
        
        loop.run_until_complete(scan_task)
        scan_result = scan_task.result()
        
        # Ensure bars are full
        progress.update(task_sast, completed=100)
        progress.update(task_sca, completed=100)
        progress.update(task_secrets, completed=100)
        progress.update(task_ai, completed=100)

    if format_out.lower() == "sarif":
        export_sarif(scan_result.findings, str(target), "results.sarif")
        raise typer.Exit(0)
    elif format_out.lower() == "json":
        data = [f.model_dump() for f in scan_result.findings]
        console.print_json(data=data)
        raise typer.Exit(0)

    # TABLE FORMAT
    console.print(f"\n✅ [bold green]Scan completed in {scan_result.duration_seconds:.2f}s[/]")
    
    if scan_result.total_findings > 0:
        findings_table = Table(title="Detailed Findings", show_lines=True)
        findings_table.add_column("Severity", justify="left", width=10)
        findings_table.add_column("Title", justify="left", style="bold")
        findings_table.add_column("File:Line", justify="left")
        findings_table.add_column("CWE", justify="left", style="italic")

        for finding in scan_result.findings:
            sev_color = "red bold" if finding.severity == Severity.CRITICAL else "red" if finding.severity == Severity.HIGH else "yellow" if finding.severity == Severity.MEDIUM else "blue"
            location = f"{finding.file_path}:{finding.line_start or 1}"
            cwe_str = ", ".join(finding.cwe) if finding.cwe else "N/A"
            findings_table.add_row(
                f"[{sev_color}]{finding.severity.value}[/]",
                finding.title,
                location,
                cwe_str
            )

        console.print(findings_table)
        
        # Show Score Card
        score_card = render_score_card(scan_result.findings)
        console.print(score_card)

        # Autofix loop
        if autofix:
            import time
            console.print("\n🛠️ [bold cyan]Starting AI Auto-Remediation...[/]")
            fixer = AIAutoFixer()
            if not fixer.enabled:
                console.print("[yellow]Auto-fixer is not configured (missing API keys).[/]")
            else:
                for idx, finding in enumerate(scan_result.findings, 1):
                    if not finding.code_snippet:
                        continue
                    console.print(f"\n[cyan]Generating fix for #{idx}: {finding.title}[/]")
                    fixed_code = asyncio.run(fixer.generate_fix(finding))
                    if fixed_code:
                        syntax = Syntax(fixed_code, "python", theme="monokai", line_numbers=True)
                        console.print(Panel(syntax, title="[green]Secured Code[/]"))
                    else:
                        console.print("[red]Failed to generate fix.[/]")
                    
                    if settings.llm_provider == "openrouter":
                        time.sleep(3)
    else:
        score_card = render_score_card([])
        console.print(score_card)

    if export_pdf:
        console.print("\n📄 [cyan]Generating Enterprise PDF Report...[/]")
        pdf_path = f"Aegis_Report_{target.name}.pdf"
        pdf_gen = PDFReportGenerator(pdf_path)
        if pdf_gen.generate(scan_result, target.name):
            console.print(f"✅ [bold green]Report saved to:[/] {os.path.abspath(pdf_path)}")
        else:
            console.print("[bold red]Failed to generate PDF report.[/]")


@app.command()
def heal(
    path: str = typer.Argument(".", help="Repository / directory to heal"),
    apply: bool = typer.Option(False, "--apply", help="Write verified fixes back to the directory"),
    run_tests: bool = typer.Option(True, "--tests/--no-tests", help="Run the project's pytest suite on the healed copy"),
    show_diff: bool = typer.Option(True, "--diff/--no-diff", help="Print unified diffs"),
):
    """Self-Healing: patch → re-scan → keep only fixes that verifiably remove findings."""
    from aegis.core.self_heal import SelfHealer
    from aegis.scanners.risk_model import format_kzt

    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Path not found:[/] {target}")
        raise typer.Exit(code=1)

    print_banner()
    with console.status("🩹 Healing in a sandbox copy and re-scanning..."):
        report = asyncio.run(SelfHealer(run_tests=run_tests).heal(target, apply_to=target if apply else None))

    table = Table(title="Self-Healing — before / after", show_lines=False)
    table.add_column("")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right", style="green")
    table.add_row("Security Score", f"{report.before_score} ({report.before_grade})", f"{report.after_score} ({report.after_grade})")
    table.add_row("Findings", str(report.before_findings), str(report.after_findings))
    table.add_row("Risk", format_kzt(report.before_risk_kzt), format_kzt(report.after_risk_kzt))
    console.print(table)

    for fix in report.fixes:
        mark = "[green]✔ verified[/]" if fix.verified else "[yellow]• no effect[/]"
        console.print(f"\n{mark} [bold]{fix.file_path}[/] — {', '.join(fix.fixers)}")
        for title in fix.fixed_findings:
            console.print(f"   [green]−[/] {title}")
        if show_diff:
            console.print(Syntax(fix.diff, "diff", theme="monokai"))
    for rel in report.reverted_files:
        console.print(f"[yellow]↩ reverted {rel}: the patch did not lower risk[/]")
    if report.tests_passed is not None:
        console.print("🧪 Tests: " + ("[green]passed[/]" if report.tests_passed else "[red]FAILED — fixes were not applied[/]"))
    if report.manual_actions:
        console.print("\n[bold]Needs a human:[/]")
        for m in report.manual_actions:
            console.print(f"  [{m.severity}] {m.title} ({m.location}) → {m.action}")
    if apply and report.tests_passed is not False:
        console.print(f"\n✅ Applied {sum(f.verified for f in report.fixes)} verified file fix(es) to {target}")
    elif not apply:
        console.print("\nDry run. Re-run with [bold]--apply[/] to write verified fixes.")


if __name__ == "__main__":
    app()
