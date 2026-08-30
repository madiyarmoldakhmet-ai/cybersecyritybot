import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from strix.scanners.sast_scanner import SASTScanner
from strix.scanners.models import SASTScanResult, Severity
from strix.scanners.pdf_generator import PDFReportGenerator
from strix.scanners.auto_fixer import AIAutoFixer
from strix.scanners.strix_runner import StrixEngine

app = typer.Typer(help="Strix Engine - Autonomous AI-DevSecOps Scanner")
console = Console()

def print_banner():
    banner = r"""
   _____ _        _         ______             _            
  / ____| |      (_)       |  ____|           (_)           
 | (___ | |_ _ __ ___  __  | |__   _ __   __ _ _ _ __   ___ 
  \___ \| __| '__| \ \/ /  |  __| | '_ \ / _` | | '_ \ / _ \\
  ____) | |_| |  | |>  <   | |____| | | | (_| | | | | |  __/
 |_____/ \__|_|  |_/_/\_\  |______|_| |_|\__, |_|_| |_|\___|
                                          __/ |             
                                         |___/              
    """
    console.print(Panel(Text(banner, style="bold blue", justify="center"), title="Strix CLI"))

@app.command()
def scan(
    target: Path = typer.Argument(..., help="Path to the repository to scan"),
    export_pdf: bool = typer.Option(False, "--export-pdf", help="Generate an Enterprise PDF report"),
    autofix: bool = typer.Option(False, "--autofix", help="Generate AI-based fixes for discovered vulnerabilities"),
    deep: bool = typer.Option(False, "--deep", help="Run Deep AI Pentest (Strix Agent) instead of fast AST scan"),
):
    """
    Scan a repository for vulnerabilities using Strix Engine.
    """
    print_banner()

    if not target.exists():
        console.print(f"[bold red]Error:[/] Target path '{target}' does not exist.")
        raise typer.Exit(code=1)

    console.print(f"🚀 [bold green]Starting scan on:[/] {target.absolute()}")

    try:
        # Run scanners asynchronously
        if deep:
            console.print("🤖 [cyan]Running Deep AI Pentest (Strix Engine)...[/]")
            engine = StrixEngine()
            scan_result: SASTScanResult = asyncio.run(engine.scan(target))
        else:
            console.print("⚡ [cyan]Running Fast DevSecOps Pipeline (SAST, SCA, Secrets)...[/]")
            scanner = SASTScanner()
            scan_result: SASTScanResult = asyncio.run(scanner.scan(target))
            
    except Exception as e:
        console.print(f"[bold red]Scan failed:[/] {e}")
        raise typer.Exit(code=1)

    console.print(f"\n✅ [bold green]Scan completed in {scan_result.duration_seconds:.2f}s[/]")
    
    # Display Summary Table
    table = Table(title="Vulnerability Summary")
    table.add_column("Severity", justify="left", style="cyan", no_wrap=True)
    table.add_column("Count", justify="right", style="magenta")

    for severity in Severity:
        count = scan_result.findings_by_severity.get(severity, 0)
        if count > 0:
            color = "red" if severity in [Severity.CRITICAL, Severity.HIGH] else "yellow" if severity == Severity.MEDIUM else "blue"
            table.add_row(f"[{color}]{severity.value}[/]", str(count))

    console.print(table)
    console.print(f"Total vulnerabilities found: [bold]{scan_result.total_findings}[/]\n")

    # Display findings
    if scan_result.total_findings > 0:
        findings_table = Table(title="Detailed Findings", show_lines=True)
        findings_table.add_column("ID", justify="center", style="dim", width=4)
        findings_table.add_column("Severity", justify="left", width=10)
        findings_table.add_column("Title", justify="left", style="bold")
        findings_table.add_column("Location", justify="left")
        findings_table.add_column("Scanner", justify="left", style="italic")

        for idx, finding in enumerate(scan_result.findings, 1):
            sev_color = "red" if finding.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow" if finding.severity == Severity.MEDIUM else "blue"
            location = f"{finding.file_path}:{finding.line_start or 1}"
            findings_table.add_row(
                str(idx),
                f"[{sev_color}]{finding.severity.value}[/]",
                finding.title,
                location,
                finding.scanner.value
            )

        console.print(findings_table)

        # Autofix loop
        if autofix:
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
                        console.print(Panel(fixed_code, title="[green]Secured Code[/]"))
                        # In a real CLI, we might ask to write to file here
                    else:
                        console.print("[red]Failed to generate fix.[/]")
    else:
        console.print("🎉 [bold green]No vulnerabilities found! Repository is secure.[/]")

    # Export PDF
    if export_pdf:
        console.print("\n📄 [cyan]Generating Enterprise PDF Report...[/]")
        pdf_path = f"Strix_Report_{target.name}.pdf"
        pdf_gen = PDFReportGenerator(pdf_path)
        if pdf_gen.generate(scan_result, target.name):
            console.print(f"✅ [bold green]Report saved to:[/] {os.path.abspath(pdf_path)}")
        else:
            console.print("[bold red]Failed to generate PDF report.[/]")


if __name__ == "__main__":
    app()
