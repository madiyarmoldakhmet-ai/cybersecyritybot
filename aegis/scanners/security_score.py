from typing import List, Tuple
from pydantic import BaseModel
from aegis.scanners.models import VulnerabilityFinding, Severity

from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.console import Group
from rich.align import Align

def calculate_score(findings: List[VulnerabilityFinding]) -> int:
    score = 100
    for finding in findings:
        if finding.severity == Severity.CRITICAL:
            score -= 25
        elif finding.severity == Severity.HIGH:
            score -= 10
        elif finding.severity == Severity.MEDIUM:
            score -= 3
        elif finding.severity == Severity.LOW:
            score -= 1
    return max(0, score)

def get_grade(score: int) -> Tuple[str, str, str]:
    """Returns (Grade, Color, Recommendation)"""
    if score >= 90:
        return "A+", "green", "Excellent! Your code is highly secure."
    elif score >= 80:
        return "A", "green", "Good job. Minor issues to fix."
    elif score >= 70:
        return "B", "yellow", "Fair. Address medium/high issues soon."
    elif score >= 60:
        return "C", "orange3", "Needs improvement. Security debt is accumulating."
    elif score >= 40:
        return "D", "red", "Poor. High risk of exploitation."
    else:
        return "F", "bright_red", "Critical failure. Do not deploy."

def generate_badge_url(score: int, grade: str) -> str:
    color_map = {
        "A+": "brightgreen",
        "A": "green",
        "B": "yellow",
        "C": "orange",
        "D": "red",
        "F": "critical"
    }
    color = color_map.get(grade, "grey")
    return f"https://img.shields.io/badge/Aegis_Security_Score-{score}%2F100_({grade})-{color}"

def render_score_card(findings: List[VulnerabilityFinding]) -> Panel:
    score = calculate_score(findings)
    grade, color, recommendation = get_grade(score)
    
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0
    }
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
            
    grade_text = Text(f"{grade}", style=f"bold {color}", justify="center")
    grade_text.stylize(f"on black")
    
    # Simple ASCII art for grade
    ascii_grade = Text(f" [ {grade} ] ", style=f"bold {color} reverse")
    
    stats_table = Table(show_header=False, box=None)
    stats_table.add_column("Severity")
    stats_table.add_column("Count")
    
    stats_table.add_row("[red bold]CRITICAL[/]", str(counts[Severity.CRITICAL]))
    stats_table.add_row("[red]HIGH[/]", str(counts[Severity.HIGH]))
    stats_table.add_row("[yellow]MEDIUM[/]", str(counts[Severity.MEDIUM]))
    stats_table.add_row("[blue]LOW[/]", str(counts[Severity.LOW]))
    
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style=color, finished_style=color),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    )
    progress.add_task("Security Health", total=100, completed=score)
    
    group = Group(
        Align.center(ascii_grade),
        "",
        progress,
        "",
        stats_table,
        "",
        Text(f"Recommendation: {recommendation}", style="italic")
    )
    
    return Panel(group, title="[bold]Aegis Security Score[/]", border_style=color, padding=(1, 2))
