"""
Data models for SAST and vulnerability scanning findings.
Standardizes results from Semgrep, Bandit, and Pip-Audit.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    PIP_AUDIT = "pip-audit"
    DAST = "dast"
    SCA = "sca"
    SECRET = "secret"
    STRIX = "aegis"
    MOBILE = "mobile"
    CUSTOM = "custom"


class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique vulnerability identifier or rule ID")
    scanner: ScannerType = Field(..., description="Scanner that identified the vulnerability")
    title: str = Field(..., description="Short summary/title of the issue")
    description: str = Field(..., description="Detailed description of the finding")
    severity: Severity = Field(..., description="Normalized severity level")
    file_path: str = Field(..., description="Relative or absolute path to the vulnerable file or endpoint")
    line_start: Optional[int] = Field(default=None, description="Starting line number")
    line_end: Optional[int] = Field(default=None, description="Ending line number")
    code_snippet: Optional[str] = Field(default=None, description="Vulnerable code snippet or HTTP payload")
    cwe: List[str] = Field(default_factory=list, description="Associated Common Weakness Enumeration IDs")
    cve: List[str] = Field(default_factory=list, description="Associated Common Vulnerabilities and Exposures IDs")
    recommendation: Optional[str] = Field(default=None, description="Remediation recommendation or fix guidance")
    raw_metadata: Dict[str, Any] = Field(default_factory=dict, description="Original tool-specific metadata")


class SASTScanResult(BaseModel):
    target_path: str = Field(..., description="Scanned directory or file path")
    total_findings: int = Field(default=0, description="Total count of findings discovered")
    findings_by_severity: Dict[Severity, int] = Field(default_factory=dict, description="Findings breakdown by severity")
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="List of normalized findings")
    duration_seconds: float = Field(default=0.0, description="Total execution duration in seconds")
    scanners_run: List[ScannerType] = Field(default_factory=list, description="Scanners executed in this audit")
    errors: List[str] = Field(default_factory=list, description="Non-fatal errors or warnings encountered during scan")


class DASTScanResult(BaseModel):
    target_url: str = Field(..., description="Scanned base URL")
    endpoints_tested: List[str] = Field(default_factory=list, description="List of audited endpoints")
    total_findings: int = Field(default=0, description="Total count of DAST findings")
    findings_by_severity: Dict[Severity, int] = Field(default_factory=dict, description="Findings breakdown by severity")
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="List of normalized findings")
    duration_seconds: float = Field(default=0.0, description="Total execution duration in seconds")
    errors: List[str] = Field(default_factory=list, description="Network or parsing errors encountered")

