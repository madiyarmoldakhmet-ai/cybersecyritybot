"""
Financial risk in tenge (₸) for an audit — translates CWE/severity into money.

The model is deliberately simple and transparent (every number it uses is listed in
``RiskAssessment.assumptions``), so a security officer can defend it in front of management:

1. **Regulatory exposure** — Art. 79 of the Code of Administrative Offences of the Republic of
   Kazakhstan (personal-data protection) sets fines from 30 up to 2000 MRP. Any HIGH/CRITICAL
   finding that can expose personal data counts against the ceiling; MEDIUM-only against the floor.
2. **Incident cost** — optional ``records_at_risk × cost_per_record_kzt`` from ``.aegis.yml``.

Each impacting finding gets a share of the total proportional to its severity so that the
report can say *which line of code* carries how much risk. This is an estimate, not legal advice.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from aegis.scanners.models import ScannerType, Severity, VulnerabilityFinding

LEGAL_BASIS = "ст. 79 КоАП РК (нарушение законодательства о персональных данных и их защите)"
DEFAULT_MRP_KZT = 4325  # МРП на 2026 год
FINE_FLOOR_MRP = 30
FINE_CEILING_MRP = 2000

SEVERITY_WEIGHT = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2, Severity.LOW: 0, Severity.INFO: 0}  # LOW = hygiene, no monetary impact

CATEGORY_LABELS = {
    "pii_leak": "Утечка персональных данных (ИИН/ПДн)",
    "data_access": "Несанкционированный доступ к данным (инъекции)",
    "credential": "Скомпрометированные ключи и токены",
    "transport": "Перехват трафика (отключён TLS)",
}

RECORD_EXPOSING = {"pii_leak", "data_access"}

_PII_CWES = {"CWE-532", "CWE-359", "CWE-312", "CWE-200", "CWE-201", "CWE-319"}
_DATA_ACCESS_CWES = {"CWE-89", "CWE-78", "CWE-88", "CWE-94", "CWE-95", "CWE-22", "CWE-502", "CWE-918", "CWE-1336", "CWE-611"}
_CREDENTIAL_CWES = {"CWE-798", "CWE-540", "CWE-321", "CWE-259"}
_TRANSPORT_CWES = {"CWE-295", "CWE-297"}
_PII_KEYWORDS = ("iin", "иин", "pii", "personal", "passport", "паспорт", "card_number", "cardholder")


class RiskSettings(BaseModel):
    """``risk:`` section of ``.aegis.yml``."""

    mrp_kzt: int = DEFAULT_MRP_KZT
    max_fine_mrp: int = FINE_CEILING_MRP
    min_fine_mrp: int = FINE_FLOOR_MRP
    records_at_risk: int = 0
    cost_per_record_kzt: int = 0


class FindingRisk(BaseModel):
    finding_id: str
    title: str
    location: str
    severity: str
    category: str
    category_label: str
    risk_kzt: int


class RiskAssessment(BaseModel):
    total_kzt: int = 0
    regulatory_kzt: int = 0
    incident_kzt: int = 0
    legal_basis: str = LEGAL_BASIS
    by_category: Dict[str, int] = Field(default_factory=dict)
    top_findings: List[FindingRisk] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)

    @property
    def headline(self) -> str:
        if not self.total_kzt:
            return "Финансовый риск по ПДн не выявлен"
        return f"Потенциальный финансовый риск: до {format_kzt(self.total_kzt)}"


def format_kzt(amount: int) -> str:
    return f"{amount:,}".replace(",", " ") + " ₸"


def classify(finding: VulnerabilityFinding) -> Optional[str]:
    """Map a finding to the business-impact category it belongs to (None = no monetary impact)."""
    cwes = set(finding.cwe)
    label = f"{finding.id} {finding.title}".lower()
    snippet = (finding.code_snippet or "").lower()
    if cwes & _PII_CWES or any(k in label for k in _PII_KEYWORDS):
        return "pii_leak"
    # an injection whose own code touches personal data (e.g. WHERE iin = ...) is a PII leak
    if cwes & _DATA_ACCESS_CWES and any(k in snippet for k in _PII_KEYWORDS):
        return "pii_leak"
    if finding.scanner in (ScannerType.SECRET, ScannerType.GIT_HISTORY) or cwes & _CREDENTIAL_CWES:
        return "credential"
    if cwes & _DATA_ACCESS_CWES:
        return "data_access"
    if cwes & _TRANSPORT_CWES or "ssl" in label or "tls" in label:
        return "transport"
    return None


def assess_risk(findings: List[VulnerabilityFinding], cfg: Optional[RiskSettings] = None) -> RiskAssessment:
    cfg = cfg or RiskSettings()
    impacting = [(f, cat) for f in findings if (cat := classify(f)) and SEVERITY_WEIGHT.get(f.severity, 0) > 0]

    assumptions = [
        f"Правовая база: {LEGAL_BASIS}; диапазон штрафа {cfg.min_fine_mrp}–{cfg.max_fine_mrp} МРП.",
        f"МРП = {format_kzt(cfg.mrp_kzt)}.",
        "HIGH/CRITICAL находки, способные раскрыть ПДн, оцениваются по верхней границе штрафа; только MEDIUM — по нижней.",
    ]
    if cfg.records_at_risk and cfg.cost_per_record_kzt:
        assumptions.append(
            f"Стоимость инцидента: {cfg.records_at_risk:,}".replace(",", " ")
            + f" записей × {format_kzt(cfg.cost_per_record_kzt)} (из .aegis.yml); "
            "учитывается, только если HIGH/CRITICAL находка открывает доступ к самим данным (ПДн, инъекции)."
        )
    assumptions.append("Оценка носит ориентировочный характер и не является юридической консультацией.")

    if not impacting:
        return RiskAssessment(assumptions=assumptions)

    high = (Severity.CRITICAL, Severity.HIGH)
    severe = any(f.severity in high for f, _ in impacting)
    # Only findings that open the data itself (PII leaks, injections) put the records at risk
    exposes_records = any(f.severity in high and cat in RECORD_EXPOSING for f, cat in impacting)
    regulatory = cfg.mrp_kzt * (cfg.max_fine_mrp if severe else cfg.min_fine_mrp)
    incident = cfg.records_at_risk * cfg.cost_per_record_kzt if exposes_records else 0
    total = regulatory + incident

    weights = [SEVERITY_WEIGHT[f.severity] for f, _ in impacting]
    weight_sum = sum(weights)
    per_finding: List[FindingRisk] = []
    by_category: Dict[str, int] = {}
    for (f, cat), w in zip(impacting, weights):
        share = round(total * w / weight_sum)
        by_category[cat] = by_category.get(cat, 0) + share
        per_finding.append(
            FindingRisk(
                finding_id=f.id,
                title=f.title,
                location=f"{f.file_path}:{f.line_start or 1}",
                severity=f.severity.value,
                category=cat,
                category_label=CATEGORY_LABELS[cat],
                risk_kzt=share,
            )
        )
    per_finding.sort(key=lambda r: r.risk_kzt, reverse=True)

    return RiskAssessment(
        total_kzt=total,
        regulatory_kzt=regulatory,
        incident_kzt=incident,
        by_category=dict(sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)),
        top_findings=per_finding[:5],
        assumptions=assumptions,
    )


class ROIEstimate(BaseModel):
    team_size: int
    recommended_tier: str
    guardian_monthly_kzt: int
    inhouse_appsec_monthly_kzt: int
    monthly_savings_kzt: int
    annual_savings_kzt: int
    roi_multiple: float
    prevented_risk_kzt: int = 0


def estimate_roi(team_size: int, prevented_risk_kzt: int = 0) -> ROIEstimate:
    """Deterministic KZ unit-economics calculator comparing Commit Guardian vs in-house AppSec FTE."""
    devs = max(1, min(int(team_size), 500))
    if devs <= 5:
        tier = "PILOT / STARTER"
        guardian_monthly = 190_000
    elif devs <= 25:
        tier = "TEAM ON-PREM"
        guardian_monthly = 190_000
    else:
        tier = "ENTERPRISE GOV/FIN"
        guardian_monthly = 650_000

    # Market baseline in KZ: ~800k KZT/month per dedicated AppSec engineer (1 FTE per ~20 developers)
    appsec_ftes = max(1, (devs + 19) // 20)
    inhouse_monthly = appsec_ftes * 800_000
    monthly_savings = max(0, inhouse_monthly - guardian_monthly)
    annual_savings = monthly_savings * 12
    roi_multiple = round(inhouse_monthly / guardian_monthly, 1)

    return ROIEstimate(
        team_size=devs,
        recommended_tier=tier,
        guardian_monthly_kzt=guardian_monthly,
        inhouse_appsec_monthly_kzt=inhouse_monthly,
        monthly_savings_kzt=monthly_savings,
        annual_savings_kzt=annual_savings,
        roi_multiple=roi_multiple,
        prevented_risk_kzt=max(0, int(prevented_risk_kzt)),
    )
