"""Self-Healing: deterministic fixers + verify-by-rescan loop."""

import ast
from pathlib import Path

import pytest

from aegis.core.demo_history import materialize_demo_repo
from aegis.core.self_heal import (
    SelfHealer,
    fix_dart_tls,
    fix_eval,
    fix_hardcoded_secrets,
    fix_pii_logging,
    fix_shell_injection,
    fix_sql_injection,
)
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding

DEMO = Path(__file__).resolve().parent.parent / "demo_targets" / "fintech_demo"


def _secret_finding(line=1):
    return VulnerabilityFinding(id="secret-abcdef12", scanner=ScannerType.SECRET, title="Hardcoded Generic API Key",
                                description="d", severity=Severity.CRITICAL, file_path="a.py", line_start=line, cwe=["CWE-798"])


def test_sql_concat_via_variable_becomes_parameterised():
    src = (
        "def q(cursor, iin):\n"
        "    query = \"SELECT * FROM w WHERE iin = '\" + iin + \"' AND active = 1\"\n"
        "    cursor.execute(query)\n"
    )
    out = fix_sql_injection(src, [])
    assert "query = 'SELECT * FROM w WHERE iin = ? AND active = 1'" in out
    assert "cursor.execute(query, (iin,))" in out
    ast.parse(out)


def test_sql_fstring_inline_and_psycopg_paramstyle():
    src = "import psycopg2\n\ndef q(cur, a, b):\n    cur.execute(f\"SELECT * FROM t WHERE a = {a} AND b = '{b}'\")\n"
    out = fix_sql_injection(src, [])
    assert "cur.execute('SELECT * FROM t WHERE a = %s AND b = %s', (a, b))" in out


def test_static_sql_is_untouched():
    src = "def q(cur):\n    cur.execute('SELECT 1')\n"
    assert fix_sql_injection(src, []) == src


def test_eval_becomes_literal_eval_with_import():
    out = fix_eval('"""doc"""\nimport os\n\ndef f(x):\n    return eval(x)\n', [])
    assert "return ast.literal_eval(x)" in out
    assert out.index("import ast") < out.index("import os")
    assert out.startswith('"""doc"""')


def test_shell_fstring_becomes_argv():
    src = "import subprocess\n\ndef f(name):\n    cmd = f\"tar -czf /tmp/{name}.tar.gz /var/ledger\"\n    subprocess.run(cmd, shell=True)\n"
    out = fix_shell_injection(src, [])
    assert "cmd = ['tar', '-czf', f'/tmp/{name}.tar.gz', '/var/ledger']" in out
    assert "subprocess.run(cmd)" in out and "shell=True" not in out


def test_shell_with_real_shell_syntax_is_left_for_a_human():
    src = "import subprocess\nsubprocess.run(f\"cat {x} | grep y\", shell=True)\n"
    assert fix_shell_injection(src, []) == src


def test_iin_is_masked_in_logs():
    out = fix_pii_logging("def f(customer_iin):\n    logger.info(f'balance for iin={customer_iin}')\n", [])
    assert "{str(customer_iin)[-4:]:*>12}" in out and "iin_masked=" in out
    value = "870412300123"
    assert f"{str(value)[-4:]:*>12}" == "********0123"


def test_hardcoded_secret_moves_to_env():
    src = 'import logging\n\nAPI_KEY = "kzt9_mP8xQ2vL7nB4cR6wJ3yH5fD1sA0e"\n'
    out = fix_hardcoded_secrets(src, [_secret_finding(3)])
    assert "API_KEY = os.environ['API_KEY']" in out and "import os" in out
    assert "kzt9_" not in out


def test_dart_tls_bypass_removed():
    src = "final c = HttpClient();\n    c.badCertificateCallback = (X509Certificate cert, String host, int port) => true;\nreturn c;\n"
    assert "badCertificateCallback" not in fix_dart_tls(src, [])


@pytest.mark.asyncio
async def test_demo_heals_from_f_and_reports_manual_key_rotation(tmp_path):
    repo = materialize_demo_repo(DEMO, tmp_path / "kz-fintech-app")
    original = (repo / "payment_gateway.py").read_text()
    report = await SelfHealer().heal(repo)

    assert report.before_grade == "F"
    assert report.after_score >= 60 and report.after_score > report.before_score
    assert report.after_findings < report.before_findings
    assert report.after_risk_kzt < report.before_risk_kzt
    assert {f.file_path for f in report.fixes if f.verified} == {"payment_gateway.py", "mobile_client.dart"}
    assert all(f.diff.startswith("--- a/") for f in report.fixes)
    # the ghost token can only be fixed by rotating it
    assert any("git filter-repo" in m.action for m in report.manual_actions)
    # heal() works on a sandbox: the source tree is untouched
    assert (repo / "payment_gateway.py").read_text() == original


@pytest.mark.asyncio
async def test_patch_that_adds_a_severe_finding_is_reverted(tmp_path):
    (tmp_path / "a.py").write_text("def f(x):\n    return eval(x)\n")
    eval_f = VulnerabilityFinding(id="dynamic-code-eval", scanner=ScannerType.CUSTOM, title="eval", description="d",
                                  severity=Severity.HIGH, file_path="a.py", line_start=2)
    new_bad = VulnerabilityFinding(id="new-critical", scanner=ScannerType.CUSTOM, title="worse", description="d",
                                   severity=Severity.CRITICAL, file_path="a.py", line_start=1)

    async def fake_scan(path: Path) -> SASTScanResult:
        healed = "literal_eval" in (path / "a.py").read_text()
        findings = [new_bad] if healed else [eval_f]
        return SASTScanResult(target_path=str(path), total_findings=len(findings), findings=findings)

    report = await SelfHealer(scan_fn=fake_scan).heal(tmp_path)
    assert report.reverted_files == ["a.py"]
    assert report.fixes == []
    assert report.after_score == report.before_score


@pytest.mark.asyncio
async def test_apply_to_writes_only_verified_files(tmp_path):
    (tmp_path / "a.py").write_text("def f(x):\n    return eval(x)\n")
    from aegis.scanners.sast_scanner import SASTScanner
    before = await SASTScanner().scan(tmp_path)
    report = await SelfHealer().heal(tmp_path, before=before, apply_to=tmp_path)
    assert report.fixes and report.fixes[0].verified
    assert "ast.literal_eval(x)" in (tmp_path / "a.py").read_text()


@pytest.mark.asyncio
async def test_heal_demo_endpoint():
    import httpx
    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/scan/demo/heal")
    assert resp.status_code == 200
    data = resp.json()
    assert data["before_grade"] == "F" and data["after_score"] > data["before_score"]
    assert data["fixed_count"] >= 8
    assert any("filter-repo" in m["action"] for m in data["manual_actions"])
