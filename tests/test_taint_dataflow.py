"""Precision tests for the variable-level, inter-procedural TaintEngine."""

from pathlib import Path

from aegis.scanners.taint_engine import TaintEngine


def _scan(tmp_path: Path, files: dict):
    for name, code in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code)
    return TaintEngine(str(tmp_path)).analyze()


def test_subscript_and_attribute_sources_are_tracked(tmp_path):
    findings = _scan(tmp_path, {"app.py": (
        "def view():\n"
        "    uid = request.args['id']\n"
        "    name = request.form.name\n"
        "    cursor.execute('SELECT * FROM u WHERE id=' + uid)\n"
        "    os.system('echo ' + name)\n"
    )})
    kinds = sorted(f.sink_kind for f in findings)
    assert kinds == ["OS Command Injection", "SQL Injection"]
    assert all(f.severity == "CRITICAL" for f in findings)


def test_parameterized_query_is_not_reported(tmp_path):
    findings = _scan(tmp_path, {"app.py": (
        "def view():\n"
        "    uid = request.args.get('id')\n"
        "    cursor.execute('SELECT * FROM u WHERE id = ?', (uid,))\n"
    )})
    assert findings == []


def test_sanitizer_on_the_value_removes_taint(tmp_path):
    findings = _scan(tmp_path, {"app.py": (
        "def view():\n"
        "    uid = request.args.get('id')\n"
        "    uid = int(uid)\n"
        "    cursor.execute(f'SELECT * FROM u WHERE id = {uid}')\n"
    )})
    assert findings == []


def test_unrelated_sanitizer_does_not_hide_the_flow(tmp_path):
    """Old engine skipped any function that called int() anywhere."""
    findings = _scan(tmp_path, {"app.py": (
        "def view():\n"
        "    page = int(request.args.get('page'))\n"
        "    name = request.args.get('name')\n"
        "    cursor.execute(f\"SELECT * FROM u WHERE name = '{name}' LIMIT {page}\")\n"
    )})
    assert len(findings) == 1
    assert "name" in findings[0].code_snippets[0]


def test_source_and_unrelated_sink_is_not_a_finding(tmp_path):
    """Old engine flagged any function that both read input and called a sink."""
    findings = _scan(tmp_path, {"app.py": (
        "def view():\n"
        "    page = request.args.get('page')\n"
        "    with open('config.json') as fh:\n"
        "        cfg = fh.read()\n"
        "    return page\n"
    )})
    assert findings == []


def test_taint_returned_from_helper_reaches_sink(tmp_path):
    findings = _scan(tmp_path, {
        "inputs.py": "def get_filter():\n    raw = request.args.get('q')\n    return raw.strip().lower()\n",
        "repo.py": (
            "def search():\n"
            "    q = get_filter()\n"
            "    sql = 'SELECT * FROM t WHERE x = ' + q\n"
            "    db.execute(sql)\n"
        ),
    })
    assert len(findings) == 1
    assert "inputs.py" in findings[0].source_file and "repo.py" in findings[0].sink_file


def test_fastapi_route_parameters_are_sources(tmp_path):
    findings = _scan(tmp_path, {"api.py": (
        "@app.get('/files/{name}')\n"
        "def download(name: str, db=Depends(get_db)):\n"
        "    return open('/srv/files/' + name).read()\n"
    )})
    assert len(findings) == 1
    assert findings[0].sink_kind == "Path Traversal"
    assert findings[0].cwe == ["CWE-22"]


def test_method_calls_and_keyword_arguments(tmp_path):
    findings = _scan(tmp_path, {"svc.py": (
        "class Reports:\n"
        "    def export(self, name):\n"
        "        subprocess.run(f'tar czf {name}.tgz /data', shell=True)\n"
        "\n"
        "def handler():\n"
        "    Reports().export(name=request.args.get('n'))\n"
    )})
    assert len(findings) == 1
    assert findings[0].sink_kind == "OS Command Injection"
    assert findings[0].taint_path == ["handler()", "-> export()"]


def test_subprocess_list_without_shell_is_high_not_critical(tmp_path):
    findings = _scan(tmp_path, {"cli.py": (
        "import sys, subprocess\n"
        "subprocess.run(['git', 'clone', sys.argv[1]])\n"
    )})
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].sink_kind == "Argument Injection"


def test_safe_yaml_loader_is_not_a_sink(tmp_path):
    findings = _scan(tmp_path, {"cfg.py": (
        "def load():\n"
        "    body = request.get_json()\n"
        "    return yaml.load(body, Loader=yaml.SafeLoader)\n"
    )})
    assert findings == []


def test_deep_chain_across_three_files(tmp_path):
    findings = _scan(tmp_path, {
        "a.py": "def entry():\n    step_one(request.json['cmd'])\n",
        "b.py": "def step_one(x):\n    payload = {'cmd': x}\n    step_two(payload)\n",
        "c.py": "def step_two(p):\n    eval(p['cmd'])\n",
    })
    assert len(findings) == 1
    assert findings[0].taint_path == ["entry()", "-> step_one()", "-> step_two()"]
    assert findings[0].sink_kind == "Code Injection"
