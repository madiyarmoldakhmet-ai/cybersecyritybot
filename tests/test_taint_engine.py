import os
import pytest
from pathlib import Path
from aegis.scanners.taint_engine import TaintEngine

@pytest.fixture
def vulnerable_project(tmp_path):
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    
    # File 1: routes.py (Source)
    routes_code = """
from service import process_user

def handle_request():
    user_input = request.args.get("id")
    process_user(user_input)
"""
    (project_dir / "routes.py").write_text(routes_code)
    
    # File 2: service.py (Pass-through)
    service_code = """
from database import fetch_user

def process_user(data):
    # some business logic
    fetch_user(data)
"""
    (project_dir / "service.py").write_text(service_code)
    
    # File 3: database.py (Sink)
    db_code = """
import sqlite3

def fetch_user(query):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # SQLi Vulnerability
    cursor.execute(f"SELECT * FROM users WHERE id = {query}")
"""
    (project_dir / "database.py").write_text(db_code)
    
    return project_dir

def test_cross_file_taint_analysis(vulnerable_project):
    engine = TaintEngine(str(vulnerable_project))
    findings = engine.analyze()
    print("Call Graph:", engine.call_graph)
    print("Findings:", findings)
    
    assert len(findings) == 1
    finding = findings[0]
    
    assert "routes.py" in finding.source_file
    assert "database.py" in finding.sink_file
    assert finding.vulnerability_type == "Tainted Data Flow"
    assert finding.severity == "CRITICAL"
    
    path_str = " ".join(finding.taint_path)
    assert "handle_request()" in path_str
    assert "-> process_user()" in path_str
    assert "-> fetch_user()" in path_str
