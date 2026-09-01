import pytest
import os
from pathlib import Path
from aegis.core.project_config import load_config

def test_load_config_defaults(tmp_path):
    config = load_config(str(tmp_path))
    assert config.ignore_paths == []
    assert config.severity_threshold == "LOW"
    assert config.ai_filter is True
    assert config.language == "en"

def test_load_config_yml(tmp_path):
    yaml_content = """
ignore_paths:
  - "tests/**"
  - "docs/**"
severity_threshold: MEDIUM
ai_filter: false
custom_rules:
  - id: no-hardcoded-urls
    pattern: "https?://(?:prod|staging)\\\\."
    title: "Hardcoded production URL"
    severity: MEDIUM
    cwe: ["CWE-798"]
"""
    (tmp_path / ".aegis.yml").write_text(yaml_content)
    
    config = load_config(str(tmp_path))
    assert len(config.ignore_paths) == 2
    assert "tests/**" in config.ignore_paths
    assert config.severity_threshold == "MEDIUM"
    assert config.ai_filter is False
    assert len(config.custom_rules) == 1
    assert config.custom_rules[0].id == "no-hardcoded-urls"
    assert config.custom_rules[0].severity == "MEDIUM"
    assert config.custom_rules[0].cwe == ["CWE-798"]
