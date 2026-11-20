import os
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

from aegis.scanners.risk_model import RiskSettings

class CustomRule(BaseModel):
    id: str
    pattern: str
    title: str
    severity: str
    cwe: List[str] = []

class ProjectConfig(BaseModel):
    ignore_paths: List[str] = Field(default_factory=list)
    ignore_rules: List[str] = Field(default_factory=list)
    severity_threshold: str = "LOW"
    custom_rules: List[CustomRule] = Field(default_factory=list)
    ai_filter: bool = True
    language: str = "en"
    risk: RiskSettings = Field(default_factory=RiskSettings)

def validate_config_path(target_dir: str) -> Optional[Path]:
    """Resolve `.aegis.yml`/`.aegis.yaml` strictly inside `target_dir` (blocks symlink escape)."""
    base_path = Path(target_dir).resolve()
    for name in (".aegis.yml", ".aegis.yaml"):
        candidate = (base_path / name).resolve()
        if candidate.is_relative_to(base_path) and candidate.is_file():
            return candidate
    return None


def load_config(target_dir: str) -> ProjectConfig:
    """
    Search for .aegis.yml or .aegis.yaml in the root of target_dir.
    If found, parse it via Pydantic ProjectConfig.
    If not found, return default ProjectConfig.
    """
    target_path = validate_config_path(target_dir)
    if not target_path:
        return ProjectConfig()

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return ProjectConfig(**data)
    except Exception as e:
        import logging
        logger = logging.getLogger("aegis.project_config")
        logger.error(f"Failed to parse {target_path}: {e}")
        return ProjectConfig()
