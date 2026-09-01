import os
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

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

def load_config(target_dir: str) -> ProjectConfig:
    """
    Search for .aegis.yml or .aegis.yaml in the root of target_dir.
    If found, parse it via Pydantic ProjectConfig.
    If not found, return default ProjectConfig.
    """
    base_path = Path(target_dir)
    config_path_yml = base_path / ".aegis.yml"
    config_path_yaml = base_path / ".aegis.yaml"
    
    target_path = None
    if config_path_yml.exists():
        target_path = config_path_yml
    elif config_path_yaml.exists():
        target_path = config_path_yaml
        
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
