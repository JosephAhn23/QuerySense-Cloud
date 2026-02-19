"""
Configuration system for QuerySense.

Implements 12-factor config principles:
- Environment variables as primary config source
- Optional config file for local development
- Per-rule thresholds
- Per-environment profiles
- Per-table overrides

Usage:
    from querysense.config import get_config, Config
    
    # Load from environment (default)
    config = get_config()
    
    # Access rule thresholds
    threshold = config.get_rule_threshold("SEQ_SCAN_LARGE_TABLE", "row_threshold")
    
    # Check if rule is enabled
    if config.is_rule_enabled("SEQ_SCAN_LARGE_TABLE"):
        ...
    
    # Get table-specific override
    threshold = config.get_table_override("orders", "seq_scan_row_threshold", default=10000)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class Environment(str, Enum):
    """Environment profiles with different default behaviors."""
    
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    
    @classmethod
    def from_string(cls, value: str) -> "Environment":
        """Parse environment from string, defaulting to development."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.DEVELOPMENT


# Note: EvidenceLevel and ImpactBand are defined in querysense.analyzer.models
# to avoid circular imports. Import from there if needed.


@dataclass
class RuleThresholds:
    """Configurable thresholds for a rule."""
    
    enabled: bool = True
    thresholds: dict[str, int | float] = field(default_factory=dict)


class RuleConfig(BaseModel):
    """Configuration for a single rule."""
    
    model_config = ConfigDict(frozen=True)
    
    enabled: bool = Field(default=True, description="Whether the rule is enabled")
    thresholds: dict[str, int | float] = Field(
        default_factory=dict,
        description="Rule-specific thresholds",
    )


class TableOverrides(BaseModel):
    """Per-table configuration overrides."""
    
    model_config = ConfigDict(frozen=True)
    
    seq_scan_row_threshold: int | None = Field(
        default=None,
        description="Override for sequential scan row threshold",
    )
    index_disabled: bool = Field(
        default=False,
        description="Disable index recommendations for this table",
    )
    skip_rules: list[str] = Field(
        default_factory=list,
        description="Rules to skip for this table",
    )


class Config(BaseModel):
    """
    QuerySense configuration.
    
    Loaded from environment variables and optional config file.
    Supports per-rule thresholds, per-environment profiles, and per-table overrides.
    """
    
    model_config = ConfigDict(frozen=True)
    
    # Environment
    environment: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Current environment (development/staging/production)",
    )
    
    # Global settings
    querysense_version: str = Field(
        default="0.5.2",
        description="QuerySense version for cache invalidation",
    )
    
    # Default thresholds (can be overridden per-rule)
    default_seq_scan_row_threshold: int = Field(
        default=10000,
        description="Default row threshold for sequential scan warnings",
    )
    default_bad_estimate_ratio: float = Field(
        default=10.0,
        description="Default ratio threshold for bad row estimates",
    )
    default_nested_loop_threshold: int = Field(
        default=1000,
        description="Default iteration threshold for nested loop warnings",
    )
    
    # Rule configurations
    rules: dict[str, RuleConfig] = Field(
        default_factory=dict,
        description="Per-rule configurations",
    )
    
    # Table overrides
    table_overrides: dict[str, TableOverrides] = Field(
        default_factory=dict,
        description="Per-table configuration overrides",
    )
    
    # Cache settings
    cache_enabled: bool = Field(
        default=True,
        description="Enable LRU caching of analysis results",
    )
    cache_size: int = Field(
        default=100,
        description="Maximum number of cached results",
    )
    cache_ttl_seconds: float = Field(
        default=300.0,
        description="Cache TTL in seconds",
    )
    
    # SQL parsing
    prefer_pglast: bool = Field(
        default=True,
        description="Prefer pglast (accurate) over sqlparse (heuristic) when available",
    )
    sql_parse_timeout_ms: int = Field(
        default=1000,
        description="Timeout for SQL parsing in milliseconds",
    )
    
    # DB probe settings (Level 3)
    db_probe_enabled: bool = Field(
        default=False,
        description="Enable database probe for validated recommendations",
    )
    db_probe_timeout_seconds: float = Field(
        default=5.0,
        description="Timeout for database probe queries",
    )
    
    # Observability
    tracing_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry-style tracing",
    )
    metrics_enabled: bool = Field(
        default=True,
        description="Enable metrics collection",
    )
    
    def get_rule_threshold(
        self,
        rule_id: str,
        threshold_name: str,
        default: int | float | None = None,
    ) -> int | float | None:
        """
        Get a threshold value for a rule.
        
        Lookup order:
        1. Rule-specific threshold in config
        2. Default threshold if name matches a default_* field
        3. Provided default value
        """
        # Check rule-specific config
        if rule_id in self.rules:
            rule_config = self.rules[rule_id]
            if threshold_name in rule_config.thresholds:
                return rule_config.thresholds[threshold_name]
        
        # Check for matching default field
        default_field = f"default_{threshold_name}"
        if hasattr(self, default_field):
            return getattr(self, default_field)
        
        return default
    
    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled."""
        if rule_id in self.rules:
            return self.rules[rule_id].enabled
        return True  # Rules enabled by default
    
    def get_table_override(
        self,
        table: str,
        field_name: str,
        default: Any = None,
    ) -> Any:
        """Get a table-specific override value."""
        if table in self.table_overrides:
            overrides = self.table_overrides[table]
            if hasattr(overrides, field_name):
                value = getattr(overrides, field_name)
                if value is not None:
                    return value
        return default
    
    def should_skip_rule_for_table(self, rule_id: str, table: str) -> bool:
        """Check if a rule should be skipped for a specific table."""
        if table in self.table_overrides:
            return rule_id in self.table_overrides[table].skip_rules
        return False
    
    def config_hash(self) -> str:
        """
        Generate a hash of the configuration for cache key inclusion.
        
        Ensures cache invalidation when config changes.
        """
        config_dict = self.model_dump(exclude={"cache_enabled", "cache_size", "cache_ttl_seconds"})
        config_json = json.dumps(config_dict, sort_keys=True, default=str)
        return hashlib.sha256(config_json.encode()).hexdigest()[:16]


def _parse_env_bool(value: str | None, default: bool = False) -> bool:
    """Parse boolean from environment variable."""
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")


def _parse_env_int(value: str | None, default: int) -> int:
    """Parse integer from environment variable."""
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _parse_env_float(value: str | None, default: float) -> float:
    """Parse float from environment variable."""
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def load_config_from_env() -> Config:
    """
    Load configuration from environment variables.
    
    Environment variable naming convention:
    - QUERYSENSE_<SETTING> for global settings
    - QUERYSENSE_RULE_<RULE_ID>_<SETTING> for rule-specific settings
    - QUERYSENSE_TABLE_<TABLE>_<SETTING> for table-specific overrides
    
    Examples:
    - QUERYSENSE_ENVIRONMENT=production
    - QUERYSENSE_SEQ_SCAN_ROW_THRESHOLD=100000
    - QUERYSENSE_RULE_SEQ_SCAN_LARGE_TABLE_ENABLED=true
    - QUERYSENSE_RULE_SEQ_SCAN_LARGE_TABLE_ROW_THRESHOLD=50000
    - QUERYSENSE_TABLE_orders_SEQ_SCAN_ROW_THRESHOLD=20000
    """
    # Parse environment
    env_str = os.environ.get("QUERYSENSE_ENVIRONMENT", "development")
    environment = Environment.from_string(env_str)
    
    # Parse global settings
    config_kwargs: dict[str, Any] = {
        "environment": environment,
        "default_seq_scan_row_threshold": _parse_env_int(
            os.environ.get("QUERYSENSE_SEQ_SCAN_ROW_THRESHOLD"), 10000
        ),
        "default_bad_estimate_ratio": _parse_env_float(
            os.environ.get("QUERYSENSE_BAD_ESTIMATE_RATIO"), 10.0
        ),
        "default_nested_loop_threshold": _parse_env_int(
            os.environ.get("QUERYSENSE_NESTED_LOOP_THRESHOLD"), 1000
        ),
        "cache_enabled": _parse_env_bool(
            os.environ.get("QUERYSENSE_CACHE_ENABLED"), True
        ),
        "cache_size": _parse_env_int(
            os.environ.get("QUERYSENSE_CACHE_SIZE"), 100
        ),
        "cache_ttl_seconds": _parse_env_float(
            os.environ.get("QUERYSENSE_CACHE_TTL_SECONDS"), 300.0
        ),
        "prefer_pglast": _parse_env_bool(
            os.environ.get("QUERYSENSE_PREFER_PGLAST"), True
        ),
        "db_probe_enabled": _parse_env_bool(
            os.environ.get("QUERYSENSE_DB_PROBE_ENABLED"), False
        ),
        "tracing_enabled": _parse_env_bool(
            os.environ.get("QUERYSENSE_TRACING_ENABLED"), False
        ),
        "metrics_enabled": _parse_env_bool(
            os.environ.get("QUERYSENSE_METRICS_ENABLED"), True
        ),
    }
    
    # Parse rule-specific settings
    rules: dict[str, RuleConfig] = {}
    rule_prefix = "QUERYSENSE_RULE_"
    
    for key, value in os.environ.items():
        if key.startswith(rule_prefix):
            parts = key[len(rule_prefix):].split("_")
            if len(parts) >= 2:
                # Reconstruct rule ID (everything except last part)
                rule_id = "_".join(parts[:-1])
                setting = parts[-1].lower()
                
                if rule_id not in rules:
                    rules[rule_id] = RuleConfig()
                
                if setting == "enabled":
                    rules[rule_id] = rules[rule_id].model_copy(
                        update={"enabled": _parse_env_bool(value, True)}
                    )
                else:
                    # Treat as threshold
                    thresholds = dict(rules[rule_id].thresholds)
                    try:
                        thresholds[setting] = float(value) if "." in value else int(value)
                        rules[rule_id] = rules[rule_id].model_copy(
                            update={"thresholds": thresholds}
                        )
                    except ValueError:
                        logger.warning("Could not parse threshold %s=%s", key, value)
    
    config_kwargs["rules"] = rules
    
    # Parse table overrides
    table_overrides: dict[str, TableOverrides] = {}
    table_prefix = "QUERYSENSE_TABLE_"
    
    for key, value in os.environ.items():
        if key.startswith(table_prefix):
            parts = key[len(table_prefix):].split("_", 1)
            if len(parts) == 2:
                table_name = parts[0].lower()
                setting = parts[1].lower()
                
                if table_name not in table_overrides:
                    table_overrides[table_name] = TableOverrides()
                
                current = table_overrides[table_name]
                
                if setting == "seq_scan_row_threshold":
                    table_overrides[table_name] = current.model_copy(
                        update={"seq_scan_row_threshold": _parse_env_int(value, 10000)}
                    )
                elif setting == "index_disabled":
                    table_overrides[table_name] = current.model_copy(
                        update={"index_disabled": _parse_env_bool(value, False)}
                    )
                elif setting == "skip_rules":
                    table_overrides[table_name] = current.model_copy(
                        update={"skip_rules": [r.strip() for r in value.split(",")]}
                    )
    
    config_kwargs["table_overrides"] = table_overrides
    
    return Config(**config_kwargs)


def load_config_from_file(path: Path) -> Config:
    """
    Load configuration from a JSON or YAML file.
    
    Falls back to environment variables for missing values.
    """
    if not path.exists():
        logger.warning("Config file not found: %s, using environment", path)
        return load_config_from_env()
    
    try:
        with open(path) as f:
            if path.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    data = yaml.safe_load(f)
                except ImportError:
                    logger.warning("PyYAML not installed, cannot load YAML config")
                    return load_config_from_env()
            else:
                data = json.load(f)
        
        return Config(**data)
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as e:
        logger.error("Failed to load config from %s: %s", path, e)
        return load_config_from_env()


@lru_cache(maxsize=1)
def get_config() -> Config:
    """
    Get the global configuration instance.
    
    Loads from:
    1. QUERYSENSE_CONFIG_FILE environment variable (if set)
    2. Environment variables (default)
    
    Result is cached for the lifetime of the process.
    """
    config_file = os.environ.get("QUERYSENSE_CONFIG_FILE")
    
    if config_file:
        return load_config_from_file(Path(config_file))
    
    return load_config_from_env()


def reset_config() -> None:
    """Reset the cached configuration (mainly for testing)."""
    get_config.cache_clear()
