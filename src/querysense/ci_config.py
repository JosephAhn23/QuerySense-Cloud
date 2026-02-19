"""
CI configuration loader for QuerySense.

Loads CI-specific settings from `.querysense-ci.yml` (or `.querysense-ci.yaml`).
This is separate from the runtime config — it controls how QuerySense behaves
in CI pipelines: what to scan, what to fail on, what to ignore.

Config file search order:
1. Explicit --config path
2. .querysense-ci.yml in current directory
3. .querysense-ci.yaml in current directory
4. .querysense/ci.yml
5. Sensible defaults (scan plans/**/*.json, fail on warning)

Example .querysense-ci.yml:

    # QuerySense CI Configuration
    # Docs: https://github.com/JosephAhn23/Query-Sense#ci-cd

    # Glob patterns for EXPLAIN JSON files to analyze
    plans:
      - "plans/**/*.json"
      - "migrations/explains/*.json"

    # Minimum severity to fail the pipeline: critical | warning | info | none
    fail_on: warning

    # Require EXPLAIN ANALYZE data (not just EXPLAIN)
    require_analyze: true

    # Baseline file for regression detection
    baseline: .querysense/baselines.json

    # Policy file for rule enforcement
    policy: .querysense/policy.yml

    # Rules to ignore (by rule_id)
    ignore_rules:
      - MISSING_BUFFERS
      - PARALLEL_QUERY_NOT_USED

    # Per-file overrides
    overrides:
      "migrations/*.json":
        fail_on: critical  # More lenient for migration plans

    # GitHub-specific settings
    github:
      annotations: true      # Emit inline PR annotations
      step_summary: true      # Write GITHUB_STEP_SUMMARY
      pr_comment: false       # Post PR comment (requires GITHUB_TOKEN)
      comment_on_pass: false  # Post comment even if all checks pass
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GitHubSettings:
    """GitHub Actions-specific settings."""

    annotations: bool = True
    step_summary: bool = True
    pr_comment: bool = False
    comment_on_pass: bool = False


@dataclass(frozen=True)
class FileOverride:
    """Per-file-pattern settings override."""

    pattern: str
    fail_on: str | None = None
    ignore_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class CIConfig:
    """
    CI pipeline configuration.

    Immutable after construction. Loaded from YAML config file
    or constructed with sensible defaults.
    """

    plans: tuple[str, ...] = ("plans/**/*.json",)
    fail_on: str = "warning"
    require_analyze: bool = True
    baseline: str = ".querysense/baselines.json"
    policy: str | None = None
    ignore_rules: tuple[str, ...] = ()
    overrides: tuple[FileOverride, ...] = ()
    github: GitHubSettings = field(default_factory=GitHubSettings)

    def effective_fail_on(self, file_path: str) -> str:
        """Get the effective fail_on level for a specific file.

        Checks overrides in order; first matching pattern wins.
        Falls back to the global fail_on setting.
        """
        for override in self.overrides:
            if fnmatch.fnmatch(file_path, override.pattern):
                if override.fail_on is not None:
                    return override.fail_on
        return self.fail_on

    def effective_ignore_rules(self, file_path: str) -> set[str]:
        """Get the effective set of ignored rules for a specific file.

        Combines global ignore_rules with any file-specific overrides.
        """
        ignored = set(self.ignore_rules)
        for override in self.overrides:
            if fnmatch.fnmatch(file_path, override.pattern):
                ignored.update(override.ignore_rules)
        return ignored

    @classmethod
    def default(cls) -> CIConfig:
        """Create a CIConfig with sensible defaults."""
        return cls()


def load_ci_config(config_path: str | Path | None = None) -> CIConfig:
    """
    Load CI configuration from file or return defaults.

    Search order when config_path is None:
    1. .querysense-ci.yml
    2. .querysense-ci.yaml
    3. .querysense/ci.yml
    4. Default configuration

    Args:
        config_path: Explicit path to config file (None for auto-discovery)

    Returns:
        CIConfig instance

    Raises:
        FileNotFoundError: If explicit config_path doesn't exist
        ValueError: If config file has invalid structure
    """
    if config_path is not None:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"CI config file not found: {path}")
        return _parse_config_file(path)

    # Auto-discover
    candidates = [
        Path(".querysense-ci.yml"),
        Path(".querysense-ci.yaml"),
        Path(".querysense/ci.yml"),
    ]

    for candidate in candidates:
        if candidate.exists():
            return _parse_config_file(candidate)

    # No config file found — return defaults
    return CIConfig.default()


def _parse_config_file(path: Path) -> CIConfig:
    """Parse a YAML config file into CIConfig.

    Uses a safe YAML subset parser to avoid requiring PyYAML as a dependency.
    Falls back to a simple key-value parser for basic configs.
    """
    content = path.read_text(encoding="utf-8")

    try:
        # Try PyYAML if available
        import yaml
        data = yaml.safe_load(content)
    except ImportError:
        # Fallback: simple YAML-like parser for common cases
        data = _simple_yaml_parse(content)

    if not isinstance(data, dict):
        raise ValueError(f"CI config must be a YAML mapping, got {type(data).__name__}")

    return _dict_to_config(data)


def _dict_to_config(data: dict[str, Any]) -> CIConfig:
    """Convert a parsed YAML dict to CIConfig."""
    # Plans
    plans_raw = data.get("plans", ("plans/**/*.json",))
    if isinstance(plans_raw, str):
        plans = (plans_raw,)
    elif isinstance(plans_raw, list):
        plans = tuple(str(p) for p in plans_raw)
    else:
        plans = ("plans/**/*.json",)

    # Fail-on
    fail_on = str(data.get("fail_on", "warning")).lower()
    if fail_on not in ("critical", "warning", "info", "none"):
        fail_on = "warning"

    # Ignore rules
    ignore_raw = data.get("ignore_rules", [])
    if isinstance(ignore_raw, list):
        ignore_rules = tuple(str(r) for r in ignore_raw)
    else:
        ignore_rules = ()

    # Overrides
    overrides_raw = data.get("overrides", {})
    overrides: list[FileOverride] = []
    if isinstance(overrides_raw, dict):
        for pattern, override_data in overrides_raw.items():
            if isinstance(override_data, dict):
                override_ignore = override_data.get("ignore_rules", [])
                overrides.append(FileOverride(
                    pattern=str(pattern),
                    fail_on=override_data.get("fail_on"),
                    ignore_rules=tuple(str(r) for r in override_ignore) if isinstance(override_ignore, list) else (),
                ))

    # GitHub settings
    github_raw = data.get("github", {})
    github = GitHubSettings(
        annotations=github_raw.get("annotations", True) if isinstance(github_raw, dict) else True,
        step_summary=github_raw.get("step_summary", True) if isinstance(github_raw, dict) else True,
        pr_comment=github_raw.get("pr_comment", False) if isinstance(github_raw, dict) else False,
        comment_on_pass=github_raw.get("comment_on_pass", False) if isinstance(github_raw, dict) else False,
    )

    # Policy
    policy_raw = data.get("policy")
    policy: str | None = None
    if policy_raw is not None:
        policy = str(policy_raw)
    else:
        # Auto-discover default policy
        default_policy = Path(".querysense/policy.yml")
        if default_policy.exists():
            policy = str(default_policy)

    return CIConfig(
        plans=plans,
        fail_on=fail_on,
        require_analyze=bool(data.get("require_analyze", True)),
        baseline=str(data.get("baseline", ".querysense/baselines.json")),
        policy=policy,
        ignore_rules=ignore_rules,
        overrides=tuple(overrides),
        github=github,
    )


def _simple_yaml_parse(content: str) -> dict[str, Any]:
    """
    Minimal YAML-like parser for simple key-value configs.

    Handles:
    - key: value
    - key: [list, items]
    - Nested objects (one level)
    - Comments (#)
    - Lists with - item syntax

    This avoids requiring PyYAML as a dependency for basic CI configs.
    """
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[str] | None = None
    current_dict: dict[str, Any] | None = None
    current_dict_key: str | None = None

    for line in content.split("\n"):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            if current_list is not None and current_key:
                # End of list on blank line
                pass
            continue

        # Check indentation level
        indent = len(line) - len(line.lstrip())

        # List item
        if stripped.startswith("- ") and current_key and indent > 0:
            value = stripped[2:].strip().strip('"').strip("'")
            if current_list is not None:
                current_list.append(value)
            continue

        # End any active list
        if current_list is not None and current_key:
            result[current_key] = current_list
            current_list = None
            current_key = None

        # End any active dict
        if current_dict is not None and current_dict_key and indent == 0:
            result[current_dict_key] = current_dict
            current_dict = None
            current_dict_key = None

        # Nested dict value
        if current_dict is not None and indent > 0 and ":" in stripped:
            k, _, v = stripped.partition(":")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if v.lower() == "true":
                current_dict[k] = True
            elif v.lower() == "false":
                current_dict[k] = False
            elif v:
                current_dict[k] = v
            continue

        # Top-level key: value
        if ":" in stripped and indent == 0:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()

            if not value:
                # Could be start of a list or nested dict
                current_key = key
                current_list = []
                # Also prepare for dict
                current_dict = {}
                current_dict_key = key
                continue

            # Inline value
            value = value.strip('"').strip("'")
            if value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                result[key] = False
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    # Flush any remaining list/dict
    if current_list is not None and current_key:
        result[current_key] = current_list
    if current_dict is not None and current_dict_key and current_dict_key not in result:
        result[current_dict_key] = current_dict

    return result


def generate_default_ci_config() -> str:
    """
    Generate a default .querysense-ci.yml config file.

    Returns:
        YAML content string
    """
    return """\
# QuerySense CI Configuration
# Docs: https://github.com/JosephAhn23/Query-Sense#ci-cd
#
# Add this file to your repo root as .querysense-ci.yml
# Then add to your GitHub Action:
#   - run: querysense ci gate

# Glob patterns for EXPLAIN JSON plan files
plans:
  - "plans/**/*.json"

# Minimum severity to fail the build: critical | warning | info | none
fail_on: warning

# Require EXPLAIN ANALYZE data (not just plain EXPLAIN)
require_analyze: true

# Baseline file for detecting plan regressions between commits
baseline: .querysense/baselines.json

# Policy file for custom rule enforcement
# policy: .querysense/policy.yml

# Rules to suppress globally
# ignore_rules:
#   - MISSING_BUFFERS
#   - PARALLEL_QUERY_NOT_USED

# Per-file overrides (glob patterns)
# overrides:
#   "migrations/*.json":
#     fail_on: critical

# GitHub Actions integration
github:
  annotations: true       # Inline PR annotations on findings
  step_summary: true      # Rich summary in Actions tab
  pr_comment: false       # PR comment (requires GITHUB_TOKEN)
  comment_on_pass: false  # Comment even when all checks pass
"""
