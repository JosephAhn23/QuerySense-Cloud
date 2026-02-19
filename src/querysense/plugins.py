"""
Plugin system for QuerySense custom rules.

Allows users to register custom rules without forking the repo.

Three ways to load custom rules:

1. Python decorator API:
    from querysense.plugins import custom_rule
    from querysense.analyzer.rules.base import Rule
    from querysense.analyzer.models import Finding, Severity

    @custom_rule
    class MyRule(Rule):
        rule_id = "MY_CUSTOM_RULE"
        severity = Severity.WARNING
        description = "My custom detection rule"

        def analyze(self, explain, prior_findings=None):
            findings = []
            # ... detection logic ...
            return findings

2. File-based plugins (~/.querysense/rules/*.py):
    Place Python files in ~/.querysense/rules/ and they'll be auto-loaded.
    Each file should contain one or more Rule subclasses decorated with @custom_rule.

3. Entry points (for pip-installable plugins):
    In your plugin's pyproject.toml:
        [project.entry-points."querysense.rules"]
        my_plugin = "my_package.rules"

Usage:
    from querysense.plugins import load_plugins, get_custom_rules

    # Load plugins from all sources
    load_plugins()

    # Get loaded custom rules
    custom = get_custom_rules()
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Registry of custom rules (separate from built-in registry)
_custom_rules: list[type] = []
_plugins_loaded: bool = False


def custom_rule(cls: type) -> type:
    """
    Decorator to register a custom rule.

    Works the same as @register_rule but keeps custom rules in a
    separate registry that won't break built-in rule ordering.

    Usage:
        @custom_rule
        class MyRule(Rule):
            rule_id = "MY_CUSTOM_RULE"
            ...
    """
    from querysense.analyzer.registry import register_rule

    # Register in the main registry so it runs during analysis
    register_rule(cls)

    # Also track in custom registry for listing/management
    if cls not in _custom_rules:
        _custom_rules.append(cls)

    return cls


def get_custom_rules() -> list[type]:
    """Get all registered custom rules."""
    return list(_custom_rules)


def load_plugins(
    *,
    plugin_dirs: list[Path] | None = None,
    load_entry_points: bool = True,
    load_file_plugins: bool = True,
) -> int:
    """
    Load custom rules from all plugin sources.

    Sources loaded in order:
    1. File-based plugins from plugin directories
    2. Entry point plugins from installed packages

    Args:
        plugin_dirs: Directories to search for .py rule files.
            Defaults to [~/.querysense/rules/, .querysense/rules/]
        load_entry_points: Whether to load entry point plugins
        load_file_plugins: Whether to load file-based plugins

    Returns:
        Number of custom rules loaded
    """
    global _plugins_loaded

    if _plugins_loaded:
        return len(_custom_rules)

    count_before = len(_custom_rules)

    # File-based plugins
    if load_file_plugins:
        dirs = plugin_dirs or _default_plugin_dirs()
        for plugin_dir in dirs:
            _load_from_directory(plugin_dir)

    # Entry point plugins
    if load_entry_points:
        _load_from_entry_points()

    _plugins_loaded = True
    loaded = len(_custom_rules) - count_before

    if loaded > 0:
        logger.info("Loaded %d custom rule(s) from plugins", loaded)

    return loaded


def _default_plugin_dirs() -> list[Path]:
    """Get default directories for file-based plugins."""
    dirs: list[Path] = []

    # User-level: ~/.querysense/rules/
    home_dir = Path.home() / ".querysense" / "rules"
    if home_dir.is_dir():
        dirs.append(home_dir)

    # Project-level: .querysense/rules/
    project_dir = Path(".querysense") / "rules"
    if project_dir.is_dir():
        dirs.append(project_dir)

    return dirs


def _load_from_directory(plugin_dir: Path) -> None:
    """Load all .py files from a plugin directory."""
    if not plugin_dir.is_dir():
        return

    for py_file in sorted(plugin_dir.glob("*.py")):
        if py_file.name.startswith("_"):
            continue

        try:
            module_name = f"querysense_plugin_{py_file.stem}"

            # Add directory to path temporarily
            str_dir = str(plugin_dir)
            if str_dir not in sys.path:
                sys.path.insert(0, str_dir)

            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)  # type: ignore[union-attr]
                logger.debug("Loaded plugin: %s from %s", module_name, py_file)

        except Exception as e:
            logger.warning("Failed to load plugin %s: %s", py_file.name, e)


def _load_from_entry_points() -> None:
    """Load rules from Python package entry points."""
    try:
        eps = importlib.metadata.entry_points()

        # Python 3.12+ returns SelectableGroups, 3.9+ returns dict
        if hasattr(eps, "select"):
            plugin_eps = eps.select(group="querysense.rules")
        elif isinstance(eps, dict):
            plugin_eps = eps.get("querysense.rules", [])
        else:
            plugin_eps = [ep for ep in eps if ep.group == "querysense.rules"]

        for ep in plugin_eps:
            try:
                ep.load()
                logger.debug("Loaded entry point plugin: %s", ep.name)
            except Exception as e:
                logger.warning("Failed to load plugin entry point %s: %s", ep.name, e)

    except Exception as e:
        logger.debug("Entry point loading not available: %s", e)
