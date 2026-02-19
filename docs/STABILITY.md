# Stability Policy

## Overview

QuerySense follows [Semantic Versioning 2.0.0](https://semver.org/). This document clarifies what stability guarantees we provide at each version level.

## Current Status: 0.x (Alpha/Beta)

QuerySense is currently in **0.x development**. This means:

- ⚠️ Breaking changes may occur in **minor** versions (0.3 → 0.4)
- ⚠️ Public API is not yet stable
- ✅ Security fixes will be backported to latest 0.x
- ✅ Bug fixes released as patch versions (0.3.0 → 0.3.1)

### What This Means for Users

```python
# In requirements.txt, pin to minor version during 0.x
querysense>=0.4.0,<0.5.0  # Safe: only patch updates
querysense>=0.4.0,<1.0.0  # Risky: may get breaking changes
```

## Stability Tiers

### Tier 1: Stable (Safe to Depend On)

These are unlikely to change, even in 0.x:

| Component | Stability | Notes |
|-----------|-----------|-------|
| CLI commands | Stable | `querysense analyze`, `fix`, `rules` |
| CLI flags | Stable | `--json`, `--format`, `--threshold` |
| JSON output schema | Stable | Finding structure, severity values |
| Exit codes | Stable | 0=success, 1=findings, 2=error |

### Tier 2: Provisional (May Change)

These may change with deprecation warnings:

| Component | Stability | Notes |
|-----------|-----------|-------|
| `Analyzer` class constructor | Provisional | New parameters may be added |
| `Finding` model fields | Provisional | New fields may be added |
| Rule IDs | Provisional | IDs won't change, new rules added |
| `AnalysisResult` structure | Provisional | New fields may be added |

### Tier 3: Unstable (Will Change)

These may change without warning in 0.x:

| Component | Stability | Notes |
|-----------|-----------|-------|
| Internal rule interfaces | Unstable | `Rule` base class internals |
| Registry implementation | Unstable | Global vs injected |
| Parser internals | Unstable | `PlanNode` structure |
| Config file format | Unstable | Not yet finalized |
| Async implementation | Unstable | New in 0.4.0 |

## Planned Breaking Changes for 1.0

The following breaking changes are planned before 1.0:

### 1. Registry Dependency Injection

```python
# Current (0.x) - Global registry
from querysense import get_registry
registry = get_registry()  # Global singleton

# Planned (1.0) - Constructor injection
analyzer = Analyzer(registry=custom_registry)
```

### 2. Async-First API

```python
# Current (0.x) - Sync with async wrapper
result = analyzer.analyze(explain)
result = await analyzer.analyze_async(explain)

# Planned (1.0) - Unified async API
result = await analyzer.analyze(explain)  # Always async
result = analyzer.analyze_sync(explain)   # Sync convenience
```

### 3. Configuration Overhaul

```python
# Current (0.x) - Constructor parameters
analyzer = Analyzer(
    max_findings_per_rule=100,
    parallel=True,
)

# Planned (1.0) - Configuration object
config = AnalyzerConfig(
    max_findings_per_rule=100,
    execution=ExecutionConfig(parallel=True),
)
analyzer = Analyzer(config)
```

## Deprecation Policy

### During 0.x

- Breaking changes may happen in minor versions
- We will try to provide deprecation warnings when feasible
- Migration guides will be provided in CHANGELOG.md

### After 1.0

- Deprecated features will warn for **2 minor versions** before removal
- Example: Deprecated in 1.2, removed in 1.4
- Deprecation warnings will include migration instructions

```python
# Example deprecation warning
import warnings

def old_method():
    warnings.warn(
        "old_method() is deprecated and will be removed in 1.4. "
        "Use new_method() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return new_method()
```

## Long-Term Support (LTS)

### Current Policy

- Only the latest 0.x version receives updates
- Security fixes may be backported to previous minor version

### Planned 1.0+ Policy

| Version | Support Level | Duration |
|---------|---------------|----------|
| Latest  | Full support  | Until next release |
| Previous | Security only | 6 months |
| Older   | Unsupported   | - |

## How to Stay Informed

1. **Watch releases** on GitHub for update notifications
2. **Read CHANGELOG.md** before upgrading
3. **Pin versions** appropriately in requirements
4. **Run tests** after upgrading

## Reporting Stability Issues

If a change breaks your code unexpectedly:

1. Check CHANGELOG.md for documented changes
2. Open a GitHub issue with:
   - Previous working version
   - Current broken version
   - Minimal reproduction code
   - Expected vs actual behavior

We take backwards compatibility seriously and will:
- Revert unintentional breaking changes
- Provide migration guidance for intentional changes
- Consider compatibility shims for major disruptions
