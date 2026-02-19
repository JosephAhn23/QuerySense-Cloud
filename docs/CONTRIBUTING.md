# Contributing to QuerySense

Thank you for your interest in contributing to QuerySense! This document explains how to get started, the development workflow, and the architecture conventions you should follow.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/JosephAhn23/Query-Sense.git
cd Query-Sense

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in development mode with all extras
pip install -e ".[dev,sql,ai,db,cloud]"

# Run tests
pytest tests/ -v

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src/querysense --ignore-missing-imports
```

## Development Workflow

1. **Create a branch** from `main` for your work.
2. **Write tests first** (or at least alongside) for any new functionality.
3. **Run the full CI suite locally** before pushing:
   ```bash
   ruff check . && ruff format --check . && pytest tests/ -v && mypy src/querysense --ignore-missing-imports
   ```
4. **Open a pull request** with a clear description of the change.

## Architecture Overview

```
src/querysense/
├── analyzer/          # Core analysis engine
│   ├── analyzer.py    # Orchestrator (Analyzer class)
│   ├── models.py      # Immutable domain models (Finding, AnalysisResult)
│   ├── rules/         # Rule implementations (plugin system)
│   │   ├── base.py    # Rule base class and protocols
│   │   └── *.py       # Individual rules
│   ├── dag.py         # Rule dependency DAG (topological sorting)
│   ├── capabilities.py # Typed capability system + FactStore
│   ├── context.py     # AnalysisContext wrapper
│   └── ...
├── cli/               # Typer-based CLI
│   ├── main.py        # Entry point and Typer app hierarchy
│   └── commands/      # Command modules (analyze, ci, baseline, etc.)
├── ir/                # Intermediate Representation (engine-agnostic)
├── parser/            # EXPLAIN JSON parser
├── output/            # Rendering (text, JSON, markdown)
├── db/                # Database probe (Level 3 analysis)
├── cloud/             # Cloud SaaS module (FastAPI)
├── exceptions.py      # Package-level exception hierarchy
├── config.py          # Configuration system (12-factor)
├── plan_diff.py       # Shared plan diff utility
├── baseline.py        # Baseline storage / regression detection
├── engine.py          # AnalysisService orchestration
└── policy.py          # Policy enforcement (CI gating)
```

### Key Principles

- **Deterministic core**: No LLM required for analysis. AI features are optional extras.
- **Observable failure**: Every rule produces PASS/SKIP/FAIL status, never silent failure.
- **Never overclaim**: Use impact bands (LOW/MEDIUM/HIGH), not specific multipliers.
- **Config is not code**: Thresholds come from environment variables, not hardcoded.
- **One concept, one module**: Each module has a single responsibility.

### Module Boundaries

Module boundaries are enforced by import-linter contracts defined in `pyproject.toml`. Run `lint-imports` to verify boundaries are respected.

### Exception Hierarchy

All exceptions inherit from `QuerySenseError` (in `querysense.exceptions`):

```
QuerySenseError
├── AnalyzerError          – Analysis orchestration errors
│   ├── RuleError          – A specific rule failed
│   └── ConfigurationError – Invalid configuration
├── ParseError             – EXPLAIN JSON parsing failures
├── IRConversionError      – IR conversion failures
├── BaselineError          – Baseline storage errors
├── PolicyError            – Policy evaluation errors
└── CloudError             – Cloud/API layer errors
```

## Adding a New Rule

1. Create a new file in `src/querysense/analyzer/rules/`:
   ```python
   from querysense.analyzer.rules.base import Rule
   from querysense.analyzer.models import Finding, Severity, RulePhase, NodeContext
   from querysense.analyzer.registry import register_rule

   @register_rule
   class MyNewRule(Rule):
       rule_id = "MY_NEW_RULE"
       version = "1.0.0"
       severity = Severity.WARNING
       description = "Detects XYZ performance issue"
       phase = RulePhase.PER_NODE
       requires: tuple[str, ...] = ()      # Capabilities needed
       provides: tuple[str, ...] = ()      # Capabilities produced

       def analyze(self, explain, prior_findings=None):
           findings = []
           for path, node, parent in self.iter_nodes_with_parent(explain):
               # Detection logic here
               pass
           return findings
   ```

2. Register the import in `src/querysense/analyzer/__init__.py`.
3. Write tests in `tests/test_<rule_name>.py`.
4. Update the rule count in `README.md` if needed.

## Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/test_dag.py -v

# With coverage
pytest tests/ --cov=querysense --cov-report=term-missing

# Backwards compatibility only
pytest tests/test_backwards_compat.py -v
```

## Code Style

- **Formatter**: Ruff (`ruff format`)
- **Linter**: Ruff (`ruff check`)
- **Type checker**: mypy (strict mode, blocking in CI)
- **Docstrings**: Google-style, required for all public APIs

## Reporting Issues

- **Slow query?** Open an issue with the EXPLAIN JSON (anonymized). If it's a common pattern, we'll add a rule.
- **Bug?** Include the QuerySense version, Python version, and reproducibility hash from the analysis output.
- **Security vulnerability?** Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
