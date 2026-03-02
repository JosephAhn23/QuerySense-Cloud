# QuerySense

<p align="center">
  <strong>Turn slow SQL into fast SQL in minutes.</strong><br/>
  Paste an execution plan, get clear fixes you can copy-paste.
</p>

<p align="center">
  <a href="https://pypi.org/project/querysense/"><img src="https://img.shields.io/badge/PyPI-querysense-8b5cf6?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.11%2B-1f2937?style=for-the-badge&logo=python&logoColor=facc15" alt="Python 3.11+"></a>
  <a href="https://github.com/JosephAhn23/Query-Sense/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/JosephAhn23/Query-Sense/ci.yml?style=for-the-badge&label=CI&color=22c55e" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-0ea5e9?style=for-the-badge" alt="MIT"></a>
</p>

<p align="center">
  <img src="docs/media/readme/readme-hero-dark.png" alt="QuerySense — slow plan in, optimized SQL out" width="920">
</p>

---

## Why QuerySense

- **Fast wins:** see bottlenecks and likely fixes right away
- **Human-friendly:** plain-English output (`--simple`, `--eli5`) for non-DBA users
- **Actionable:** generate SQL fixes and migration files from findings
- **Multi-engine:** PostgreSQL, MySQL, SQL Server, MongoDB
- **Private-first:** works offline, no account required

---

## Quick Start

```bash
pip install querysense
querysense analyze plan.json --simple
querysense fix plan.json > fixes.sql
```

---

## Workflow

```bash
# 1. Analyze a plan
querysense analyze plan.json

# 2. Generate fixes
querysense fix plan.json > fixes.sql

# 3. Compare before vs after
querysense diff before.json after.json
```

![Workflow](docs/media/readme/readme-workflow-dark.png)

---

## Example Output

```
$ querysense analyze plan.json

[WARNING] Seq Scan on orders (250,000 rows)  ~4.8x faster with index
  Fix:
  CREATE INDEX idx_orders_status ON orders(status);

[WARNING] Row estimate 5,000x off on orders
  Fix:
  ANALYZE orders;

Analyzed 2 findings in 1.5ms
```

![CLI](docs/media/readme/readme-cli-dark.png)

---

## Features

- **Plan Analysis:** detect costly scans, bad estimates, spills, and join issues
- **Safe SQL Rewrites:** `querysense rewrite --sql ...` with optional sandbox checks
- **Migration Outputs:** Flyway, Liquibase, Alembic, Django, dbmate
- **I/O Visibility:** buffer-focused analysis and before/after comparisons
- **CI Integration:** fail builds on performance regressions with `querysense ci`

---

`v2.0.0` · 190+ tests · 37+ detection rules · Python 3.11+

## License

MIT
