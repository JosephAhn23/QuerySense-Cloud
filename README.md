# QuerySense

<p align="center">
  <img src="query.png" alt="QuerySense — 2.3s seq scan to 0.04s index scan" width="600">
</p>

<p align="center">
  <a href="https://pypi.org/project/querysense/"><img src="https://badge.fury.io/py/querysense.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT"></a>
  <a href="https://github.com/JosephAhn23/Query-Sense/actions/workflows/ci.yml"><img src="https://github.com/JosephAhn23/Query-Sense/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

Free, open-source database optimizer. Paste an EXPLAIN plan, get copy-paste SQL fixes. PostgreSQL, MySQL, MongoDB, SQL Server. Works offline. No account required.

## Install

```bash
pip install querysense
```

## Usage

```bash
# Analyze a slow query
querysense analyze plan.json

# Get copy-paste SQL fixes
querysense fix plan.json > fixes.sql

# Scan a live database
querysense scan --dsn postgresql://localhost/mydb

# Compare before/after
querysense diff before.json after.json

# CI/CD gate
querysense ci gate
```

## Example

```
$ querysense analyze plan.json

  Seq Scan on orders (250,000 rows) → CREATE INDEX idx_orders_status ON orders(status);
  Row estimate 5,000x off on orders → ANALYZE orders;

  2 findings in 1.5ms
```

37+ detection rules. 190 tests passing in <1s.

## License

MIT
