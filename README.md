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
  <img src="query.png" alt="QuerySense dashboard preview showing sequential scan fixed to index scan" width="920">
</p>

<p align="center">
  <sub>
    Dark-mode friendly README: neon accents, visual flow, low jargon.
  </sub>
</p>

---

## Why people like it

- ⚡ **Fast wins:** see bottlenecks and likely fixes right away
- 🧠 **Human-friendly:** plain-English output (`--simple`, `--eli5`) for non-DBA users
- 🛠 **Actionable:** generate SQL fixes and migration files from findings
- 🌐 **Multi-engine:** PostgreSQL, MySQL, SQL Server, MongoDB support in one CLI
- 🔒 **Private-first:** works offline, no account required

---

## Glow Workflow

> 🌑 **Before:** "Why is this query slow?"  
> 🌈 **After:** "Here is the exact fix and expected impact."

### 1) Analyze a plan

```bash
querysense analyze plan.json
```

### 2) Generate fixes

```bash
querysense fix plan.json > fixes.sql
```

### 3) Compare before vs after

```bash
querysense diff before.json after.json
```

---

## Quick Start (Copy/Paste)

```bash
pip install querysense
querysense analyze plan.json --simple
querysense fix plan.json > fixes.sql
```

---

## Visual Walkthrough (for WOW factor)

> Add 3-4 GIFs/screenshots in `assets/` and keep captions short.

```text
assets/
  01-before-plan.png
  02-analyze-output.gif
  03-fix-generated.png
  04-after-diff.gif
```

### Step 1 — Before: slow plan
![Before plan placeholder](assets/01-before-plan.png)
**🔴 Before:** sequential scan, high cost, long runtime

### Step 2 — Analyze: instant diagnosis
![Analyze output placeholder](assets/02-analyze-output.gif)
**🟣 Analyze:** top findings + severity + likely speedup

### Step 3 — Fix: copy-paste SQL
![Fix output placeholder](assets/03-fix-generated.png)
**🟢 Fix:** create index, update stats, or rewrite query

### Step 4 — After: measurable win
![After diff placeholder](assets/04-after-diff.gif)
**✨ After:** cost drops and execution time improves

---

## Example Output

```text
$ querysense analyze plan.json

[WARNING] Seq Scan on orders (250,000 rows)  ~4.8x faster with index
  Fix:
  CREATE INDEX idx_orders_status ON orders(status);

[WARNING] Row estimate 5,000x off on orders
  Fix:
  ANALYZE orders;

Analyzed 2 findings in 1.5ms
```

---

## Feature Highlights

- 🔍 **Plan Analysis:** detect costly scans, bad estimates, spills, and join issues
- 🧪 **Safe SQL Rewrites:** `querysense rewrite --sql ...` with optional sandbox checks
- 📦 **Migration Outputs:** Flyway, Liquibase, Alembic, Django, dbmate formats
- 📉 **I/O Visibility:** buffer-focused analysis and before/after comparisons
- 🧰 **CI Integration:** fail builds on performance regressions with `querysense ci`

---

## Credibility Snapshot

- ✅ **Version:** `2.0.0`
- ✅ **Tests:** 190+ tests
- ✅ **Rules:** 37+ detection rules
- ✅ **Python:** 3.11+

---

## Pro Tips for a Dark-Mode “Glow” README

- Use badges with deep backgrounds (`1f2937`, `0f172a`) plus neon accents
- Keep paragraphs short; rely on visuals, whitespace, and bold labels
- Prefer "before/after" captions over technical internals
- Add one short GIF at top and 3 step GIFs below for instant trust

---

## Install

```bash
pip install querysense
```

## License

MIT
