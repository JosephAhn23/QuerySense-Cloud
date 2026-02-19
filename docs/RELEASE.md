# Release Process

## Quick Release

```bash
# 1. Bump version in pyproject.toml
#    Edit: [project] version = "X.Y.Z"

# 2. Commit the version bump
git add pyproject.toml
git commit -m "Bump version to X.Y.Z"

# 3. Tag the release
git tag vX.Y.Z

# 4. Push commit and tag
git push origin main --tags
```

PyPI publishes automatically when the tag is pushed.

## Version Location

The version is defined in **one place**:

```
pyproject.toml → [project] → version
```

Example:
```toml
[project]
name = "querysense"
version = "0.4.0"  # ← bump this
```

## Checklist

Before releasing:

- [ ] Update `CHANGELOG.md` with changes
- [ ] Bump version in `pyproject.toml`
- [ ] Bump version in `src/querysense/__init__.py` (keep in sync)
- [ ] Run tests: `pytest`
- [ ] Commit changes
- [ ] Tag: `git tag vX.Y.Z`
- [ ] Push: `git push origin main --tags`

## First-Time Setup

Enable PyPI Trusted Publishing:

1. Go to PyPI → your project → **Settings**
2. Click **Add a new pending publisher** (or manage existing)
3. Fill in:
   - Owner: `JosephAhn23`
   - Repository: `Query-Sense`
   - Workflow name: `publish.yml`
   - Environment: *(leave blank)*
4. Save

Now tags trigger automatic publishing with no tokens needed.
