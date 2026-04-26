# Copilot Instructions for aws-credential-manager

Use this file as the primary source of truth for working in this repository. Only search the codebase when these instructions are incomplete or proven incorrect.

## Repository Summary

- Purpose: manage multiple sets of AWS credentials (especially ephemeral SAML-derived credentials) in a local SQLite database, then retrieve/resolve credentials by ARN, account+role, or access key.
- Project type: Python library + CLI tools.
- Main runtime: Python 3.10+ (CI runs Python 3.10; local validation here used Python 3.11).
- Primary libraries: `boto3`, `SQLAlchemy`, `chardet`.
- Test stack: `pytest`, `moto`.
- Package entry points:
  - `multicred-import` -> `multicred/importer.py`
  - `multicred-get` -> `multicred/credhelper.py`
  - `multicred-manage` -> `multicred/manager.py`

## High-Level Layout

- Root files:
  - `README.md`: rationale and module overview.
  - `setup.py`: package metadata, dependencies, console scripts.
  - `requirements.txt`: runtime dependencies.
  - `requirements-dev.txt`: test/dev dependencies (does not include `pyflakes`).
  - `conftest.py`: shared pytest fixtures using `moto` and in-memory SQLite.
- Core package (`multicred/`):
  - `credentials.py`: credential/identity objects and parsing from shared credentials file.
  - `dbschema.py`: SQLAlchemy models.
  - `dbstorage.py`: storage implementation for identities/credentials/relationships.
  - `resolver.py`: resolver that can follow parent identity links and call `sts:AssumeRole`.
  - `importer.py`, `credhelper.py`, `manager.py`: CLI implementations.
  - `interfaces.py`: storage/resolver protocols.
- Tests (`tests/`):
  - `test_credentials.py`, `test_identity.py`, `test_dbstorage.py`, `test_resolver.py`, `test_utils.py`.
- CI/automation:
  - `.github/workflows/python-app.yml`: install deps, run `pyflakes .`, run `pytest`.
  - `.github/workflows/python-publish.yml`: `python -m build` and upload release assets.
  - `.github/dependabot.yml`: weekly pip updates; grouped boto updates.
  - `.github/CODEOWNERS`: `@cg2v` owns all files.

## Architecture Notes for Fast Changes

- Storage and resolution are intentionally separated:
  - `DBStorage` persists and queries identities/credentials.
  - `StorageBasedResolver` resolves creds directly or by traversing linked parent identities and assuming roles.
- Identity matching uses parsed ARN semantics (`multicred/utils.py` and `parse_principal`) rather than string-equality only.
- CLI default DB location is `~/.aws/multicred.db` (`sqlite:///...`) in all three CLI modules.
- Most behavior regressions are caught by tests in `tests/test_dbstorage.py` and `tests/test_resolver.py`.

## Bootstrap, Build, Lint, Test, Run (Validated)

Always run commands from repository root.

### 1) Environment bootstrap (always first)

Windows PowerShell (validated):

```powershell
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python -m pip install -e .
```

Why this order matters:
- `pytest` fails before dependency install (`CommandNotFoundException` when pytest is missing).
- Console scripts (`multicred-import`, `multicred-get`, `multicred-manage`) are not available until `pip install -e .`.

### 2) Lint

CI runs:

```bash
pyflakes .
```

Local recommendation (always use this scoped variant if a local `.venv/` exists):

```powershell
.\.venv\Scripts\python -m pip install pyflakes
.\.venv\Scripts\python -m pyflakes multicred tests conftest.py setup.py
```

Important:
- `pyflakes` is installed explicitly in CI and is not pinned in `requirements-dev.txt`.
- Running `pyflakes .` locally can scan `.venv/` and emit large third-party warnings; scope lint to repo sources as above.

### 3) Tests

```powershell
.\.venv\Scripts\python -m pytest -q
```

Validated result in this environment: `45 passed`.
Typical runtime observed: about 50 seconds locally.

### 4) Build/package

```powershell
.\.venv\Scripts\python -m pip install build
.\.venv\Scripts\python -m build
```

Expected output artifacts:
- `dist/*.tar.gz` (sdist)
- `dist/*.whl` (wheel)

### 5) Run CLI tools

After editable install:

```powershell
.\.venv\Scripts\multicred-import --help
.\.venv\Scripts\multicred-get --help
.\.venv\Scripts\multicred-manage --help
```

If these fail with command-not-found, rerun `pip install -e .`.

## Clean/Reset Steps for Reproducible Validation

Use before final verification:

```powershell
Remove-Item -Recurse -Force .pytest_cache, htmlcov, build, dist -ErrorAction SilentlyContinue
Remove-Item -Force .coverage -ErrorAction SilentlyContinue
```

Then rerun in this strict order:
1. Bootstrap (`pip install ...`, then `pip install -e .`)
2. Lint (scoped pyflakes command)
3. Tests (`pytest -q`)
4. Build (`python -m build`)

## CI and Pre-Checkin Expectations

- Main validation pipeline: `.github/workflows/python-app.yml`.
- Branches validated by workflow triggers: `main`, `experiments`.
- Checks that matter before proposing changes:
  - Lint equivalent to CI (`pyflakes`)
  - Full pytest run
  - Packaging build (`python -m build`) when touching packaging/runtime imports

## Non-Obvious Dependencies and Behaviors

- `moto` is required for tests that simulate AWS APIs.
- `pyflakes` is required for lint but not declared in `requirements-dev.txt`.
- Resolver behavior may perform STS assume-role calls through linked identities; keep `dbstorage.py` and `resolver.py` changes in sync.
- Tests rely heavily on fixtures in `conftest.py`; update fixtures if identity/credential object contracts change.

## Agent Working Agreement

- Trust this document first.
- Do not start with broad code search.
- Only search when:
  - required information is missing here, or
  - commands/paths in this file are shown to be incorrect in the current run.
- Prefer minimal, targeted edits and validate with lint + tests before finishing.
