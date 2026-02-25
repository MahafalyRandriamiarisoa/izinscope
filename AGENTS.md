# AGENTS.md

## Cursor Cloud specific instructions

**izinscope** is a Python CLI tool for checking whether IPs/domains are within a defined security scope. It is a single-module package (`izinscope/__init__.py`) with no web server, database, or Docker dependency.

### Stack
- Python 3.12, Poetry (package manager), dnspython (runtime), pytest + black (dev)

### Common commands
| Task | Command |
|---|---|
| Install deps | `poetry install` |
| Run tests | `poetry run pytest -v` |
| Format check | `poetry run black --check .` |
| CLI help | `poetry run izinscope --help` |
| Single IP check | `poetry run izinscope -s <scope_file> -i <ip>` |

### Notes
- Poetry must be on `PATH`. The pip-installed binary lands in `~/.local/bin`; make sure it is exported: `export PATH="$HOME/.local/bin:$PATH"`.
- `black --check` currently reports formatting issues on the existing source files; this is pre-existing and not caused by agent changes.
- All tests are fully mocked (no network required). They run in < 1 s.
- There is no build step; the project is installed in editable mode via `poetry install`.
