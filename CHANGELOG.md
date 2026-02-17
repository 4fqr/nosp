# Changelog

## Unreleased (main)

- Added: cross-platform improvements and fallbacks; many public APIs include `*_safe` Result-returning variants.
- Added: command‑line interface (`nosp`) with `init-db`, `scan`, `analyze`, `watch` commands.
- Added: default local AI model set to `mistral-small` (recommended for endpoint use).
- Added: structured error reporting (`nosp_error.log`) and centralized error helpers in `python/nosp/errors.py`.
- Added: privileged integration test scaffolding (skipped by default; see docs) and unit tests for CLI.
- Added: packaging entry point (`nosp`) in `pyproject.toml` for console installs.
- Removed: underscore-marked documentation file to reduce clutter.
- Documentation: README, USAGE and Guide updated with model recommendations and privileged-test instructions.
