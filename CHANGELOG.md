# Changelog

## 0.1.2a0 — v0.1.2-alpha

- `__version__` is now read from installed distribution metadata instead of a hard-coded
  literal, which had drifted from `pyproject.toml` in v0.1.1-alpha.
- No other change. Use this tag rather than v0.1.1-alpha.

## 0.1.1a0 — v0.1.1-alpha

- Packaging metadata: PEP 639 `license`/`license-files`, project URLs, explicit `package-dir`, schema data files.
- README documents install, CLI verification with expected output, the public API, and the evidence boundary.
- Continuous integration on Python 3.11, 3.12, and 3.13.
- Source formatting and unused-import removal. No change to `SCHEMA_VERSION`, digests, or validation behavior.

## 0.1.0a0 — v0.1.0-alpha

- Initial public extraction: content-bound run manifest, fail-closed validation, CLI.
