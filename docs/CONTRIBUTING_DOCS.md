# Documentation Guidelines for TechScan

This document defines how we write and maintain documentation for the TechScan web app, aligning with best practices you shared: descriptive comments, clear parameters/returns, examples, regular updates, structured sections, and optional automated tooling.

## Goals
- Enable fast onboarding and reliable knowledge transfer.
- Keep documentation updated alongside code changes.
- Provide layered docs: README (overview) → Full docs → API spec → Code docstrings.

## Structure
- `README.md`: concise overview with links to detailed docs.
- `docs/README_full.md`: comprehensive guide (setup, config, server, DB schema, APIs, UI, scanners, operations, troubleshooting, testing).
- `docs/openapi.yaml`: formal API specification (OpenAPI 3.0.3).
- `docs/CONTRIBUTING_DOCS.md`: this guideline.
- Optional Sphinx: `docs/sphinx/` (autodoc from Python docstrings) — recommended when docstrings are in place.

## Writing Style
- Use clear, consistent language; avoid ambiguous jargon.
- Prefer active voice and short sentences.
- Keep sections scannable with headings and bullets.

## Python Docstring Style (Google Style)
- Module-level docstring describes purpose and key responsibilities.
- Functions/methods include: summary, Args, Returns, Raises, Examples.

Example:
```python
def compute_diff(latest: dict | None, previous: dict | None) -> dict:
    """Compute added/removed/changed technologies between two scan payloads.

    Args:
      latest: Latest scan payload with `technologies` array (optional).
      previous: Previous scan payload with `technologies` array (optional).

    Returns:
      Dict with keys `added`, `removed`, `changed` listing deltas.

    Examples:
      >>> compute_diff({"technologies": [{"name": "jQuery", "version": "3.7.1"}]}, None)
      {'added': [{'name': 'jQuery', 'version': '3.7.1'}], 'removed': [], 'changed': []}
    """
    ...
```

## API Documentation
- Maintain `docs/openapi.yaml`—update when endpoints change.
- Include response shapes and parameter constraints.
- Derive examples from real responses where possible.

## Code Samples
- Provide minimal, runnable examples in docs for common flows:
  - Fetch stats and render cards.
  - Query domain detail and compute diffs.
  - List domains using a technology.
- Prefer `curl`/PowerShell snippets for REST examples.

## Update Cadence
- Every code PR that changes an endpoint, schema, or behavior MUST update:
  - Relevant docstrings
  - `docs/openapi.yaml`
  - `docs/README_full.md` sections (if user-facing change)
  - Link adjustments in `README.md` when needed

## Optional Automation
- Sphinx with autodoc: generate HTML docs from Python docstrings.
- CI job to validate OpenAPI schema (lint) and link-check docs.

## Checklist per Change
- [ ] Docstrings added/updated
- [ ] OpenAPI updated
- [ ] Full README updated
- [ ] Examples added/updated
- [ ] Links verified

## Versioning
- Tag releases and add a short changelog in `CHANGELOG.md`.
- Note API-breaking changes clearly in release notes.
