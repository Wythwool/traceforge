# Release Checklist

Use this checklist before tagging a release.

1. Update `pyproject.toml` and `src/traceforge/__init__.py` to the same version.
2. Run the local checks:

   ```bash
   python -m pip install ".[test,lint,disasm]"
   python -m ruff check .
   python -m pytest -q
   python -m build
   ```

3. Install the built wheel in a clean environment and run:

   ```bash
   traceforge --version
   traceforge ruleset validate
   ```

4. Create a short changelog entry with the user-facing changes.
5. Tag the release from `main` after CI passes.
