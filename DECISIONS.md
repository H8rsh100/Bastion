# Bastion — Design Decisions

Documenting choices made during implementation where the planning docs left room for interpretation.

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Used `all-MiniLM-L6-v2` instead of `bge-small` for embeddings | Lighter weight (~80MB), well-tested, runs fully offline, 384-dim vectors are sufficient for CVE text similarity |
| 2 | PowerShell-compatible build commands | Development machine runs Windows with PowerShell as default shell |
| 3 | Added `backend/config.py` for centralized configuration | Avoids hardcoded values scattered across modules; all tunables in one place with env-var overrides |
