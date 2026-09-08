# Investigation Agent

Evidence-grounded, AI-assisted SOC incident investigation using deterministic rules and
correlation, security-knowledge RAG, and structured LLM reasoning.

The authoritative implementation plan is [INVESTIGATION_AGENT_PLAN.md](INVESTIGATION_AGENT_PLAN.md).
Existing learning material in `docs/` is preserved as supporting context.

## Current status

Checkpoints 0 and 1 are complete. See [PROGRESS.md](PROGRESS.md) for verified status.
No evaluation metrics are reported until the reproducible evaluation scripts have run.

## Architecture boundary

Incident evidence is normalized and correlated deterministically. Public Microsoft, Sysmon,
Sigma, and MITRE ATT&CK material is ingested into a separate knowledge corpus. Only a bounded
case, rule matches, and cited knowledge are supplied to the investigation model.

The Python layout uses one installable package at `src/investigation_agent/`. Its subpackages
match the functional boundaries in the PLAN while avoiding ambiguous top-level imports.

## Local setup

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
pytest
uvicorn investigation_agent.api.main:app --reload
```

Run the UI separately:

```bash
streamlit run ui/app.py
```

## Docker

```bash
docker compose up --build
python scripts/smoke_test.py
```

Services:

- API and OpenAPI: `http://localhost:18000/docs`
- Streamlit: `http://localhost:8501`
- PostgreSQL: `localhost:5432`
- Qdrant: `http://localhost:6333/dashboard`

Use `.env` to override local defaults. Do not commit credentials.

## Prepare the security knowledge corpus

The curated list in `config/sources.yaml` covers Microsoft Windows Security event pages, the
official Sysmon reference, a small scenario-relevant Sigma subset, and a pinned Enterprise
ATT&CK STIX release. Remote bytes and provenance sidecars are cached under `data/raw/`; normalized
logical documents are written under `data/processed/knowledge/`. Generated data is intentionally
gitignored and can be reproduced from the source config.

```bash
python scripts/ingest_knowledge.py --prepare-only
```

After the first run, preparation can be reproduced without network access:

```bash
python scripts/ingest_knowledge.py --prepare-only --offline
```

Use `--refresh` to re-fetch every curated source. Unchanged source bytes retain their original
download timestamp and content hash; normalized JSONL is only replaced when its bytes change.

Checkpoint 2 will add source-specific chunks, embeddings, and Qdrant indexing. Calling the script
without `--prepare-only` currently exits explicitly instead of pretending indexing occurred.
