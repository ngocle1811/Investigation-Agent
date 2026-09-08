# Investigation Agent

Evidence-grounded, AI-assisted SOC incident investigation using deterministic rules and
correlation, security-knowledge RAG, and structured LLM reasoning.

The authoritative implementation plan is [INVESTIGATION_AGENT_PLAN.md](INVESTIGATION_AGENT_PLAN.md).
Existing learning material in `docs/` is preserved as supporting context.

## Current status

Checkpoints 0, 1, and 2 are complete. See [PROGRESS.md](PROGRESS.md) for verified status.
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

## Prepare and index the security knowledge corpus

The curated list in `config/sources.yaml` covers Microsoft Windows Security event pages, the
official Sysmon reference, a small scenario-relevant Sigma subset, and a pinned Enterprise
ATT&CK STIX release. Remote bytes and provenance sidecars are cached under `data/raw/`; normalized
logical documents and deterministic chunks are written under `data/processed/knowledge/`.
Generated data and local embedding models are intentionally gitignored and can be reproduced
from the source config.

Run the full pipeline (download/cache, normalize, source-aware chunk, embed, and Qdrant sync):

```bash
python scripts/ingest_knowledge.py
```

The default embedding provider is the local, CPU-friendly FastEmbed model
`BAAI/bge-small-en-v1.5`; it requires no paid API key. The first run downloads the model to
`data/models/fastembed/`. Provider, model, and batch size can be overridden with the
`EMBEDDING_PROVIDER`, `EMBEDDING_MODEL`, and `EMBEDDING_BATCH_SIZE` environment variables.

To stop after Checkpoint 1 normalization:

```bash
python scripts/ingest_knowledge.py --prepare-only
```

After the source and model caches exist, the full pipeline can be reproduced without fetching
the curated sources again:

```bash
python scripts/ingest_knowledge.py --offline
```

Use `--refresh` to re-fetch every curated source. Unchanged source bytes retain their original
download timestamp and content hash; normalized document/chunk JSONL files are only replaced when
their bytes change. Qdrant uses deterministic point IDs, replaces each current document's points,
and removes documents no longer present in the corpus.

Chunking boundaries are source-aware:

- Microsoft Windows event pages: one stored parent plus retrievable logical-section children.
- Sysmon: one stored parent plus retrievable chunks grouped by Event ID/logical section.
- Sigma: exactly one retrievable chunk per complete rule.
- MITRE ATT&CK: exactly one retrievable chunk per technique or sub-technique, with tactic and
  parent-technique metadata.

Only `contextualized_content` is embedded. The original `content` remains in each Qdrant payload
for evidence display and citation. Search excludes parent-only chunks by default and accepts exact
filters for `document_id`, `source`, `source_type`, `event_id`, `sigma_rule_id`, `technique_id`,
and `tactic`:

```powershell
Invoke-RestMethod "http://localhost:18000/knowledge/search?q=failed%20logon&event_id=4625"
```

With the Docker API running, verify all four top-result acceptance queries:

```bash
python scripts/smoke_test_knowledge.py
```

The verified corpus currently contains 18 documents, 102 stored Qdrant points, and 97 retrievable
chunks. See `config/rag.yaml` and `.env.example` for the checked-in defaults.
