# Project Progress

## Checkpoint 0 — Project Bootstrap

- [x] Read the complete implementation plan and inspect the existing repository.
- [x] Preserve existing learning and architecture documents.
- [x] Create repository/package structure and initialize Git metadata.
- [x] Add FastAPI, Streamlit, PostgreSQL, and Qdrant bootstrap code.
- [x] Add Docker Compose, environment/config files, and structured JSON logging.
- [x] Add bootstrap unit tests and smoke-test command.
- [x] Install the local environment and pass formatting/tests.
- [x] Pass the Docker Compose smoke test for API, Streamlit, PostgreSQL, and Qdrant.

## Checkpoint 1 — Knowledge Ingestion

- [x] Implement Microsoft Windows documentation loader.
- [x] Implement Microsoft Sysmon documentation loader.
- [x] Implement Sigma YAML loader.
- [x] Implement MITRE ATT&CK STIX loader with an explicit technique allowlist.
- [x] Normalize documents with stable IDs, hashes, source version, and metadata.
- [x] Cache raw sources and provenance sidecars under `data/raw/`.
- [x] Produce 18 normalized documents with `scripts/ingest_knowledge.py --prepare-only`.
- [x] Verify an offline second run is idempotent (18 unchanged; output not rewritten).
- [x] Pass tests and ingestion smoke test.

## Checkpoint 2 — Chunk + Index

- [ ] Not started.

## Checkpoints 3–11

- [ ] Not started.

## Current blockers

None. Paid model/API credentials are not required for the completed checkpoints.

## Important decisions

- `INVESTIGATION_AGENT_PLAN.md` is the source of truth; `docs/` remains supporting material.
- Code is packaged under `src/investigation_agent/` for reliable imports and distribution.
- Health checks expose dependency state without logging connection strings or credentials.
- External source URLs and model/retrieval parameters remain configurable.
- The host API defaults to port `18000` because port `8000` is already used by an unrelated
  local project; the container still listens on standard port `8000`.
- Raw and processed knowledge artifacts are reproducible and gitignored; curated URLs, loader
  logic, parser fixtures, and tests are version controlled.
- ATT&CK raw data is pinned to Enterprise ATT&CK STIX `19.1`; Sigma rule URLs use the upstream
  branch while each normalized document records its own rule modified date and content hash.

## Next action

Begin Checkpoint 2 with source-aware hierarchical chunking, contextual metadata prepend,
configurable local embeddings, and Qdrant indexing. Add `/knowledge/search` only after chunk and
index tests pass.
