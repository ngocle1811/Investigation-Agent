# Project Progress

## Checkpoint 0 - Project Bootstrap

- [x] Read the complete implementation plan and inspect the existing repository.
- [x] Preserve existing learning and architecture documents.
- [x] Create repository/package structure and initialize Git metadata.
- [x] Add FastAPI, Streamlit, PostgreSQL, and Qdrant bootstrap code.
- [x] Add Docker Compose, environment/config files, and structured JSON logging.
- [x] Add bootstrap unit tests and smoke-test command.
- [x] Install the local environment and pass formatting/tests.
- [x] Pass the Docker Compose smoke test for API, Streamlit, PostgreSQL, and Qdrant.

## Checkpoint 1 - Knowledge Ingestion

- [x] Implement Microsoft Windows documentation loader.
- [x] Implement Microsoft Sysmon documentation loader.
- [x] Implement Sigma YAML loader.
- [x] Implement MITRE ATT&CK STIX loader with an explicit technique allowlist.
- [x] Normalize documents with stable IDs, hashes, source version, and metadata.
- [x] Cache raw sources and provenance sidecars under `data/raw/`.
- [x] Produce 18 normalized documents with `scripts/ingest_knowledge.py --prepare-only`.
- [x] Verify an offline second run is idempotent (18 unchanged; output not rewritten).
- [x] Pass tests and ingestion smoke test.

## Checkpoint 2 - Source-aware Chunking and Qdrant Indexing

- [x] Preserve logical Microsoft section boundaries as parent/child chunks.
- [x] Group Sysmon content by Event ID while preserving a document parent.
- [x] Keep each Sigma rule and MITRE technique/sub-technique as one retrieval unit.
- [x] Add deterministic chunk IDs, parent IDs, hashes, source/version/date fields, and metadata.
- [x] Add deterministic source context while preserving original content separately.
- [x] Add an embedding provider abstraction and local FastEmbed default with discovered dimension.
- [x] Add deterministic Qdrant point IDs, metadata indexes, idempotent upsert, and stale cleanup.
- [x] Add dense retrieval and `/knowledge/search` metadata filters.
- [x] Verify 18 documents -> 102 points (5 parents + 97 retrievable), vector size 384.
- [x] Verify a second offline full run: 18 unchanged, JSONL unchanged, still 102 points.
- [x] Verify top results for Event 4625, Sysmon Event 1, MITRE T1059.001, and Sigma PowerShell.
- [x] Pass 21 tests (including in-memory Qdrant integration tests), Ruff checks, and the
  containerized four-query smoke test.

## Checkpoints 3-11

- [ ] Not started.

## Current blockers

None. Paid model/API credentials are not required for the completed checkpoints.

## Important decisions

- `INVESTIGATION_AGENT_PLAN.md` is the source of truth; `docs/` remains supporting material.
- Code is packaged under `src/investigation_agent/` for reliable imports and distribution.
- Incident evidence and the public security knowledge corpus remain separate data paths.
- Parent chunks supply hierarchy but are excluded from dense retrieval by default.
- Only contextualized text is embedded; original source text remains available for evidence use.
- Embedding dimension is discovered from the configured provider and validated against Qdrant.
- The host API defaults to port `18000`; the container listens on port `8000`.
- Raw/processed knowledge and model caches are reproducible and gitignored.
- ATT&CK data is pinned to Enterprise ATT&CK STIX `19.1`; normalized Sigma documents retain
  modified dates and content hashes from upstream source data.

## Next action

Begin Checkpoint 3 only when explicitly requested: event schema and synthetic dataset generation.
