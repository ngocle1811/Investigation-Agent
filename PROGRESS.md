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

## Checkpoint 3 - Security Event Schema and Synthetic Dataset

- [x] Add a strict normalized `SecurityEvent` schema for Windows Security, Sysmon, network,
  and DNS telemetry with nullable source-specific fields.
- [x] Add 8 suspicious scenarios (`S01`-`S08`) and 4 benign controls (`B01`-`B04`) with
  static semantic-role ground truth in YAML.
- [x] Validate every template MITRE mapping against the current configured technique subset.
- [x] Generate three deterministic variants per template with stable case/event IDs and
  timezone-aware causal timelines.
- [x] Interleave 20-80 benign noise events with 3-10 relevant events per case.
- [x] Model duplicate, missing, out-of-order, multiple-user, and simultaneous-process input
  edge cases while preserving a canonical timeline.
- [x] Restrict generated domains and IP addresses to example domains, private networks, and
  RFC documentation ranges; use only inert synthetic command markers.
- [x] Generate 36 cases (24 suspicious, 12 benign), 1,943 total events, and a deterministic
  summary using seed 42.
- [x] Verify byte-for-byte idempotency on a second generation run.
- [x] Pass 32 total tests, including 11 Checkpoint 3 tests, and `ruff check .`.

## Checkpoint 4 - Deterministic Detection, Correlation, and Case Building

- [x] Add strict `DetectionRule`, `RuleMatch`, `CandidateBehavior`, and `InvestigationCase`
  schemas with deterministic IDs and validated event references.
- [x] Configure severity weights, escalation thresholds, rule parameters, process sets, trusted
  contexts, windows, and network boundaries in `config/correlation_rules.yaml`.
- [x] Implement R001-R010: authentication thresholds/sequences, PowerShell, parent-child,
  process/network, external-login/process, scheduled-task, DNS/network, and exact safe markers.
- [x] Add reusable sorting, grouping, time-window, followed-by, parent-child, same-process, and
  stable-fingerprint deduplication primitives.
- [x] Canonicalize out-of-order input while retaining event IDs and prevent synthetic duplicates
  from affecting thresholds or generating duplicate rule matches.
- [x] Verify missing chain events do not trigger complete correlations and that users/processes
  sharing a host or timestamp remain isolated by their correlation keys.
- [x] Aggregate overlapping matches into deterministic candidate behaviors without duplicating
  supporting event evidence.
- [x] Build one bounded investigation case per synthetic record; runtime building has no ground
  truth dependency and evaluation truth is optional.
- [x] Add deterministic severity scoring where an isolated R003 PowerShell match is score 2/low
  and cannot meet the score-7 escalation threshold.
- [x] Add `scripts/run_detection.py` and export 36 cases plus an expected-versus-actual report.
- [x] Produce 57 rule matches and 27 candidate behaviors; detect 24/24 suspicious cases, miss
  0/24, escalate 0/12 benign cases, and hit 57/57 expected rules with no unexpected hits.
- [x] Verify a second detection run is byte-for-byte idempotent.
- [x] Pass 52 total tests, including 20 Checkpoint 4 tests, and `ruff check .`.

### Checkpoint 3 corrections discovered during Checkpoint 4

- Noise process/login identities previously reused the story user and could manufacture R002 or
  R007 correlation. Noise now uses isolated background identities; seed, case/event counts, and
  stable ID format are unchanged, and the dataset was regenerated.
- Rule expectations were aligned with the final non-overlapping rule semantics: R006/R009/R010
  were added where their full chains or exact markers exist, scheduled-task detection moved from
  the old R007 placeholder to R008, and B02 now explicitly expects its permitted low-level R003
  match. These are semantic corrections, not metric-driven label changes.

## Checkpoints 5-11

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
- Synthetic template truth is configuration-owned and does not depend on an LLM or future
  detection implementation.
- Synthetic cases preserve canonical event order; simulated ingest order and missing-event IDs
  are separate metadata so edge-case tests remain reproducible.
- Synthetic external indicators use only reserved example domains and documentation IP ranges.
- Detection and correlation are deterministic and preserve original event references; no LLM
  decides which event, rule, or sequence matches.
- Rule thresholds and severity weights live in configuration instead of being scattered through
  Python code.
- Runtime case building is ground-truth independent. Expected-versus-actual comparison is a
  separate evaluation path, and exported cases omit ground truth by default.
- Low-level signals are not synonymous with escalation: B02 may match R003 while remaining a
  non-escalated benign case.
- ATT&CK data is pinned to Enterprise ATT&CK STIX `19.1`; normalized Sigma documents retain
  modified dates and content hashes from upstream source data.

## Next action

Checkpoint 4 is complete. Begin Checkpoint 5 only when explicitly requested: RAG query
construction and retrieval baseline work.
