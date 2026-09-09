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

## Checkpoint 5 - Dense Retrieval Baseline

- [x] Add a replaceable retriever protocol and normalized, flattened dense retrieval results with
  ranks, scores, source metadata, original content, and contextualized content.
- [x] Preserve exact metadata filters for source, source type, Event ID, MITRE technique ID, and
  Sigma rule ID; add conservative identifier-hint parsing with explicit caller filters winning.
- [x] Add separate parent lookup and stable `K1`-style citation mapping without returning parent
  chunks in ordinary search results.
- [x] Curate and lock 50 golden queries before the first evaluation: 15 Windows Event, 10 Sysmon,
  15 MITRE ATT&CK, and 10 Sigma queries across five query types.
- [x] Validate unique query IDs, all expected chunks/documents/sources, non-parent targets, and
  explicit Event/MITRE/Sigma identifier references before evaluation.
- [x] Implement binary Recall@1/3/5 and MRR, source and query-type slices, per-query results,
  categorized failures, and mean/P50/P95 steady-state latency.
- [x] Add readable search and evaluation CLIs plus deterministic JSON and CSV report writers.
- [x] Evaluate all 50 queries against 97 retrievable chunks using dense FastEmbed retrieval only.
- [x] Achieve Recall@1 0.6800, Recall@3 0.9000, Recall@5 0.9400, and MRR 0.7867, exceeding the
  planned Recall@5 acceptance target of 0.75.
- [x] Record warm-start latency of 41.778 ms mean, 39.320 ms P50, and 68.139 ms P95.
- [x] Preserve all three top-5 misses as baseline evidence: two correct-document/wrong-section
  Windows 4625 misses and one semantic Sysmon Event 22 section miss.
- [x] Pass 59 total tests (7 new retrieval-baseline tests), `ruff check .`, and formatting checks;
  verify search, parent lookup, filters, and citations against the live Qdrant corpus.

### Baseline breakdown by source

| Source type | Queries | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| MITRE ATT&CK | 15 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Sigma | 10 | 0.9000 | 1.0000 | 1.0000 | 0.9333 |
| Sysmon | 10 | 0.7000 | 0.9000 | 0.9000 | 0.7833 |
| Windows Event | 15 | 0.2000 | 0.7333 | 0.8667 | 0.4778 |

### Baseline breakdown by query type

| Query type | Queries | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Description | 9 | 0.6667 | 1.0000 | 1.0000 | 0.8333 |
| Exact identifier | 15 | 0.7333 | 0.8667 | 1.0000 | 0.8222 |
| Natural language | 9 | 0.6667 | 0.8889 | 0.8889 | 0.7593 |
| Semantic | 9 | 0.7778 | 1.0000 | 1.0000 | 0.8704 |
| Vocabulary mismatch | 8 | 0.5000 | 0.7500 | 0.7500 | 0.6042 |

## Checkpoints 6-11

- [ ] Not started.

## Grounded Investigation Vertical Slice - Priority After Checkpoint 5

- [x] Reuse the Checkpoint 4 `InvestigationCase`, `RuleMatch`, and `CandidateBehavior` models rather
  than creating a parallel detection pipeline.
- [x] Assemble only the rule matches and event IDs referenced by the selected candidate behavior;
  exclude synthetic ground truth, unrelated noise, labels, and unrestricted raw event payloads.
- [x] Generate deterministic retrieval queries from behavior type, configured rule descriptions,
  observed telemetry types, security concepts, and rule-owned MITRE mappings.
- [x] Reuse dense Checkpoint 5 retrieval with configurable primary top-k and small exact
  metadata-aware technique lookups; add no BM25, RRF, or reranking.
- [x] Preserve retrieval rank, score, chunk/document IDs, source, title, section, URL, text, and
  metadata in the bounded investigation context.
- [x] Add a strict provider-independent `InvestigationReport` with timeline, fact/inference
  findings, suspicious reasons, MITRE mappings, recommended investigation actions, and limitations.
- [x] Add a dedicated system prompt with visibly separated CandidateBehavior, incident-evidence,
  and security-knowledge blocks.
- [x] Add a structured LLM protocol, deterministic offline mock, optional OpenAI Responses API,
  and official Google Gen AI SDK adapters using JSON-schema output.
- [x] Fail closed after generation on unknown event/chunk IDs, mismatched case ID, altered timeline
  timestamps, or MITRE mappings unsupported by cited retrieved knowledge.
- [x] Add three manually selected fixtures from the existing dataset: `INC-S02-V01`
  authentication anomaly, `INC-S04-V01` Office-to-PowerShell, and `INC-S08-V01`
  process/DNS/external-network activity.
- [x] Run all three cases end-to-end against the live 97-chunk Qdrant corpus; all 3/3 passed schema,
  evidence, knowledge, key-event, timeline, action, and expected-MITRE checks.
- [x] Add a single-case/all-demo JSON CLI and a transparent deterministic evaluator without an
  LLM-as-judge.
- [x] Add stable investigation tests with fake/mock providers; the full suite has 69
  passing tests; the normal test suite makes no paid or network LLM calls.
- [x] Run `INC-S02-V01`, `INC-S04-V01`, and `INC-S08-V01` with the configured live
  `gemini-3.7-flash` model and Qdrant-backed retrieval; all 3/3 passed schema, evidence, knowledge,
  key-event, timeline, timestamp, action, expected-MITRE, and overall checks.
- [x] Record zero hallucinated event IDs and save the live reports plus deterministic evaluation
  at `artifacts/eval/investigation_demo_gemini.json` without provider secrets or raw API metadata.
- [x] Demonstrate fail-closed grounding with deterministic rejection of fabricated event
  `INC-S04-V01-E9999`; this negative test does not call Gemini.

## Current blockers

None for the recorded prototype evaluation. Offline tests require no paid model/API credentials;
live reruns depend on Gemini quota and model availability.

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
- Checkpoint 5 is deliberately dense-only; BM25, RRF, reranking, and LLM generation are excluded
  so later checkpoints have an honest comparison baseline.
- Golden queries and expected chunks were manually curated from source content and locked before
  the first retrieval run; failed queries were not relabeled or tuned away afterward.
- Retrieval metrics are chunk-level and binary per query. MRR uses the first relevant chunk, and
  latency is measured after one model warm-up embedding that is not part of the golden set.
- Parent chunks remain excluded from normal retrieval and are fetched through an explicit parent
  lookup only when more document context is required.
- The investigation model never receives the entire case log. Its incident context is exactly the
  evidence graph already linked by a deterministic candidate behavior.
- Rule-owned MITRE IDs may trigger a focused metadata-aware dense lookup, but a report mapping is
  accepted only when its cited retrieved chunk supports the same technique ID.
- Structured-output conformance is necessary but not sufficient: every provider passes through the
  same deterministic fail-closed reference, case, timestamp, and MITRE support validator.
- The offline mock demonstrates orchestration and grounding deterministically. The three-case live
  Gemini evaluation verifies this bounded demo path, but it is not a broad real-world model-quality
  or detection-accuracy benchmark.

## Next action

The grounded investigation vertical slice is complete. Hybrid BM25+dense retrieval, Reciprocal
Rank Fusion, reranking, UI, anomaly-detection ML, and production integrations remain explicitly
deferred until requested.
