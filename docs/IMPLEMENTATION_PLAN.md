# Proposed Implementation Plan

This plan aligns security learning with future implementation. It does not authorize or include application code.

## Guardrails for every phase

- Preserve raw evidence and stable identifiers.
- Keep detection, correlation, incident membership, and ATT&CK mapping deterministic.
- Treat Event, Alert, and Incident as different models.
- Treat Evidence, Finding, Hypothesis, and Confirmed Fact as different concepts.
- Mark all current components **Proposed**.
- Place graph correlation, ML detection, multi-agent SOC, and remediation under **Future Extension**.

## Phase 0 — SOC and security-event concepts

### Security knowledge prerequisite

- None beyond general software development.

### Learn first

- SOC and analyst responsibilities.
- SIEM vs EDR roles.
- Event vs Alert vs Incident.

### Proposed implementation task

- Write a one-page domain contract for `RawEvent`, `NormalizedEvent`, `Detection`, and `Incident`.
- Define which statements are evidence, findings, hypotheses, and confirmed facts.

### Acceptance criteria

- The four models are distinguishable without referring to implementation details.
- No event is automatically described as an alert or incident.
- The architecture review confirms the deterministic/AI boundary.

## Phase 1 — Security Events

### Security knowledge prerequisite

- Basic authentication, process, and network event interpretation.
- Common fields: timestamp, user, host, source/destination IP, process, parent process, command line, and domain.

### Learn first

- Read one event from each of the three MVP log families.
- Explain which fields are facts and which interpretations require context.

### Proposed implementation task

- Create a `security_events` module with a `RawEvent` model.
- Add JSON/JSONL fixtures for failed login, successful login, process start, DNS query, and network connection.
- Add golden, benign, malformed, and insufficient-evidence fixture sets.

### Acceptance criteria

- Fixtures are deterministic, version-controlled, and contain stable IDs/timestamps.
- Every fixture declares its source type.
- Malformed fixtures are separated from valid fixtures.
- No real SIEM/EDR dependency is required.

## Phase 2 — Normalizer

### Security knowledge prerequisite

- Security field semantics.
- Parent-child processes.
- Source/destination network direction.
- Timestamp normalization and ordering.

### Learn first

- Explain why matching syntax is not enough when field semantics differ.
- Explain the security meaning of a process tree and event timeline.

### Proposed implementation task

- Define a `NormalizedEvent` schema.
- Create adapters for the authentication-like, Sysmon-like, and Zeek-like fixtures.
- Preserve raw-source references and reject invalid required fields.

### Acceptance criteria

- `username`, `user_name`, and `account` normalize to `user` without losing source provenance.
- All timestamps use one documented representation and sort correctly.
- Process and network fields retain their direction/parentage semantics.
- Reprocessing the same fixture produces the same normalized output.

## Phase 3 — Detection Rules

### Security knowledge prerequisite

- Detection vs correlation.
- Rule thresholds.
- IOC vs behavior/TTP.
- False positives and false negatives.
- Basic brute-force and contextual PowerShell behavior.

### Learn first

- Explain why PowerShell alone is not malicious.
- Define a golden case and a benign control for each rule.

### Proposed implementation task

- Add a brute-force threshold rule.
- Add a success-after-failures rule.
- Add a contextual suspicious-PowerShell rule.
- Add a fixture-only suspicious IP/domain rule.
- Emit a structured `Detection` containing rule ID, evidence IDs, severity, and rationale.

### Acceptance criteria

- The golden brute-force scenario fires.
- The benign login scenario does not fire.
- Benign administrative PowerShell does not fire solely because it is PowerShell.
- Every detection is reproducible and references source evidence.
- No LLM call participates in the decision.

## Phase 4 — Correlation Engine

### Security knowledge prerequisite

- Temporal reasoning.
- Entity and process relationships.
- Shared IOC reasoning.
- Evidence linkage and Alert vs Incident.

### Learn first

- Justify additive weights such as same user `+2`, same host `+2`, same IP `+2`, within ten minutes `+1`, same process `+2`, and shared IOC `+3`.
- Explain why one alert may remain independent.

### Proposed implementation task

- Retrieve candidate events/incidents within a documented time window.
- Calculate a transparent correlation score and per-feature explanation.
- Return a correlated group plus create/update recommendation.

### Acceptance criteria

- Same inputs always produce the same score and explanation.
- Golden related activity groups into one case.
- Unrelated or distant benign activity remains separate.
- Every link names the exact evidence and reason.
- Thresholds are configuration, not LLM output.

## Phase 5 — Incident Model and Lifecycle

### Security knowledge prerequisite

- Candidate/Open/Investigating/Triaged/Resolved/Closed meanings.
- Basic triage.
- Severity vs confidence.
- Evidence vs finding vs hypothesis.

### Learn first

- Explain valid state transitions.
- Build an ordered timeline from evidence without altering raw events.

### Proposed implementation task

- Define the `Incident` model, evidence references, entities, severity, confidence, status, and timeline.
- Implement explicit lifecycle transitions including Needs More Evidence and False Positive.
- Implement deterministic create/update behavior from correlation results.

### Acceptance criteria

- Invalid lifecycle transitions are rejected.
- Evidence IDs remain traceable to stored events.
- Severity and confidence are stored separately.
- Needs More Evidence can return to Investigating only after new evidence is attached.
- A False Positive conclusion does not delete raw evidence.

## Phase 6 — MITRE ATT&CK Mapper

### Security knowledge prerequisite

- Tactic, technique, sub-technique, and TTP.
- Evidence-to-technique mapping.

### Learn first

- Explain T1110 Brute Force and T1059.001 PowerShell.
- Identify the evidence needed before either mapping is allowed.

### Proposed implementation task

- Create a small deterministic mapping table from detection/behavior IDs to ATT&CK IDs.
- Store technique ID, mapping rule/version, and supporting evidence IDs.
- Reject unsupported technique IDs.

### Acceptance criteria

- Repeated password guessing maps to T1110 only when its detection evidence exists.
- PowerShell maps to T1059.001 only when the contextual rule fires.
- Each mapping has evidence and mapping-version traceability.
- No raw log is sent to an LLM to guess a technique.

## Phase 7 — Security RAG

### Security knowledge prerequisite

- Read basic ATT&CK technique content.
- Identify trustworthy sources.
- Understand citation traceability.

### Learn first

- Verify that a passage supports a proposed investigation claim.
- Reuse existing chunking, embedding, metadata, retrieval, reranking, and grounding knowledge.

### Proposed implementation task

- Ingest a small approved ATT&CK/security corpus.
- Store `technique_id`, `source`, `version`, `url/reference`, and `document_type` metadata.
- Retrieve by technique IDs, entities, and keywords with citations.

### Acceptance criteria

- Known technique queries retrieve the expected approved chunks.
- Every chunk has source and version metadata.
- Citations resolve to the supporting chunk/reference.
- Retrieval failure is explicit and never fabricates knowledge.
- RAG output cannot create a Detection or correlation link.

## Phase 8 — LLM Investigation Copilot

### Security knowledge prerequisite

- SOC investigation questions.
- Incident timelines.
- IOC vs TTP usage.
- Evidence, finding, hypothesis, and confirmed-fact separation.

### Learn first

- Ask what happened, when, which user/host, which evidence, possible explanation, and next evidence to inspect.
- Use “Possible hypothesis” and “Insufficient evidence” correctly.

### Proposed implementation task

- Define a structured report schema.
- Build a prompt from the incident, ordered evidence, deterministic ATT&CK mappings, and cited chunks.
- Add deterministic validation, retry/fallback, and optional human review.
- Store only validated reports.

### Acceptance criteria

- The report includes summary, severity explanation, timeline, key evidence, techniques, hypotheses, next steps, confidence, and citations.
- Every factual event/IOC/technique reference exists in supplied inputs.
- Unsupported root cause is rejected or rewritten as an explicit hypothesis.
- Missing evidence produces an explicit insufficiency statement.
- The LLM never becomes the primary detection or correlation engine.

## Phase 9 — Evaluation

### Security knowledge prerequisite

- False-positive/false-negative interpretation.
- Evidence and citation traceability.
- Difference between deterministic correctness and LLM quality.

### Learn first

- Define expected outputs before running the system.
- Separate rule/correlation tests from grounded-report evaluation.

### Proposed implementation task

- Build golden, benign, malformed, and insufficient-evidence end-to-end scenarios.
- Measure rule outcomes, correlation grouping, technique mappings, citation validity, schema validity, and unsupported claims.
- Record failures by layer.

### Acceptance criteria

- Golden scenarios produce expected deterministic detections, groups, incidents, and mappings.
- Benign scenarios do not produce false incidents.
- Malformed data fails safely with clear errors.
- Insufficient evidence does not produce confident unsupported claims.
- Evaluation identifies whether a failure belongs to deterministic security logic, retrieval, generation, or validation.

## Future Extension

- Real SIEM/EDR APIs and streaming/Kafka ingestion.
- ECS/OCSF breadth and advanced Windows Event IDs.
- Sigma, YARA, IDS signatures, and ML anomaly detection.
- Graph databases, attack graphs, and probabilistic correlation.
- Full incident-response playbooks and case-system integration.
- Broad ATT&CK coverage and automated content-version updates.
- Hybrid retrieval and advanced reranking.
- Multi-agent SOC orchestration and automated remediation.

## Assumptions / TBD

- **Assumption:** local deterministic fixtures are sufficient to prove the MVP workflow.
- **Assumption:** initial rules and mappings favor transparency over breadth.
- **TBD:** language/framework, package naming, persistence, API/UI, model/provider, deployment, privacy requirements, and cost limits.
- **TBD:** correlation thresholds and severity policy require calibration against agreed golden and benign cases.
- **TBD:** production threat-modeling, authentication/authorization, secrets, retention, tenant isolation, and compliance are out of the learning-design scope but mandatory before production deployment.

## Approval gate

Implementation begins only after the architecture and security-learning pack is reviewed and approved.
