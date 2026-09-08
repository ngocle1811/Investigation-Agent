# Security Event Correlation & MITRE ATT&CK Copilot

This directory contains the proposed MVP architecture and security-learning pack. It is a design artifact only: no application module is implemented yet.

## 1. What does the project do?

It turns fixture-based security events into evidence-backed incidents and analyst-facing investigation reports. Detection, correlation, incident membership, and ATT&CK mapping are deterministic; RAG supplies cited knowledge, and the LLM drafts a grounded report.

## 2. What is the main workflow?

`Security Events → Normalizer → Detection Rules → Correlation Engine → Incident → MITRE ATT&CK → RAG → Investigation Copilot → Investigation Report`

## 3. What security knowledge is needed?

| Step | Security knowledge | Depth | Learn before coding? |
|---|---|---|---|
| Events | SOC, SIEM/EDR roles, Event vs Alert vs Incident, basic log types | Basic | Yes |
| Normalizer | security fields, process tree, network direction, timestamps | Basic | Yes |
| Detection | rule logic, thresholds, IOC vs behavior, FP/FN | Basic | Yes |
| Correlation | evidence, time/entity/process/IOC relationships | Basic–Intermediate | Yes |
| Incident | Alert vs Incident, lifecycle, triage, severity vs confidence | Basic | Yes |
| MITRE | TTP, tactic, technique, sub-technique, evidence mapping | Beginner–Basic | Yes |
| RAG | ATT&CK reading, trusted sources, citation traceability | Security Beginner | Mostly reuse existing RAG skills |
| LLM Copilot | investigation questions, timeline, evidence vs hypothesis | Basic | Yes |
| Report | analyst-friendly structure, traceability, severity explanation | Beginner | Yes |

## 4. Where should learning begin?

Start with Event vs Alert vs Incident, then learn the roles of a SOC, SIEM, and EDR. The first learning outcome is: “I can read a basic authentication, process, and network event without treating every event as suspicious.”

## 5. Where should coding begin after approval?

Start with a small `security_events` module containing the `RawEvent` contract and JSON/JSONL fixtures for authentication, process, and network activity. The Normalizer is the next module.

## 6. Which parts use AI?

- RAG retrieves trusted, versioned, cited security knowledge.
- The LLM Copilot synthesizes incident facts and retrieved knowledge into a structured draft.
- Deterministic validation checks the draft before it can be stored.

## 7. Which parts must not use an LLM as the main engine?

- Detection decisions
- Correlation scores and incident membership
- Incident state transitions
- Evidence-to-ATT&CK mappings
- Report schema, evidence-ID, technique-ID, and citation validation

## 8. What is not required before the MVP?

### NOT REQUIRED BEFORE MVP

- Deep pentesting
- Exploit development
- Malware reverse engineering
- Deep cryptography
- Advanced Active Directory
- Advanced network security
- Splunk or Elastic administration
- Real EDR integration
- Neo4j or attack graphs
- ML anomaly detection
- Multi-agent SOC orchestration
- Automated remediation

These are **Future Extension** topics, not prerequisites.

## Diagrams

1. [Project Security Learning Map](./01-project-security-learning-map.architecture.html) — full proposed architecture and per-step knowledge cards.
2. [Learn → Build Roadmap](./02-learn-build-roadmap.workflow.html) — minimum learning outcomes aligned to the build order.
3. [Event → Incident Data Flow](./03-event-to-incident.dataflow.html) — data assets and security concept used by every transform.
4. [Detection & Correlation Workflow](./04-detection-correlation.workflow.html) — deterministic decisions, benign branch, and create/update outcomes.
5. [Investigation Sequence](./05-investigation.sequence.html) — deterministic security reasoning, RAG, LLM synthesis, validation, and persistence.
6. [Incident Lifecycle](./06-incident.lifecycle.html) — case states, evidence recovery, and false-positive exit.

The JSON specifications beside each HTML file are the Archify sources.

### Vietnamese versions / Bản tiếng Việt

1. [Bản đồ kiến trúc và học bảo mật](./01-project-security-learning-map.vi.architecture.html)
2. [Lộ trình Học → Xây dựng](./02-learn-build-roadmap.vi.workflow.html)
3. [Luồng dữ liệu Event → Incident](./03-event-to-incident.vi.dataflow.html)
4. [Workflow phát hiện và tương quan](./04-detection-correlation.vi.workflow.html)
5. [Trình tự điều tra có căn cứ](./05-investigation.vi.sequence.html)
6. [Vòng đời Incident](./06-incident.vi.lifecycle.html)

Each Vietnamese HTML has a matching `.vi.*.json` Archify source. Technical identifiers and product/framework names remain unchanged intentionally. Archify currently falls back to English for fixed Viewer controls because the renderer does not provide a Vietnamese UI locale.

## Layer boundaries

| Layer | Responsibilities | Explicit exclusion |
|---|---|---|
| Deterministic security logic | validation, normalization, detection, correlation, incident state, ATT&CK mapping | no LLM decision authority |
| MITRE/security understanding | evidence meaning, timelines, triage, severity, TTP interpretation | no unsupported technique guesses |
| RAG/LLM support | cited retrieval and structured report synthesis | no primary detection or correlation |

## Assumptions / TBD

- **Assumption:** the repository is greenfield; every depicted application component is `Proposed`.
- **Assumption:** the MVP consumes local JSON/JSONL fixtures in batch mode, not a live SIEM/EDR stream.
- **Assumption:** initial coverage includes authentication, process, and network examples, with T1110 and T1059.001 as golden ATT&CK mappings.
- **Assumption:** correlation starts with transparent additive weights over user, host, IP, process, time proximity, and shared IOC.
- **Assumption:** RAG content keeps `technique_id`, `source`, `version`, `url/reference`, and `document_type` metadata.
- **TBD:** programming language, package layout, persistence technology, UI/API surface, and LLM provider are implementation decisions after architecture review.
- **TBD:** exact severity policy, correlation threshold, and benchmark dataset must be calibrated with golden and benign scenarios.
- **Future Extension:** streaming ingestion, production SIEM/EDR connectors, full ATT&CK coverage, graph/probabilistic correlation, multi-agent SOC, and automated remediation.

## Review gate

Do not begin implementation until this architecture pack is reviewed and approved.
