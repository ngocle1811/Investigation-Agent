# Security Learning Checklist

Use this as a readiness gate, not as a requirement to master security before starting. Each section contains only the minimum knowledge needed for its module.

## Before coding Security Events

- [ ] I can explain Event vs Alert vs Incident.
- [ ] I know what a SOC analyst does.
- [ ] I can explain the different roles of SIEM and EDR.
- [ ] I can read a basic authentication event.
- [ ] I can read a basic process event.
- [ ] I can read a basic network event.

## Before coding the Normalizer

- [ ] I understand `user`, `host`, `src_ip`, `dst_ip`, `process_name`, `parent_process`, `command_line`, and `domain`.
- [ ] I can explain parent and child processes.
- [ ] I can explain why `winword.exe → powershell.exe` may deserve attention without calling it malware by itself.
- [ ] I understand source vs destination and IP/domain/port at a basic level.
- [ ] I know why timestamps and event ordering must be preserved.

## Before coding Detection Rules

- [ ] I can explain rule-based detection and thresholds.
- [ ] I can distinguish an IOC from behavior/TTP.
- [ ] I can explain false positives and false negatives.
- [ ] I understand a basic brute-force pattern and success-after-failures pattern.
- [ ] I know that PowerShell requires suspicious context; the executable alone is not malicious.
- [ ] I can define one golden scenario and one benign scenario per rule.

## Before coding Correlation

- [ ] I can explain the difference between detection and correlation.
- [ ] I can link activity by user, host, IP, process, time proximity, and shared IOC.
- [ ] I can read a simple process chain.
- [ ] I can explain why each event is evidence for or against one incident.
- [ ] I can justify every contribution to a transparent correlation score.
- [ ] I know that one alert is not automatically an incident.

## Before coding the Incident Model

- [ ] I can explain Candidate, Open, Investigating, Triaged, Resolved, and Closed.
- [ ] I understand basic triage and prioritization.
- [ ] I can distinguish severity from confidence.
- [ ] I can distinguish raw evidence, interpreted finding, hypothesis, and confirmed fact.
- [ ] I can build an ordered incident timeline without changing source evidence.

## Before coding MITRE ATT&CK Mapping

- [ ] I can explain MITRE ATT&CK at a high level.
- [ ] I can distinguish tactic, technique, sub-technique, and procedure.
- [ ] I can explain TTP.
- [ ] I can map repeated password guessing to T1110 using evidence.
- [ ] I can map evidenced PowerShell execution to T1059.001 without asking an LLM to guess.
- [ ] I know I do not need to memorize the entire ATT&CK matrix.

## Before coding Security RAG

- [ ] I can read and summarize a technique description.
- [ ] I can identify a trusted security source.
- [ ] I can verify that a retrieved passage supports the intended claim.
- [ ] I can preserve technique ID, source, version, reference, and document type metadata.
- [ ] I understand that RAG provides knowledge and does not replace the Detection Engine.

## Before coding the Investigation Copilot

- [ ] I can ask: what happened, when, which user, which host, and what evidence supports it?
- [ ] I can separate evidence, finding, hypothesis, and confirmed fact.
- [ ] I can explain a timeline in attack order.
- [ ] I understand how IOC and TTP play different roles in an investigation.
- [ ] I can label uncertainty as “Possible hypothesis” or “Insufficient evidence.”
- [ ] I can state the next evidence an analyst should inspect.
- [ ] I can define guardrails against invented events, IOCs, techniques, or root cause.

## Before coding the Investigation Report

- [ ] I can write an analyst-friendly summary.
- [ ] Every factual claim can link to evidence or a cited source.
- [ ] Hypotheses are visibly different from confirmed facts.
- [ ] Severity includes an explanation.
- [ ] Missing evidence remains explicit.

## Before end-to-end evaluation

- [ ] I have a golden attack-like scenario with expected detections, incident links, and ATT&CK mappings.
- [ ] I have a benign scenario that must not produce a false incident.
- [ ] I have an insufficient-evidence scenario that must not produce a confident root-cause claim.
- [ ] I can measure false positives, false negatives, evidence traceability, citation validity, and unsupported claims.
- [ ] I know deterministic engine tests and LLM-output evaluations are separate test suites.

## Not required before MVP

- [ ] I will defer deep pentesting, exploit development, malware reverse engineering, deep cryptography, advanced AD/network security, SIEM administration, real EDR integration, Neo4j, ML anomaly detection, multi-agent SOC, and automated remediation.
