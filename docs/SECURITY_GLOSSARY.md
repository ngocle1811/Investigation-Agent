# Security Glossary

Newbie-friendly definitions use examples from the proposed Security Event Correlation & MITRE ATT&CK Copilot MVP.

## SOC

**Definition:** A Security Operations Center is the people, processes, and tools used to monitor and investigate security activity.

**Example:** A SOC analyst reviews `INC-001`, checks its evidence, and decides what to investigate next.

## SIEM

**Definition:** A Security Information and Event Management system centralizes and searches logs from many sources and can run alerting rules.

**Example:** A future SIEM connector could send authentication events to the MVP; the MVP currently uses JSON fixtures.

## EDR

**Definition:** Endpoint Detection and Response monitors activity on devices, such as processes, commands, files, and network connections.

**Example:** A Sysmon-like fixture representing `powershell.exe` approximates one event an EDR might collect.

## Event

**Definition:** A record that something happened. An event is not automatically suspicious.

**Example:** `login_success` for Alice on `PC01` is an event.

## Alert

**Definition:** A notification created when a detection rule finds something that deserves review.

**Example:** Five failed logins within ten minutes create a possible brute-force alert.

## Incident

**Definition:** An investigation case containing related evidence, events, and alerts. It has a lifecycle, severity, entities, and timeline.

**Example:** `INC-001` groups failed logins, a later success, PowerShell execution, and a suspicious outbound connection.

## Evidence

**Definition:** A traceable fact used to support or challenge a finding or hypothesis. Evidence should retain its source and identifier.

**Example:** `evt-002` shows that Alice successfully logged in after repeated failures.

## IOC

**Definition:** An Indicator of Compromise is a concrete observable such as an IP address, domain, file hash, or filename associated with suspicious activity.

**Example:** A test domain in a network fixture is a shared IOC linking two detections.

## TTP

**Definition:** Tactics, Techniques, and Procedures describe an attacker’s goal, method, and concrete way of performing it.

**Example:** Credential guessing is behavior that can map to the Brute Force technique rather than only to one source IP.

## Tactic

**Definition:** A tactic is the attacker’s high-level objective—the “why” of an activity.

**Example:** Credential Access is a possible objective behind repeated password guessing.

## Technique

**Definition:** A technique is a method used to achieve a tactic—the “how” at a standardized level.

**Example:** T1110 Brute Force describes repeated attempts to obtain valid credentials.

## Sub-technique

**Definition:** A sub-technique is a more specific form of a technique.

**Example:** T1059.001 PowerShell is a sub-technique of Command and Scripting Interpreter.

## MITRE ATT&CK

**Definition:** MITRE ATT&CK is a knowledge base that organizes observed adversary behavior into tactics, techniques, and sub-techniques.

**Example:** The deterministic mapper links an evidenced PowerShell behavior to T1059.001.

## Detection

**Definition:** Detection asks, “What activity is suspicious?” In this MVP, explicit deterministic rules answer that question.

**Example:** A threshold rule fires when at least five `login_failed` events occur for the same user within ten minutes.

## Correlation

**Definition:** Correlation asks, “Do these related events or alerts belong to the same case?” It uses shared entities, time, processes, and IOCs.

**Example:** Alerts for the same user and host within ten minutes receive a higher correlation score.

## False Positive

**Definition:** A false positive occurs when a rule flags benign activity as suspicious.

**Example:** An administrator’s expected PowerShell maintenance command triggers an overly broad PowerShell rule.

## False Negative

**Definition:** A false negative occurs when suspicious activity is present but a detection fails to flag it.

**Example:** A brute-force rule misses four rapid failures because its threshold requires five.

## Process Tree

**Definition:** A process tree shows parent-child relationships between running programs.

**Example:** `winword.exe → powershell.exe` is a process-tree relationship that may need contextual review.

## Parent Process

**Definition:** The parent process is the program that started another process.

**Example:** In the example chain, `winword.exe` is the parent of `powershell.exe`.

## Command Line

**Definition:** A command line records the executable and arguments used to start a process. Arguments often provide more useful context than the process name alone.

**Example:** A PowerShell command containing an encoded payload is more suspicious than `powershell.exe` with a normal administrative command.

## Triage

**Definition:** Triage is the first structured review used to confirm relevance, assess priority, and decide the next action.

**Example:** An analyst checks `INC-001`’s evidence and severity before deeper investigation.

## Severity

**Definition:** Severity estimates potential impact or urgency. It is different from confidence, which estimates how certain the conclusion is.

**Example:** An incident affecting an important account may be high severity even while the root-cause confidence remains low.

## Timeline

**Definition:** A timeline orders evidence by time so an analyst can understand what happened before and after each action.

**Example:** Failed logins occur first, then a successful login, then PowerShell, then an outbound connection.

## Hypothesis

**Definition:** A hypothesis is a possible explanation that still needs evidence. It must not be presented as a confirmed fact.

**Example:** “Alice’s account may be compromised” is a hypothesis until the evidence supports confirmation.

## Finding

**Definition:** A finding is an interpretation directly supported by cited evidence but may not establish complete root cause.

**Example:** “Five failed logins for Alice occurred within ten minutes” is a finding supported by event IDs.

## Confidence

**Definition:** Confidence expresses how strongly the available evidence supports a conclusion. It must not be used as a substitute for severity.

**Example:** The report can state high severity but medium confidence when impact could be serious and evidence remains incomplete.

## Grounding

**Definition:** Grounding limits an AI response to supplied evidence and trusted retrieved sources.

**Example:** The Copilot can discuss T1110 only when the incident mapping and cited ATT&CK content support it.

## Citation Traceability

**Definition:** Citation traceability makes it possible to identify the source and version supporting a knowledge claim.

**Example:** A retrieved chunk keeps its `technique_id`, source, version, and URL/reference in report metadata.
