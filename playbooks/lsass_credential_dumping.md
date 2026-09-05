# Incident Response Playbook: LSASS Credential Dumping

## Purpose

This playbook provides an investigation and response workflow for suspicious
activity involving attempts to access or dump LSASS process memory.

## Detection Trigger

Cyberion ThreatShield Detection:

- Rule ID: 9
- Rule Name: PowerShell LSASS MiniDumpWriteDump Activity
- Severity: High
- MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
- Relevant Event ID: 4104

## Initial Triage

When this alert is generated, review:

- Hostname
- User account
- Event timestamp
- PowerShell script path
- Script Block content
- Parent and child processes
- Related endpoint-security alerts

## Investigation

Determine whether the activity is authorized or suspicious.

Review:

1. PowerShell execution around the alert timestamp.
2. References to the LSASS process.
3. Memory-dump related functionality.
4. Files created around the same time.
5. Process ancestry and command-line information.
6. Authentication activity involving the affected account.
7. Other alerts from the same host.

## Evidence to Collect

Preserve relevant:

- Windows PowerShell logs
- Sysmon process events
- Authentication logs
- File-creation telemetry
- Endpoint-security alerts
- Relevant timestamps
- User and host information

## False Positive Considerations

Possible legitimate explanations include:

- Authorized diagnostic activity
- Approved administrative scripts
- Security or forensic tools
- Controlled security testing

Validate the activity using organizational context before classifying it
as malicious.

## Response Guidance

If the activity is confirmed unauthorized:

- Escalate the incident according to organizational procedures.
- Isolate the affected endpoint using approved security controls.
- Preserve relevant evidence for investigation.
- Review the affected account for suspicious authentication activity.
- Follow approved credential-reset or credential-protection procedures.
- Investigate related hosts and accounts for additional suspicious activity.

## Escalation

Escalate when:

- The activity is unauthorized.
- Additional credential-access alerts are observed.
- Suspicious authentication follows the event.
- Similar activity appears on multiple hosts.
- The affected account has elevated privileges.

## Closure Criteria

Close the investigation when:

- The activity has been explained and documented.
- Relevant evidence has been reviewed.
- Required containment and remediation actions are complete.
- Related alerts have been investigated.
- Final analyst findings are recorded.

## Related Cyberion ThreatShield Evidence

- Threat Hunt: `reports/threat_hunt_1.md`
- Detection Evidence: `reports/rule_test_evidence.md`
- Detection Rule: Rule 9
- MITRE ATT&CK: T1003.001
