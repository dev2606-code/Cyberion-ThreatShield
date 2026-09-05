# Incident Response Playbook: WMI Command Execution

## Purpose

This playbook provides an investigation and response workflow for suspicious
command execution involving Windows Management Instrumentation (WMI).

## Detection Triggers

Primary Detection:

- Rule ID: 15
- Rule Name: Command Shell Spawned by WMI Provider
- Severity: High
- MITRE ATT&CK: T1047 - Windows Management Instrumentation
- Relevant Event ID: 1

Correlated Detection:

- Rule ID: 4
- Rule Name: SMB Network Connection
- Severity: Medium
- MITRE ATT&CK: T1021.002
- Relevant Event ID: 3

## Initial Triage

Review:

- Hostname
- User account
- Event timestamp
- Parent process
- Child process
- Command line
- Network connections
- Authentication activity
- Related alerts from the same host

## Investigation

1. Confirm whether WmiPrvSE.exe spawned a command shell.
2. Review the command executed by cmd.exe.
3. Identify the account associated with the process.
4. Review SMB activity around the same timestamp.
5. Check authentication events for related remote logons.
6. Review access to administrative shares.
7. Search for similar activity on other hosts.
8. Determine whether the activity was authorized administration.

## Evidence to Collect

Preserve relevant:

- Sysmon Event ID 1 process events
- Sysmon Event ID 3 network events
- Windows authentication logs
- WMI-related events
- SMB/network telemetry
- Process command lines
- User and host information
- Relevant timestamps
- Endpoint-security alerts

## Detection Correlation

The tested EVTX sample produced:

- Events Parsed: 7
- Total Alerts: 4
- Rule 15 Alerts: 3
- Rule 4 Alerts: 1

Observed process relationship:

WmiPrvSE.exe
    |
    v
cmd.exe
    |
    v
whoami.exe

Observed command activity included:

`whoami /all`

SMB-related network activity was also detected in the same sample.

## False Positive Considerations

Possible legitimate explanations include:

- Authorized remote administration
- System-management software
- Administrative automation
- Approved WMI scripts
- Controlled penetration testing

Validate account, host, source, and change-management context before
classifying the activity as malicious.

## Response Guidance

If the activity is confirmed unauthorized:

- Escalate according to organizational incident-response procedures.
- Isolate affected systems using approved security controls when appropriate.
- Preserve process, authentication, and network evidence.
- Review the involved account for suspicious activity.
- Investigate related hosts for similar WMI or SMB activity.
- Follow approved credential-protection procedures if account compromise is suspected.

## Escalation

Escalate when:

- WMI execution is unauthorized.
- Administrative shares are involved unexpectedly.
- Suspicious authentication activity is correlated.
- Multiple hosts show similar behavior.
- Privileged accounts are involved.
- Additional lateral-movement indicators are identified.

## Closure Criteria

Close the investigation when:

- The WMI activity has been explained and documented.
- Related SMB and authentication activity has been reviewed.
- Required containment and remediation actions are complete.
- Related hosts and accounts have been investigated.
- Final analyst findings are recorded.

## Related Cyberion ThreatShield Evidence

- Threat Hunt: `reports/threat_hunt_2.md`
- Detection Evidence: `reports/rule_test_evidence.md`
- Primary Detection: Rule 15 / T1047
- Correlated Detection: Rule 4 / T1021.002
