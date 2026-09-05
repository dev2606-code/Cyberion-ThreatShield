# Investigation Notes: PowerShell LSASS Memory Dump Activity

## Investigation Reference

- Threat Hunt: Threat Hunt #1
- Detection Rule: Rule 9 - PowerShell LSASS MiniDumpWriteDump Activity
- Severity: High
- MITRE ATT&CK: T1003.001
- Data Source: Windows PowerShell Operational Logs
- Event ID: 4104

## Observed Host

- Computer: MSEDGEWIN10
- Timestamp: 2020-06-30 14:24:08 UTC

## Observed Artifacts

### Script Path

C:\Users\Public\lsass_wer_ps.ps1

### PowerShell Indicators

The recorded script block contained references to:

- Get-Process lsass
- MiniDumpWriteDump
- IO.FileStream
- Process memory dump functionality

## Detection Evidence

Cyberion ThreatShield parsed:

- Events: 4
- Alerts: 1
- Matching Rule: Rule 9
- Detection Result: PASS

## Analyst Notes

The combination of LSASS process access and MiniDumpWriteDump-related
functionality is a high-priority investigation signal associated with
credential-access behavior.

These artifacts should not automatically be treated as confirmed malicious
IOCs. Their legitimacy should be determined using endpoint, user, process,
and organizational context.

## Recommended Correlation

Review related:

- PowerShell execution
- Process creation
- File creation
- Authentication events
- Endpoint-security alerts
- Activity from the same user and host

## Related Files

- reports/threat_hunt_1.md
- reports/rule_test_evidence.md
- playbooks/lsass_credential_dumping.md
