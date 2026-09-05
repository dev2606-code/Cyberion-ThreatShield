# Investigation Notes: WMI Command Execution and SMB Activity

## Investigation Reference

Primary Detection:

- Rule 15 - Command Shell Spawned by WMI Provider
- Severity: High
- MITRE ATT&CK: T1047

Correlated Detection:

- Rule 4 - SMB Network Connection
- Severity: Medium
- MITRE ATT&CK: T1021.002

## Observed Host and User

- Computer: IEWIN7
- User: IEWIN7\IEUser
- Primary Timestamp: 2019-04-30 20:32:51 UTC

## Observed Process Artifacts

Parent Process:

C:\Windows\System32\wbem\WmiPrvSE.exe

Child Process:

C:\Windows\System32\cmd.exe

Observed command activity included:

whoami /all

## Network / Share Artifact

Command output referenced the local administrative share path:

\\127.0.0.1\ADMIN$\

The sample also generated an SMB Network Connection detection.

## Detection Evidence

Cyberion ThreatShield parsed:

- Events: 7
- Total Alerts: 4
- Rule 15 Alerts: 3
- Rule 4 Alerts: 1

## Analyst Notes

The WmiPrvSE.exe to cmd.exe parent-child relationship provides evidence of
WMI-associated command execution.

SMB-related activity in the same telemetry provides additional investigation
context. These observations should be correlated with authentication,
source-host, administrative-share, and endpoint telemetry before determining
whether the activity was unauthorized.

## Recommended Correlation

Review:

- Authentication events
- Source host information
- WMI activity
- SMB connections
- Administrative-share access
- Process creation
- Related endpoint alerts
- Account activity

## Related Files

- reports/threat_hunt_2.md
- reports/rule_test_evidence.md
- playbooks/wmi_command_execution.md
