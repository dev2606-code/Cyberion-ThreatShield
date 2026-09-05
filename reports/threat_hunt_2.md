# Threat Hunt 2: WMI-Based Command Execution

## Hunt Hypothesis

WMI activity may have been used to execute commands on a Windows host.

## Data Source

- Windows Sysmon
- Event ID 1 - Process Creation
- Event ID 3 - Network Connection
- EVTX Sample: LM_wmiexec_impacket_sysmon_whoami.evtx

## Host Information

Host:
IEWIN7

User:
IEWIN7\IEUser

Primary Timestamp:
2019-04-30 20:32:51 UTC

## Investigation

Sysmon telemetry recorded cmd.exe being launched by WmiPrvSE.exe.

Observed parent process:

C:\Windows\System32\wbem\WmiPrvSE.exe

Observed child process:

C:\Windows\System32\cmd.exe

The command shell executed:

whoami /all

A child whoami.exe process was subsequently created.

## Observed Process Chain

WmiPrvSE.exe
    ↓
cmd.exe
    ↓
whoami.exe

## Command Line Evidence

cmd.exe /Q /c whoami /all

The command output was redirected to a path under:

\\127.0.0.1\ADMIN$\...

## MITRE ATT&CK Mapping

Technique:
T1047 - Windows Management Instrumentation

Tactic:
Execution

## Hunt Result

SUSPICIOUS ACTIVITY IDENTIFIED

The hypothesis is supported by the available telemetry.

WmiPrvSE.exe spawned cmd.exe, which executed whoami /all. This process relationship is consistent with WMI-based command execution behavior.

## Analyst Assessment

The process chain is an important investigation signal because WmiPrvSE.exe is acting as the parent of a command shell.

The available telemetry supports WMI-based command execution, but additional authentication and source-host evidence would be required to determine the full remote execution path and attribution.

## Recommended Investigation

Correlate with:

- Windows authentication events
- Source host information
- SMB activity
- Remote administrative share access
- Additional WMI events
- Process creation events
- Network connections
- Account activity

## Conclusion

Threat Hunt #2 identified WMI-related command execution activity on IEWIN7.

The available evidence supports the original hypothesis that WMI was used to launch a command shell and execute system-discovery commands.
## False Positive Considerations

Potential legitimate explanations may include:

- Authorized remote administration
- System-management software using WMI
- Administrative automation scripts
- Controlled penetration-testing or security-validation activity

The parent-child process relationship, account context, source host,
authentication events, and surrounding network activity should be reviewed
before classifying the activity as malicious.

## Detection Rule Correlation

The observed threat-hunting evidence is covered by the Cyberion ThreatShield detection engine.

Detection Rule:
Rule 15 - Command Shell Spawned by WMI Provider

Severity:
High

MITRE ATT&CK:
T1047 - Windows Management Instrumentation

Detection Logic:
- ParentImage ends with "\wmiprvse.exe"
- Image ends with "\cmd.exe"

This rule provides automated detection coverage for the suspicious behavior identified during Threat Hunt #2.

## Multi-Rule Detection Correlation

Analysis of the WMI execution EVTX sample produced multiple related detection alerts.

### Detection Summary

- Events Parsed: 7
- Total Alerts: 4
- Rule 15 Alerts: 3
- Rule 4 Alerts: 1

### Rule 15 - Command Shell Spawned by WMI Provider

- Severity: High
- MITRE ATT&CK: T1047
- Event ID: 1
- Parent Process: WmiPrvSE.exe
- Child Process: cmd.exe
- Observed Command: whoami /all

Three process-creation events matched Rule 15.

### Rule 4 - SMB Network Connection

- Severity: Medium
- MITRE ATT&CK: T1021.002
- Event ID: 3
- Image: System

One network-connection event matched Rule 4.

### Analyst Correlation

The sample contains both WMI-based command execution and SMB-related
network activity. Correlating these alerts provides more investigation
context than reviewing either detection independently.

The evidence supports investigation of related WMI execution and SMB
activity on the affected host, while additional source-host and
authentication telemetry would be required to establish the complete
activity chain.
