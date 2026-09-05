# Threat Hunt 1: Suspicious PowerShell LSASS Memory Dump Activity

## Hunt Hypothesis

PowerShell activity may be attempting to access and dump LSASS process
memory for credential-related purposes.

## Data Source

- Windows PowerShell Operational Logs
- Event ID: 4104
- EVTX Sample: Powershell_4104_MiniDumpWriteDump_Lsass.evtx

## Host Information

Host: MSEDGEWIN10

Timestamp:
2020-06-30 14:24:08 UTC

User SID:
S-1-5-21-3461203602-4096304019-2269080069-1000

## Investigation

PowerShell Script Block Logging recorded execution of:

C:\Users\Public\lsass_wer_ps.ps1

The script contained:

Get-Process lsass

and references to:

MiniDumpWriteDump

The script also contained logic for creating a dump file using
IO.FileStream.

## Observed Activity

PowerShell
    ↓
lsass_wer_ps.ps1
    ↓
Get-Process lsass
    ↓
MiniDumpWriteDump
    ↓
Memory dump functionality

## MITRE ATT&CK Mapping

Technique:
T1003.001 - OS Credential Dumping: LSASS Memory

Tactic:
Credential Access

## Hunt Result

SUSPICIOUS ACTIVITY IDENTIFIED

The hypothesis is supported by the available telemetry. PowerShell
Script Block Logging shows a script targeting the LSASS process and
using MiniDumpWriteDump-related functionality.

## Analyst Assessment

This behavior is consistent with LSASS memory-dump activity and should
be treated as a high-priority investigation signal.

The available sample demonstrates the script behavior, but additional
host telemetry would be required to determine the complete execution
chain and final impact.

## Recommended Investigation

Correlate this event with:

- PowerShell process creation
- Parent process information
- File creation events
- LSASS process access events
- User authentication activity
- Related endpoint security alerts

## Conclusion

Threat Hunt #1 successfully identified suspicious PowerShell activity
targeting LSASS memory. The available evidence supports the original
hunt hypothesis.
## False Positive Considerations

Potential legitimate explanations may include:

- Authorized debugging or diagnostic activity
- Approved administrative scripts
- Security or forensic tools collecting process-memory information
- Controlled security testing

These possibilities should be validated using user context, process ancestry,
file reputation, endpoint alerts, and change-management records.

## Detection Rule Correlation

The observed threat-hunting evidence is covered by the Cyberion ThreatShield detection engine.

Detection Rule:
Rule 9 - PowerShell LSASS MiniDumpWriteDump Activity

Severity:
High

MITRE ATT&CK:
T1003.001 - OS Credential Dumping: LSASS Memory

Detection Logic:
- Event ID 4104
- ScriptBlockText contains "Get-Process lsass"
- ScriptBlockText contains "MiniDumpWriteDump"

This rule provides automated detection coverage for the suspicious behavior identified during Threat Hunt #1.

## Detection Validation Result

The Cyberion ThreatShield detection engine was tested against the EVTX
sample used for this threat hunt.

### Test Summary

- Events Parsed: 4
- Total Alerts: 1
- Rule 9 Alerts: 1
- Severity: High
- MITRE ATT&CK: T1003.001
- Event ID: 4104
- Host: MSEDGEWIN10
- Script Path: C:\Users\Public\lsass_wer_ps.ps1

### Validation Result

PASS

Rule 9 successfully detected the PowerShell script-block activity containing
both `Get-Process lsass` and `MiniDumpWriteDump`.

No additional Cyberion ThreatShield detection rules triggered on this sample.

This validates the correlation between the threat-hunting hypothesis,
observed telemetry, MITRE ATT&CK mapping, and automated detection logic.
