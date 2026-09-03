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