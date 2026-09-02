# Cyberion ThreatShield - Data Dictionary

## Log Source 1: Windows Sysmon

**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample File:** exec_sysmon_1_ftp.evtx  
**Channel:** Microsoft-Windows-Sysmon/Operational  
**Event ID:** 1 - Process Creation

## Important Fields

| Field | Example Value | Detection Meaning |
|---|---|---|
| UtcTime | 2019-05-12 17:20:49.261 | Time when the activity occurred |
| Computer | IEWIN7 | Computer where the event occurred |
| ProcessId | 2392 | ID of the created process |
| Image | C:\Windows\System32\cmd.exe | Process that was created |
| CommandLine | cmd.exe /C calc.exe | Command executed by the process |
| User | IEWIN7\IEUser | User associated with the activity |
| ParentProcessId | 3668 | ID of the parent process |
| ParentImage | C:\Windows\System32\ftp.exe | Process that started the child process |
| IntegrityLevel | Medium | Integrity level of the process |
| Hashes | SHA1, MD5, SHA256 | Used to identify/correlate the executable |

## Initial Observation

The Sysmon event shows that `ftp.exe` started `cmd.exe`.

The command line shows that `cmd.exe` was used to execute `calc.exe`.

Process relationship:

ftp.exe → cmd.exe → calc.exe

This is an unusual process relationship and requires further investigation before classification.