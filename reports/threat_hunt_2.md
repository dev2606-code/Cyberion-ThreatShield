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