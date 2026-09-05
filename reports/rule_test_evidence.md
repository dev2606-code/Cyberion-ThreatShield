# Cyberion ThreatShield - Detection Rule Test Evidence

## Rule 1: Suspicious Command Shell Spawned by FTP

**Rule File:** suspicious_ftp_cmd.yml  
**MITRE ATT&CK:** T1059.003 - Windows Command Shell  
**Log Source:** Windows Sysmon Process Creation  
**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample:** exec_sysmon_1_ftp.evtx

### Detection Logic

Parent process:

ftp.exe

Child process:

cmd.exe

### Evidence Observed

ParentImage = C:\Windows\System32\ftp.exe

Image = C:\Windows\System32\cmd.exe

CommandLine = cmd.exe /C ...calc.exe

### Test Result

MATCHED

The required ParentImage and Image fields were present in the real sample telemetry.

### False Positive Consideration

Legitimate administrative, testing, or scripted activity may potentially create a similar process relationship.

---

## Rule 2: Windows Failed Logon Attempt

**Rule File:** windows_failed_logon.yml  
**MITRE ATT&CK Target:** T1110 - Brute Force  
**Log Source:** Windows Security  
**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample:** CA_4624_4625_LogonType2_LogonProc_chrome.evtx

### Detection Logic

EventID = 4625

### Evidence Observed

EventID = 4625

TargetUserName = IEUser

TargetDomainName = MSEDGEWIN10

Channel = Security

Computer = MSEDGEWIN10

### Test Result

MATCHED

The sample contains Windows Security Event ID 4625.

### False Positive Consideration

A failed logon can occur because of an incorrect password, expired credentials, or legitimate application/service authentication problems.

### Note

This rule detects individual failed logon events. It does not by itself confirm brute-force activity.
---

## Rule 3: RDP Network Connection

**Rule File:** rdp_network_connection.yml  
**MITRE ATT&CK:** T1021.001 - Remote Desktop Protocol  
**Log Source:** Windows Sysmon Network Connection  
**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample:** tunna_iis_rdp_smb_tunneling_sysmon_3.evtx

### Detection Logic

DestinationPort = 3389

AND

Protocol = tcp

### Evidence Observed

Protocol = tcp

SourceIp = 127.0.0.1

SourcePort = 49947

DestinationIp = 127.0.0.1

DestinationPort = 3389

Image = C:\Windows\System32\inetsrv\w3wp.exe

User = IIS APPPOOL\DefaultAppPool

### Test Result

MATCHED

The sample telemetry contains TCP network connections to destination port 3389.

### False Positive Consideration

Legitimate Remote Desktop administration, remote support, and authorized IT activity can generate connections to port 3389.

### Note

A connection to TCP port 3389 alone does not prove malicious RDP or lateral movement activity. Authentication, process, user, source/destination, and timing context should be correlated.
---

## Rule 4: SMB Network Connection

**Rule File:** smb_network_connection.yml  
**MITRE ATT&CK:** T1021.002 - SMB/Windows Admin Shares  
**Log Source:** Windows Sysmon Network Connection  
**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample:** tunna_iis_rdp_smb_tunneling_sysmon_3.evtx

### Detection Logic

DestinationPort = 445

AND

Protocol = tcp

### Evidence Observed

Protocol = tcp

SourceIp = 127.0.0.1

DestinationIp = 127.0.0.1

DestinationPort = 445

DestinationPortName = microsoft-ds

Image = C:\Windows\System32\inetsrv\w3wp.exe

User = IIS APPPOOL\DefaultAppPool

### Test Result

MATCHED

The sample contains TCP network connections to destination port 445.

### False Positive Consideration

Normal Windows file sharing, administrative access, and internal SMB communication can legitimately use TCP port 445.

### Note

A connection to port 445 alone does not prove malicious SMB or lateral movement activity. Additional process, authentication, host, and timing context should be correlated.
---

## Rule 5: IIS Worker Process Making RDP Connection

**Rule File:** iis_rdp_connection.yml  
**MITRE ATT&CK:** T1021.001 - Remote Desktop Protocol  
**Log Source:** Windows Sysmon Network Connection  
**Sample:** tunna_iis_rdp_smb_tunneling_sysmon_3.evtx

### Detection Logic

Image ends with:

\w3wp.exe

AND

DestinationPort = 3389

AND

Protocol = tcp

### Evidence Observed

Image =
C:\Windows\System32\inetsrv\w3wp.exe

User =
IIS APPPOOL\DefaultAppPool

Protocol =
tcp

SourceIp =
127.0.0.1

SourcePort =
49947

DestinationIp =
127.0.0.1

DestinationPort =
3389

### Test Result

MATCHED

The sample contains an IIS worker process making a TCP connection to destination port 3389.

### False Positive Consideration

Authorized IIS administration, legitimate testing, or approved internal automation may generate similar activity.

### Note

This match is an investigation signal only. A connection from w3wp.exe to port 3389 does not by itself prove malicious RDP or lateral movement activity.
---

## Rule 6: Process Spawned by Windows Remote Management Provider

**Rule File:** winrm_child_process.yml  
**MITRE ATT&CK:** T1021.006 - Windows Remote Management  
**Log Source:** Windows Sysmon Process Creation  
**Sample:** LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx

### Detection Logic

ParentImage ends with wsmprovhost.exe

### Evidence Observed

EventID = 1

ParentImage = C:\Windows\System32\wsmprovhost.exe

ParentCommandLine = C:\Windows\system32\wsmprovhost.exe -Embedding

Image = C:\Windows\System32\HOSTNAME.EXE

User = insecurebank\Administrator

### Test Result

MATCHED

The sample contains a process creation event where wsmprovhost.exe is the parent process.

### False Positive Consideration

Legitimate PowerShell Remoting, Windows Remote Management, and authorized administrative automation can generate this behavior.

### Note

The presence of wsmprovhost.exe as a parent process does not by itself prove malicious remote activity. Additional user, command-line, network, and authentication context should be correlated.
---

## Rule 7: PowerShell Script Block With Base64 Decoding

**Rule File:** powershell_base64_scriptblock.yml
**MITRE ATT&CK:** T1059.001 - PowerShell
**Log Source:** PowerShell Script Block Logging
**Event ID:** 4104
**Sample:** phish_windows_credentials_powershell_scriptblockLog_4104.evtx

### Detection Logic

EventID = 4104

AND

ScriptBlockText contains FromBase64String

### Evidence Observed

EventID = 4104

ScriptBlockText contains:
FromBase64String

The same script block also contains GzipStream-related content.

### Test Result

MATCHED

The required Event ID and ScriptBlockText pattern were observed in the sample telemetry.

### False Positive Consideration

Legitimate PowerShell scripts, deployment tools, and administrative automation may use Base64 encoding.

### Note

Base64 decoding alone does not prove malicious PowerShell activity. Additional script content, user, process, network, and execution context should be investigated.
---

## Rule 8: PowerShell Credential Access via GetNetworkCredential

**Rule File:** powershell_getnetworkcredential.yml  
**Log Source:** PowerShell Script Block Logging  
**Event ID:** 4104  
**Sample:** phish_windows_credentials_powershell_scriptblockLog_4104.evtx

### Detection Logic

EventID = 4104

AND

ScriptBlockText contains GetNetworkCredential

### Evidence Observed

EventID = 4104

ScriptBlockText contains:
GetNetworkCredential

The same script block also contains credential-related fields such as UserName, Domain, and Password.

### Test Result

MATCHED

The required Event ID and ScriptBlockText pattern were observed in the sample telemetry.

### False Positive Consideration

Legitimate administrative scripts or approved automation may use GetNetworkCredential.

### Note

The presence of GetNetworkCredential alone does not prove credential theft. Additional script context, user activity, and related telemetry should be reviewed.
---

## Rule 9: PowerShell LSASS MiniDumpWriteDump Activity

**Rule File:** powershell_lsass_minidump.yml
**MITRE ATT&CK:** T1003.001 - LSASS Memory
**Log Source:** PowerShell Script Block Logging
**Event ID:** 4104
**Sample:** Powershell_4104_MiniDumpWriteDump_Lsass.evtx

### Detection Logic

EventID = 4104

AND

ScriptBlockText contains:
- Get-Process lsass
- MiniDumpWriteDump

### Evidence Observed

EventID = 4104

ScriptBlockText contains:
Get-Process lsass

ScriptBlockText contains:
MiniDumpWriteDump

Script Path:
C:\Users\Public\lsass_wer_ps.ps1

### Test Result

MATCHED

The required PowerShell Script Block event and both detection strings were observed in the sample telemetry.

### False Positive Consideration

Authorized forensic memory acquisition, security testing, and approved diagnostic tools may generate similar behavior.

### Note

This match is a strong investigation signal, but surrounding user, process, host, and authorization context should still be reviewed.
---

## Rule 10: Scheduled Task Creation Executing Command Shell

**Rule File:** scheduled_task_cmd.yml
**MITRE ATT&CK:** T1053.005 - Scheduled Task/Job: Scheduled Task
**Log Source:** Windows Security
**Event ID:** 4698
**Sample:** temp_scheduled_task_4698_4699.evtx

### Detection Logic

EventID = 4698

AND

TaskContent contains cmd.exe

### Evidence Observed

SubjectUserName = Administrator

TaskName = \CYAlyNSS

TaskContent contains:
cmd.exe

Arguments contain:
tasklist

### Test Result

MATCHED

The scheduled task creation event contains cmd.exe in its task content.

### False Positive Consideration

Legitimate administrative tasks, maintenance automation, and software deployment may create scheduled tasks that execute cmd.exe.

### Note

A scheduled task using cmd.exe is not automatically malicious. Task name, command, user, timing, and surrounding activity should be correlated.
---

## Rule 11: Winlogon Shell Registry Modification

**Rule File:** winlogon_shell_modification.yml  
**MITRE ATT&CK:** T1547.004 - Winlogon Helper DLL  
**Log Source:** Windows Sysmon Registry Event  
**Event ID:** 13  
**Sample:** sysmon_13_1_persistence_via_winlogon_shell.evtx

### Detection Logic

TargetObject contains:

\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

### Evidence Observed

EventID = 13

Image = C:\Users\IEUser\Downloads\a.exe

TargetObject contains:
\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

Details contains:
BRE6BgE2JubB.exe, explorer.exe

### Test Result

MATCHED

The sample contains modification of the Winlogon Shell registry value.

### False Positive Consideration

Legitimate system configuration, authorized administrative changes, or approved software may modify Winlogon-related registry values.

### Note

A Winlogon Shell modification is an important persistence investigation signal, but the surrounding process, user, registry value, and authorization context should also be reviewed.
---

## Rule 12: PowerShell Execution Policy Changed to Unrestricted

**Rule File:** powershell_executionpolicy_unrestricted.yml  
**MITRE ATT&CK:** T1059.001 - PowerShell  
**Log Source:** Windows Sysmon Registry Event  
**Event ID:** 13  
**Sample:** de_powershell_execpolicy_changed_sysmon_13.evtx

### Detection Logic

TargetObject ends with:

\Microsoft.PowerShell\ExecutionPolicy

AND

Details = Unrestricted

### Evidence Observed

EventID = 13

Image =
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

TargetObject =
HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy

Details = Unrestricted

### Test Result

MATCHED

The sample contains a registry modification where the PowerShell ExecutionPolicy value was changed to Unrestricted.

### False Positive Consideration

Authorized administrators, troubleshooting activity, development environments, or approved configuration changes may modify the PowerShell execution policy.

### Note

Changing the PowerShell execution policy to Unrestricted is an investigation signal and does not alone prove malicious activity.
---

## Rule 13: MSHTA Execution of HTA File

**Rule File:** mshta_hta_execution.yml  
**MITRE ATT&CK:** T1218.005 - Mshta  
**Log Source:** Windows Sysmon Process Creation  
**Event ID:** 1  
**Sample:** sysmon_mshta_sharpshooter_stageless_meterpreter.evtx

### Detection Logic

Image ends with:

\mshta.exe

AND

CommandLine contains:

.hta

### Evidence Observed

EventID = 1

Image =
C:\Windows\System32\mshta.exe

CommandLine =
"C:\Windows\System32\mshta.exe" "...Temporary Internet Files...\update.hta"

ParentImage =
C:\Program Files\Internet Explorer\iexplore.exe

User =
IEWIN7\IEUser

### Test Result

MATCHED

The sample contains a process creation event where mshta.exe executes an HTA file.

### False Positive Consideration

Legitimate HTA applications, legacy enterprise software, and authorized administrative scripts may use mshta.exe.

### Note

MSHTA execution alone does not prove malicious activity. The HTA source, parent process, command line, user, and related network activity should also be investigated.
---

## Rule 14: Rundll32 PCWUTL LaunchApplication Execution

**Rule File:** rundll32_pcwutl_launchapplication.yml  
**MITRE ATT&CK:** T1218.011 - Rundll32  
**Log Source:** Windows Sysmon Process Creation  
**Event ID:** 1  
**Sample:** exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx

### Detection Logic

Image ends with:

\rundll32.exe

AND

CommandLine contains:
- pcwutl.dll
- LaunchApplication

### Evidence Observed

EventID = 1

Image =
C:\Windows\System32\rundll32.exe

CommandLine =
"C:\Windows\System32\rundll32.exe" pcwutl.dll,LaunchApplication c:\Windows\system32\calc.exe

ParentImage =
C:\Windows\System32\cmd.exe

User =
IEWIN7\IEUser

### Test Result

MATCHED

The sample contains rundll32.exe using pcwutl.dll with the LaunchApplication function.

### False Positive Consideration

Legitimate Windows troubleshooting, compatibility tools, or authorized administrative testing may generate similar activity.

### Note

Rundll32 execution alone is not proof of malicious activity. The DLL, exported function, launched application, parent process, and user context should be investigated.
---

## Rule 15: Command Shell Spawned by WMI Provider

**Rule File:** wmi_cmd_execution.yml  
**MITRE ATT&CK:** T1047 - Windows Management Instrumentation  
**Log Source:** Windows Sysmon Process Creation  
**Event ID:** 1  
**Sample:** LM_wmiexec_impacket_sysmon_whoami.evtx

### Detection Logic

ParentImage ends with:

\WmiPrvSE.exe

AND

Image ends with:

\cmd.exe

### Evidence Observed

EventID = 1

ParentImage =
C:\Windows\System32\wbem\WmiPrvSE.exe

Image =
C:\Windows\System32\cmd.exe

CommandLine =
cmd.exe /Q /c whoami /all ...

User =
IEWIN7\IEUser

A child whoami.exe process was also observed.

### Test Result

MATCHED

The sample contains cmd.exe being spawned by the Windows WMI Provider process.

### False Positive Consideration

Legitimate WMI administration, authorized remote management, and enterprise management software may generate similar process relationships.

### Note

WmiPrvSE.exe spawning cmd.exe is an investigation signal. User, command line, remote authentication, network activity, and surrounding processes should be correlated before classifying the activity as malicious.
---

## Rule 16: New Windows Service Executing Command Shell

**Rule File:** service_cmd_creation.yml
**MITRE ATT&CK:** T1543.003 - Windows Service
**Log Source:** Windows System
**Event ID:** 7045
**Sample:** LM_Remote_Service02_7045.evtx

### Detection Logic

EventID = 7045

AND

ImagePath contains cmd.exe

### Evidence Observed

EventID = 7045

ServiceName = spoolfool

ImagePath = cmd.exe

ServiceType = user mode service

StartType = auto start

AccountName = LocalSystem

A second service named spoolsv was also observed with ImagePath = cmd.exe.

### Test Result

MATCHED

The sample contains Windows service installation events configured to execute cmd.exe.

### False Positive Consideration

Authorized administrative scripts, testing environments, or legitimate service installation workflows may potentially generate similar activity.

### Note

Event ID 7045 with cmd.exe as the service ImagePath is an investigation signal. Service name, account, command, host, and surrounding activity should be correlated before classification.
---

## Rule 17: Member Added to Local Administrators Group

**Rule File:** member_added_to_administrators.yml
**MITRE ATT&CK:** T1098 - Account Manipulation
**Log Source:** Windows Security
**Event ID:** 4732
**Sample:** Network_Service_Guest_added_to_admins_4732.evtx

### Detection Logic

EventID = 4732

AND

TargetUserName = Administrators

AND

TargetDomainName = Builtin

### Evidence Observed

EventID = 4732

TargetUserName = Administrators

TargetDomainName = Builtin

SubjectUserName = IEUser

MemberSid values observed:
- S-1-5-21-3461203602-4096304019-2269080069-501
- S-1-5-20

### Test Result

MATCHED

The sample contains events where members were added to the built-in local Administrators group.

### False Positive Consideration

Authorized administrators, helpdesk operations, software deployment, or legitimate account-management activity may add members to the Administrators group.

### Note

An Event ID 4732 involving the Administrators group is an important investigation signal, but the added account, initiating user, host, and authorization context should also be reviewed.
---

## Rule 18: Remote Desktop Enabled via Registry

**Rule File:** rdp_enabled_registry.yml  
**MITRE ATT&CK:** T1021.001 - Remote Desktop Protocol  
**Log Source:** Windows Sysmon Registry Event  
**Event ID:** 13  
**Sample:** sysmon_13_rdp_settings_tampering.evtx

### Detection Logic

TargetObject ends with:

\Control\Terminal Server\fDenyTSConnections

AND

Details = DWORD (0x00000000)

### Evidence Observed

EventID = 13

Image =
C:\Users\IEUser\Desktop\RDPWrap-v1.6.2\RDPWInst.exe

TargetObject =
HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections

Details =
DWORD (0x00000000)

### Test Result

MATCHED

The sample contains a registry modification that sets
fDenyTSConnections to zero.

### False Positive Consideration

Authorized administrators, remote-support tools, or approved system configuration may legitimately enable Remote Desktop.

### Note

Enabling RDP is not by itself proof of malicious activity. The initiating process, user, host, authentication events, and surrounding network activity should also be investigated.
---

## Rule 19: Windows Defender Threat Action Event

**Rule File:** windows_defender_threat_action.yml
**Log Source:** Microsoft Windows Defender Operational
**Event ID:** 1117
**Sample:** WinDefender_Events_1117_1116_AtomicRedTeam.evtx

### Detection Logic

EventID = 1117

### Evidence Observed

EventID = 1117

Threat Name =
Backdoor:ASP/Ace.T

Process Name =
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Detection User =
MSEDGEWIN10\IEUser

Path =
file:_C:\AtomicRedTeam\atomic-red-team-master\atomics\T1100\shells\cmd.aspx

### Test Result

MATCHED

Windows Defender generated Event ID 1117 for an action associated with a detected threat.

### False Positive Consideration

Security testing, antivirus validation, and authorized malware-simulation exercises may generate similar Defender events.

### Note

Event ID 1117 shows Defender taking action on a detected threat. The threat name, affected path, process, user, and related Defender events should be reviewed during investigation.
---

## Rule 20: Regsvr32 Scrobj DLL Scriptlet Execution

**Rule File:** regsvr32_scrobj_execution.yml
**MITRE ATT&CK:** T1218.010 - Regsvr32
**Log Source:** Windows Sysmon Process Creation
**Event ID:** 1
**Sample:** exec_sysmon_lobin_regsvr32_sct.evtx

### Detection Logic

Image ends with:

\regsvr32.exe

AND

CommandLine contains:
- /i:
- scrobj.dll

### Evidence Observed

EventID = 1

Image =
C:\Windows\System32\regsvr32.exe

CommandLine contains:
/u /s /i:<remote URL> scrobj.dll

ParentImage =
C:\Windows\System32\cmd.exe

User =
IEWIN7\IEUser

### Test Result

MATCHED

The sample contains regsvr32.exe using the /i parameter together with scrobj.dll.

### False Positive Consideration

Authorized administrative activity, software registration, or security testing may generate similar behavior.

### Note

The detection should be investigated using the complete command line, parent process, user, network activity, and surrounding process events.
## Threat Hunt Detection Validation

### Rule 9 - PowerShell LSASS MiniDumpWriteDump Activity

**Test Sample:** `Powershell_4104_MiniDumpWriteDump_Lsass.evtx`

**Result:** PASS

Observed detection:

- Rule ID: 9
- Severity: High
- MITRE ATT&CK: T1003.001
- Event ID: 4104
- Host: MSEDGEWIN10
- Evidence: `Get-Process lsass`
- Evidence: `MiniDumpWriteDump`
- Script Path: `C:\Users\Public\lsass_wer_ps.ps1`

The detection engine successfully identified PowerShell script-block activity associated with LSASS memory-dump behavior.

---

### Rule 15 - Command Shell Spawned by WMI Provider

**Test Sample:** `LM_wmiexec_impacket_sysmon_whoami.evtx`

**Result:** PASS

Test summary:

- Events Parsed: 7
- Total Alerts Detected: 4
- Rule 15 Matches: 3
- Severity: High
- MITRE ATT&CK: T1047
- Event ID: 1
- Host: IEWIN7
- User: IEWIN7\IEUser
- Parent Process: `WmiPrvSE.exe`
- Child Process: `cmd.exe`
- Observed Command: `whoami /all`

The detection engine successfully identified command shells spawned by the WMI Provider process. Multiple matching process-creation events were present in the sample.

---
