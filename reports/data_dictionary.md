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
---

## Log Source 2: Windows Security / Authentication Logs

**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample File:** CA_4624_4625_LogonType2_LogonProc_chrome.evtx  
**Provider:** Microsoft-Windows-Security-Auditing

### Events Analyzed

- Event ID 4625 - Failed Logon
- Event ID 4624 - Successful Logon

## Important Fields

| Field | Example Value | Detection Meaning |
|---|---|---|
| TargetUserName | IEUser | Account involved in the logon activity |
| TargetDomainName | MSEDGEWIN10 | Domain/computer context of the account |
| LogonType | 2 | Interactive logon type |
| LogonProcessName | Chrome | Logon process recorded in the event |
| WorkstationName | MSEDGEWIN10 | Workstation associated with the event |
| ProcessName | chrome.exe | Process associated with the authentication event |
| IpAddress | - | No usable IP value recorded in this event |
| Status | 0xc000006d | Authentication failure status code |
| SubStatus | 0xc000006a | More specific failure status code |

## Initial Observation

A Windows Security Event ID 4625 recorded a failed logon for the IEUser account.

The event used Logon Type 2 and recorded Chrome as the associated logon process.

The dataset also contains Event ID 4624 successful logon events.

A separate Event ID 4624 was observed for the SYSTEM account with Logon Type 5 and services.exe. This represents a different service logon context and should not be mixed with the IEUser event.

Further event correlation is required before making a security classification.
---

## Network Connection Telemetry: Sysmon Event ID 3

**Dataset:** EVTX-ATTACK-SAMPLES  
**Sample File:** tunna_iis_rdp_smb_tunneling_sysmon_3.evtx  
**Provider:** Microsoft-Windows-Sysmon  
**Event ID:** 3 - Network Connection

### Important Fields

| Field | Example Value | Meaning |
|---|---|---|
| UtcTime | 2019-09-03 11:04:05.797 | Time of network connection |
| Image | w3wp.exe | Process associated with the connection |
| User | IIS APPPOOL\DefaultAppPool | Account context of the process |
| Protocol | tcp | Network protocol used |
| SourceIp | 127.0.0.1 | Source IP address |
| SourcePort | 49947 | Source port |
| DestinationIp | 127.0.0.1 | Destination IP address |
| DestinationPort | 3389 | Destination port |
| DestinationHostname | MSEDGEWIN10 | Destination computer name |

### Initial Observation

Sysmon Event ID 3 recorded network connections involving the IIS worker process `w3wp.exe`.

One observed connection was:

w3wp.exe → TCP → 127.0.0.1:49947 → 127.0.0.1:3389

Additional connections involving port 445 were also observed.

These network events require further correlation before making a security classification.
---

## Log Source 3: Zeek Network Logs

**Log Type:** Zeek conn.log  
**Purpose:** Network connection monitoring

### Important Fields

| Field | Example Value | Detection Meaning |
|---|---|---|
| ts | 1591367999.305988 | Connection timestamp |
| uid | C1 | Unique connection identifier |
| id.orig_h | 192.168.4.76 | Originating/source IP address |
| id.orig_p | 36844 | Originating/source port |
| id.resp_h | 192.168.4.1 | Responding/destination IP address |
| id.resp_p | 53 | Responding/destination port |
| proto | udp | Network protocol |
| service | dns | Detected network service |
| duration | 0.066851 | Duration of the connection |
| conn_state | SF | Observed connection state |

### Sample Connection 1

Source:

192.168.4.76:36844

Destination:

192.168.4.1:53

Protocol: UDP  
Service: DNS

### Sample Connection 2

Source:

192.168.4.76:46378

Destination:

31.3.245.133:80

Protocol: TCP  
Service: HTTP

### Initial Observation

The Zeek conn.log records network connection metadata.

It can be used to identify source and destination systems, ports, protocols, services, connection duration, and connection state.

These fields can help detection engineers investigate unusual network communication and correlate network activity with endpoint and authentication telemetry.