# Cyberion ThreatShield - MITRE ATT&CK Mapping

## Technique 1: Windows Command Shell

**Technique ID:** T1059.003  
**Tactic:** Execution  
**Technique:** Command and Scripting Interpreter: Windows Command Shell

### Why Selected

Our Sysmon process telemetry contains cmd.exe process execution.

Observed process relationship:

ftp.exe
   ↓
cmd.exe
   ↓
command involving calc.exe

Windows Command Shell telemetry is useful for detecting or hunting unusual command execution and suspicious parent-child process relationships.

### Relevant Log Source

Windows Sysmon - Process Creation

### Important Detection Fields

- Image
- CommandLine
- ParentImage
- ParentCommandLine
- User
- UtcTime

### Note

The presence of cmd.exe alone does not prove malicious activity. Additional context and correlation are required before classifying the activity as malicious.
---

## Technique 2: Brute Force

**Technique ID:** T1110  
**Tactic:** Credential Access  
**Technique:** Brute Force

### Why Selected

Windows Security authentication telemetry can be used to identify repeated failed logon attempts.

Our analyzed sample contains:

- Event ID 4625 - Failed Logon
- Event ID 4624 - Successful Logon
- TargetUserName
- LogonType
- WorkstationName
- ProcessName
- Status and SubStatus

These fields are useful for detecting patterns such as multiple failed authentication attempts and a possible later successful logon.

### Relevant Log Source

Windows Security / Authentication Logs

### Important Detection Fields

- EventID
- TargetUserName
- TargetDomainName
- LogonType
- WorkstationName
- IpAddress
- Status
- SubStatus
- TimeCreated

### Note

A single failed logon does not indicate a brute-force attack.

Brute-force detection requires a repeated or iterative pattern of authentication attempts and additional context.
---

## Technique 3: Remote Desktop Protocol

**Technique ID:** T1021.001
**Tactic:** Lateral Movement
**Technique:** Remote Services: Remote Desktop Protocol

### Why Selected

Our network telemetry contains connections involving destination port 3389.

One observed connection was:

w3wp.exe
   ↓
TCP
   ↓
127.0.0.1:49947
   ↓
127.0.0.1:3389

Port 3389 is associated with Remote Desktop Protocol (RDP).

RDP telemetry is useful for detecting or hunting unusual remote access and lateral movement activity.

### Relevant Log Sources

- Windows Sysmon Event ID 3 - Network Connection
- Windows Security Authentication Logs

### Important Detection Fields

- SourceIp
- SourcePort
- DestinationIp
- DestinationPort
- Image
- User
- Protocol
- LogonType
- UtcTime

### Note

A connection to port 3389 alone does not prove malicious RDP activity.

Additional authentication, process, host, and network context should be correlated before classifying the activity as malicious.
---

## Technique 4: Application Layer Protocol

**Technique ID:** T1071
**Tactic:** Command and Control
**Technique:** Application Layer Protocol

### Why Selected

Our Zeek network telemetry contains application-layer services such as HTTP and DNS.

Observed examples include:

- TCP traffic using HTTP
- UDP traffic using DNS

Application-layer network telemetry can help identify unusual communication patterns that may require investigation.

### Relevant Log Source

Zeek Network Logs - conn.log

### Important Detection Fields

- id.orig_h
- id.orig_p
- id.resp_h
- id.resp_p
- proto
- service
- duration
- conn_state
- ts

### Note

Normal HTTP or DNS traffic does not indicate Command and Control activity.

Additional evidence, behavioral patterns, destinations, frequency, and other telemetry must be analyzed before classifying communication as malicious.
---

## Technique 5: Network Service Discovery

**Technique ID:** T1046
**Tactic:** Discovery
**Technique:** Network Service Discovery

### Why Selected

Our project includes network telemetry from Zeek conn.log and Sysmon Event ID 3.

These logs provide information about:

- Source IP addresses
- Destination IP addresses
- Source and destination ports
- Network protocols
- Network services
- Processes associated with network connections

This telemetry can be used to hunt for patterns such as one system connecting to multiple hosts or multiple ports in a short period of time.

### Relevant Log Sources

- Zeek Network Logs
- Windows Sysmon Event ID 3

### Important Detection Fields

- SourceIp / id.orig_h
- DestinationIp / id.resp_h
- DestinationPort / id.resp_p
- Protocol / proto
- service
- Image
- User
- UtcTime / ts

### Note

A single network connection does not indicate Network Service Discovery.

Multiple connection attempts, destination hosts, ports, timing, process information, and environmental context should be analyzed before classifying activity as suspicious.