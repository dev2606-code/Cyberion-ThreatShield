# Cyberion ThreatShield - Project Architecture

## 1. Overview

Cyberion ThreatShield is a cybersecurity detection engineering and
threat-hunting project designed to analyze Windows security telemetry,
create Sigma detection rules, and investigate suspicious activity.

## 2. Detection Pipeline

EVTX Attack Samples
        ↓
EVTX Parsing
        ↓
XML Event Extraction
        ↓
Security Event Analysis
        ↓
MITRE ATT&CK Mapping
        ↓
Sigma Detection Rules
        ↓
Rule Validation
        ↓
Evidence Testing
        ↓
Threat Hunting
        ↓
Analyst Findings and Reports

## 3. Data Source

The project currently analyzes Windows EVTX telemetry including:

- Sysmon
- Windows Security
- Windows System
- PowerShell Operational
- Windows Defender Operational

## 4. EVTX Parsing

Windows EVTX samples are parsed using Python and python-evtx.

Important fields extracted include:

- EventID
- TimeCreated
- Computer
- User
- Image
- CommandLine
- ParentImage
- ParentCommandLine
- SourceIp
- DestinationIp
- DestinationPort
- TargetObject
- Details
- ScriptBlockText

## 5. Detection Engineering

Observed telemetry is converted into Sigma detection rules.

Each rule contains:

- Title
- UUID
- Description
- Log source
- Detection logic
- Condition
- False-positive considerations
- Severity level
- MITRE ATT&CK mapping where supported

## 6. Rule Validation

Sigma CLI is used to validate the detection rules.

Current status:

Total Sigma Rules: 20
Validation: Passed

## 7. Evidence Testing

Detection logic is compared with fields observed in the EVTX/XML
telemetry.

Evidence is documented in:

reports/rule_test_evidence.md

## 8. Threat Hunting

Two structured threat hunts have been completed.

### Threat Hunt 1

PowerShell LSASS Memory Dump Activity

MITRE ATT&CK:
T1003.001 - OS Credential Dumping: LSASS Memory

### Threat Hunt 2

WMI-Based Command Execution

MITRE ATT&CK:
T1047 - Windows Management Instrumentation

## 9. Reporting Layer

Project reports currently include:

- Rule testing evidence
- Threat Hunt 1
- Threat Hunt 2
- Detection coverage
- Project architecture

## 10. Current Architecture Summary

Windows EVTX
     ↓
Python EVTX Parser
     ↓
XML / Event Evidence
     ↓
Detection Engineering
     ↓
20 Sigma Rules
     ↓
Sigma Validation
     ↓
Evidence Verification
     ↓
Threat Hunting
     ↓
Security Analyst Report

## Conclusion

Cyberion ThreatShield combines telemetry analysis, detection
engineering, MITRE ATT&CK mapping, Sigma rules, and threat hunting
into a structured security-analysis workflow.