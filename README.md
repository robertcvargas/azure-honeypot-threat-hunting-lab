# Azure Honeypot Threat Hunting Lab 🕵️‍♂️

An Azure-hosted MySQL honeypot built to practice detection engineering, log analysis, and DFIR against a live, unscripted breach. Rather than working from a canned dataset, this lab exposed a real database to the internet, captured real attacker activity, and used that traffic to build and tune detection rules in Microsoft Sentinel.

![Honeypot Architecture](images/HoneyPot%20Architecture.png)

Built on the lognpacific cyber-range platform, then extended with custom detection rules, DFIR analysis, and incident write-ups.

## Overview

- **Target:** Azure VM (`corp-sql-server`) running MySQL, deliberately exposed with weak credentials (`root`/`root`) to attract attacker traffic
- **Telemetry:** MySQL audit logs ingested into Log Analytics, plus endpoint telemetry from Microsoft Defender for Endpoint (MDE)
- **Detection:** Custom KQL analytics rules in Microsoft Sentinel, tuned against observed attacker behavior
- **Outcome:** Confirmed a live ransomware deployment and a separate interactive RDP compromise, both traced and documented from raw logs through to a written incident report

## Lab Environment

| Component | Details |
|---|---|
| Host | Azure VM — ARM resource name `corp-sql-server1`, OS hostname `corp-sql-server` |
| Database | MySQL, general query logging enabled (`general_log=1` in `my.ini`) |
| Log pipeline | Data Collection Rule (DCR) ingesting MySQL audit logs into a custom `MySQLAudit_CL` table |
| Credentials | Intentionally weak: `root`/`root`, exposed as both `'root'@'%'` and `'root'@'localhost'` |
| Background noise | Scheduled cyber-range simulation scripts (port scans, EICAR test files, simulated ransomware) run every ~12 minutes and were explicitly filtered out of attacker attribution |

> **Note on naming:** the OS hostname is truncated to 15 characters by the Windows NetBIOS limit during VM provisioning, while the ARM resource name is not. MDE tables (`DeviceLogonEvents`, `DeviceInfo`) reference the OS hostname; Azure Monitor tables (`MySQLAudit_CL`) reference the ARM resource name in `_ResourceId`. This mismatch was a recurring source of confusion early on — always verify the actual `DeviceName` with a quick `DeviceInfo | distinct DeviceName` query rather than assuming it.

## Detection Engineering

Sentinel analytics rules were tuned to the attack pattern actually observed in this environment — brute-force attempts escalating to a successful breach within roughly 5 minutes:

- **Query frequency:** every 5 minutes
- **Lookback period:** 5–10 minutes
- **Alert suppression:** 1 hour
- **Incident grouping:** all matching events grouped into a single incident over a 1-hour window

Example detection logic (simplified):

```kql
// Successful logons to privileged accounts on the honeypot host
DeviceLogonEvents
| where DeviceName =~ "corp-sql-server"
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

```kql
// MySQL authentication events scoped to the honeypot resource
MySQLAudit_CL
| where _ResourceId endswith "corp-sql-server1"
| where Event_class_s =~ "connect"
| project TimeGenerated, _ResourceId, User_s, Status_s, IP_s
```

A couple of hard-won KQL lessons baked into these queries:
- Use `=~` instead of `==` for string comparisons — logging sources are inconsistent about case
- `endswith` requires the *full* correct suffix (including trailing characters like the `1` in `corp-sql-server1`); `contains` is looser but can mask an underlying naming mismatch instead of catching it

## Investigation & Key Findings

Analysis pulled from six telemetry sources — MySQL auth and query logs, `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceRegistryEvents` — along with two MDE live-response DFIR packages compared pre- and post-breach.

**Confirmed ransomware deployment**
Traced a MySQL-targeted ransomware attack originating from `64.89.163.141` (same /24 subnet as a prior incident, suggesting a repeat actor or shared infrastructure). The attacker dropped the database, left two ransom notes with distinct BTC wallet addresses, and ran anti-forensic cleanup (`PURGE BINARY LOGS`, `RESET MASTER`) before issuing a `SHUTDOWN`.

**Confirmed interactive RDP compromise**
Identified a successful interactive RDP logon to the administrator account from `141.98.80.88` at 03:37 AM on Sep 3. No follow-on persistence or destructive activity was found in the available telemetry for this session.

**Commodity credential stuffing**
Multiple source IPs ran a generic `sa`/`admin`/`root` probe sequence consistent with automated, multi-database scanning tools rather than targeted attacks.

**Anomalous non-brute-force session**
A session from `102.218.58.66` produced roughly 70 rapid, *successful* connections — a pattern distinct from brute-forcing, worth flagging separately rather than folding into the credential-stuffing bucket.

**New IOC surfaced through DFIR comparison**
`112.186.10.67` showed a high failed-logon count in the DFIR packages but was completely absent from the standard MDE table exports — only visible by directly comparing the pre/post-breach forensic packages.

**MDE telemetry undersampling**
Comparing raw `Security.evtx` records against `DeviceLogonEvents` showed one IP with roughly 59x more login attempts in the raw event log than what surfaced in MDE's own table — a reminder that MDE tables alone can significantly undercount attacker activity, and raw DFIR packages are necessary for full fidelity.

## Lessons Learned

- Always verify hostname/resource-name mapping empirically rather than assuming consistency across log sources
- String matching in KQL needs to account for case and suffix precision, or detections silently miss events
- Scheduled background "noise" (lab simulation scripts, in this case) needs to be explicitly excluded before attributing activity to a real attacker
- Table-based EDR telemetry can undersample real attacker activity — raw forensic packages remain necessary for a complete picture
- Suppression and grouping windows should be derived from the *observed* attack tempo, not left at defaults

## Tools & Stack

`Azure (VMs, NSG, Log Analytics, DCR, Run Command)` · `Microsoft Sentinel` · `Microsoft Defender for Endpoint` · `MySQL` · `KQL`
