# Penetration Test Report

**Client:** Example Corporation  
**Assessment Type:** Internal Network  
**Engagement ID:** PENTEST-2024-001  
**Report Date:** 2026-02-04  
**Version:** 1.0  
**Classification:** CONFIDENTIAL

---

**Assessment Period:** 2024-01-15 to 2024-01-22

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Attack Narrative](#attack-narrative)
4. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
5. [Detailed Findings](#detailed-findings)
6. [Appendix](#appendix)

---


## Executive Summary

Example Corporation engaged a penetration test of their Internal Network environment from 2024-01-15 to 2024-01-22.

### Overall Risk Assessment

**Critical Risk**

The assessment identified critical vulnerabilities that pose immediate risk to the organization. Immediate remediation is strongly recommended.

### Finding Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 1 |
| 🟡 Medium | 1 |
| 🟢 Low | 1 |
| 🔵 Informational | 0 |
| **Total** | **4** |

### Key Findings

1. 🔴 **Domain Admin via Kerberoasting** (CRITICAL)
2. 🟠 **ADCS ESC1 Privilege Escalation** (HIGH)
3. 🟡 **SMB Signing Disabled** (MEDIUM)


## Methodology

The assessment followed a structured methodology aligned with industry standards:

### Assessment Approach

The assessment followed PTES (Penetration Testing Execution Standard) methodology, including reconnaissance, enumeration, vulnerability assessment, exploitation, and post-exploitation phases.

### Scope

Internal network assessment covering 192.168.1.0/24, all Active Directory assets, and internal web applications.

### Testing Team

| Role | Name |
|------|------|
| Penetration Tester | Security Analyst - Bombina AI |
| Penetration Tester | Lead Tester - John Doe |

## Attack Narrative

The following describes the attack path taken during the assessment:


### Phase 1: Initial Foothold

After successful phishing simulation, the testing team obtained valid domain credentials for a standard user account (jdoe).

### Phase 2: Enumeration

BloodHound data collection revealed the Kerberoastable service account (svc_backup) with Domain Admin privileges.

### Phase 3: Privilege Escalation

The svc_backup account was Kerberoasted and cracked, providing Domain Admin access within 4 hours.

### Phase 4: Objective Achievement

With Domain Admin credentials, the team demonstrated access to:
- Domain Controller file systems
- SQL Server databases containing PII
- Backup infrastructure

Additionally, the ADCS vulnerability (ESC1) was identified as an alternative escalation path.



## MITRE ATT&CK® Mapping

The following matrix shows the ATT&CK techniques observed during the assessment:

| Tactic | Techniques Observed |
|--------|---------------------|
| Privilege Escalation | `T1649 - Steal or Forge Authentication Certificates` |
| Credential Access | `T1558.003 - Kerberoasting`, `T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay` |

### Technique Details

- **T1558.003 - Kerberoasting** - 🔴 Found in [FIND-001](#find-001): Domain Admin via Kerberoasting
- **T1649 - Steal or Forge Authentication Certificates** - 🟠 Found in [FIND-002](#find-002): ADCS ESC1 Privilege Escalation
- **T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay** - 🟡 Found in [FIND-003](#find-003): SMB Signing Disabled


---

## Detailed Findings


---

### 🔴 FIND-001: Domain Admin via Kerberoasting

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **Status** | Open |
| **CVSS Score** | 9.8 |
| **CWE** | CWE-521 |

**Affected Assets:**
- `svc_backup@example.local`
- `DC01.example.local`

#### Description

A service account with Domain Admin privileges was configured with a weak password. The account's SPN allowed Kerberoasting, and the password was cracked offline within 4 hours using hashcat.

#### Impact

Complete domain compromise. An attacker could access all domain resources, exfiltrate sensitive data, deploy ransomware, or establish persistent backdoors.

#### Evidence

```
impacket-GetUserSPNs -dc-ip 192.168.1.10 example.local/jdoe
$krb5tgs$23$*svc_backup$EXAMPLE.LOCAL$...[hash truncated]...

hashcat -m 13100 hash.txt rockyou.txt
[CRACKED] Summer2023!
```

#### Remediation

1. Immediately change the svc_backup password to a 25+ character random string
2. Remove unnecessary Domain Admin privileges from service accounts
3. Implement Group Managed Service Accounts (gMSA) for service accounts
4. Enable monitoring for Kerberoasting (Event ID 4769 with encryption type 0x17)

#### MITRE ATT&CK® Mapping

- **Credential Access**: T1558.003 - Kerberoasting

#### References

- https://attack.mitre.org/techniques/T1558/003/
- https://adsecurity.org/?p=2293


---

### 🟠 FIND-002: ADCS ESC1 Privilege Escalation

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **Status** | Open |
| **CVSS Score** | 8.8 |
| **CWE** | CWE-863 |

**Affected Assets:**
- `CA01.example.local`
- `UserAuthentication template`

#### Description

A certificate template 'UserAuthentication' was found with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT enabled, allowing any authenticated user to request certificates for arbitrary users including Domain Admins.

#### Impact

Any domain user can escalate to Domain Admin by requesting a certificate with Domain Admin SAN.

#### Evidence

```
Certify.exe find /vulnerable

[!] Vulnerable Certificate Template: UserAuthentication
    CA Name: CA01.example.local
    Enrollee Supplies Subject: True
    Client Authentication: True
```

#### Remediation

1. Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from the template
2. Restrict enrollment permissions to specific security groups
3. Enable 'CA certificate manager approval' for sensitive templates
4. Implement certificate request monitoring

#### MITRE ATT&CK® Mapping

- **Privilege Escalation**: T1649 - Steal or Forge Authentication Certificates



---

### 🟡 FIND-003: SMB Signing Disabled

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **Status** | Open |
| **CVSS Score** | 5.9 |

**Affected Assets:**
- `192.168.1.50`
- `192.168.1.51`
- `192.168.1.52`

#### Description

SMB signing is not enforced on multiple servers, allowing potential relay attacks.

#### Impact

Attacker can relay NTLM authentication to execute commands on vulnerable servers.

#### Evidence

```
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
[*] 192.168.1.50 - SMB signing: False
[*] 192.168.1.51 - SMB signing: False
[*] 192.168.1.52 - SMB signing: False
```

#### Remediation

Enable and require SMB signing via Group Policy:
- Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
- Set 'Microsoft network server: Digitally sign communications (always)' to Enabled

#### MITRE ATT&CK® Mapping

- **Credential Access**: T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay



---

### 🟢 FIND-004: Default Credentials on Network Device

| Attribute | Value |
|-----------|-------|
| **Severity** | LOW |
| **Status** | Open |
| **CVSS Score** | 3.1 |

**Affected Assets:**
- `192.168.1.200 (HP LaserJet)`

#### Description

A network printer was found using default credentials.

#### Impact

Limited impact - printer configuration could be modified.

#### Evidence

```
Default credentials admin:admin allowed access to printer web interface.
```

#### Remediation

Change default credentials on all network devices.



---

## Appendix

### Severity Rating Definitions

| Rating | Description |
|--------|-------------|
| 🔴 Critical | Immediate exploitation possible with significant business impact. Requires immediate attention. |
| 🟠 High | Exploitation possible with notable impact. Should be addressed within 30 days. |
| 🟡 Medium | Exploitation possible with moderate impact. Should be addressed within 90 days. |
| 🟢 Low | Exploitation difficult or impact limited. Address as resources permit. |
| 🔵 Informational | Best practice recommendation or observation. No direct security impact. |

### Disclaimer

This report contains confidential information about the security posture of Example Corporation. Distribution should be limited to authorized personnel. The findings represent point-in-time observations and may not reflect the current state of the environment.

---

*Report generated by Bombina Report Generator*
