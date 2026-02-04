#!/usr/bin/env python3
"""
Active Directory Attack Extractor for Bombina
Generates high-quality training samples for AD/Entra attacks
Focus: Kerberos attacks, delegation abuse, ADCS, lateral movement

Usage: python extract_ad.py
"""

import json
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "datasets" / "ad_attacks"

# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVE DIRECTORY ATTACK KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

AD_ATTACKS = [
    # KERBEROS ATTACKS
    {
        "name": "Kerberoasting",
        "technique": "Request TGS for SPNs, crack offline",
        "category": "credential_access",
        "reasoning": """Kerberoasting targets service accounts with SPNs (Service Principal Names). Any authenticated domain user can request a TGS ticket for any SPN. The ticket is encrypted with the service account's password hash - extract and crack offline. Detection: Large numbers of TGS requests for SPNs is anomalous. Stealth approach: Request tickets slowly over time, target specific high-value SPNs rather than all SPNs. Tool selection: Rubeus kerberoast is common but has signatures - consider impacket GetUserSPNs.py or manual PowerShell. Focus on service accounts with weak passwords and adminCount=1 (privileged accounts).""",
        "constraints": "Requires domain authentication, targets service accounts"
    },
    {
        "name": "AS-REP Roasting",
        "technique": "Request AS-REP for accounts without pre-auth",
        "category": "credential_access",
        "reasoning": """Accounts with 'Do not require Kerberos preauthentication' enabled return AS-REP with data encrypted using the account's password hash. Can be requested without any authentication for known usernames. Detection: AS-REQ without preauthentication is logged (Event ID 4768). Stealth: This is quiet compared to Kerberoasting since you don't need to authenticate first. Enumerate DONT_REQ_PREAUTH accounts via LDAP. Common on legacy accounts or service accounts with compatibility requirements. Crack using hashcat mode 18200.""",
        "constraints": "Requires accounts with Kerberos preauth disabled"
    },
    {
        "name": "Golden Ticket",
        "technique": "Forge TGT using KRBTGT hash",
        "category": "persistence",
        "reasoning": """With the KRBTGT account hash, forge TGTs for any user including non-existent users. Provides complete domain control and persistence surviving password changes (until KRBTGT is rotated twice). Detection: Anomalous TGT lifetimes, forged PAC data, authentication from unusual sources. Requires initial domain compromise to obtain KRBTGT hash via DCSync or DC memory access. Stealth: Use legitimate user accounts rather than built-in admin. Match normal TGT lifetime (10 hours default). Detection risk is high if security monitoring is mature - behavioral analytics can detect Golden Ticket use.""",
        "constraints": "Requires KRBTGT hash (domain compromise prerequisite)"
    },
    {
        "name": "Silver Ticket",
        "technique": "Forge TGS using service account hash",
        "category": "persistence",
        "reasoning": """Forge service tickets using the service account's password hash. More targeted than Golden Ticket - grants access only to specific service. Does not touch DC during authentication - harder to detect. Detection: Tickets without corresponding TGT, anomalous service access patterns. Common targets: CIFS for file share access, LDAP for directory queries, HTTP for web services. Stealth: Silver Tickets never contact the DC, making detection harder. But service logs show the access. Best used for targeted data access rather than broad lateral movement.""",
        "constraints": "Requires service account hash, limited to specific service"
    },
    {
        "name": "DCSync",
        "technique": "Replicate AD credentials via DRSUAPI",
        "category": "credential_access",
        "reasoning": """Abuse replication privileges to request password hashes directly from DC without touching LSASS. Requires: Replicating Directory Changes + Replicating Directory Changes All (typically Domain Admin or specific delegation). Detection: Event ID 4662 with specific GUIDs for replication. Very noisy in monitored environments. Stealth: Target specific accounts rather than full domain dump. Timing during backup windows may blend with legitimate replication. If DCSync is detected, consider alternative credential access via LSASS on endpoints instead.""",
        "constraints": "Requires replication privileges (high privilege prerequisite)"
    },
    
    # DELEGATION ATTACKS
    {
        "name": "Unconstrained Delegation Abuse",
        "technique": "Capture TGTs from connecting users",
        "category": "lateral_movement",
        "reasoning": """Servers with unconstrained delegation cache TGTs of connecting users. Compromise the server → extract TGTs from memory → impersonate users including admins. Coercion techniques: Force high-privilege accounts to authenticate (PrinterBug, PetitPotam). Detection: Unusual authentication patterns, TGT use from unexpected sources. Stealth: Printer Bug coercion is common and may be overlooked. PetitPotam is newer and more likely monitored. Focus on servers where admin authentication is expected (file servers, management servers). LAPS deployment complicates but doesn't prevent.""",
        "constraints": "Requires compromised server with unconstrained delegation"
    },
    {
        "name": "Constrained Delegation Abuse",
        "technique": "S4U2Self + S4U2Proxy",
        "category": "lateral_movement",
        "reasoning": """Accounts with constrained delegation can impersonate users to specific services. S4U2Self obtains ticket as any user to self. S4U2Proxy forwards to allowed service. If TRUSTED_TO_AUTH_FOR_DELEGATION set, can impersonate protected users. Detection: Service-for-User extensions in Kerberos logs. Tool: Rubeus s4u. Enumeration: Find accounts with msDS-AllowedToDelegateTo attribute populated. The attack is service-specific but can be powerful if delegation targets CIFS, LDAP, or HTTP on sensitive servers.""",
        "constraints": "Requires account with constrained delegation configured"
    },
    {
        "name": "Resource-Based Constrained Delegation (RBCD)",
        "technique": "Write msDS-AllowedToActOnBehalfOfOtherIdentity",
        "category": "lateral_movement",
        "reasoning": """If you can write to msDS-AllowedToActOnBehalfOfOtherIdentity on a computer, configure RBCD to allow controlled computer to impersonate users to target. Common escalation path: compromise user → create machine account → configure RBCD → impersonate admin to target. Requires: Write access to target computer object, any computer account we control. Detection: Attribute modification logged. Stealth: RBCD is newer and less monitored than traditional delegation. Machine account creation has quota (default 10) but is not suspicious. Very powerful when combined with LAPS abuse or workstation compromise.""",
        "constraints": "Requires write access to target computer's AD object"
    },
    
    # ADCS ATTACKS
    {
        "name": "ESC1 - Enrollee Supplies Subject",
        "technique": "Request certificate with arbitrary SAN",
        "category": "privilege_escalation",
        "reasoning": """If certificate template allows enrollee to specify Subject Alternative Name (SAN), request certificate for any user (e.g., Domain Admin). Template vulnerable if: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag set, enrollment rights granted to attackable principal, client authentication EKU. Detection: Certificate requests with non-matching subject. Tool: Certify.exe find /vulnerable, then Certify.exe request. This is currently one of the most powerful AD escalation paths. Stealth: Certificate issuance is logged but often not monitored. Use certificate immediately and don't persist if stealth is priority.""",
        "constraints": "Requires vulnerable certificate template"
    },
    {
        "name": "ESC4 - Vulnerable Template ACL",
        "technique": "Modify certificate template",
        "category": "privilege_escalation", 
        "reasoning": """If you have write access to a certificate template, modify it to enable ESC1 conditions (supply subject, client auth EKU). Requires: WriteProperty or WriteDacl on template object. Modify template → request cert as admin → revert template. Detection: Template modification is logged. Stealth: Rapid modification, request, and revert reduces detection window. ADCS misconfigurations are common because templates are complex and often misconfigured during setup.""",
        "constraints": "Requires write access to certificate template"
    },
    {
        "name": "ESC8 - NTLM Relay to ADCS HTTP",
        "technique": "Relay NTLM to Certificate Authority",
        "category": "privilege_escalation",
        "reasoning": """Relay NTLM authentication to ADCS web enrollment endpoint to obtain certificate as relayed user. Coerce high-privilege account to authenticate to attacker → relay to http://ca/certsrv → obtain admin certificate. Detection: Web enrollment logs show request source. Requires: Web enrollment enabled on CA, ability to coerce authentication. Stealth: Coercion + relay is noisy. PetitPotam coercion is monitored in mature environments. Success depends on speed - authentication coercion to certificate issuance before detection.""",
        "constraints": "Requires ADCS web enrollment, coercion capability"
    },
    
    # CREDENTIAL ACCESS
    {
        "name": "LSASS Memory Extraction",
        "technique": "Dump LSASS process memory",
        "category": "credential_access",
        "reasoning": """LSASS process contains cached credentials, Kerberos tickets, and NTLM hashes. Classic target but heavily monitored. Detection: Process access to LSASS (Sysmon Event 10), suspicious minidump creation. EDR products specifically monitor LSASS. Stealth alternatives: 1) Nanodump - uses syscalls to avoid userland hooks. 2) HandleKatz - duplicates handles instead of direct access. 3) Credential Guard bypass if applicable. 4) Target endpoints rather than servers - less monitoring. 5) Use comsvcs.dll MiniDump via rundll32. Each method has tradeoffs between reliability and detection.""",
        "constraints": "Requires local admin, heavily monitored by EDR"
    },
    {
        "name": "DPAPI Abuse",
        "technique": "Decrypt domain DPAPI secrets",
        "category": "credential_access",
        "reasoning": """DPAPI protects credentials stored by Windows applications. Domain backup key on DC can decrypt any domain user's DPAPI blobs. Target: Chrome passwords, RDP credentials, scheduled task credentials. Requires: Domain backup key (lsadump::backupkeys) or user's password. Detection: Backup key extraction from DC is logged. Stealth: DPAPI abuse on endpoints is quieter - if you have user context, decrypt their blobs locally. Domain backup key extraction is high-value but high-risk. Consider targeting specific users' DPAPI after workstation compromise.""",
        "constraints": "Requires domain backup key or user password"
    },
    {
        "name": "AD Connect Password Extraction",
        "technique": "Extract sync account credentials",
        "category": "credential_access",
        "reasoning": """Azure AD Connect stores credentials for directory synchronization. AADInternals can extract: MSOL service account (has DCSync rights), Azure AD sync account. Requires: Local admin on AD Connect server. Detection: Registry and file access on AD Connect server. This is a critical target in hybrid environments - provides path from on-prem to cloud or enables DCSync without Domain Admin. Stealth: Low visibility once on the server. The initial access to AD Connect server is the monitored phase.""",
        "constraints": "Requires local admin on AD Connect server"
    },
    
    # GROUP POLICY
    {
        "name": "GPO Abuse",
        "technique": "Modify Group Policy Objects",
        "category": "persistence",
        "reasoning": """GPO modification provides persistence and lateral movement. If you have write access to GPO linked to target OUs: deploy scheduled tasks, startup scripts, or credential harvesting. Enumeration: BloodHound shows GPO attack paths. Detection: GPO modifications are logged (Event 5136, 5137). Stealth: Modify existing scheduled tasks rather than creating new. Use GPOs linked to specific OUs rather than Default Domain Policy. Immediate scripts are more detectable than scheduled tasks with delayed execution.""",
        "constraints": "Requires write access to GPO"
    },
    {
        "name": "GPP Credential Harvesting",
        "technique": "Extract credentials from Group Policy Preferences",
        "category": "credential_access",
        "reasoning": """Legacy GPP stored encrypted passwords in SYSVOL with published key (MS14-025). Any domain user can read SYSVOL. Modern environments shouldn't have these, but legacy policies persist. Detection: SYSVOL access is normal - extraction is not detectable. Search: Groups.xml, Services.xml, Scheduledtasks.xml, Datasources.xml. Tool: Get-GPPPassword. Low-risk, high-reward reconnaissance activity. Even patched environments may have old policies that were never removed.""",
        "constraints": "Requires legacy GPP passwords to exist"
    },
    
    # TRUST ATTACKS
    {
        "name": "Cross-Forest SID History Injection",
        "technique": "Add SID to SIDHistory for cross-forest access",
        "category": "lateral_movement",
        "reasoning": """With appropriate privileges in one forest, inject SIDs from trusted forest into SIDHistory. When authenticating across trust, SIDHistory SIDs are included in token. Requires: Domain Admin in source forest, trust without SID Filtering. Detection: SIDHistory modification is logged. SID Filtering should prevent this - check trust properties. If Quarantine is disabled (SID Filtering off), cross-forest escalation is possible. Valuable for attacking parent/child domain trusts and acquisitions with forest trusts.""",
        "constraints": "Requires Domain Admin, trust without SID Filtering"
    },
    {
        "name": "Trust Ticket Attack",
        "technique": "Forge inter-realm TGT",
        "category": "lateral_movement",
        "reasoning": """With trust key, forge inter-realm TGT to access trusted domain. Enumerate trust: nltest /domain_trusts. Extract trust key: lsadump::trust on DC. Forge ticket with appropriate SIDs for access to trusted domain. Detection: Anomalous inter-realm authentication. This provides access across trusts without compromising the target domain directly. Stealth: Inter-realm authentication is normal for users accessing cross-domain resources - blend with legitimate traffic patterns.""",
        "constraints": "Requires trust key extraction"
    }
]

# ═══════════════════════════════════════════════════════════════════════════════
# DEFENSE EVASION & DETECTION SAMPLES
# ═══════════════════════════════════════════════════════════════════════════════

AD_DEFENSE_SAMPLES = [
    {
        "instruction": "You're conducting an internal AD pentest. EDR is deployed on all endpoints with LSASS protection.",
        "input": "Need credentials but traditional LSASS dump will be detected. What alternatives?",
        "output": "With EDR protecting LSASS, pivot to alternative credential sources: 1) Kerberoasting - no endpoint detection, attacks service accounts offline. 2) AS-REP Roasting - similar offline attack for accounts without preauth. 3) DPAPI extraction - less monitored than LSASS, can get Chrome passwords, RDP creds. 4) Cached credentials in registry (SECURITY hive) - requires offline extraction or local admin. 5) Targeted phishing for specific user credentials. 6) Check for credential files (unattend.xml, scripts with passwords). 7) Network credential capture (Responder if on same VLAN). The goal is finding credentials without touching LSASS. Prioritize Kerberoasting as it's quiet and effective against service accounts."
    },
    {
        "instruction": "You've obtained Domain Admin through ADCS ESC1. How do you maintain persistence while avoiding detection?",
        "input": "Security team has SIEM with alerts on Domain Admin usage. Need stealth persistence.",
        "output": "Persistence after Domain Admin access with detection avoidance: 1) Create inconspicuous service account with DCSync rights rather than using Domain Admins - less monitored. 2) Certificate-based persistence - issue long-lived certificate for your service account. 3) Add controlled computer to Domain Controllers OU with constrained delegation - unusual but powerful. 4) RBCD configuration on sensitive servers - modify msDS-AllowedToActOnBehalfOfOtherIdentity. 5) Skeleton Key on DC - allows any password authentication, but requires service restart to remove. 6) Shadow Credentials - add Key Credential to admin account for certificate-based auth. Avoid: Adding users to Domain Admins (heavily monitored), Golden Ticket use (behavioral detection), obvious service accounts. Prioritize certificate and delegation-based persistence."
    },
    {
        "instruction": "BloodHound shows path to Domain Admin via constrained delegation. Path is 4 hops. Analyze the attack chain.",
        "input": "Compromised user → Server A (unconstrained) → Service Account (constrained to DC) → Domain Admin via S4U → DCSync",
        "output": "Attack chain analysis: Hop 1 (User → Server A): Need to compromise Server A with unconstrained delegation. Check for local admin via group membership or vulnerability. If server has LAPS, need to extract LAPS password. Hop 2 (Server A → Service Account): Unconstrained delegation captures TGTs. Coerce authentication from service account using PrinterBug or access service that authenticates back. Hop 3 (S4U to DC): With service account hash and constrained delegation to DC, use Rubeus s4u to impersonate Domain Admin to LDAP service. Hop 4 (DCSync): With Domain Admin TGS to DC LDAP, perform DCSync. Detection points: Coercion is detectable, S4U extensions logged, DCSync very visible. Timing: Execute rapidly to minimize detection window. Alternative: If first hop is risky, look for shorter paths in BloodHound."
    },
    {
        "instruction": "SMB Signing is enforced across the domain. How does this affect your attack approach?",
        "input": "Compromised workstation, need lateral movement. NTLM relay blocked by SMB signing.",
        "output": "SMB Signing mitigation adjustment: Relay attacks to SMB are blocked, but alternatives exist: 1) Relay to LDAP/LDAPS - often lacks signing requirement. Use for Shadow Credentials or RBCD attack. 2) Relay to HTTP services - ADCS web enrollment (ESC8), Exchange, SCCM. 3) Pass-the-Hash directly - signing doesn't prevent PTH, only relay. 4) Kerberos-based movement - overpass-the-hash, pass-the-ticket don't require SMB relay. 5) WMI/WinRM lateral movement - different protocol entirely. 6) Check for legacy systems without signing - older servers may not enforce. SMB signing blocks one technique but doesn't prevent lateral movement. Adjust tools: Use impacket ntlmrelayx with LDAP target, or switch to Kerberos-based authentication for lateral movement."
    },
    {
        "instruction": "Target AD environment uses Credential Guard on all DCs and sensitive servers.",
        "input": "Standard LSASS dump returns empty results on Credential Guard systems. How to proceed?",
        "output": "Credential Guard isolates secrets in VSM - LSASS dump is ineffective. Approaches: 1) Target non-CG systems first - workstations often lack Credential Guard. 2) Kerberos attacks bypass CG entirely - Kerberoasting, AS-REP roasting, delegation abuse work regardless. 3) DPAPI extraction still works - Chrome passwords, RDP creds are not protected by CG. 4) DCSync works if you have replication rights - doesn't touch LSASS. 5) ADCS attacks - certificate-based authentication bypasses CG. 6) Shadow Credentials attack - Key Credential to msDS-KeyCredentialLink works against CG-protected accounts. 7) Network credential capture - Responder, relay attacks capture auth in transit. Key insight: Credential Guard protects LSASS memory but doesn't protect against Kerberos protocol abuse or authentication relay. Pivot strategy to these alternatives."
    }
]


def generate_ad_samples() -> List[Dict]:
    """Generate training samples from AD attack knowledge."""
    samples = []
    
    # Core attack samples
    for attack in AD_ATTACKS:
        # Standard attack reasoning
        samples.append({
            "instruction": f"You are conducting an Active Directory penetration test.",
            "input": f"Considering {attack['name']} ({attack['technique']}). Constraints: {attack['constraints']}. Analyze this attack path.",
            "output": attack['reasoning']
        })
        
        # Decision-making sample
        samples.append({
            "instruction": f"Evaluate whether to use {attack['name']} in current engagement.",
            "input": f"Category: {attack['category']}. Technique: {attack['technique']}. What factors determine if this is the right approach?",
            "output": f"Decision factors for {attack['name']}: {attack['reasoning'][:400]}... Consider: 1) Do we meet the constraints ({attack['constraints']})? 2) What's the detection risk vs. reward? 3) Are there quieter alternatives in the same category ({attack['category']})? 4) What access does success provide? Always enumerate current position thoroughly before committing to attack path."
        })
        
        # Failure handling
        samples.append({
            "instruction": f"Your {attack['name']} attack failed or was blocked.",
            "input": f"The {attack['technique']} technique didn't work as expected. What now?",
            "output": f"When {attack['name']} fails: 1) Analyze why - missing permissions, detection/blocking, or misconfiguration? 2) Check constraints: {attack['constraints']} - are these actually met? 3) Alternative techniques in {attack['category']} category should be considered. 4) Adjust detection tolerance - was it blocked by security controls or just incorrect execution? 5) Document the failure for reporting - blocked attacks inform defensive posture. Don't retry immediately if detected - reassess operational security."
        })
    
    # Defense awareness samples
    samples.extend(AD_DEFENSE_SAMPLES)
    
    return samples


def main():
    """Generate and save AD attack samples."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA ACTIVE DIRECTORY EXTRACTOR
   Generating AD/Kerberos/ADCS training samples
═══════════════════════════════════════════════════════════════════
""")
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    samples = generate_ad_samples()
    
    output_file = OUTPUT_DIR / "ad_samples.jsonl"
    with open(output_file, 'w') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"✅ Generated {len(samples)} AD attack samples")
    print(f"📁 Output: {output_file}")


if __name__ == "__main__":
    main()
