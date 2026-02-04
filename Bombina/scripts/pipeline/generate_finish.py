#!/usr/bin/env python3
"""
Finish Line Generator - Final 200+ unique samples
"""

import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_specific_attack_samples():
    """Generate specific attack technique samples"""
    samples = []
    
    attacks = [
        ("pass the ticket", "Kerberos authentication using stolen ticket instead of password. Use Mimikatz or Rubeus to export/import tickets. Works when password unknown but ticket available."),
        ("overpass the hash", "Use NTLM hash to request Kerberos ticket. Combines pass-the-hash with Kerberos. Use Rubeus asktgt or Mimikatz sekurlsa::pth."),
        ("DCSync attack", "Simulate domain controller replication to extract credentials. Requires Replicating Directory Changes rights. Use Mimikatz lsadump::dcsync."),
        ("skeleton key attack", "Inject into LSASS to allow any password alongside real one. Provides domain-wide backdoor. Requires DA and physical access."),
        ("DCShadow attack", "Register rogue DC to make unauthorized directory changes. Stealthier than DCSync. Complex to execute, requires high privileges."),
        ("Zerologon exploitation", "CVE-2020-1472 allows setting DC machine account password to empty. Provides path to domain admin. Critical severity."),
        ("PrintNightmare", "CVE-2021-34527 allows RCE via Windows Print Spooler. Multiple variants. Can escalate privileges or achieve RCE remotely."),
        ("PetitPotam attack", "Coerce Windows host to authenticate to attacker. Use for NTLM relay. No authentication required in original version."),
        ("RBCD attack", "Resource-Based Constrained Delegation abuse. Grant computer write access to impersonate users. Useful for privilege escalation."),
        ("shadow credentials", "Add msDS-KeyCredentialLink to user/computer for auth without password. Requires GenericWrite. Persist access stealthily."),
        ("DPAPI extraction", "Extract credentials protected by Data Protection API. Backup keys on DC, user keys in profile. Use Mimikatz or SharpDPAPI."),
        ("LSA secrets dump", "Extract secrets from LSA registry. Contains service accounts, autologon creds. Requires SYSTEM. Use secretsdump or Mimikatz."),
        ("SAM database extraction", "Dump local user hashes from SAM file. Requires SYSTEM. Use reg save, secretsdump, or volume shadow copy."),
        ("NTDS.dit extraction", "Domain controller database with all password hashes. Use ntdsutil, secretsdump, or vssadmin for volume shadow copy."),
        ("group policy preferences", "GPP stored creds in SYSVOL were encrypted with published key. Historical finding. Use Get-GPPPassword."),
        ("constrained delegation abuse", "Impersonate users to configured services. Check msDS-AllowedToDelegateTo. Use Rubeus s4u for impersonation."),
        ("unconstrained delegation", "Host can impersonate any user to any service. Force auth from target, capture and use TGT. Very powerful."),
        ("ADCS attack ESC1", "Certificate template allows requester to specify SAN. Request cert as any user. Domain compromise path."),
        ("ADCS ESC8 attack", "NTLM relay to AD CS HTTP enrollment. Obtain certificate for relayed account. Use petitpotam + ntlmrelayx."),
        ("token impersonation", "Use stolen or duplicated tokens to operate as another user. Requires SeImpersonate or SeAssignPrimaryToken privilege."),
        ("potato attacks", "Various privilege escalation techniques using token impersonation. JuicyPotato, PrintSpoofer, RoguePotato, GodPotato."),
        ("named pipe impersonation", "Create pipe that privileged process connects to. Impersonate connecting user. Classic Windows privesc technique."),
        ("dll hijacking", "Place malicious DLL where vulnerable program searches. Application loads your DLL instead. Check missing DLLs with procmon."),
        ("unquoted service path", "Service path with spaces and no quotes allows DLL injection. Example: C:\\Program Files\\App\\service.exe runs C:\\Program.exe first."),
        ("weak service permissions", "Modify service binary path or configuration. Requires SERVICE_CHANGE_CONFIG or write to binary location."),
        ("alwaysinstallelevated", "GPO allowing any user to install MSI with SYSTEM. Create malicious MSI for instant SYSTEM shell."),
        ("registry autorun exploitation", "Add malicious entry to Run/RunOnce keys. Executes at login. Persistence technique, sometimes privesc."),
        ("scheduled task abuse", "Create or hijack scheduled tasks. Check for weak permissions on task files or folders."),
        ("environment variable injection", "Modify PATH or other variables to hijack execution. Works with relative paths in scripts."),
        ("sudo token reuse", "Linux /proc/[pid]/mem manipulation to inject into existing sudo session. Requires specific kernel versions."),
    ]
    
    for technique, description in attacks:
        samples.append({
            "instruction": f"Explain how {technique} works in penetration testing.",
            "input": "",
            "output": description
        })
    
    return samples


def generate_defense_evasion_samples():
    """Defense evasion samples"""
    samples = []
    
    evasions = [
        ("avoid antivirus detection", "Methods: custom compiled payloads, obfuscation, encryption, living-off-the-land, process injection, in-memory execution. Test against target AV in lab."),
        ("bypass application whitelisting", "Use: trusted applications (msiexec, certutil, CMSTP), script hosts (PowerShell, WScript), InstallUtil, regsvr32. Each has different bypass."),
        ("evade network detection", "Techniques: encrypted channels, legitimate protocols (HTTPS, DNS), timing variations, traffic blending, domain fronting."),
        ("bypass AMSI", "Patch AMSI in memory, use obfuscation, length bypass, test detections. Multiple public bypasses available, but detected quickly."),
        ("avoid EDR detection", "Direct syscalls, unhooking, ETW patching, avoiding monitored APIs. Increasingly difficult as EDR improves."),
        ("disable Windows Defender", "Set-MpPreference -DisableRealtimeMonitoring $true (requires admin). Or exclude paths/processes. May trigger alerts."),
        ("bypass UAC", "Methods: fodhelper, eventvwr, sdclt. Abuse auto-elevating programs. Many public techniques, but signature varies."),
        ("hide processes", "Techniques: process hollowing, process doppelganging, direct syscalls. Avoid common process lists and suspicious names."),
        ("evade logging", "Disable PowerShell logging, clear event logs, timestomping, log rotation abuse. Detection vs evasion tradeoff."),
        ("traffic tunneling", "Encapsulate C2 in allowed protocols: HTTP, HTTPS, DNS, ICMP. Use legitimate services as proxies."),
        ("domain fronting", "Route traffic through CDN to hide true destination. Increasingly blocked by providers but still useful."),
        ("living off the land", "Use legitimate tools: PowerShell, WMI, certutil, bitsadmin, msiexec. No dropped binaries, blend with normal activity."),
        ("fileless techniques", "Execute entirely in memory. Registry storage, WMI subscription, macro execution. No files on disk to detect."),
        ("timestamp manipulation", "Modify file timestamps to blend with legitimate files. Use touch or SetFileTime. Helps avoid forensic timeline."),
        ("log evasion", "Target specific events, clear selectively, modify log settings. Better than clearing all logs which is suspicious."),
    ]
    
    for topic, description in evasions:
        samples.append({
            "instruction": f"How do I {topic} during a penetration test?",
            "input": "",
            "output": description
        })
    
    return samples


def generate_infrastructure_samples():
    """Infrastructure testing samples"""
    samples = []
    
    infra = [
        ("test VMware vSphere", "Check for CVE-2021-21985 (vCenter RCE), default credentials, exposed APIs. vCenter provides complete infrastructure access."),
        ("test Citrix environments", "Look for CVE-2019-19781 (path traversal), CVE-2020-8193 (auth bypass). Citrix often externally exposed."),
        ("pentest VPN infrastructure", "Test for: weak authentication, split tunneling issues, protocol vulnerabilities. VPN is perimeter gateway."),
        ("test load balancers", "Check for: management interface exposure, default credentials, HTTP request smuggling, cache poisoning."),
        ("pentest mail servers", "Test: open relay, user enumeration (VRFY, EXPN), weak TLS, credential spraying against OWA/webmail."),
        ("test backup systems", "Look for: exposed consoles, weak credentials, unencrypted backups, restore capability without auth."),
        ("pentest print servers", "Check for: exposed management, LDAP credentials, PrintNightmare, SNMP information disclosure."),
        ("test file shares", "Enumerate: accessible shares, sensitive files, permission issues. Use CrackMapExec, smbmap, or smbclient."),
        ("pentest monitoring systems", "Check: default credentials, command injection in checks, exposed APIs. Monitoring often has broad access."),
        ("test hypervisors", "Look for: escape vulnerabilities, management interface exposure, default credentials, unpatched CVEs."),
        ("pentest network devices", "Check: default/weak credentials, SNMP community strings, firmware vulnerabilities, management exposure."),
        ("test wireless infrastructure", "Evaluate: encryption (WPA2/3), rogue AP detection, guest network isolation, credential capture."),
        ("pentest VoIP systems", "Check: SIP vulnerabilities, VLAN hopping, credential interception, toll fraud potential."),
        ("test industrial systems", "Caution required. Check: protocol exposure, authentication, network segmentation. Don't disrupt operations."),
        ("pentest IoT devices", "Look for: default credentials, unencrypted communications, firmware vulnerabilities, debug interfaces."),
    ]
    
    for topic, description in infra:
        samples.append({
            "instruction": f"How do I {topic}?",
            "input": "During authorized penetration test",
            "output": description
        })
    
    return samples


def generate_compliance_samples():
    """Compliance-related samples"""
    samples = []
    
    compliance = [
        ("PCI DSS penetration testing", "Quarterly scans required. Annual pentest. Internal and external. Document methodology. Test segmentation controls."),
        ("HIPAA security testing", "Risk assessment required. Technical safeguards testing. Document access controls. Verify audit logging."),
        ("SOC 2 penetration testing", "Annual pentest typically. Test availability, security, confidentiality controls. Provide attestation letter."),
        ("GDPR security testing", "Regular testing required. Test data protection measures. Verify encryption. Check access controls."),
        ("ISO 27001 testing", "Regular vulnerability assessments. Penetration testing as control. Document in risk treatment plan."),
        ("NIST CSF alignment", "Map findings to NIST categories. Identify, Protect, Detect, Respond, Recover framework alignment."),
        ("pentest report for auditors", "Include: scope, methodology, findings with evidence, risk ratings, remediation guidance. Executive summary crucial."),
        ("vulnerability vs penetration test", "Vuln scan finds issues automatically. Pentest manually exploits to prove impact. Pentest validates scanner findings."),
        ("scope for compliance testing", "In-scope systems clearly defined. Include connected systems. Test time windows. Emergency contacts required."),
        ("remediation verification", "Retest after fixes. Confirm vulnerability resolved. Document verification. Update risk register."),
    ]
    
    for topic, description in compliance:
        samples.append({
            "instruction": f"What should I know about {topic}?",
            "input": "",
            "output": description
        })
    
    return samples


def generate_postexploit_samples():
    """Post-exploitation samples"""
    samples = []
    
    postex = [
        ("establish persistence on Windows", "Options: scheduled tasks, services, registry Run keys, WMI subscriptions, startup folder, DLL hijacking. Choose based on needed privilege."),
        ("establish persistence on Linux", "Options: cron jobs, systemd services, bashrc/profile, SSH keys, kernel modules. Consider what survives reboot."),
        ("extract browser credentials", "Use LaZagne, SharpWeb, or manual extraction. Check Chrome, Firefox, Edge profiles. Decrypt with DPAPI key."),
        ("dump Active Directory", "Methods: DCSync if privileged, NTDS.dit via shadow copy, secretsdump remotely. Get all domain hashes."),
        ("find sensitive files", "Search for: *.config, *.xml, *.ini, password*, credential*, *.key, *.pem. Check home directories, web roots."),
        ("capture network credentials", "Run Responder for LLMNR/NBT-NS poisoning. Capture and crack/relay NetNTLMv2 hashes."),
        ("pivot through network", "Use: SSH tunneling, Chisel, Ligolo-ng, Metasploit routes. Forward traffic through compromised host."),
        ("escalate to domain admin", "Paths: Kerberoasting, AS-REP roasting, delegation abuse, GPO abuse, ADCS exploitation. Run BloodHound to find path."),
        ("extract credentials from memory", "Windows: Mimikatz sekurlsa::logonpasswords. Linux: /proc memory analysis, strings on dumps. Get plaintext if available."),
        ("create backdoor account", "Add user to local/domain admins. Risk: easily detected. Better: use existing service account or machine account."),
        ("exfiltrate data safely", "Use encrypted channels. Consider: size, speed, detection. Options: HTTPS, DNS tunneling, cloud storage, email."),
        ("cover tracks", "Clear relevant logs, modify timestamps, remove artifacts. Balance: complete cleanup vs detection risk."),
        ("maintain access after password change", "Methods: golden ticket, skeleton key, shadow credentials, additional accounts, SSH keys. Plan for credential rotation."),
        ("move laterally with credentials", "Tools: CrackMapExec, PsExec, WinRM, RDP, SSH. Choose based on available credentials and protocols."),
        ("enumerate cloud from on-prem", "Check: Azure AD Connect, stored credentials, service accounts. Pivot from AD to cloud environment."),
    ]
    
    for topic, description in postex:
        samples.append({
            "instruction": f"How do I {topic} during an authorized penetration test?",
            "input": "",
            "output": description
        })
    
    return samples


def generate_misc_samples():
    """Miscellaneous unique samples"""
    samples = []
    
    misc = [
        ("difference between red and blue team", "Red team simulates attackers, tests defenses end-to-end. Blue team defends, detects, responds. Purple team combines both for improvement."),
        ("CTF vs real pentest", "CTF: defined challenges, clear flags. Pentest: realistic scope, business impact focus, professional reporting required."),
        ("bug bounty vs pentest", "Bug bounty: specific scope, public program, per-finding reward. Pentest: comprehensive, time-boxed, fixed fee, full report."),
        ("when to stop testing", "Stop when: scope exhausted, time limit reached, client requests, risk of damage, or objectives achieved."),
        ("handle finding real malware", "Document, don't interact unnecessarily. Inform client immediately. May indicate prior breach. Consider IR involvement."),
        ("test production safely", "Time windows, change management, backups verified, rollback plan, emergency contacts. Minimal invasive testing."),
        ("prioritize findings", "CVSS helps but consider: exploitability, business impact, data exposure, compliance. Adjust for context."),
        ("retesting best practices", "Verify specific fix. Test for regression. Document confirmation. Update status in report."),
        ("handle scope creep", "Document additional requests. Require written approval. Adjust timeline/budget. Protect yourself contractually."),
        ("difference between VA and PT", "Vulnerability Assessment identifies issues. Penetration Test exploits to prove impact. PT validates VA findings."),
        ("physical penetration testing", "Test: access controls, tailgating, badge cloning, lock picking. Requires specific authorization. Document everything."),
        ("social engineering engagement", "Define: targets, methods, success criteria. Phishing, vishing, physical. Report awareness gaps. Train don't shame."),
        ("wireless penetration testing", "Capture handshakes, test encryption, rogue AP detection, guest isolation. Document channel and BSSID."),
        ("mobile app penetration testing", "Static and dynamic analysis. Check: API security, data storage, authentication, transport security. Use MobSF, Frida."),
        ("API penetration testing", "Map endpoints, test auth/authz, injection points, rate limiting, business logic. Use Postman, Burp for testing."),
        ("thick client testing", "Analyze: network traffic, local storage, binary. Look for hardcoded creds, insecure protocols, injection points."),
        ("source code review tips", "Focus: auth, input validation, crypto usage, dangerous functions. Use SAST tools plus manual review."),
        ("container security testing", "Check: image vulnerabilities, runtime config, secrets exposure, escape possibilities, network segmentation."),
        ("kubernetes pentest approach", "Enumerate: pods, secrets, RBAC. Test: API access, service accounts, container escapes, network policies."),
        ("serverless security testing", "Test: function permissions, event injection, dependency vulnerabilities, environment variables with secrets."),
    ]
    
    for topic, description in misc:
        samples.append({
            "instruction": f"Explain {topic}.",
            "input": "",
            "output": description
        })
    
    return samples


def main():
    """Generate all finish line samples"""
    print("🏁 Finish line push...")
    
    all_samples = []
    
    generators = [
        ("attacks", generate_specific_attack_samples),
        ("evasion", generate_defense_evasion_samples),
        ("infra", generate_infrastructure_samples),
        ("compliance", generate_compliance_samples),
        ("postex", generate_postexploit_samples),
        ("misc", generate_misc_samples),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name}...")
        samples = generator()
        all_samples.extend(samples)
        
        category_file = OUTPUT_DIR / f"finish_{name}.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples")
    
    # Save combined
    combined_file = OUTPUT_DIR / "finish_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} finish line samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
