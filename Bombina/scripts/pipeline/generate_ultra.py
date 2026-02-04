#!/usr/bin/env python3
"""
Ultra Generator - Generate large volume of variations
"""

import json
import random
from pathlib import Path
import itertools

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_how_to_samples():
    """Generate many how-to samples"""
    samples = []
    
    how_tos = [
        ("enumerate users on a Windows domain", "Use net user /domain, PowerView Get-DomainUser, or LDAP queries. BloodHound also collects user information. For unauthenticated enum, try Kerberos user enumeration with kerbrute."),
        ("bypass antivirus on Windows", "Consider: custom compiled payloads, obfuscation, living-off-the-land binaries, in-memory execution, AMSI bypass techniques, or staged delivery. Test against target AV in a lab first."),
        ("perform network pivoting", "Use SSH tunneling (-D for SOCKS), Chisel for HTTP tunnels, Ligolo-ng for complex scenarios, or Metasploit autoroute. Choose based on what protocols are allowed through firewalls."),
        ("crack NTLM hashes", "Use hashcat -m 1000 hash.txt wordlist.txt. Add rules for better coverage (-r best64.rule). For stronger passwords, use larger wordlists or hybrid attacks."),
        ("find credentials in memory", "On Windows use Mimikatz sekurlsa::logonpasswords. Create LSASS dump with procdump and analyze offline. On Linux, check /proc for process memory or use volatility for memory dumps."),
        ("exploit SQL injection for RCE", "Depends on database: MSSQL xp_cmdshell, MySQL INTO OUTFILE + webshell, PostgreSQL COPY TO PROGRAM, Oracle Java stored procedures. Each requires specific privileges."),
        ("enumerate shares on a network", "Use smbclient -L, smbmap, or CrackMapExec smb TARGET --shares. For mass enumeration, use enum4linux or CrackMapExec with credential lists."),
        ("perform password spraying", "Use tools like Spray, Ruler (O365), or CrackMapExec. Key: stay under lockout threshold, usually 1 password per 30+ minutes. Target accounts without MFA."),
        ("escalate privileges on Linux", "Run LinPEAS or manual checks: SUID binaries, sudo -l, cron jobs, kernel version. Check GTFOBins for exploitation techniques. Common paths: sudo misconfig, SUID, kernel exploits."),
        ("escalate privileges on Windows", "Run WinPEAS or manual checks: whoami /priv, unquoted paths, weak service permissions. Check for AlwaysInstallElevated, token privileges like SeImpersonate."),
        ("test for XXE vulnerabilities", "Inject XML external entity: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>. Check for out-of-band detection if no direct response. Use Burp Collaborator."),
        ("perform subdomain enumeration", "Use subfinder, amass, or dnsrecon for automated discovery. Also check SSL certs (crt.sh), DNS zone transfers, Google dorks, and wayback machine."),
        ("exploit deserialization vulnerabilities", "Identify serialization format (Java, PHP, .NET, Python). Use ysoserial for Java, PHPGGC for PHP. Look for gadget chains in application libraries."),
        ("bypass CSRF protection", "Check for: token reuse, token fixation, weak token generation, missing validation on some requests. Try removing token entirely, using token from another session."),
        ("exploit SSRF vulnerabilities", "Test with internal IPs (127.0.0.1, 169.254.169.254), internal hostnames. Bypass filters with encoding, DNS rebinding, or URL parser differences."),
        ("perform ARP spoofing", "Use arpspoof or Ettercap. Enable IP forwarding. Careful: can disrupt network if done wrong. Useful for MitM attacks on switched networks."),
        ("extract passwords from browsers", "Use tools like LaZagne, SharpWeb, or Mimikatz dpapi. Browsers store credentials in profile folders, often encrypted with user's password."),
        ("exploit JWT vulnerabilities", "Test: algorithm confusion (none), weak secrets, key confusion (RS256 to HS256), expiration bypass. Use jwt_tool or manual manipulation."),
        ("perform DNS zone transfer", "dig axfr @nameserver domain.com. If successful, you get all DNS records. Most servers don't allow this anymore, but worth checking."),
        ("exploit file upload vulnerabilities", "Try: extension bypass (.php5, .phtml), content-type manipulation, null byte injection, double extensions. Upload webshell if successful."),
        ("scan for open ports quickly", "Masscan for speed: masscan -p1-65535 TARGET --rate=1000. Follow up with nmap for service detection on found ports."),
        ("exploit LDAP injection", "Test with: *, )(uid=*))(|(uid=*, |, &. Look for authentication bypass or data disclosure. Less common but similar to SQL injection."),
        ("perform Kerberoasting", "Use Rubeus kerberoast or GetUserSPNs.py. Crack tickets with hashcat -m 13100. Target service accounts with weak passwords."),
        ("exploit timing-based vulnerabilities", "Use consistent measurements, many samples. Compare timing between valid/invalid inputs. Useful for username enumeration, password cracking info."),
        ("test for command injection", "Add: ; id, | id, $(id), `id` to parameters. Check for blind injection with sleep or DNS callbacks. Escape special characters."),
        ("extract data from network traffic", "Capture with tcpdump/Wireshark. Analyze with NetworkMiner, look for credentials, files, API keys. Check for unencrypted protocols."),
        ("exploit template injection", "Test with {{7*7}}, ${7*7}, <%= 7*7 %>. If evaluated, identify template engine and escalate to RCE. Common in Python (Jinja2), Java, Ruby."),
        ("perform reconnaissance on a target", "OSINT: company info, employees, tech stack. Technical: DNS, subdomains, ports, services. Use theHarvester, recon-ng, Shodan, Google dorks."),
        ("test API security", "Map endpoints, test authentication/authorization, parameter manipulation, rate limiting, injection points, business logic. Use Postman or Burp for API testing."),
        ("identify web technologies", "Use Wappalyzer, WhatWeb, or response analysis. Check headers, cookies, file extensions, JavaScript libraries, error messages for clues."),
    ]
    
    for topic, answer in how_tos:
        samples.append({
            "instruction": f"How do I {topic}?",
            "input": f"During authorized penetration test, need to {topic}.",
            "output": answer
        })
    
    return samples


def generate_what_is_samples():
    """Generate definitional samples"""
    samples = []
    
    definitions = [
        ("buffer overflow", "Memory corruption vulnerability where data exceeds allocated buffer size, overwriting adjacent memory. Can lead to code execution if attacker controls overwritten data (like return address)."),
        ("race condition", "Bug where outcome depends on timing of events. In security: TOCTOU (time-of-check-time-of-use) allows bypass of checks by changing state between check and use."),
        ("SQL injection", "Injection attack where malicious SQL is inserted into queries via user input. Allows data extraction, authentication bypass, or even RCE depending on database configuration."),
        ("cross-site scripting", "XSS allows injecting malicious scripts into web pages viewed by others. Types: reflected (URL), stored (database), DOM-based (client-side). Leads to session theft, defacement."),
        ("privilege escalation", "Gaining higher privileges than originally granted. Vertical: user to admin. Horizontal: accessing another user's data. Critical for expanding access during pentests."),
        ("lateral movement", "Moving through network after initial compromise. Using credentials, trust relationships, or vulnerabilities to access additional systems toward objectives."),
        ("pass the hash", "Authentication technique using password hash instead of plaintext. Works because Windows NTLM auth only needs hash. No password cracking required."),
        ("golden ticket", "Forged Kerberos TGT created with KRBTGT hash. Provides complete domain access, valid for years, survives most password resets. Ultimate AD persistence."),
        ("DNS rebinding", "Attack where DNS record changes IP rapidly. Used to bypass same-origin policy or access internal systems via victim's browser making requests."),
        ("SSRF", "Server-Side Request Forgery - making server make requests to attacker-chosen destinations. Access internal services, cloud metadata, or perform port scanning."),
        ("XXE", "XML External Entity - processing malicious XML that includes external resources. Leads to file read, SSRF, or denial of service."),
        ("deserialization attack", "Exploiting unsafe deserialization of user data. Malicious serialized objects execute code when deserialized by vulnerable applications."),
        ("CSRF", "Cross-Site Request Forgery - tricking authenticated user into performing unwanted actions. Exploits browser's automatic cookie inclusion for requests."),
        ("IDOR", "Insecure Direct Object Reference - accessing resources by manipulating identifiers (user ID, file name). Leads to unauthorized data access."),
        ("clickjacking", "UI redressing attack using invisible iframes. Trick users into clicking hidden elements, performing unintended actions on target site."),
        ("CORS misconfiguration", "Cross-Origin Resource Sharing allowing unintended origins to access resources. Can lead to sensitive data exposure from authenticated contexts."),
        ("subdomain takeover", "Claiming abandoned subdomains pointing to decommissioned services. The DNS record exists but the service doesn't, allowing attacker registration."),
        ("kerberoasting", "Requesting service tickets for accounts with SPNs, then cracking offline. Targets service accounts with weak passwords. No special privileges needed."),
        ("AS-REP roasting", "Targeting accounts without Kerberos pre-authentication. Request AS-REP, crack offline. Similar to Kerberoasting but different mechanism."),
        ("credential stuffing", "Using breached credentials from other sites. Relies on password reuse. Different from brute force - uses known valid credentials."),
        ("DNS tunneling", "Encoding data in DNS queries/responses to bypass firewalls. Slow but often works when other protocols are blocked. Used for C2 or exfiltration."),
        ("living off the land", "Using legitimate system tools for malicious purposes. Avoids dropping custom binaries. Examples: PowerShell, WMI, certutil, bitsadmin."),
        ("C2 framework", "Command and Control infrastructure for managing compromised hosts. Examples: Cobalt Strike, Metasploit, Empire. Provides payload generation, comms, post-exploitation."),
        ("webshell", "Malicious script uploaded to web server providing remote access. Usually simple: accepts commands, returns output. Persistent backdoor access."),
        ("reverse shell", "Connection from victim to attacker (outbound), bypassing inbound firewall rules. Attacker listens, victim connects back with shell access."),
        ("bind shell", "Shell listening on victim's port for attacker connection. Requires inbound access, easier to detect. Less common than reverse shells."),
        ("payload", "Code or commands delivered during exploitation. Can be shellcode, scripts, or full agents. Chosen based on target OS, constraints, and objectives."),
        ("persistence", "Maintaining access across reboots or credential changes. Methods: scheduled tasks, registry keys, services, implants, backdoor accounts."),
        ("pivoting", "Using compromised host to access otherwise unreachable networks. Essential for internal assessments. Implements through tunnels or proxies."),
        ("foothold", "Initial access to target network. Usually single compromised system. Starting point for lateral movement and privilege escalation."),
    ]
    
    for term, definition in definitions:
        samples.append({
            "instruction": f"What is {term} in the context of penetration testing?",
            "input": "",
            "output": definition
        })
    
    return samples


def generate_when_samples():
    """Generate when-to-use samples"""
    samples = []
    
    whens = [
        ("when should I use nmap vs masscan", "Use masscan for initial fast port discovery across large networks. Use nmap for detailed service/version detection and scripts on discovered ports. They complement each other."),
        ("when should I pivot vs stay local", "Pivot when: target data is on other systems, you need to reach specific objectives, or current system has limited value. Stay local when: still enumerating, gathering credentials, or establishing persistence."),
        ("when should I report a finding immediately", "Report immediately if: critical vulnerability found, evidence of prior compromise, sensitive data exposed, or anything that could cause immediate business harm."),
        ("when should I use authenticated vs unauthenticated scanning", "Start unauthenticated to simulate external attacker. Use authenticated scans for comprehensive view. Authenticated finds more but simulates insider/credentialed attacker."),
        ("when should I stop testing", "Stop when: scope is exhausted, time is up, client requests stop, you might cause damage, or you've achieved objectives. Always communicate with client."),
        ("when should I use automated vs manual testing", "Use automated for coverage and finding low-hanging fruit. Manual for: logic flaws, complex vulnerabilities, understanding application behavior. Best results combine both."),
        ("when should I escalate privileges vs move laterally", "Escalate when: need higher access for current objectives, limited by current privileges. Move laterally when: current system doesn't have what you need, or to find easier escalation paths."),
        ("when should I use phishing vs technical attacks", "Use phishing when: in scope, perimeter is hardened, or testing user awareness. Technical attacks when: faster path exists, or phishing isn't in scope."),
        ("when should I use existing tools vs write custom", "Use existing tools for known vulnerabilities and standard techniques. Write custom when: evading detection, unique vulnerability, or specific requirements not met by existing tools."),
        ("when should I crack hashes vs pass them", "Crack when: you need plaintext (password reuse, policies), or target only accepts plaintext. Pass when: NTLM auth available, faster than cracking, or strong passwords."),
        ("when should I use Metasploit", "Use Metasploit when: exploit module exists, you need post-exploitation features, or quick reliable exploitation. Avoid when: stealth is critical or custom approach needed."),
        ("when should I use DNS exfiltration", "Use DNS exfil when: other outbound traffic blocked, HTTP/HTTPS not available, need slow but reliable data transfer. It's often the last protocol blocked."),
        ("when should I target domain controllers", "Target DCs when: you have path to reach them, need domain credentials, or seeking domain dominance. They're high-value but also high-risk targets."),
        ("when should I use proxy tools like Burp", "Use Burp/ZAP when: testing web applications, need to intercept/modify requests, or want to analyze traffic. Essential for any serious web app testing."),
        ("when should I engage with client's security team", "Engage when: testing IDS/SOC response (if in scope), you've been detected and need to continue, or you find evidence of real compromise."),
    ]
    
    for question, answer in whens:
        samples.append({
            "instruction": question.capitalize() + "?",
            "input": "",
            "output": answer
        })
    
    return samples


def generate_why_samples():
    """Generate why explanations"""
    samples = []
    
    whys = [
        ("why use multiple enumeration tools", "Different tools have different signatures, databases, and techniques. Using multiple increases coverage and reduces false negatives. What one misses, another might find."),
        ("why document everything during a pentest", "Documentation provides: evidence for reports, ability to reproduce findings, CYA if something goes wrong, learning for future engagements, and meets professional standards."),
        ("why avoid production systems when possible", "Production systems risk: business disruption, data loss, reputation damage, legal issues. Test in staging when possible, treat production with extreme care."),
        ("why verify scope before testing", "Out-of-scope testing is unauthorized access - potentially illegal. Scope verification protects you legally and maintains client trust. Always confirm in writing."),
        ("why use encrypted channels for exfiltration", "Encrypted traffic: avoids DLP detection, blends with normal traffic, protects client data. Even in testing, handle data responsibly."),
        ("why test during business hours sometimes", "Testing during business hours: blends with normal traffic, tests realistic detection, mimics real attacker who might choose noisy times."),
        ("why maintain detailed timestamps", "Timestamps help: correlate with security events, prove when actions occurred, investigate incidents, and create accurate timelines for reports."),
        ("why not change passwords on compromised accounts", "Changing passwords: alerts defenders, may disrupt operations, isn't your system to modify, and you might lock yourself out. Document and report instead."),
        ("why prefer stealth even with authorization", "Stealth testing: evaluates detection capabilities, simulates real attacks, provides value beyond just finding vulnerabilities. Unless scope specifies noisy testing."),
        ("why credential reuse is a significant finding", "Password reuse: means one breach compromises multiple systems, indicates poor security culture, and is exploitable path for attackers."),
        ("why patch management matters", "Unpatched systems: have known vulnerabilities, are easy targets, indicate larger security program issues. Many breaches exploit known, patched vulnerabilities."),
        ("why network segmentation is critical", "Segmentation: limits lateral movement, contains breaches, protects sensitive systems. Flat networks allow attackers to move freely."),
        ("why MFA doesn't solve everything", "MFA can be: bypassed (phishing, fatigue), not universally deployed, poorly implemented, or social engineered. It's a layer, not a solution."),
        ("why default credentials are still common", "Default creds persist due to: rapid deployment, lack of hardening processes, forgotten devices, vendor documentation. Always worth checking."),
        ("why internal pentests matter", "Internal tests: simulate insider threats, test lateral movement controls, find issues not visible externally. Assume breach mindset."),
    ]
    
    for question, answer in whys:
        samples.append({
            "instruction": question.capitalize() + "?",
            "input": "",
            "output": answer
        })
    
    return samples


def generate_tips_samples():
    """Generate tip samples"""
    samples = []
    
    tips = [
        "Always screenshot your findings - screenshots are irrefutable evidence for reports.",
        "Keep multiple shells/access methods - if one dies, you don't lose your foothold.",
        "Test exploits in a lab first before running against real targets.",
        "Save all tool output to files - you can always analyze later.",
        "Check version numbers carefully - one minor version can mean vulnerable or not.",
        "Rotate IP addresses if possible to avoid detection correlation.",
        "Use tmux or screen to keep sessions alive and organized.",
        "Always have an exit strategy - know how to clean up if needed.",
        "Read the full output of tools - important details often hidden in verbose output.",
        "Check robots.txt and sitemap.xml early - they often reveal hidden paths.",
        "Look at JavaScript files for API endpoints and secrets.",
        "Error messages often leak valuable information - trigger them intentionally.",
        "Check backup files (.bak, .old, ~) - they often contain source code.",
        "DNS records can reveal internal naming schemes and infrastructure.",
        "HTTP headers often leak server versions and technologies.",
        "Comments in HTML/JS can reveal debugging endpoints or credentials.",
        "Run whoami and id after every shell - confirm your context.",
        "Keep credential lists organized by source and privilege level.",
        "Test null byte injection in file paths and parameters.",
        "Check for timing differences in login responses - username enumeration.",
        "Cookie attributes (HttpOnly, Secure) often missing - easy findings.",
        "Test all HTTP methods on endpoints - PUT/DELETE often overlooked.",
        "Look for admin panels at common paths (/admin, /manager, /wp-admin).",
        "Check SSL certificates for additional domain names and email addresses.",
        "Use Burp's response comparison to spot subtle differences.",
        "Set up a dedicated note-taking system before you start testing.",
        "Run continuous monitoring (tcpdump, procmon) to catch everything.",
        "Check for exposed .git or .svn directories - source code goldmine.",
        "Test for HTTP request smuggling on load balancers.",
        "Always decode Base64 strings you encounter - often contain secrets.",
    ]
    
    for tip in tips:
        samples.append({
            "instruction": "Give me a penetration testing tip.",
            "input": random.choice(["", "Looking for practical advice", "Need a quick tip"]),
            "output": tip
        })
    
    return samples


def main():
    """Generate all ultra samples"""
    print("🔥 Generating ultra samples...")
    
    all_samples = []
    
    generators = [
        ("how_to", generate_how_to_samples),
        ("what_is", generate_what_is_samples),
        ("when_to", generate_when_samples),
        ("why", generate_why_samples),
        ("tips", generate_tips_samples),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name}...")
        samples = generator()
        all_samples.extend(samples)
        
        # Save category file
        category_file = OUTPUT_DIR / f"ultra_{name}.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples saved to ultra_{name}.jsonl")
    
    # Save combined
    combined_file = OUTPUT_DIR / "ultra_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} ultra samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
