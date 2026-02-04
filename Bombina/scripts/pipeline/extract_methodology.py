#!/usr/bin/env python3
"""
HackTricks Data Extractor for Bombina
Extracts structured methodology from HackTricks-style content
Generates high-quality reasoning samples from pentest methodology

Usage: python extract_methodology.py
"""

import json
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "datasets"

# ═══════════════════════════════════════════════════════════════════════════════
# METHODOLOGY KNOWLEDGE BASE
# Based on common pentest methodologies and frameworks
# ═══════════════════════════════════════════════════════════════════════════════

RECONNAISSANCE_TECHNIQUES = [
    {
        "name": "Passive DNS Enumeration",
        "category": "initial_access",
        "description": "Gather DNS information without direct target interaction",
        "techniques": ["Historical DNS records", "Certificate Transparency logs", "Subdomain enumeration via passive sources"],
        "tools": ["SecurityTrails", "crt.sh", "DNSDumpster", "Sublist3r (passive mode)"],
        "reasoning": "Passive recon provides attack surface information without alerting the target. Certificate Transparency logs reveal all SSL certificates issued for a domain, exposing subdomains. Historical DNS can show decommissioned but still-resolving hosts. This intelligence shapes active testing priorities."
    },
    {
        "name": "OSINT for Social Engineering",
        "category": "initial_access",
        "description": "Gather information about people and organization for social engineering",
        "techniques": ["LinkedIn scraping", "Email pattern discovery", "Organizational structure mapping", "Technology stack identification"],
        "tools": ["theHarvester", "LinkedIn", "Hunter.io", "Maltego"],
        "reasoning": "Human factors often present the easiest path into an organization. Understanding reporting structures identifies high-value targets. Email patterns enable credential stuffing and phishing. Technology stack knowledge helps craft convincing pretexts. OSINT should precede any social engineering attempts."
    },
    {
        "name": "Network Mapping",
        "category": "initial_access",
        "description": "Identify live hosts, open ports, and network topology",
        "techniques": ["Host discovery", "Port scanning", "Service enumeration", "OS fingerprinting"],
        "tools": ["nmap", "masscan", "Shodan", "Censys"],
        "reasoning": "Network mapping reveals the attack surface. Different scanning techniques trade stealth for speed - SYN scans are faster, connect scans are more reliable through firewalls. Service versions identify potential vulnerabilities. OS detection helps select appropriate exploits. Scan timing affects both detection probability and accuracy."
    }
]

WEB_ATTACK_TECHNIQUES = [
    {
        "name": "Authentication Testing",
        "category": "web_attacks",
        "description": "Test authentication mechanisms for weaknesses",
        "techniques": ["Default credentials", "Brute force", "Password spraying", "Credential stuffing", "Session management flaws"],
        "tools": ["Burp Suite", "Hydra", "wfuzz"],
        "reasoning": "Authentication is often the first barrier to application access. Test for default credentials first - they're common and non-destructive. Password spraying avoids lockouts by testing few passwords across many accounts. Session tokens should be unpredictable and properly invalidated. MFA bypass techniques include phishing, SIM swapping, and implementation flaws."
    },
    {
        "name": "Authorization Testing (IDOR)",
        "category": "web_attacks",
        "description": "Test for insecure direct object references",
        "techniques": ["Parameter manipulation", "Forced browsing", "Horizontal privilege escalation", "Vertical privilege escalation"],
        "tools": ["Burp Suite", "Autorize extension"],
        "reasoning": "Authorization flaws are extremely common because they require custom implementation for each application. Testing involves changing IDs in requests to access other users' data. Numeric IDs are easiest to enumerate; UUIDs are harder but not immune. Always test with multiple user roles. Automated tools can help but manual testing catches logic flaws."
    },
    {
        "name": "Injection Testing",
        "category": "web_attacks",
        "description": "Test for various injection vulnerabilities",
        "techniques": ["SQL injection", "NoSQL injection", "Command injection", "LDAP injection", "XPath injection"],
        "tools": ["sqlmap", "Burp Suite", "custom payloads"],
        "reasoning": "Injection vulnerabilities occur when user input is incorporated into commands or queries without proper sanitization. Each injection type has specific syntax - understand the backend technology. Error-based techniques provide immediate feedback; blind techniques require inference. Second-order injection stores payloads for later execution in different contexts."
    },
    {
        "name": "File Upload Exploitation",
        "category": "web_attacks",
        "description": "Exploit insecure file upload functionality",
        "techniques": ["Extension bypass", "Content-type manipulation", "Polyglot files", "Path traversal in filenames"],
        "tools": ["Burp Suite", "ExifTool"],
        "reasoning": "File uploads can lead to code execution if the server processes uploaded files. Test extension filters with double extensions (.php.jpg), null bytes, and case variations. Content-type validation is client-side only - manipulate in proxy. Polyglot files are valid as multiple types. Even without execution, uploads to web root enable stored XSS."
    },
    {
        "name": "Server-Side Request Forgery",
        "category": "web_attacks",
        "description": "Exploit server-side request functionality",
        "techniques": ["Internal port scanning", "Cloud metadata access", "Protocol smuggling", "DNS rebinding"],
        "tools": ["Burp Suite Collaborator", "ssrf_proxy"],
        "reasoning": "SSRF turns the vulnerable server into an attack proxy. Cloud metadata endpoints (169.254.169.254) often expose credentials and configuration. Internal services trust requests from localhost - SSRF bypasses network segmentation. DNS rebinding defeats IP-based protections. Out-of-band detection confirms SSRF even without visible response."
    }
]

PRIVILEGE_ESCALATION_LINUX = [
    {
        "name": "SUID/SGID Exploitation",
        "category": "privilege_escalation",
        "description": "Exploit misconfigured SUID/SGID binaries",
        "techniques": ["GTFOBins abuse", "Library hijacking", "PATH manipulation"],
        "tools": ["find", "strings", "ltrace"],
        "reasoning": "SUID binaries run with owner privileges regardless of who executes them. Find them with 'find / -perm -4000'. GTFOBins documents exploitation techniques for common binaries. Custom SUID programs may have vulnerabilities not present in system binaries. Library hijacking works when the binary loads libraries from writable locations."
    },
    {
        "name": "Sudo Misconfigurations",
        "category": "privilege_escalation",
        "description": "Exploit sudo permissions and configurations",
        "techniques": ["sudo -l enumeration", "GTFOBins sudo", "LD_PRELOAD injection", "Environment variable abuse"],
        "tools": ["sudo", "custom scripts"],
        "reasoning": "'sudo -l' shows allowed commands - always check first. NOPASSWD entries are immediate wins. Some commands allow shell escape even when restricted. LD_PRELOAD works if env_keep allows it. Sudo versions below certain patches have exploitable vulnerabilities (CVE-2019-14287, CVE-2021-3156)."
    },
    {
        "name": "Cron Job Exploitation",
        "category": "privilege_escalation",
        "description": "Exploit scheduled task misconfigurations",
        "techniques": ["Writable script exploitation", "PATH hijacking", "Wildcard injection"],
        "tools": ["pspy", "crontab"],
        "reasoning": "Cron jobs run with the owner's privileges. Find them in /etc/crontab, /etc/cron.*, and user crontabs. Writable scripts can be modified to execute arbitrary commands. PATH variables in cron context may differ from interactive shells - hijack early PATH entries. Wildcards in commands (tar *) enable injection."
    },
    {
        "name": "Capabilities Abuse",
        "category": "privilege_escalation",
        "description": "Exploit Linux capabilities for privilege escalation",
        "techniques": ["cap_setuid", "cap_net_bind_service", "cap_dac_override"],
        "tools": ["getcap", "setcap"],
        "reasoning": "Capabilities provide granular privileges without full root. 'getcap -r /' finds binaries with capabilities. CAP_SETUID allows changing UID - immediate root. CAP_DAC_OVERRIDE bypasses file permissions - read /etc/shadow. CAP_NET_RAW enables packet capture. Less common than SUID but often overlooked."
    },
    {
        "name": "Kernel Exploitation",
        "category": "privilege_escalation",
        "description": "Exploit kernel vulnerabilities for root access",
        "techniques": ["DirtyCow", "PwnKit", "Dirty Pipe"],
        "tools": ["linux-exploit-suggester", "exploit-db"],
        "reasoning": "Kernel exploits provide reliable root access but risk system stability. Match kernel version to known exploits. Test in lab environment first when possible. Recent exploits: PwnKit (CVE-2021-4034) affects almost all Linux with polkit, Dirty Pipe (CVE-2022-0847) affects kernels 5.8+. Kernel exploits should be last resort due to crash risk."
    }
]

PRIVILEGE_ESCALATION_WINDOWS = [
    {
        "name": "Token Manipulation",
        "category": "privilege_escalation",
        "description": "Exploit Windows token privileges",
        "techniques": ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "Token impersonation"],
        "tools": ["Potato attacks", "PrintSpoofer", "whoami /priv"],
        "reasoning": "Service accounts often have SeImpersonate - check with 'whoami /priv'. Potato family exploits (JuicyPotato, RoguePotato, GodPotato) abuse this to get SYSTEM. PrintSpoofer is simpler and works on newer Windows. These techniques require specific privileges but provide reliable SYSTEM access."
    },
    {
        "name": "Service Exploitation",
        "category": "privilege_escalation",
        "description": "Exploit misconfigured Windows services",
        "techniques": ["Unquoted service paths", "Weak service permissions", "DLL hijacking"],
        "tools": ["PowerUp", "accesschk", "sc.exe"],
        "reasoning": "Services run as SYSTEM or privileged accounts. Unquoted paths with spaces allow binary planting. Weak permissions (SERVICE_CHANGE_CONFIG) allow reconfiguring the service binary. DLL hijacking works when services load DLLs from writable locations. Always check service configuration as part of Windows privesc enumeration."
    },
    {
        "name": "Registry Exploitation",
        "category": "privilege_escalation",
        "description": "Exploit registry misconfigurations",
        "techniques": ["AlwaysInstallElevated", "Autoruns", "Credential extraction"],
        "tools": ["reg query", "PowerUp", "winPEAS"],
        "reasoning": "Registry stores configuration including security-relevant settings. AlwaysInstallElevated allows any MSI to run as SYSTEM - instant privesc. Autoruns identify programs that run at startup/logon with higher privileges. Credentials may be stored in registry (VNC, putty, WinSCP). Registry-based privesc is often overlooked."
    },
    {
        "name": "UAC Bypass",
        "category": "privilege_escalation",
        "description": "Bypass User Account Control",
        "techniques": ["fodhelper", "eventvwr", "DLL hijacking UAC"],
        "tools": ["UACME", "fodhelper.exe", "eventvwr.exe"],
        "reasoning": "UAC prevents unauthorized elevation but has bypass techniques. Bypasses work when already running as admin without elevation. Auto-elevating Microsoft binaries can be abused. Fodhelper and eventvwr read from user-writable registry locations. UAC bypass is horizontal movement from admin to elevated admin, not true privesc."
    },
    {
        "name": "Credential Harvesting",
        "category": "privilege_escalation",
        "description": "Extract credentials from Windows systems",
        "techniques": ["SAM dump", "LSASS dump", "Credential Manager", "DPAPI"],
        "tools": ["Mimikatz", "secretsdump", "lazagne"],
        "reasoning": "Windows stores credentials in multiple locations. SAM contains local password hashes - requires SYSTEM to dump. LSASS holds plaintext passwords and hashes for logged-in users. Credential Manager stores saved passwords. DPAPI protects user secrets with master keys derived from password. Credential harvesting enables lateral movement."
    }
]

LATERAL_MOVEMENT_TECHNIQUES = [
    {
        "name": "Pass-the-Hash",
        "category": "lateral_movement",
        "description": "Authenticate using NTLM hash without knowing password",
        "techniques": ["SMB PTH", "WMI PTH", "RDP restricted admin PTH"],
        "tools": ["Mimikatz", "CrackMapExec", "impacket"],
        "reasoning": "NTLM authentication accepts hashes directly - no need to crack. Captured hashes from LSASS, SAM, or network relay can authenticate to other systems where the account has access. PTH works across the domain for domain accounts. Restricted Admin mode enables PTH over RDP. Detection: unusual logon events, lateral account usage."
    },
    {
        "name": "Kerberos Attacks",
        "category": "lateral_movement",
        "description": "Abuse Kerberos protocol for lateral movement",
        "techniques": ["Pass-the-Ticket", "Overpass-the-Hash", "Golden Ticket", "Silver Ticket"],
        "tools": ["Mimikatz", "Rubeus", "impacket"],
        "reasoning": "Kerberos tickets prove identity to services. Captured TGT (pass-the-ticket) provides domain access. Overpass-the-hash requests TGT using NTLM hash. Golden ticket forges TGT with krbtgt hash - complete domain compromise. Silver ticket forges service tickets - targeted access. Kerberos attacks are powerful but require understanding the protocol."
    },
    {
        "name": "Remote Execution",
        "category": "lateral_movement",
        "description": "Execute commands on remote systems",
        "techniques": ["PSExec", "WMI", "WinRM", "DCOM", "SSH"],
        "tools": ["PsExec", "CrackMapExec", "Evil-WinRM", "impacket"],
        "reasoning": "Multiple protocols enable remote command execution with appropriate credentials. PSExec requires SMB and admin shares - creates service, highly detectable. WMI uses DCOM - less visible but slower. WinRM is legitimate admin protocol - blends in. Choose based on detection tolerance and available credentials. Each method leaves different artifacts."
    },
    {
        "name": "Internal Pivoting",
        "category": "lateral_movement",
        "description": "Access network segments through compromised hosts",
        "techniques": ["SSH tunneling", "Chisel", "SOCKS proxying", "Port forwarding"],
        "tools": ["ssh", "chisel", "proxychains", "socat"],
        "reasoning": "Compromised hosts can pivot to otherwise unreachable networks. SSH tunneling is built-in and encrypted. Chisel provides HTTP tunnels that bypass many firewalls. SOCKS proxying routes arbitrary TCP through pivot. Port forwarding exposes specific internal services. Pivoting extends reach but adds complexity and failure points."
    }
]

PERSISTENCE_TECHNIQUES = [
    {
        "name": "Linux Persistence",
        "category": "persistence",
        "description": "Maintain access to compromised Linux systems",
        "techniques": ["SSH keys", "Cron jobs", "Systemd services", ".bashrc modification", "PAM backdoors"],
        "tools": ["ssh-keygen", "crontab", "systemctl"],
        "reasoning": "Persistence ensures continued access after initial exploitation. SSH keys are most common and legitimate-looking. Cron jobs execute periodically but are visible in standard locations. Systemd services provide reliable persistence with restart capability. Bashrc runs on user login - user-level persistence. PAM backdoors capture credentials and allow hardcoded access."
    },
    {
        "name": "Windows Persistence",
        "category": "persistence",
        "description": "Maintain access to compromised Windows systems",
        "techniques": ["Registry Run keys", "Scheduled Tasks", "Services", "WMI subscriptions", "DLL hijacking"],
        "tools": ["reg", "schtasks", "sc", "WMI"],
        "reasoning": "Windows offers many persistence mechanisms at different privilege levels. Registry Run keys are simple but well-monitored. Scheduled tasks provide flexibility in timing and triggers. Services require admin but are very reliable. WMI subscriptions are stealthy but complex. Choose based on required privileges, reliability needs, and detection tolerance."
    },
    {
        "name": "Web Shell Persistence",
        "category": "persistence",
        "description": "Maintain access through web application backdoors",
        "techniques": ["PHP web shells", "ASPX shells", "JSP shells", "Obfuscated shells"],
        "tools": ["Custom shells", "Weevely", "China Chopper"],
        "reasoning": "Web shells provide remote access through the web server. Simple shells execute commands via HTTP parameters. Obfuscation evades signature detection. Memory-only shells leave no files. Detection includes file integrity monitoring and web traffic analysis. Web shells blend with normal traffic but require the web server to remain running."
    }
]

DATA_EXFILTRATION_TECHNIQUES = [
    {
        "name": "Data Staging and Exfiltration",
        "category": "c2_exfil",
        "description": "Prepare and transfer data out of target environment",
        "techniques": ["Compression", "Encryption", "Chunking", "Protocol tunneling"],
        "tools": ["tar", "7z", "openssl", "DNS exfil tools"],
        "reasoning": "Exfiltration must balance speed, stealth, and reliability. Compress data to reduce transfer size and time. Encrypt to prevent content inspection. Chunk large datasets to avoid triggering size-based alerts. Protocol selection: HTTPS blends with normal traffic, DNS is rarely blocked but slow, ICMP tunneling is unusual. DLP systems monitor for sensitive patterns - avoid obvious data."
    },
    {
        "name": "Out-of-Band Exfiltration",
        "category": "c2_exfil",
        "description": "Exfiltrate data through non-standard channels",
        "techniques": ["DNS tunneling", "ICMP tunneling", "Steganography", "Cloud storage abuse"],
        "tools": ["dnscat2", "iodine", "Invoke-DNSExfiltrator"],
        "reasoning": "When standard channels are blocked or monitored, alternatives exist. DNS tunneling encodes data in DNS queries - rarely blocked. ICMP carries data in ping packets. Steganography hides data in images. Legitimate cloud services (Google Drive, Dropbox) are often whitelisted. Each method has bandwidth and reliability tradeoffs."
    }
]


def generate_samples_from_techniques(techniques: List[Dict], source_name: str) -> Dict[str, List[Dict]]:
    """Generate training samples from technique definitions."""
    samples_by_category = {}
    
    for tech in techniques:
        category = tech["category"]
        if category not in samples_by_category:
            samples_by_category[category] = []
        
        # Sample 1: When to use this technique
        samples_by_category[category].append({
            "instruction": f"When and how should you use {tech['name']} in a penetration test?",
            "input": f"Planning the {category.replace('_', ' ')} phase. What's the approach?",
            "output": f"{tech['description']}. {tech['reasoning']} Key techniques include: {', '.join(tech['techniques'][:3])}. Recommended tools: {', '.join(tech['tools'][:3])}."
        })
        
        # Sample 2: Tool selection for this technique
        samples_by_category[category].append({
            "instruction": f"Which tools are best for {tech['name']}?",
            "input": "Need to select appropriate tooling for this phase.",
            "output": f"For {tech['name']}, consider: {', '.join(tech['tools'])}. Each has tradeoffs: {tech['tools'][0]} is commonly used but may have detection signatures. {tech['reasoning'][:200]}..."
        })
        
        # Sample 3: Methodology reasoning
        samples_by_category[category].append({
            "instruction": f"Explain the methodology behind {tech['name']}.",
            "input": f"Why is this technique effective for {category.replace('_', ' ')}?",
            "output": f"{tech['reasoning']} The key techniques ({', '.join(tech['techniques'])}) each serve different scenarios. Success requires understanding both the technique and the target environment."
        })
    
    return samples_by_category


def save_samples(samples_by_category: Dict[str, List[Dict]], source: str):
    """Save samples to appropriate category files."""
    total = 0
    
    for category, samples in samples_by_category.items():
        output_dir = OUTPUT_DIR / category
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / f"{source}_samples.jsonl"
        
        with open(output_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        
        print(f"  📁 {category}: {len(samples)} samples → {output_file.name}")
        total += len(samples)
    
    return total


def main():
    """Main extraction function."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA METHODOLOGY EXTRACTOR
   Generating pentest methodology training samples
═══════════════════════════════════════════════════════════════════
""")
    
    total = 0
    
    # Generate from all technique categories
    technique_sets = [
        (RECONNAISSANCE_TECHNIQUES, "recon"),
        (WEB_ATTACK_TECHNIQUES, "web"),
        (PRIVILEGE_ESCALATION_LINUX, "privesc_linux"),
        (PRIVILEGE_ESCALATION_WINDOWS, "privesc_windows"),
        (LATERAL_MOVEMENT_TECHNIQUES, "lateral"),
        (PERSISTENCE_TECHNIQUES, "persistence"),
        (DATA_EXFILTRATION_TECHNIQUES, "exfil")
    ]
    
    for techniques, source in technique_sets:
        print(f"📂 Processing {source} techniques...")
        samples = generate_samples_from_techniques(techniques, source)
        total += save_samples(samples, f"methodology_{source}")
    
    print(f"""
═══════════════════════════════════════════════════════════════
✅ METHODOLOGY EXTRACTION COMPLETE

Total new samples: {total}

Run quality scorer next:
  python quality_scorer.py
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
