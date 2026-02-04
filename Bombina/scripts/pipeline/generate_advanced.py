#!/usr/bin/env python3
"""
Advanced Pentest Training Sample Generator
Generates reasoning-focused samples for specific attack categories
Target: Add 2000+ samples to reach "Solid" tier (5k-8k)
"""

import json
import random
from pathlib import Path
from datetime import datetime

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# ENVIRONMENT CONTEXTS
# ============================================

ENVIRONMENTS = [
    {
        "name": "corporate_ad",
        "description": "Large enterprise Active Directory environment",
        "controls": ["EDR (CrowdStrike)", "SIEM (Splunk)", "PAM (CyberArk)", "NAC"],
        "network": "Flat network, 500+ workstations, multi-domain forest",
        "hardening": ["SMB signing enabled", "LDAP signing required", "NTLM restricted"]
    },
    {
        "name": "startup_cloud",
        "description": "Cloud-native startup on AWS",
        "controls": ["CloudTrail", "GuardDuty", "WAF", "Basic IAM"],
        "network": "VPC with public/private subnets, EKS cluster",
        "hardening": ["SSO enabled", "MFA on root", "No direct EC2 access"]
    },
    {
        "name": "healthcare",
        "description": "Healthcare organization with HIPAA requirements",
        "controls": ["DLP", "Encryption at rest", "Audit logging", "Network segmentation"],
        "network": "Segmented VLANs, medical device network isolated",
        "hardening": ["Strict firewall rules", "USB disabled", "VPN-only remote access"]
    },
    {
        "name": "financial",
        "description": "Financial services with PCI-DSS compliance",
        "controls": ["IDS/IPS", "FIM", "SIEM", "DLP", "Privileged session monitoring"],
        "network": "CDE isolated, jump boxes required, micro-segmentation",
        "hardening": ["All traffic encrypted", "MFA everywhere", "Weekly patching"]
    },
    {
        "name": "small_business",
        "description": "Small business with limited security budget",
        "controls": ["Basic antivirus", "Firewall", "Cloud email filtering"],
        "network": "Flat network, SOHO router, no segmentation",
        "hardening": ["Default configurations", "Outdated systems", "Shared admin accounts"]
    },
    {
        "name": "government",
        "description": "Government agency with classified data",
        "controls": ["Air-gapped networks", "Badge access", "HIDS on all systems"],
        "network": "Multiple classification levels, strict data diodes",
        "hardening": ["STIG hardened", "Whitelisting", "USB ports disabled"]
    },
    {
        "name": "manufacturing_ot",
        "description": "Manufacturing plant with OT/IT convergence",
        "controls": ["OT-specific firewall", "Historian servers", "Basic monitoring"],
        "network": "Purdue model, Level 3.5 DMZ, legacy PLCs",
        "hardening": ["Some systems can't be patched", "24/7 uptime required"]
    },
    {
        "name": "university",
        "description": "Large university with research networks",
        "controls": ["Decentralized IT", "BYOD policy", "eduroam"],
        "network": "Open network policy, research clusters, student housing",
        "hardening": ["Varies by department", "Legacy research systems", "High bandwidth"]
    }
]

# ============================================
# ATTACK SCENARIOS BY CATEGORY
# ============================================

def generate_initial_access_samples():
    """Generate initial access reasoning samples"""
    samples = []
    
    scenarios = [
        {
            "situation": "External pentest against {env_name} with no credentials",
            "vectors": [
                ("phishing", "Target users with crafted emails", "MEDIUM", "High success but leaves traces in email logs"),
                ("web_app", "Look for vulnerable web applications", "LOW", "Passive recon first, then targeted exploitation"),
                ("vpn_brute", "Attempt VPN credential stuffing", "HIGH", "Noisy, may trigger lockouts"),
                ("exposed_services", "Find internet-exposed services", "LOW", "Shodan/Censys recon, then version-specific exploits"),
                ("supply_chain", "Compromise third-party vendor", "MEDIUM", "Complex but effective against hardened targets"),
                ("physical", "Social engineering or physical access", "MEDIUM", "Depends on physical security controls"),
            ]
        },
        {
            "situation": "Assumed breach scenario, starting with workstation access",
            "vectors": [
                ("local_privesc", "Escalate privileges on current host", "LOW", "Check for misconfigs, unquoted paths, service accounts"),
                ("credential_hunting", "Search for cached credentials", "LOW", "Browser, keepass, config files, memory"),
                ("lateral_movement", "Move to other systems", "MEDIUM", "Depends on network segmentation"),
                ("domain_recon", "Enumerate AD environment", "LOW", "BloodHound, PowerView, ldapsearch"),
            ]
        },
        {
            "situation": "Red team engagement with physical access to lobby",
            "vectors": [
                ("badge_cloning", "Clone employee badge", "MEDIUM", "Requires proximity to targets"),
                ("rogue_device", "Plant network implant", "MEDIUM", "LAN Turtle, Pi, WiFi Pineapple"),
                ("tailgating", "Follow employee through secure door", "LOW", "Social engineering required"),
                ("usb_drop", "Leave malicious USB devices", "MEDIUM", "Depends on USB policy enforcement"),
            ]
        }
    ]
    
    for env in ENVIRONMENTS:
        for scenario in scenarios:
            situation = scenario["situation"].format(env_name=env["description"])
            
            for vector_name, vector_desc, risk, reasoning in scenario["vectors"]:
                # Build detailed reasoning
                controls_text = ", ".join(env["controls"])
                hardening_text = ", ".join(env["hardening"])
                
                output = f"""Given the {env['description']} with controls ({controls_text}) and hardening ({hardening_text}):

[ANALYSIS]
Attack Vector: {vector_name} - {vector_desc}
Detection Risk: {risk}
Reasoning: {reasoning}

[CONSIDERATION OF CONTROLS]
- Security controls present: {controls_text}
- Impact on this vector: {"High detection likelihood" if risk == "HIGH" else "Moderate detection risk" if risk == "MEDIUM" else "Low detection risk if executed carefully"}

[RECOMMENDED APPROACH]
1. {"Start with passive reconnaissance to minimize detection" if risk != "HIGH" else "Consider alternative vectors first due to high detection risk"}
2. {"Enumerate specific versions before attempting exploitation" if "web_app" in vector_name or "exposed_services" in vector_name else "Prepare fallback plans in case of detection"}
3. {"Have exfil channels ready before engagement" if env["name"] in ["government", "financial"] else "Standard operational security practices"}

[DETECTION INDICATORS TO AVOID]
- {f"Email gateway alerts (SPF/DKIM failures)" if "phishing" in vector_name else f"Network IDS signatures" if risk == "HIGH" else "Anomalous login patterns"}
- EDR behavioral detection for any payload execution
- SIEM correlation rules for lateral movement patterns"""
                
                samples.append({
                    "instruction": f"You are conducting an external penetration test. Analyze the viability of {vector_name} as an initial access vector.",
                    "input": f"Environment: {situation}\nControls: {controls_text}\nHardening: {hardening_text}",
                    "output": output.strip()
                })
    
    return samples


def generate_lateral_movement_samples():
    """Generate lateral movement reasoning samples"""
    samples = []
    
    techniques = [
        {
            "name": "Pass-the-Hash",
            "risk": "MEDIUM",
            "requirements": ["Local admin hash", "Target system with same local admin"],
            "detection": ["NTLM relay detection", "Unusual login patterns", "Event ID 4624 type 3"],
            "evasion": ["Use during business hours", "Target systems user normally accesses", "Avoid domain controllers initially"]
        },
        {
            "name": "Pass-the-Ticket",
            "risk": "LOW",
            "requirements": ["Valid Kerberos ticket", "Target accepts Kerberos auth"],
            "detection": ["Ticket reuse from different IP", "Anomalous service access", "Event ID 4769"],
            "evasion": ["Use tickets close to their creation time", "Match user's normal behavior patterns"]
        },
        {
            "name": "WMI Execution",
            "risk": "MEDIUM",
            "requirements": ["Admin credentials", "WMI enabled on target", "Network access to target"],
            "detection": ["WMI process creation events", "wmic.exe execution", "WinRM logs"],
            "evasion": ["Use PowerShell remoting instead if available", "Execute during admin maintenance windows"]
        },
        {
            "name": "PSExec",
            "risk": "HIGH",
            "requirements": ["Admin credentials", "ADMIN$ share accessible", "File sharing enabled"],
            "detection": ["Service creation events", "Named pipe connections", "File write to ADMIN$"],
            "evasion": ["Use modified/renamed binary", "Delete service after use", "Consider alternatives"]
        },
        {
            "name": "SSH Lateral Movement",
            "risk": "LOW",
            "requirements": ["SSH credentials or keys", "SSH service running"],
            "detection": ["SSH login events", "New SSH connections from unusual sources"],
            "evasion": ["Use existing admin's SSH keys", "Match normal SSH patterns"]
        },
        {
            "name": "RDP Lateral Movement",
            "risk": "MEDIUM",
            "requirements": ["Valid credentials", "RDP enabled", "Network access"],
            "detection": ["RDP connection events", "GUI-based activity logging", "Screenshots in PAM"],
            "evasion": ["Use restricted admin mode", "SharpRDP for command execution only"]
        },
        {
            "name": "DCOM Execution",
            "risk": "LOW",
            "requirements": ["Admin credentials", "DCOM enabled"],
            "detection": ["DCOM connection events", "Unusual DCOM applications"],
            "evasion": ["Use common DCOM applications", "Blend with normal RPC traffic"]
        },
        {
            "name": "SMB Admin Shares",
            "risk": "MEDIUM",
            "requirements": ["Admin credentials", "SMB accessible", "Admin shares enabled"],
            "detection": ["SMB connection logs", "File access on C$ share"],
            "evasion": ["Access shares that admin normally uses", "Avoid bulk file operations"]
        }
    ]
    
    for env in ENVIRONMENTS:
        for technique in techniques:
            # Adjust risk based on environment
            adjusted_risk = technique["risk"]
            if env["name"] in ["government", "financial"] and technique["risk"] == "LOW":
                adjusted_risk = "MEDIUM"
            elif env["name"] == "small_business" and technique["risk"] == "HIGH":
                adjusted_risk = "MEDIUM"
            
            output = f"""Technique: {technique["name"]}
Environment: {env["description"]}

[RISK ASSESSMENT]
Base Risk Level: {technique["risk"]}
Adjusted Risk for Environment: {adjusted_risk}
Rationale: {"Heightened monitoring in {0} increases detection probability".format(env["name"]) if adjusted_risk != technique["risk"] else "Standard risk assessment applies"}

[REQUIREMENTS CHECK]
Prerequisites:
{chr(10).join(f"- {req}" for req in technique["requirements"])}

Environment Compatibility:
- Network: {env["network"]}
- Controls that may detect: {", ".join([c for c in env["controls"] if any(d.lower() in c.lower() for d in ["EDR", "SIEM", "IDS"])])}

[DETECTION VECTORS]
{chr(10).join(f"- {det}" for det in technique["detection"])}

[EVASION STRATEGIES]
{chr(10).join(f"- {eva}" for eva in technique["evasion"])}

[RECOMMENDATION]
{"✓ PROCEED WITH CAUTION" if adjusted_risk != "HIGH" else "⚠ CONSIDER ALTERNATIVES"} - {technique["name"]} in {env["description"]}
{"Primary technique - low detection risk with proper execution" if adjusted_risk == "LOW" else "Secondary option - prepare fallback before execution" if adjusted_risk == "MEDIUM" else "Last resort - high detection probability, use only if other options exhausted"}"""
            
            samples.append({
                "instruction": "Analyze the viability and risks of a lateral movement technique in a specific environment.",
                "input": f"Technique: {technique['name']}\nEnvironment: {env['description']}\nControls: {', '.join(env['controls'])}\nNetwork: {env['network']}",
                "output": output.strip()
            })
    
    return samples


def generate_privilege_escalation_samples():
    """Generate privilege escalation reasoning samples"""
    samples = []
    
    windows_privesc = [
        ("Unquoted Service Path", "LOW", "Check for spaces in unquoted paths", ["sc qc", "wmic service get name,pathname"]),
        ("Weak Service Permissions", "LOW", "Modify service binary or config", ["accesschk.exe", "sc sdshow"]),
        ("AlwaysInstallElevated", "LOW", "Install MSI with SYSTEM privileges", ["reg query HKLM\\..\\Installer", "msiexec"]),
        ("Scheduled Task Abuse", "MEDIUM", "Modify or hijack scheduled tasks", ["schtasks /query", "icacls on task files"]),
        ("Token Impersonation", "MEDIUM", "Steal tokens from privileged processes", ["Incognito", "Potato attacks"]),
        ("UAC Bypass", "LOW", "Bypass User Account Control", ["fodhelper", "eventvwr", "sdclt methods"]),
        ("Kernel Exploits", "HIGH", "Exploit kernel vulnerabilities", ["Check KB patches", "Watson.exe"]),
        ("DLL Hijacking", "LOW", "Plant malicious DLL in search path", ["Process Monitor", "Check PATH order"]),
        ("Credential Extraction", "MEDIUM", "Extract creds from LSASS/SAM", ["Mimikatz", "secretsdump"]),
        ("GPP Passwords", "INFO", "Decrypt Group Policy Preferences passwords", ["gpp-decrypt", "PowerSploit"]),
    ]
    
    linux_privesc = [
        ("SUID Binary Abuse", "LOW", "Exploit misconfigured SUID binaries", ["find / -perm -4000", "GTFOBins"]),
        ("Sudo Misconfiguration", "LOW", "Abuse sudo rules", ["sudo -l", "check NOPASSWD entries"]),
        ("Cron Job Abuse", "LOW", "Modify cron scripts or env", ["cat /etc/crontab", "pspy for hidden crons"]),
        ("Kernel Exploits", "HIGH", "Exploit kernel vulnerabilities", ["uname -a", "linux-exploit-suggester"]),
        ("Capabilities Abuse", "LOW", "Exploit file capabilities", ["getcap -r /", "GTFOBins for caps"]),
        ("NFS Root Squashing", "MEDIUM", "Exploit NFS misconfigurations", ["showmount -e", "check no_root_squash"]),
        ("Docker Escape", "MEDIUM", "Escape from container to host", ["Check mounted sockets", "privileged containers"]),
        ("Writable /etc/passwd", "LOW", "Add user with root privileges", ["ls -la /etc/passwd", "openssl passwd"]),
        ("PATH Injection", "LOW", "Hijack commands via PATH manipulation", ["echo $PATH", "check relative commands"]),
        ("LD_PRELOAD Injection", "LOW", "Preload malicious library", ["check env_keep in sudoers", "create .so"]),
    ]
    
    for os_type, techniques in [("Windows", windows_privesc), ("Linux", linux_privesc)]:
        for env in ENVIRONMENTS[:4]:  # Subset of environments
            for technique, risk, description, tools in techniques:
                output = f"""Privilege Escalation Analysis: {technique}
Target OS: {os_type}
Environment: {env["description"]}

[TECHNIQUE OVERVIEW]
{description}

[DETECTION RISK]
Risk Level: {risk}
Detection Vectors:
- {"EDR will flag known exploits" if risk == "HIGH" else "May trigger behavioral alerts" if risk == "MEDIUM" else "Unlikely to generate alerts if executed carefully"}
- {f"SIEM correlation possible" if "EDR" in " ".join(env["controls"]) or "SIEM" in " ".join(env["controls"]) else "Limited monitoring expected"}

[ENUMERATION STEPS]
{chr(10).join(f"{i+1}. {tool}" for i, tool in enumerate(tools))}

[EXECUTION CONSIDERATIONS]
- Timing: {"Execute during high-activity periods to blend in" if risk != "LOW" else "Low risk, can execute when convenient"}
- Cleanup: {"Critical - remove all artifacts" if risk == "HIGH" else "Remove temporary files" if risk == "MEDIUM" else "Standard cleanup"}
- Fallback: {"Have alternative technique ready" if risk == "HIGH" else "Note results for report"}

[ENVIRONMENT-SPECIFIC NOTES]
- Controls: {", ".join(env["controls"])}
- Impact: {"This technique is likely detected by " + env["controls"][0] if risk == "HIGH" else "May evade most controls with careful execution"}"""
                
                samples.append({
                    "instruction": f"Analyze the {technique} privilege escalation technique on {os_type}.",
                    "input": f"Current access: Low-privileged user\nTarget: {os_type} system in {env['description']}\nGoal: Achieve administrative/root access",
                    "output": output.strip()
                })
    
    return samples


def generate_evasion_samples():
    """Generate detection evasion reasoning samples"""
    samples = []
    
    edr_products = [
        ("CrowdStrike Falcon", ["Behavioral AI", "Memory scanning", "Kernel hooks"], ["Process hollowing detected", "Cobalt Strike signatures", "AMSI bypass attempts"]),
        ("Microsoft Defender ATP", ["Cloud analysis", "AMSI", "Attack surface reduction"], ["Living-off-the-land blocked", "Macro execution monitored", "PowerShell constrained"]),
        ("Carbon Black", ["Behavioral analysis", "Process tree monitoring", "Network containment"], ["Process injection detected", "Unusual parent-child relationships flagged"]),
        ("SentinelOne", ["AI behavioral engine", "Autonomous response", "Deep visibility"], ["Ransomware behavior blocked", "Fileless attacks detected"]),
        ("Cylance", ["AI-based prevention", "Memory protection", "Script control"], ["Malicious files blocked pre-execution", "Memory exploits prevented"]),
    ]
    
    evasion_techniques = [
        ("Process Injection", "Inject code into legitimate process", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
        ("AMSI Bypass", "Disable Windows Antimalware Scan Interface", ["Memory patching", "CLR hooking", "Reflection loading"]),
        ("ETW Blinding", "Disable Event Tracing for Windows", ["Patch ntdll!EtwEventWrite", "Unhook ETW providers"]),
        ("Direct Syscalls", "Bypass user-mode hooks", ["Hell's Gate", "Halo's Gate", "SysWhispers"]),
        ("Unhooking", "Remove EDR hooks from ntdll", ["Fresh ntdll from disk", "Manual mapping"]),
        ("Sleep Obfuscation", "Evade memory scanning during sleep", ["Ekko", "Foliage", "Stack encryption"]),
        ("Payload Encryption", "Encrypt payloads at rest", ["AES encryption", "XOR encoding", "Custom packers"]),
        ("Living-off-the-Land", "Use built-in tools", ["certutil", "mshta", "regsvr32", "msbuild"]),
    ]
    
    for edr_name, edr_capabilities, edr_detections in edr_products:
        for technique_name, technique_desc, technique_methods in evasion_techniques:
            # Analyze compatibility
            detection_risk = "HIGH" if any(d.lower() in technique_name.lower() for d in edr_detections) else "MEDIUM"
            
            output = f"""Evasion Analysis: {technique_name} vs {edr_name}

[EDR CAPABILITIES]
Product: {edr_name}
Detection Methods:
{chr(10).join(f"- {cap}" for cap in edr_capabilities)}

Known Detections:
{chr(10).join(f"- {det}" for det in edr_detections)}

[TECHNIQUE ANALYSIS]
Name: {technique_name}
Description: {technique_desc}
Methods: {", ".join(technique_methods)}

[COMPATIBILITY ASSESSMENT]
Risk Level: {detection_risk}
Analysis: {"This technique is specifically monitored by {0}".format(edr_name) if detection_risk == "HIGH" else "May evade detection with proper implementation"}

[RECOMMENDATIONS]
{"⚠ HIGH RISK - Consider alternatives" if detection_risk == "HIGH" else "✓ Proceed with modifications"}

Implementation Notes:
1. {"Avoid standard implementations - custom code required" if detection_risk == "HIGH" else "Standard implementation may work with minor modifications"}
2. {"Test in isolated environment with same EDR first" if detection_risk == "HIGH" else "Test timing and execution flow"}
3. {"Combine with other techniques for layered evasion" if detection_risk == "HIGH" else "Monitor for behavioral alerts during execution"}

[ALTERNATIVE APPROACHES]
If {technique_name} fails:
- {"Consider direct syscalls for lower-level access" if "injection" in technique_name.lower() else "Use LOLBins for initial execution"}
- {"Implement custom packer with sleep obfuscation" if "payload" in technique_name.lower() else "Blend with legitimate admin activity"}"""
            
            samples.append({
                "instruction": f"Analyze how to evade {edr_name} when using {technique_name}.",
                "input": f"EDR: {edr_name}\nTechnique: {technique_name} - {technique_desc}\nGoal: Execute technique without triggering alerts",
                "output": output.strip()
            })
    
    return samples


def generate_failure_recovery_samples():
    """Generate failure analysis and recovery samples"""
    samples = []
    
    failure_scenarios = [
        {
            "attack": "Kerberoasting",
            "failure": "No crackable hashes returned",
            "causes": ["Strong password policy", "Managed Service Accounts (gMSA)", "No SPNs on user accounts"],
            "recovery": ["Target machine accounts instead", "Look for AS-REP roastable accounts", "Focus on other credential access methods"]
        },
        {
            "attack": "Password Spraying",
            "failure": "Accounts locked out",
            "causes": ["Aggressive lockout policy", "Too fast spray rate", "Honeypot accounts triggered"],
            "recovery": ["Wait for lockout to expire", "Identify lockout threshold and slow down", "Target service accounts with different policy"]
        },
        {
            "attack": "Lateral Movement via SMB",
            "failure": "Access denied to all targets",
            "causes": ["SMB signing enforced", "Local admin password randomized (LAPS)", "Firewall blocking SMB"],
            "recovery": ["Try WinRM/PSRemoting instead", "Look for systems not in LAPS", "Use DCOM or WMI execution"]
        },
        {
            "attack": "Mimikatz Credential Dump",
            "failure": "Credential Guard enabled",
            "causes": ["Virtualization-based security", "HVCI enabled", "Modern Windows hardening"],
            "recovery": ["Target DPAPI secrets instead", "Look for cached credentials in other locations", "Focus on Kerberos ticket extraction"]
        },
        {
            "attack": "Phishing Campaign",
            "failure": "All emails blocked",
            "causes": ["Email gateway filtering", "DMARC/DKIM/SPF enforcement", "URL/attachment sandboxing"],
            "recovery": ["Use legitimate email service", "Avoid malicious attachments", "Try callback phishing (vishing)"]
        },
        {
            "attack": "Web Application Exploitation",
            "failure": "WAF blocking all payloads",
            "causes": ["ModSecurity rules", "Cloud WAF (Cloudflare/AWS WAF)", "Input validation"],
            "recovery": ["Identify WAF vendor and version", "Try encoding/obfuscation bypasses", "Look for unprotected API endpoints"]
        },
        {
            "attack": "Privilege Escalation via SUID",
            "failure": "No exploitable SUID binaries",
            "causes": ["Minimal installation", "SUID bits removed in hardening", "SELinux/AppArmor restrictions"],
            "recovery": ["Check for capabilities on files", "Look at sudo misconfigurations", "Enumerate cron jobs and systemd timers"]
        },
        {
            "attack": "Domain Admin Compromise",
            "failure": "All paths require MFA",
            "causes": ["Conditional access policies", "PAM solution enforcing MFA", "Smart card requirement"],
            "recovery": ["Look for MFA fatigue attack opportunity", "Target systems not covered by MFA", "Attempt token theft from already-authenticated sessions"]
        }
    ]
    
    for scenario in failure_scenarios:
        output = f"""Attack Failure Analysis: {scenario["attack"]}

[FAILURE OBSERVED]
{scenario["failure"]}

[ROOT CAUSE ANALYSIS]
Potential causes:
{chr(10).join(f"- {cause}" for cause in scenario["causes"])}

[IMPACT ASSESSMENT]
- Immediate: Attack path blocked, need alternative approach
- Detection risk: {"High - multiple failed attempts may trigger alerts" if "locked" in scenario["failure"].lower() or "blocked" in scenario["failure"].lower() else "Medium - failure itself may not generate alerts"}
- Time impact: Recovery will add {"significant" if len(scenario["recovery"]) > 2 else "moderate"} time to engagement

[RECOVERY OPTIONS]
{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(scenario["recovery"]))}

[RECOMMENDED PATH FORWARD]
Primary: {scenario["recovery"][0]}
Rationale: Most likely to succeed given the observed security controls

Secondary: {scenario["recovery"][1] if len(scenario["recovery"]) > 1 else "Re-evaluate after primary attempt"}

[LESSONS LEARNED]
- Document this control for the final report
- Note the effective security measure for client positive feedback
- Adjust attack methodology for similar environments"""
        
        samples.append({
            "instruction": "An attack has failed during a penetration test. Analyze the failure and recommend recovery steps.",
            "input": f"Failed Attack: {scenario['attack']}\nFailure Symptom: {scenario['failure']}\nEnvironment: Corporate network with modern security controls",
            "output": output.strip()
        })
    
    return samples


def generate_blue_team_samples():
    """Generate blue team perspective samples"""
    samples = []
    
    attack_detections = [
        {
            "attack": "Pass-the-Hash",
            "indicators": ["Event ID 4624 Type 3 with NTLM", "Same hash from different IPs", "Unusual workstation-to-workstation authentication"],
            "mitigations": ["Credential Guard", "LAPS deployment", "Restrict NTLM usage"],
            "detection_queries": ["SecurityEvent | where EventID == 4624 and LogonType == 3 | where AuthenticationPackageName == 'NTLM'"]
        },
        {
            "attack": "Kerberoasting",
            "indicators": ["Event ID 4769 with RC4 encryption", "Mass TGS requests in short time", "Unusual service ticket requests"],
            "mitigations": ["AES-only Kerberos", "Long random SPN passwords", "gMSA for service accounts"],
            "detection_queries": ["SecurityEvent | where EventID == 4769 and TicketEncryptionType == 0x17 | summarize count() by TargetUserName"]
        },
        {
            "attack": "DCSync",
            "indicators": ["Event ID 4662 with GUID for GetChanges", "Non-DC requesting replication", "DS-Replication-Get-Changes extended right"],
            "mitigations": ["Monitor for non-DC replication", "AdminSDHolder protection", "Limit DA group membership"],
            "detection_queries": ["SecurityEvent | where EventID == 4662 and ObjectType contains 'DS-Replication-Get-Changes'"]
        },
        {
            "attack": "Golden Ticket",
            "indicators": ["TGT with abnormal lifetime", "No corresponding AS-REQ", "Event ID 4769 without 4768"],
            "mitigations": ["Reset KRBTGT password twice", "Monitor for impossible TGT lifetimes", "Enable AES Kerberos"],
            "detection_queries": ["Check for TGT without preceding AS-REQ in authentication logs"]
        },
        {
            "attack": "Lateral Movement via WMI",
            "indicators": ["Event ID 5857 (WMI activity)", "WmiPrvSE.exe spawning child processes", "Remote WMI connections"],
            "mitigations": ["Restrict WMI namespaces", "Monitor WMI subscriptions", "Network segmentation"],
            "detection_queries": ["Process creation events where parent is WmiPrvSE.exe"]
        },
        {
            "attack": "Cobalt Strike Beacon",
            "indicators": ["Beaconing traffic patterns", "Named pipes (default \\\\pipe\\)", "Malleable C2 metadata"],
            "mitigations": ["Network traffic analysis", "Named pipe monitoring", "Memory scanning"],
            "detection_queries": ["NetFlow analysis for regular interval callbacks to same destination"]
        }
    ]
    
    for detection in attack_detections:
        output = f"""Blue Team Analysis: Detecting {detection["attack"]}

[ATTACK OVERVIEW]
{detection["attack"]} is a common technique used by attackers for credential access/lateral movement.

[DETECTION INDICATORS]
{chr(10).join(f"- {ind}" for ind in detection["indicators"])}

[DETECTION ENGINEERING]
Sample Detection Query:
```
{detection["detection_queries"][0]}
```

Alert Logic:
- Trigger: Match on indicators above
- Severity: High
- Response: Automated ticket creation, analyst investigation required

[MITIGATION RECOMMENDATIONS]
{chr(10).join(f"- {mit}" for mit in detection["mitigations"])}

[INCIDENT RESPONSE]
If {detection["attack"]} is detected:
1. Isolate affected systems immediately
2. Dump memory for forensic analysis
3. Reset affected credentials
4. Review logs for scope of compromise
5. Hunt for persistence mechanisms

[RED TEAM AWARENESS]
As a pentester, knowing these detections helps you:
- Understand what blue teams are looking for
- Modify techniques to reduce detection probability
- Document which controls successfully detect your activities
- Recommend specific improvements in your report"""
        
        samples.append({
            "instruction": "Explain how to detect this attack technique from a blue team perspective, and how red teamers can use this knowledge.",
            "input": f"Attack Technique: {detection['attack']}",
            "output": output.strip()
        })
    
    return samples


def main():
    """Generate all samples and save to files"""
    print("🔥 Generating advanced pentest training samples...")
    
    all_samples = []
    
    # Generate samples from each category
    generators = [
        ("initial_access", generate_initial_access_samples),
        ("lateral_movement", generate_lateral_movement_samples),
        ("privilege_escalation", generate_privilege_escalation_samples),
        ("evasion", generate_evasion_samples),
        ("failure_recovery", generate_failure_recovery_samples),
        ("blue_team", generate_blue_team_samples),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name} samples...")
        samples = generator()
        all_samples.extend(samples)
        
        # Save category-specific file
        category_file = OUTPUT_DIR / f"{name}_advanced.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples saved to {category_file.name}")
    
    # Save combined file
    combined_file = OUTPUT_DIR / "advanced_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} advanced samples generated")
    print(f"📁 Combined file: {combined_file}")
    
    return len(all_samples)


if __name__ == "__main__":
    main()
