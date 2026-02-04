#!/usr/bin/env python3
"""
Synthetic Training Data Generator for Bombina
Generates thousands of UNIQUE training samples by combining templates with variations

This generates:
- Tool usage reasoning samples
- Attack chain planning samples  
- Failure analysis samples
- Detection evasion samples
- Blue team/defensive samples

Usage: python generate_synthetic.py [--count 5000]
"""

import json
import random
import argparse
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Set
from itertools import product

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "datasets"

# Track generated samples to avoid duplicates
GENERATED_HASHES: Set[str] = set()

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

TOOLS = {
    "nmap": {
        "description": "Network scanner for host discovery and service enumeration",
        "use_cases": ["port scanning", "service detection", "OS fingerprinting", "vulnerability scanning"],
        "flags": ["-sS", "-sV", "-sC", "-O", "-A", "-p-", "-T4", "--script"],
        "detection_risk": "medium-high",
        "alternatives": ["masscan", "rustscan", "zmap"]
    },
    "gobuster": {
        "description": "Directory and file brute-forcer",
        "use_cases": ["directory enumeration", "subdomain enumeration", "vhost discovery"],
        "flags": ["dir", "dns", "vhost", "-w", "-t", "-x", "-o"],
        "detection_risk": "medium",
        "alternatives": ["dirsearch", "ffuf", "feroxbuster"]
    },
    "ffuf": {
        "description": "Fast web fuzzer",
        "use_cases": ["parameter fuzzing", "directory brute forcing", "subdomain enumeration"],
        "flags": ["-w", "-u", "-mc", "-fc", "-t", "-H", "-X"],
        "detection_risk": "medium",
        "alternatives": ["wfuzz", "gobuster", "dirsearch"]
    },
    "sqlmap": {
        "description": "Automated SQL injection tool",
        "use_cases": ["SQL injection detection", "database enumeration", "data extraction"],
        "flags": ["-u", "--dbs", "--tables", "--dump", "--batch", "--level", "--risk", "--tamper"],
        "detection_risk": "high",
        "alternatives": ["manual testing", "burp suite", "ghauri"]
    },
    "hydra": {
        "description": "Password brute-forcing tool",
        "use_cases": ["SSH brute force", "HTTP auth brute force", "FTP brute force"],
        "flags": ["-l", "-L", "-p", "-P", "-t", "-f", "-V"],
        "detection_risk": "high",
        "alternatives": ["medusa", "ncrack", "crowbar"]
    },
    "burpsuite": {
        "description": "Web application security testing platform",
        "use_cases": ["proxy interception", "request manipulation", "vulnerability scanning"],
        "flags": ["proxy", "repeater", "intruder", "scanner"],
        "detection_risk": "low-medium",
        "alternatives": ["OWASP ZAP", "mitmproxy", "caido"]
    },
    "metasploit": {
        "description": "Exploitation framework",
        "use_cases": ["exploit development", "payload generation", "post-exploitation"],
        "flags": ["use", "set", "exploit", "sessions", "meterpreter"],
        "detection_risk": "high",
        "alternatives": ["manual exploitation", "custom scripts", "cobalt strike"]
    },
    "bloodhound": {
        "description": "Active Directory reconnaissance tool",
        "use_cases": ["AD enumeration", "attack path analysis", "privilege escalation paths"],
        "flags": ["SharpHound", "collectors", "neo4j", "queries"],
        "detection_risk": "medium-high",
        "alternatives": ["PowerView", "ADRecon", "PingCastle"]
    },
    "crackmapexec": {
        "description": "Swiss army knife for pentesting networks",
        "use_cases": ["SMB enumeration", "credential validation", "command execution"],
        "flags": ["smb", "winrm", "ssh", "-u", "-p", "-H", "--sam"],
        "detection_risk": "high",
        "alternatives": ["smbclient", "impacket", "netexec"]
    },
    "impacket": {
        "description": "Python classes for network protocols",
        "use_cases": ["SMB attacks", "Kerberos attacks", "NTLM relay"],
        "flags": ["secretsdump", "psexec", "wmiexec", "ntlmrelayx"],
        "detection_risk": "high",
        "alternatives": ["crackmapexec", "Rubeus", "manual implementation"]
    },
    "responder": {
        "description": "LLMNR/NBT-NS/MDNS poisoner",
        "use_cases": ["credential capture", "NTLM hash capture", "relay attacks"],
        "flags": ["-I", "-w", "-r", "-f", "-P"],
        "detection_risk": "medium",
        "alternatives": ["Inveigh", "mitm6", "Pretender"]
    },
    "nikto": {
        "description": "Web server scanner",
        "use_cases": ["web vulnerability scanning", "server misconfiguration detection"],
        "flags": ["-h", "-p", "-ssl", "-Tuning", "-output"],
        "detection_risk": "high",
        "alternatives": ["nuclei", "whatweb", "manual testing"]
    },
    "nuclei": {
        "description": "Template-based vulnerability scanner",
        "use_cases": ["vulnerability scanning", "misconfiguration detection", "CVE detection"],
        "flags": ["-t", "-u", "-l", "-severity", "-silent"],
        "detection_risk": "medium-high",
        "alternatives": ["nikto", "custom scripts", "manual testing"]
    },
    "john": {
        "description": "Password cracker",
        "use_cases": ["hash cracking", "password recovery", "wordlist attacks"],
        "flags": ["--wordlist", "--rules", "--format", "--incremental"],
        "detection_risk": "offline",
        "alternatives": ["hashcat", "ophcrack", "rainbow tables"]
    },
    "hashcat": {
        "description": "Advanced password recovery",
        "use_cases": ["hash cracking", "GPU acceleration", "rule-based attacks"],
        "flags": ["-m", "-a", "-w", "-r", "--potfile-disable"],
        "detection_risk": "offline",
        "alternatives": ["john", "ophcrack", "online crackers"]
    }
}

# Target types and their characteristics
TARGETS = {
    "web_application": {
        "common_ports": [80, 443, 8080, 8443],
        "attack_surface": ["login forms", "APIs", "file uploads", "search functions", "user profiles"],
        "common_vulns": ["XSS", "SQLi", "IDOR", "CSRF", "file inclusion", "SSRF"]
    },
    "linux_server": {
        "common_ports": [22, 80, 443, 21, 25, 3306, 5432],
        "attack_surface": ["SSH", "web services", "databases", "cron jobs", "SUID binaries"],
        "common_vulns": ["weak SSH", "sudo misconfig", "kernel exploits", "service exploits"]
    },
    "windows_server": {
        "common_ports": [135, 139, 445, 3389, 5985, 5986],
        "attack_surface": ["SMB", "RDP", "WinRM", "Active Directory", "services"],
        "common_vulns": ["EternalBlue", "PrintNightmare", "credential theft", "Kerberoasting"]
    },
    "active_directory": {
        "common_ports": [88, 389, 636, 445, 3268, 3269],
        "attack_surface": ["Kerberos", "LDAP", "DNS", "Group Policy", "trusts"],
        "common_vulns": ["Kerberoasting", "AS-REP roasting", "delegation abuse", "ACL attacks"]
    },
    "network_device": {
        "common_ports": [22, 23, 161, 443],
        "attack_surface": ["management interfaces", "SNMP", "routing protocols"],
        "common_vulns": ["default credentials", "SNMP community strings", "firmware vulns"]
    },
    "database": {
        "common_ports": [1433, 3306, 5432, 1521, 27017],
        "attack_surface": ["authentication", "network exposure", "stored procedures"],
        "common_vulns": ["weak auth", "SQLi", "privilege escalation", "data exposure"]
    },
    "api": {
        "common_ports": [80, 443, 8080],
        "attack_surface": ["endpoints", "authentication", "rate limiting", "input validation"],
        "common_vulns": ["BOLA", "broken auth", "injection", "mass assignment"]
    }
}

# Phases of engagement
PHASES = [
    ("reconnaissance", "Gathering information about the target"),
    ("scanning", "Active enumeration of services and vulnerabilities"),
    ("gaining_access", "Exploiting vulnerabilities to gain initial foothold"),
    ("maintaining_access", "Establishing persistence mechanisms"),
    ("privilege_escalation", "Elevating privileges on compromised systems"),
    ("lateral_movement", "Moving through the network to other systems"),
    ("data_exfiltration", "Extracting sensitive data from target"),
    ("covering_tracks", "Removing evidence of compromise")
]

# Outcomes and their implications
OUTCOMES = ["success", "partial_success", "blocked", "detected", "failed"]

# ═══════════════════════════════════════════════════════════════════════════════
# SAMPLE GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_tool_usage_sample() -> Dict:
    """Generate a sample about when/how to use a specific tool."""
    tool_name = random.choice(list(TOOLS.keys()))
    tool = TOOLS[tool_name]
    use_case = random.choice(tool["use_cases"])
    target_type = random.choice(list(TARGETS.keys()))
    
    templates = [
        {
            "instruction": f"When should you use {tool_name} during a penetration test?",
            "input": f"I'm testing a {target_type.replace('_', ' ')} and need to {use_case}.",
            "output": f"{tool_name} is appropriate for {use_case}. {tool['description']}. Detection risk: {tool['detection_risk']}. For a {target_type.replace('_', ' ')}, focus on {random.choice(TARGETS[target_type]['attack_surface'])}. Consider alternatives like {', '.join(tool['alternatives'][:2])} if stealth is priority. Key flags: {', '.join(random.sample(tool['flags'], min(3, len(tool['flags']))))}."
        },
        {
            "instruction": f"Compare {tool_name} with its alternatives for {use_case}.",
            "input": "Need to choose the right tool for the engagement.",
            "output": f"{tool_name}: {tool['description']} Detection risk is {tool['detection_risk']}. Alternatives: {tool['alternatives'][0]} - often faster but less features. {tool['alternatives'][1] if len(tool['alternatives']) > 1 else 'Manual testing'} - more control but slower. Choose based on: 1) detection tolerance, 2) time constraints, 3) specific features needed. For {use_case}, {tool_name} excels when thoroughness matters more than stealth."
        },
        {
            "instruction": f"Explain the detection risks of using {tool_name}.",
            "input": f"Planning to use {tool_name} for {use_case}. Concerned about being detected.",
            "output": f"{tool_name} has {tool['detection_risk']} detection risk. Common signatures: distinctive user-agent strings, scanning patterns, request timing. Mitigation: use timing options to slow scans, customize signatures where possible, run during high-traffic periods. Alternative approach: {tool['alternatives'][0]} may have different detection profile. Remember that even 'low risk' tools leave logs - assume all actions are recorded and plan accordingly."
        }
    ]
    
    return random.choice(templates)


def generate_attack_chain_sample() -> Dict:
    """Generate a sample about attack chain planning and execution."""
    target = random.choice(list(TARGETS.keys()))
    target_info = TARGETS[target]
    vuln = random.choice(target_info["common_vulns"])
    phase_idx = random.randint(0, len(PHASES) - 2)
    current_phase, phase_desc = PHASES[phase_idx]
    next_phase, next_desc = PHASES[phase_idx + 1]
    
    templates = [
        {
            "instruction": f"You've completed {current_phase} on a {target.replace('_', ' ')}. What's the next step?",
            "input": f"Found potential {vuln} vulnerability. Current phase: {phase_desc}",
            "output": f"Transitioning from {current_phase} to {next_phase}. {next_desc}. Given the {vuln} finding: 1) Validate the vulnerability is exploitable. 2) Assess potential impact and document evidence. 3) Plan exploitation approach considering detection risk. 4) Have contingency if exploit fails. For {target.replace('_', ' ')}, typical {next_phase} involves targeting {random.choice(target_info['attack_surface'])}. Always maintain notes for the report."
        },
        {
            "instruction": f"Plan an attack chain for a {target.replace('_', ' ')} with {vuln}.",
            "input": "Need to develop exploitation strategy from initial finding to objective.",
            "output": f"Attack chain for {vuln} on {target.replace('_', ' ')}: 1) Confirm vulnerability scope and version details. 2) Research known exploits and POCs. 3) Set up test environment if possible to validate exploit. 4) Execute exploitation with appropriate precautions. 5) Establish persistence if authorized. 6) Look for privilege escalation paths via {random.choice(target_info['attack_surface'])}. 7) Document entire chain for reproducibility. Key consideration: each step increases detection probability - have exfil and cleanup plans ready."
        },
        {
            "instruction": f"Your {vuln} exploit against {target.replace('_', ' ')} succeeded. Now what?",
            "input": f"Have initial access. Ports observed: {', '.join(map(str, random.sample(target_info['common_ports'], min(3, len(target_info['common_ports'])))))}",
            "output": f"Post-exploitation on {target.replace('_', ' ')}: 1) Situational awareness - identify user context, system info, network position. 2) Persistence - establish backup access before proceeding. 3) Credential harvesting - memory, files, configs. 4) Lateral movement potential - what can we reach from here? 5) Data identification - locate sensitive information per scope. 6) Evidence collection - screenshots, file samples for report. Prioritize based on engagement objectives. Time-box each activity to maintain momentum."
        }
    ]
    
    return random.choice(templates)


def generate_failure_analysis_sample() -> Dict:
    """Generate a sample about handling failures and blocks."""
    tool_name = random.choice(list(TOOLS.keys()))
    tool = TOOLS[tool_name]
    outcome = random.choice(["blocked", "detected", "failed"])
    
    failure_reasons = {
        "blocked": ["WAF blocking requests", "IPS dropping packets", "rate limiting triggered", "IP blacklisted"],
        "detected": ["alert generated", "SOC investigating", "account locked", "traffic flagged"],
        "failed": ["service unavailable", "exploit didn't work", "wrong version", "unexpected response"]
    }
    
    reason = random.choice(failure_reasons[outcome])
    
    templates = [
        {
            "instruction": f"Your {tool_name} scan was {outcome}. How do you proceed?",
            "input": f"Reason: {reason}. Need to continue testing but avoid escalation.",
            "output": f"When {tool_name} is {outcome} due to {reason}: 1) Pause and assess - don't repeat failed actions. 2) Analyze why - examine responses/logs for clues. 3) Alternative approaches: {', '.join(tool['alternatives'][:2])}. 4) Technique variations: different timing, encoding, or methodology. 5) If detected, coordinate with client per ROE - may need to pause. Recovery strategy depends on engagement type - red team has more flexibility than standard pentest. Document the block for the report."
        },
        {
            "instruction": f"Exploit attempt failed - {reason}. What's your analysis?",
            "input": f"Used {tool_name} for initial attempt. Target seems hardened.",
            "output": f"Failure analysis for {reason}: 1) Version mismatch - confirm target version matches exploit requirements. 2) Configuration differences - target may have non-default settings. 3) Security controls - {reason} suggests active defense. 4) Technique noise - {tool_name} has {tool['detection_risk']} detection risk. Next steps: manual verification of vulnerability, alternative exploitation path, or pivot to different attack vector. Failure information is valuable - document defensive capabilities observed."
        },
        {
            "instruction": f"You've been {outcome} while using {tool_name}. Damage assessment?",
            "input": "Need to understand impact and decide whether to continue.",
            "output": f"Impact assessment for {outcome} event: 1) Immediate - stop related activities to prevent correlation. 2) Evaluate scope - is it this technique or your source IP? 3) Check ROE - what's the protocol for detection events? 4) Attribution risk - can they identify your testing infrastructure? 5) Evidence - what logs exist of your activities? Decision framework: if authorized testing and client notified, may continue with modified approach. If {reason} indicates sophisticated defense, valuable intelligence about security maturity."
        }
    ]
    
    return random.choice(templates)


def generate_detection_evasion_sample() -> Dict:
    """Generate samples about avoiding detection."""
    tool_name = random.choice(list(TOOLS.keys()))
    tool = TOOLS[tool_name]
    detection_mechanism = random.choice([
        "WAF", "IDS/IPS", "SIEM", "EDR", "antivirus", 
        "log analysis", "behavioral analysis", "network monitoring"
    ])
    
    templates = [
        {
            "instruction": f"How do you evade {detection_mechanism} while using {tool_name}?",
            "input": "Target has active security monitoring. Need to test thoroughly while minimizing alerts.",
            "output": f"Evasion strategies for {detection_mechanism} with {tool_name}: 1) Timing - slow down requests, avoid burst patterns. 2) Signatures - {tool_name} has known signatures, modify user-agent and patterns where possible. 3) Fragmentation - break requests into smaller pieces. 4) Encryption - use HTTPS to prevent content inspection. 5) Legitimate traffic - blend with normal patterns. 6) Source rotation - multiple IPs if available. 7) Off-hours - lower analyst attention on weekends/nights. Balance thoroughness with stealth - consider {tool['alternatives'][0]} as potentially lower-profile alternative."
        },
        {
            "instruction": f"Target has {detection_mechanism}. What modifications to your approach?",
            "input": f"Planning to use {tool_name}. Detection risk is {tool['detection_risk']}.",
            "output": f"{detection_mechanism} changes the engagement approach: 1) Reconnaissance - identify {detection_mechanism} vendor/version if possible. 2) Known bypasses - research specific evasion techniques for this product. 3) Threshold testing - determine detection thresholds with minimal probes. 4) Alternative tools - {', '.join(tool['alternatives'][:2])} may have different signatures. 5) Manual techniques - often less detectable than automated tools. 6) Timing attacks - spread activity over time to avoid correlation. For {tool_name} with {tool['detection_risk']} risk, consider whether the intelligence gained justifies the detection probability."
        }
    ]
    
    return random.choice(templates)


def generate_blue_team_sample() -> Dict:
    """Generate defensive/blue team perspective samples."""
    tool_name = random.choice(list(TOOLS.keys()))
    tool = TOOLS[tool_name]
    attack_type = random.choice(tool["use_cases"])
    
    templates = [
        {
            "instruction": f"As a defender, how would you detect {tool_name} usage?",
            "input": f"Building detection rules for {attack_type} attempts.",
            "output": f"Detection strategy for {tool_name}: 1) Network signatures - distinctive traffic patterns, user-agents, request sequences. 2) Log analysis - high volume requests to same endpoint, sequential parameter testing. 3) Behavioral - {attack_type} creates anomalous patterns vs normal users. 4) Endpoint - process execution, file access patterns if applicable. Specific indicators: {tool['flags'][0]} and {tool['flags'][1]} usage patterns in logs. Alert tuning: balance sensitivity vs false positives. Consider deception (honeypots) to catch attackers using {tool_name}."
        },
        {
            "instruction": f"How should a SOC respond to detected {attack_type}?",
            "input": f"Alert triggered indicating possible {tool_name} activity.",
            "output": f"Response procedure for {attack_type} detection: 1) Validate - is this true positive or false positive? Check source reputation, request patterns. 2) Scope - is this isolated or part of larger campaign? 3) Contain - block source IP if confirmed malicious, not if authorized testing. 4) Investigate - what was accessed/attempted? Any success indicators? 5) Remediate - if exploitation occurred, isolate affected systems. 6) Learn - update detection rules based on observed techniques. For {tool_name} specifically, check if this is authorized penetration testing before escalating."
        },
        {
            "instruction": f"What defenses effectively prevent {attack_type}?",
            "input": f"Hardening systems against attacks like those performed by {tool_name}.",
            "output": f"Defense in depth against {attack_type}: 1) Prevention - input validation, least privilege, patching. 2) Detection - {tool['detection_risk']} risk attacks are detectable through network and endpoint monitoring. 3) Response - automated blocking, alert escalation, playbooks. 4) Recovery - backups, incident response plan. Specific mitigations for {tool_name}: rate limiting defeats automated scanning, CAPTCHA prevents brute force, strong authentication. Defense should assume motivated attackers will find alternatives - focus on detection and response alongside prevention."
        }
    ]
    
    return random.choice(templates)


def generate_scenario_sample() -> Dict:
    """Generate complex scenario-based samples."""
    target = random.choice(list(TARGETS.keys()))
    target_info = TARGETS[target]
    tools = random.sample(list(TOOLS.keys()), 3)
    
    scenario_types = [
        {
            "instruction": f"Plan a comprehensive assessment of a {target.replace('_', ' ')}.",
            "input": f"Scope includes: {', '.join(random.sample(target_info['attack_surface'], min(3, len(target_info['attack_surface']))))}. Time: 1 week.",
            "output": f"Assessment plan for {target.replace('_', ' ')}: Day 1-2: Reconnaissance and scanning using {tools[0]} for initial enumeration. Focus on {target_info['attack_surface'][0]}. Day 3-4: Vulnerability identification targeting {', '.join(target_info['common_vulns'][:2])}. Use {tools[1]} for deeper testing. Day 5: Exploitation attempts on confirmed vulnerabilities. Day 6: Post-exploitation and lateral movement if initial access achieved. Day 7: Documentation and report preparation. Throughout: maintain detailed notes, screenshot evidence, track time per activity. Prioritize by risk - {target_info['common_vulns'][0]} typically highest impact for {target.replace('_', ' ')}."
        },
        {
            "instruction": f"You're conducting a red team exercise against infrastructure including a {target.replace('_', ' ')}.",
            "input": "Objective: demonstrate risk of data breach. Must avoid detection by SOC.",
            "output": f"Red team approach for {target.replace('_', ' ')}: Phase 1 (External): OSINT and passive recon - no active scanning initially. Identify employees for potential phishing. Phase 2 (Initial Access): Targeted phishing or external vulnerability exploitation. Avoid noisy tools like direct {tools[0]} scans. Phase 3 (Internal): If foothold achieved, slow lateral movement. Use living-off-the-land techniques over {tools[2]}. Target {', '.join(target_info['attack_surface'][:2])} for credential access. Phase 4 (Objective): Locate and simulate data exfiltration without triggering DLP. Success metric: demonstrate access to sensitive data without SOC detection."
        }
    ]
    
    return random.choice(scenario_types)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN GENERATION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

GENERATORS = [
    (generate_tool_usage_sample, "initial_access", 0.20),
    (generate_attack_chain_sample, "lateral_movement", 0.20),
    (generate_failure_analysis_sample, "failure_analysis", 0.20),
    (generate_detection_evasion_sample, "evasion", 0.15),
    (generate_blue_team_sample, "blue_team", 0.15),
    (generate_scenario_sample, "initial_access", 0.10)
]


def sample_hash(sample: Dict) -> str:
    """Generate hash for deduplication."""
    content = f"{sample.get('instruction', '')}{sample.get('input', '')}"
    return hashlib.md5(content.encode()).hexdigest()


def generate_samples(count: int) -> Dict[str, List[Dict]]:
    """Generate specified number of UNIQUE samples across categories."""
    samples_by_category = {}
    attempts = 0
    max_attempts = count * 5  # Prevent infinite loops
    generated = 0
    duplicates = 0
    
    while generated < count and attempts < max_attempts:
        attempts += 1
        
        # Weighted random selection of generator
        rand = random.random()
        cumulative = 0
        for generator, category, weight in GENERATORS:
            cumulative += weight
            if rand <= cumulative:
                sample = generator()
                h = sample_hash(sample)
                
                # Skip duplicates
                if h in GENERATED_HASHES:
                    duplicates += 1
                    break
                
                GENERATED_HASHES.add(h)
                
                if category not in samples_by_category:
                    samples_by_category[category] = []
                samples_by_category[category].append(sample)
                generated += 1
                break
    
    print(f"  ℹ️  Attempts: {attempts}, Duplicates skipped: {duplicates}")
    
    return samples_by_category


def save_samples(samples_by_category: Dict[str, List[Dict]]):
    """Save generated samples to appropriate category files."""
    total = 0
    
    for category, samples in samples_by_category.items():
        output_dir = OUTPUT_DIR / category
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / "synthetic_samples.jsonl"
        
        with open(output_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        
        print(f"  📁 {category}: {len(samples)} samples")
        total += len(samples)
    
    return total


def main():
    parser = argparse.ArgumentParser(description='Generate synthetic training data for Bombina')
    parser.add_argument('--count', type=int, default=5000, help='Number of samples to generate')
    args = parser.parse_args()
    
    print(f"""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA SYNTHETIC DATA GENERATOR
   Creating {args.count} varied training samples
═══════════════════════════════════════════════════════════════════
""")
    
    print("📂 Generating samples...")
    samples = generate_samples(args.count)
    
    print("\n💾 Saving samples...")
    total = save_samples(samples)
    
    print(f"""
═══════════════════════════════════════════════════════════════
✅ SYNTHETIC GENERATION COMPLETE

Total samples generated: {total}
Categories: {', '.join(samples.keys())}

Run quality scorer next:
  python quality_scorer.py
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
