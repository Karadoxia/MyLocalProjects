#!/usr/bin/env python3
"""
Bombina Massive Deep Knowledge Expansion
Target: 3000+ additional deep knowledge samples for innovation capability
"""

import json
import hashlib
import random
from pathlib import Path
from itertools import product, combinations

output_dir = Path(__file__).parent.parent / "data" / "deep_knowledge"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output, category="deep"):
    content = f"{instruction}|{input_text}"
    h = hashlib.md5(content.encode()).hexdigest()
    if h not in seen_hashes:
        seen_hashes.add(h)
        all_samples.append({
            "instruction": instruction, 
            "input": input_text, 
            "output": output,
            "category": category
        })
        return True
    return False

print("="*70)
print("🚀 BOMBINA MASSIVE DEEP KNOWLEDGE EXPANSION")
print("="*70)

# ============================================================
# COMPREHENSIVE VULNERABILITY KNOWLEDGE BASE
# ============================================================
print("\n📚 Building Comprehensive Vulnerability Knowledge...")

# CWE-based vulnerability patterns
cwes = [
    ("CWE-79", "Cross-site Scripting (XSS)", "web", "Improper neutralization of input during web page generation"),
    ("CWE-89", "SQL Injection", "database", "Improper neutralization of special elements used in SQL command"),
    ("CWE-78", "OS Command Injection", "system", "Improper neutralization of special elements used in OS command"),
    ("CWE-22", "Path Traversal", "filesystem", "Improper limitation of pathname to restricted directory"),
    ("CWE-352", "Cross-Site Request Forgery", "web", "Missing or incorrect protection against CSRF"),
    ("CWE-434", "Unrestricted Upload", "web", "Unrestricted upload of file with dangerous type"),
    ("CWE-611", "XXE", "xml", "Improper restriction of XML external entity reference"),
    ("CWE-918", "SSRF", "network", "Server-side request forgery"),
    ("CWE-287", "Improper Authentication", "auth", "Missing or incorrect authentication implementation"),
    ("CWE-862", "Missing Authorization", "authz", "Software does not perform authorization check"),
    ("CWE-863", "Incorrect Authorization", "authz", "Authorization logic error"),
    ("CWE-502", "Deserialization of Untrusted Data", "data", "Deserializing untrusted data leading to code execution"),
    ("CWE-94", "Code Injection", "code", "Improper control of code generation"),
    ("CWE-400", "Resource Exhaustion", "dos", "Uncontrolled resource consumption"),
    ("CWE-306", "Missing Authentication for Critical Function", "auth", "Critical function accessible without authentication"),
    ("CWE-798", "Hardcoded Credentials", "auth", "Use of hardcoded credentials"),
    ("CWE-327", "Broken Crypto", "crypto", "Use of broken or risky cryptographic algorithm"),
    ("CWE-312", "Cleartext Storage", "data", "Cleartext storage of sensitive information"),
    ("CWE-319", "Cleartext Transmission", "network", "Cleartext transmission of sensitive information"),
    ("CWE-532", "Log Injection", "logging", "Information exposure through log files"),
    ("CWE-117", "Log Forgery", "logging", "Improper output neutralization for logs"),
    ("CWE-601", "Open Redirect", "web", "URL redirection to untrusted site"),
    ("CWE-200", "Information Exposure", "info", "Exposure of sensitive information to unauthorized actor"),
    ("CWE-209", "Error Information Exposure", "info", "Sensitive information in error message"),
    ("CWE-639", "Authorization Bypass Through User-Controlled Key", "authz", "IDOR vulnerability"),
    ("CWE-640", "Weak Password Recovery", "auth", "Weak password recovery mechanism"),
    ("CWE-384", "Session Fixation", "session", "Session fixation vulnerability"),
    ("CWE-613", "Insufficient Session Expiration", "session", "Session does not expire properly"),
    ("CWE-614", "Missing Secure Cookie Flag", "session", "Sensitive cookie without secure flag"),
    ("CWE-1004", "Missing HttpOnly Cookie Flag", "session", "Sensitive cookie without httponly flag"),
]

technologies = [
    ("Java Spring Boot", "Java/Spring ecosystem"),
    ("Node.js Express", "JavaScript/Node ecosystem"),
    ("Python Django", "Python/Django ecosystem"),
    ("Python Flask", "Python/Flask ecosystem"),
    ("PHP Laravel", "PHP/Laravel ecosystem"),
    ("Ruby on Rails", "Ruby/Rails ecosystem"),
    (".NET Core", "Microsoft .NET ecosystem"),
    ("Go Gin/Echo", "Golang web ecosystem"),
    ("React/Next.js", "Frontend/SSR ecosystem"),
    ("Angular", "Frontend ecosystem"),
    ("Vue.js", "Frontend ecosystem"),
    ("GraphQL APIs", "GraphQL ecosystem"),
    ("REST APIs", "RESTful API ecosystem"),
    ("gRPC Services", "gRPC ecosystem"),
    ("Kubernetes", "Container orchestration"),
    ("Docker", "Container runtime"),
    ("AWS Services", "Amazon cloud services"),
    ("Azure Services", "Microsoft cloud services"),
    ("GCP Services", "Google cloud services"),
    ("MongoDB", "NoSQL database"),
    ("PostgreSQL", "Relational database"),
    ("Redis", "In-memory data store"),
    ("Elasticsearch", "Search engine"),
    ("Apache Kafka", "Message streaming"),
    ("RabbitMQ", "Message queue"),
]

# Generate vulnerability + technology combinations
for (cwe_id, cwe_name, category, description), (tech, tech_desc) in product(cwes[:15], technologies[:12]):
    add_sample(
        f"How does {cwe_name} ({cwe_id}) manifest in {tech}?",
        f"Vulnerability: {description}. Technology: {tech_desc}.",
        f"""## {cwe_name} in {tech}

### Vulnerability Overview
**{cwe_id}: {cwe_name}**
{description}

### Technology Context
**{tech}** ({tech_desc})

### How This Manifests

In {tech}, {cwe_name.lower()} typically occurs when:
1. User input is processed without proper validation
2. The application's {category} handling has gaps
3. Framework defaults aren't secure or are misconfigured
4. Developer assumptions don't match reality

### Specific Patterns in {tech}

**Code Pattern (Vulnerable)**:
- Direct use of user input in {category} operations
- Missing input validation middleware
- Incorrect framework configuration
- Bypassed security controls

**Root Cause**:
{description}. In {tech}, this often happens due to framework-specific patterns that developers follow without understanding security implications.

### Exploitation Approach

1. **Identification**: Detect {tech} in use, find {category} entry points
2. **Testing**: Probe for {cwe_name.lower()} indicators
3. **Validation**: Confirm exploitability
4. **Exploitation**: Develop {tech}-specific payload

### Finding Novel Instances

To find new {cwe_name.lower()} in {tech}:
- Study {tech} security documentation
- Review common patterns and anti-patterns
- Test framework-specific edge cases
- Analyze recent CVEs in {tech} ecosystem

### Defense Bypass

Common defenses in {tech}:
- Input validation libraries
- Framework security middleware
- WAF rules

Bypass approaches:
- Encoding variations
- Parser differentials
- Framework-specific quirks
- Business logic level attacks""",
        category=f"cwe_{category}"
    )

print(f"   CWE patterns: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# ATTACK TECHNIQUE DEEP KNOWLEDGE
# ============================================================
print("\n📚 Building Attack Technique Deep Knowledge...")

mitre_techniques = [
    # Initial Access
    ("T1190", "Exploit Public-Facing Application", "initial_access", "web exploit, API exploitation, public service exploitation"),
    ("T1133", "External Remote Services", "initial_access", "VPN, RDP, SSH, remote access exploitation"),
    ("T1566", "Phishing", "initial_access", "spear phishing, attachment, link, service phishing"),
    ("T1195", "Supply Chain Compromise", "initial_access", "software supply chain, hardware supply chain"),
    ("T1199", "Trusted Relationship", "initial_access", "partner access, vendor access, MSP abuse"),
    
    # Execution
    ("T1059", "Command and Scripting Interpreter", "execution", "PowerShell, cmd, bash, Python execution"),
    ("T1203", "Exploitation for Client Execution", "execution", "browser exploit, document exploit"),
    ("T1047", "Windows Management Instrumentation", "execution", "WMI for remote execution"),
    ("T1053", "Scheduled Task/Job", "execution", "scheduled task abuse, cron job manipulation"),
    ("T1569", "System Services", "execution", "service execution, service manipulation"),
    
    # Persistence
    ("T1098", "Account Manipulation", "persistence", "adding accounts, SSH keys, credentials"),
    ("T1136", "Create Account", "persistence", "local, domain, cloud account creation"),
    ("T1543", "Create or Modify System Process", "persistence", "Windows service, systemd, launchd"),
    ("T1546", "Event Triggered Execution", "persistence", "startup items, logon scripts"),
    ("T1505", "Server Software Component", "persistence", "web shell, IIS module, SQL stored procedures"),
    
    # Privilege Escalation
    ("T1548", "Abuse Elevation Control Mechanism", "privilege_escalation", "sudo, setuid, bypass UAC"),
    ("T1134", "Access Token Manipulation", "privilege_escalation", "token impersonation, token theft"),
    ("T1068", "Exploitation for Privilege Escalation", "privilege_escalation", "kernel exploit, driver exploit"),
    ("T1484", "Domain Policy Modification", "privilege_escalation", "GPO modification, domain trust manipulation"),
    ("T1078", "Valid Accounts", "privilege_escalation", "default, domain, local, cloud accounts"),
    
    # Defense Evasion
    ("T1140", "Deobfuscate/Decode Files or Information", "defense_evasion", "decode payload, decrypt malware"),
    ("T1562", "Impair Defenses", "defense_evasion", "disable AV, disable logging, firewall disable"),
    ("T1070", "Indicator Removal", "defense_evasion", "log deletion, timestomping, artifact removal"),
    ("T1036", "Masquerading", "defense_evasion", "rename system utilities, invalid code signature"),
    ("T1055", "Process Injection", "defense_evasion", "DLL injection, process hollowing, thread hijacking"),
    
    # Credential Access
    ("T1110", "Brute Force", "credential_access", "password guessing, credential stuffing"),
    ("T1555", "Credentials from Password Stores", "credential_access", "browser passwords, password managers"),
    ("T1003", "OS Credential Dumping", "credential_access", "LSASS, SAM, DCSync, /etc/shadow"),
    ("T1558", "Steal or Forge Kerberos Tickets", "credential_access", "Golden Ticket, Kerberoasting"),
    ("T1552", "Unsecured Credentials", "credential_access", "files, registry, cloud metadata, history"),
    
    # Discovery
    ("T1087", "Account Discovery", "discovery", "local, domain, email, cloud account enum"),
    ("T1482", "Domain Trust Discovery", "discovery", "forest trust, domain trust enumeration"),
    ("T1046", "Network Service Discovery", "discovery", "port scanning, service enumeration"),
    ("T1069", "Permission Groups Discovery", "discovery", "local, domain, cloud group enumeration"),
    ("T1057", "Process Discovery", "discovery", "process listing, security tool identification"),
    
    # Lateral Movement
    ("T1021", "Remote Services", "lateral_movement", "RDP, SSH, SMB, WinRM, VNC"),
    ("T1550", "Use Alternate Authentication Material", "lateral_movement", "pass-the-hash, pass-the-ticket"),
    ("T1570", "Lateral Tool Transfer", "lateral_movement", "tool staging, payload transfer"),
    ("T1534", "Internal Spearphishing", "lateral_movement", "internal phishing campaigns"),
    ("T1210", "Exploitation of Remote Services", "lateral_movement", "remote service exploitation"),
    
    # Collection
    ("T1560", "Archive Collected Data", "collection", "compression, encryption of stolen data"),
    ("T1119", "Automated Collection", "collection", "scripted data collection"),
    ("T1005", "Data from Local System", "collection", "file access, database access"),
    ("T1039", "Data from Network Shared Drive", "collection", "share enumeration, file theft"),
    ("T1114", "Email Collection", "collection", "local email, remote email, forwarding"),
    
    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration", "C2 channel data exfil"),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", "DNS, ICMP, other protocols"),
    ("T1567", "Exfiltration Over Web Service", "exfiltration", "cloud storage, code repos, paste sites"),
    ("T1029", "Scheduled Transfer", "exfiltration", "time-based exfiltration"),
    ("T1537", "Transfer Data to Cloud Account", "exfiltration", "cloud-to-cloud transfer"),
]

for technique_id, technique_name, tactic, examples in mitre_techniques:
    add_sample(
        f"Explain {technique_name} ({technique_id}) in depth for attack planning",
        f"Tactic: {tactic}. Examples: {examples}.",
        f"""## MITRE ATT&CK: {technique_name}

### Technique Overview
**ID**: {technique_id}
**Name**: {technique_name}
**Tactic**: {tactic.replace('_', ' ').title()}

### Examples
{examples}

### Deep Technical Understanding

**What This Technique Achieves**:
{technique_name} enables attackers to {tactic.replace('_', ' ')} by {examples.split(',')[0].strip()}.

**Why This Works**:
- Systems need this functionality for legitimate purposes
- Security controls often don't block legitimate-looking use
- Implementation details create exploitation opportunities
- Defenders can't block everything

### Execution Methodology

**Phase 1: Preparation**
- Identify target systems where this applies
- Gather required access/credentials
- Prepare tools and payloads
- Plan for detection avoidance

**Phase 2: Execution**
- Execute {technique_name.lower()} technique
- Handle errors and edge cases
- Validate success
- Clean up artifacts

**Phase 3: Exploitation**
- Use gained capability
- Progress to next objective
- Maintain operational security

### Innovation Vectors

Finding novel applications of {technique_name}:
1. **New contexts**: Where else can this apply?
2. **New variations**: What sub-techniques exist?
3. **New combinations**: What chains well with this?
4. **Defense evasion**: How to do this stealthily?

### Detection Considerations

**What Defenders Look For**:
- Indicators specific to {technique_name}
- Behavioral patterns
- Artifact generation
- Logging and monitoring

**Evasion Approaches**:
- Modify indicators
- Use allowed functionality
- Blend with normal operations
- Time operations carefully

### Chaining Opportunities

{technique_name} chains with:
- Previous techniques that provide prerequisites
- Following techniques that use its output
- Parallel techniques for redundancy
- Alternative techniques as fallback""",
        category=f"technique_{tactic}"
    )

print(f"   MITRE techniques: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# EXPLOITATION SCENARIOS BY ENVIRONMENT
# ============================================================
print("\n📚 Building Environment-Specific Exploitation...")

environments = [
    ("Active Directory", ["Domain Controller", "LDAP", "Kerberos", "Group Policy", "NTLM"], 
     "Windows domain environment with centralized authentication and management"),
    ("Azure AD", ["Entra ID", "Conditional Access", "PIM", "Azure RBAC", "Service Principals"],
     "Microsoft cloud identity and access management"),
    ("AWS Cloud", ["IAM", "EC2", "S3", "Lambda", "VPC"],
     "Amazon Web Services cloud infrastructure"),
    ("Kubernetes", ["Pods", "RBAC", "Secrets", "Service Accounts", "Network Policies"],
     "Container orchestration platform"),
    ("Linux Server", ["SSH", "sudo", "cron", "systemd", "kernel"],
     "Linux-based server infrastructure"),
    ("Windows Server", ["RDP", "WMI", "PowerShell", "Services", "Registry"],
     "Windows-based server infrastructure"),
    ("Web Application", ["Authentication", "Sessions", "APIs", "Databases", "Files"],
     "Internet-facing web application"),
    ("Internal Network", ["Segmentation", "Firewalls", "VLANs", "Routing", "DNS"],
     "Corporate internal network"),
    ("CI/CD Pipeline", ["Jenkins", "GitHub Actions", "GitLab CI", "Artifacts", "Secrets"],
     "Software build and deployment pipeline"),
    ("Container Environment", ["Docker", "Runtime", "Images", "Volumes", "Networks"],
     "Containerized application environment"),
]

attack_objectives = [
    ("initial access", "gain first foothold in the environment"),
    ("privilege escalation", "elevate from limited to full access"),
    ("lateral movement", "move through the environment to other systems"),
    ("persistence", "maintain long-term access"),
    ("credential theft", "obtain credentials for further access"),
    ("data exfiltration", "extract sensitive data from the environment"),
]

for (env_name, components, env_desc), (objective, obj_desc) in product(environments, attack_objectives):
    add_sample(
        f"Achieve {objective} in {env_name} environment",
        f"Environment: {env_desc}. Components: {', '.join(components[:3])}. Objective: {obj_desc}.",
        f"""## Environment Attack: {objective.title()} in {env_name}

### Environment Overview
**{env_name}**: {env_desc}

**Key Components**:
{chr(10).join([f"- {comp}" for comp in components])}

### Attack Objective
**{obj_desc.capitalize()}**

### Attack Methodology

**Reconnaissance**:
- Enumerate {env_name} components
- Identify {components[0]} and {components[1]} configurations
- Map attack surface for {objective}

**Vulnerability Identification**:
- Check {components[0]} for misconfigurations
- Test {components[1]} for known issues
- Look for {env_name}-specific weaknesses

**Exploitation**:
1. Target most vulnerable component
2. Exploit to achieve {objective}
3. Validate access/capability gained
4. Prepare for next phase

### {env_name}-Specific Techniques

For {objective} in {env_name}:
- **{components[0]}**: Primary attack vector
- **{components[1]}**: Secondary/supporting vector
- **{components[2]}**: Alternative approach

### Common Attack Paths

```
Entry → {components[0]} → {objective}
     ↘ {components[1]} → {objective}
```

### Innovation Opportunities

Novel {objective} in {env_name}:
1. Undocumented features in {components[0]}
2. Interaction between {components[1]} and {components[2]}
3. Version-specific vulnerabilities
4. Configuration edge cases

### Defense Understanding

{env_name} defenses against {objective}:
- Monitoring and logging
- Access controls
- Segmentation
- Hardening

Bypass approaches:
- Living-off-the-land
- Blend with legitimate operations
- Exploit allowed functionality
- Time-based evasion""",
        category=f"env_{env_name.lower().replace(' ', '_')}"
    )

print(f"   Environment scenarios: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# TOOL DEEP KNOWLEDGE
# ============================================================
print("\n📚 Building Tool Deep Knowledge...")

tools = [
    ("Nmap", "network scanning", ["port scanning", "service detection", "OS fingerprinting", "NSE scripts"]),
    ("Burp Suite", "web testing", ["proxy", "scanner", "intruder", "repeater", "extensions"]),
    ("Metasploit", "exploitation", ["exploits", "payloads", "post modules", "auxiliary", "meterpreter"]),
    ("BloodHound", "AD analysis", ["collection", "path finding", "ACL analysis", "kerberos"]),
    ("Impacket", "Windows protocols", ["SMB", "Kerberos", "LDAP", "MSSQL", "DCSync"]),
    ("CrackMapExec", "network pivoting", ["SMB", "WinRM", "MSSQL", "LDAP", "SSH"]),
    ("Responder", "credential capture", ["LLMNR", "NBT-NS", "mDNS", "WPAD", "relay"]),
    ("Mimikatz", "credential dumping", ["sekurlsa", "kerberos", "lsadump", "vault", "dpapi"]),
    ("Hashcat", "password cracking", ["rules", "masks", "wordlists", "modes", "optimization"]),
    ("SQLMap", "SQL injection", ["detection", "exploitation", "database access", "OS access"]),
    ("Nuclei", "vulnerability scanning", ["templates", "scanning", "customization", "automation"]),
    ("ffuf", "fuzzing", ["directory", "parameter", "header", "virtual host", "filters"]),
    ("Gobuster", "enumeration", ["directory", "DNS", "vhost", "S3", "GCS"]),
    ("Chisel", "tunneling", ["forward", "reverse", "SOCKS", "port forwarding"]),
    ("Ligolo-ng", "pivoting", ["tunneling", "agent", "proxy", "double pivot"]),
    ("Cobalt Strike", "post-exploitation", ["beacon", "aggressor", "malleable C2", "pivoting"]),
    ("Sliver", "C2 framework", ["implants", "pivots", "traffic", "extensions"]),
    ("Havoc", "C2 framework", ["demon", "listeners", "scripts", "modules"]),
    ("PowerShell Empire", "post-exploitation", ["agents", "modules", "stagers", "listeners"]),
    ("LinPEAS/WinPEAS", "privilege escalation", ["enumeration", "checks", "paths", "credentials"]),
]

for tool_name, tool_purpose, capabilities in tools:
    for capability in capabilities:
        add_sample(
            f"Master {tool_name} {capability} capability for advanced attacks",
            f"Tool: {tool_name}. Purpose: {tool_purpose}. Capability: {capability}.",
            f"""## Tool Mastery: {tool_name} - {capability.title()}

### Tool Overview
**{tool_name}**: {tool_purpose}

### Capability: {capability.title()}

**What This Enables**:
{capability.title()} in {tool_name} allows you to {tool_purpose} with focus on {capability}.

### Advanced Usage

**Basic Syntax**:
- Standard {capability} usage
- Common options and flags
- Output interpretation

**Advanced Techniques**:
- Optimization for speed/stealth
- Customization for specific targets
- Chaining with other capabilities
- Automation approaches

### Tactical Application

**When to Use**:
- Scenario 1: {capability} needed for reconnaissance
- Scenario 2: {capability} needed for exploitation
- Scenario 3: {capability} needed for post-exploitation

**How to Use Effectively**:
1. Prepare {tool_name} environment
2. Configure for target specifics
3. Execute {capability} operation
4. Analyze and act on results

### Evasion Considerations

**Detection Risks**:
- Network signatures for {tool_name}
- Behavioral patterns of {capability}
- Artifact generation

**Evasion Techniques**:
- Traffic obfuscation
- Slow/distributed operation
- Custom modifications
- Alternative tools

### Combining Capabilities

{capability.title()} works well with:
{chr(10).join([f"- {cap}: For combined effect" for cap in capabilities if cap != capability][:3])}

### Building Expertise

To master {capability} in {tool_name}:
1. Practice in lab environment
2. Study documentation deeply
3. Analyze how experts use it
4. Develop custom scripts/configs
5. Contribute improvements""",
            category="tool_mastery"
        )

print(f"   Tool mastery: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# ADVANCED ATTACK SCENARIOS
# ============================================================
print("\n📚 Building Advanced Attack Scenarios...")

scenarios = [
    {
        "name": "Cloud Infrastructure Takeover",
        "target": "AWS environment with multiple accounts",
        "entry": "Compromised developer workstation",
        "objective": "Full control of production infrastructure",
        "key_steps": ["credential theft", "IAM enumeration", "privilege escalation", "cross-account access", "infrastructure control"]
    },
    {
        "name": "Domain Dominance",
        "target": "Enterprise Active Directory",
        "entry": "Phishing to employee workstation",
        "objective": "Domain Admin and persistence",
        "key_steps": ["local privesc", "credential dumping", "lateral movement", "Kerberos attacks", "DC compromise"]
    },
    {
        "name": "Supply Chain Compromise",
        "target": "Software vendor CI/CD pipeline",
        "entry": "Compromised build server",
        "objective": "Trojanized software distribution",
        "key_steps": ["pipeline access", "build manipulation", "artifact tampering", "signing bypass", "distribution"]
    },
    {
        "name": "Zero Trust Network Penetration",
        "target": "Modern zero trust architecture",
        "entry": "Compromised endpoint with EDR",
        "objective": "Access to sensitive data",
        "key_steps": ["EDR bypass", "identity pivoting", "conditional access bypass", "data access", "exfiltration"]
    },
    {
        "name": "Container Escape to Host",
        "target": "Kubernetes cluster",
        "entry": "Compromised container",
        "objective": "Host system access and cluster control",
        "key_steps": ["container enumeration", "escape technique", "host access", "cluster credentials", "full control"]
    },
    {
        "name": "Ransomware Simulation",
        "target": "Enterprise network with backups",
        "entry": "RDP brute force",
        "objective": "Encrypt critical data including backups",
        "key_steps": ["network enumeration", "backup discovery", "backup destruction", "domain spread", "encryption"]
    },
    {
        "name": "Financial System Compromise",
        "target": "Banking application",
        "entry": "Web application vulnerability",
        "objective": "Transaction manipulation",
        "key_steps": ["web exploitation", "database access", "business logic analysis", "transaction injection", "cover tracks"]
    },
    {
        "name": "IoT Network Pivot",
        "target": "Corporate network via IoT devices",
        "entry": "Vulnerable IoT device",
        "objective": "Access to internal resources",
        "key_steps": ["IoT exploitation", "network access", "segmentation bypass", "internal scanning", "lateral movement"]
    },
]

for scenario in scenarios:
    add_sample(
        f"Execute {scenario['name']} attack campaign",
        f"Target: {scenario['target']}. Entry: {scenario['entry']}. Objective: {scenario['objective']}.",
        f"""## Advanced Attack Scenario: {scenario['name']}

### Scenario Overview
**Target**: {scenario['target']}
**Initial Access**: {scenario['entry']}
**Objective**: {scenario['objective']}

### Attack Phases

{chr(10).join([f"**Phase {i+1}: {step.title()}**" for i, step in enumerate(scenario['key_steps'])])}

### Detailed Execution

**Phase 1: {scenario['key_steps'][0].title()}**
- Initial foothold established via {scenario['entry']}
- Enumerate local environment
- Identify paths to next phase

**Phase 2: {scenario['key_steps'][1].title()}**
- Build on Phase 1 results
- Expand access and capabilities
- Prepare for privilege advancement

**Phase 3: {scenario['key_steps'][2].title()}**
- Escalate privileges as needed
- Expand network access
- Identify critical targets

**Phase 4: {scenario['key_steps'][3].title()}**
- Move toward final objective
- Address remaining obstacles
- Validate progress

**Phase 5: {scenario['key_steps'][4].title()}**
- Achieve primary objective
- Establish persistence
- Ensure operational success

### OPSEC Considerations

Throughout the campaign:
- Minimize detection footprint
- Use living-off-the-land techniques
- Time operations carefully
- Have fallback plans

### Success Criteria

The campaign succeeds when:
1. Initial access is established
2. Privileges are escalated sufficiently
3. Objective ({scenario['objective']}) is achieved
4. Access can be maintained

### Innovation Points

Where novel techniques help:
- Custom tooling for {scenario['target']}
- Bypass techniques for defenses
- Chain optimization
- Detection evasion

### Learning Outcomes

This scenario teaches:
1. Multi-phase attack execution
2. Environment-specific techniques
3. Operational planning
4. Adaptive attack methodology""",
        category="advanced_scenario"
    )

print(f"   Advanced scenarios: {len(all_samples) - start}")

# ============================================================
# SAVE MASSIVE DATASET
# ============================================================
print(f"\n{'='*70}")
print("💾 SAVING MASSIVE DEEP KNOWLEDGE DATASET")
print(f"{'='*70}")

random.shuffle(all_samples)

split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

train_file = output_dir / "massive_train.jsonl"
val_file = output_dir / "massive_val.jsonl"

with open(train_file, "w") as f:
    for s in train_samples:
        f.write(json.dumps(s) + "\n")

with open(val_file, "w") as f:
    for s in val_samples:
        f.write(json.dumps(s) + "\n")

categories = {}
for s in all_samples:
    cat = s.get("category", "unknown")
    categories[cat] = categories.get(cat, 0) + 1

print(f"\n✅ Total samples: {len(all_samples)}")
print(f"   Train: {len(train_samples)}")
print(f"   Val: {len(val_samples)}")
print(f"\n📊 Top categories:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:15]:
    print(f"   - {cat}: {count}")
print(f"\n📁 Output: {output_dir}")
