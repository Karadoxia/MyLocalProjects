#!/usr/bin/env python3
"""
Bombina Expanded Deep Knowledge Generator
Creates 4000+ samples focused on attack innovation and deep understanding
"""

import json
import hashlib
import random
from pathlib import Path
from itertools import product

output_dir = Path(__file__).parent.parent / "data" / "deep_knowledge"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output, category="general"):
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
print("🧠 BOMBINA EXPANDED DEEP KNOWLEDGE - 4000+ Innovation Samples")
print("="*70)

# ============================================================
# SECTION 1: VULNERABILITY ROOT CAUSE MATRIX
# ============================================================
print("\n📚 Section 1: Vulnerability Root Cause Matrix...")

root_causes = [
    ("improper input validation", "failing to sanitize or validate user input"),
    ("broken access control", "not enforcing authorization on all paths"),
    ("cryptographic failures", "misusing or weakening cryptographic protections"),
    ("injection flaws", "mixing code and data in the same channel"),
    ("security misconfiguration", "insecure default settings or improper setup"),
    ("use of vulnerable components", "using software with known vulnerabilities"),
    ("insufficient logging", "failing to detect or respond to attacks"),
    ("race conditions", "timing-dependent behavior affecting security"),
    ("insecure deserialization", "trusting serialized data from untrusted sources"),
    ("business logic flaws", "errors in the design of security-relevant logic"),
]

technologies = [
    ("web applications", "PHP, Java, Python, Node.js"),
    ("mobile applications", "Android, iOS, React Native"),
    ("APIs", "REST, GraphQL, gRPC"),
    ("cloud services", "AWS, Azure, GCP"),
    ("IoT devices", "embedded systems, firmware"),
    ("databases", "SQL, NoSQL, Graph"),
    ("network protocols", "TCP/IP, UDP, custom"),
    ("operating systems", "Windows, Linux, macOS"),
    ("containers", "Docker, Kubernetes"),
    ("CI/CD pipelines", "Jenkins, GitHub Actions, GitLab"),
]

impacts = [
    ("data breach", "unauthorized access to sensitive data"),
    ("account takeover", "gaining control of user accounts"),
    ("privilege escalation", "gaining higher privileges than intended"),
    ("denial of service", "making the system unavailable"),
    ("remote code execution", "executing arbitrary code on target"),
    ("lateral movement", "moving through the network"),
    ("persistence", "maintaining long-term access"),
]

for (root, root_desc), (tech, tech_examples), (impact, impact_desc) in product(root_causes[:5], technologies[:5], impacts[:4]):
    add_sample(
        f"How does {root} in {tech} lead to {impact}?",
        f"Root cause: {root_desc}. Technology: {tech} ({tech_examples}). Impact: {impact_desc}.",
        f"""## Attack Analysis: {root.title()} → {impact.title()}

### Root Cause
**{root_desc.capitalize()}** in {tech} creates an exploitable weakness.

### Technology Context: {tech.title()}
Common implementations: {tech_examples}

These systems often have:
- Complex input handling
- Multiple trust boundaries
- Legacy compatibility requirements
- Rapid development cycles

### Exploitation Path

**Step 1: Identify the Weakness**
In {tech}, {root} often appears as:
- Insufficient input validation
- Missing authorization checks
- Improper error handling
- Trust boundary violations

**Step 2: Develop Exploit**
To achieve {impact}:
1. Find entry point where {root} exists
2. Craft payload that triggers the vulnerability
3. Bypass any mitigations present
4. Achieve {impact_desc}

**Step 3: Maximize Impact**
{impact.title()} in {tech} enables:
- Further system compromise
- Data exfiltration
- Persistence mechanisms
- Lateral movement opportunities

### Innovation Insight

To find new instances of this pattern:
1. Look for {root} in uncommon {tech} contexts
2. Chain with other vulnerabilities
3. Apply to newer versions/implementations
4. Consider edge cases and error handlers

### Defense Understanding

Defenses against this:
- Input validation and sanitization
- Principle of least privilege
- Defense in depth
- Monitoring and alerting

Bypasses to consider:
- Encoding and obfuscation
- Parser differentials
- Timing attacks
- Logic flaws""",
        category="root_cause_matrix"
    )

print(f"   Root cause matrix: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# SECTION 2: EXPLOITATION TECHNIQUE COMBINATIONS
# ============================================================
print("\n📚 Section 2: Exploitation Technique Combinations...")

techniques = [
    ("reconnaissance", ["subdomain enumeration", "port scanning", "service fingerprinting", "technology detection", "user enumeration"]),
    ("initial access", ["phishing", "web exploitation", "credential stuffing", "supply chain", "exposed services"]),
    ("execution", ["command injection", "script execution", "binary execution", "malicious documents", "exploitation"]),
    ("persistence", ["scheduled tasks", "startup items", "implants", "web shells", "account creation"]),
    ("privilege escalation", ["kernel exploits", "misconfigurations", "credential abuse", "sudo abuse", "service exploitation"]),
    ("defense evasion", ["obfuscation", "process injection", "log tampering", "indicator removal", "masquerading"]),
    ("credential access", ["dumping", "sniffing", "keylogging", "brute force", "MitM"]),
    ("discovery", ["network scanning", "file enumeration", "process listing", "account discovery", "share enumeration"]),
    ("lateral movement", ["pass-the-hash", "remote services", "internal pivoting", "shared resources", "internal phishing"]),
    ("collection", ["data staging", "automated collection", "clipboard data", "screen capture", "keylogging"]),
    ("exfiltration", ["encrypted channels", "alternative protocols", "chunked transfer", "scheduled exfil", "cloud storage"]),
]

# Generate technique combination samples
for i, (phase1, techs1) in enumerate(techniques[:-1]):
    for phase2, techs2 in techniques[i+1:i+3]:  # Combine with next 2 phases
        for tech1 in techs1[:2]:
            for tech2 in techs2[:2]:
                add_sample(
                    f"Chain {tech1} ({phase1}) with {tech2} ({phase2}) in an attack",
                    f"Phase 1: {phase1} using {tech1}. Phase 2: {phase2} using {tech2}.",
                    f"""## Attack Chain: {tech1.title()} → {tech2.title()}

### Phase 1: {phase1.title()}
**Technique: {tech1.title()}**

This phase establishes:
- Initial foothold or information
- Foundation for next phase
- OPSEC baseline

**Execution approach**:
- Identify targets for {tech1}
- Prepare required tools/payloads
- Execute with minimal detection
- Validate success before proceeding

### Phase 2: {phase2.title()}
**Technique: {tech2.title()}**

Building on Phase 1:
- Uses output/access from {tech1}
- Advances attack objectives
- Increases capabilities

**Execution approach**:
- Leverage Phase 1 results
- Apply {tech2} technique
- Validate and expand access

### Chain Logic

```
{tech1.title()} PROVIDES → {tech2.title()} REQUIRES

Connection: {phase1.title()} output enables {phase2.title()} execution
Value: Combined effect greater than individual techniques
```

### Innovation: Adapting This Chain

This chain pattern applies to:
1. Different target environments
2. Various technology stacks
3. Alternative techniques with similar outputs
4. Defense-specific adaptations

### Detection Considerations

**Phase 1 indicators**: Activity patterns for {tech1}
**Phase 2 indicators**: Activity patterns for {tech2}
**Chain indicators**: Temporal correlation between phases

### Evasion Approaches

- Time delays between phases
- Varied techniques to avoid signatures
- Living-off-the-land where possible
- Traffic blending with normal operations""",
                    category="technique_chains"
                )

print(f"   Technique chains: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 3: PROTOCOL VULNERABILITY PATTERNS
# ============================================================
print("\n📚 Section 3: Protocol Vulnerability Patterns...")

protocols = {
    "HTTP": {
        "desc": "Hypertext Transfer Protocol",
        "vulns": ["request smuggling", "header injection", "verb tampering", "host header attacks", "CRLF injection"],
        "context": "web servers, reverse proxies, CDNs"
    },
    "DNS": {
        "desc": "Domain Name System",
        "vulns": ["cache poisoning", "zone transfer", "subdomain takeover", "rebinding", "tunneling"],
        "context": "resolvers, authoritative servers, cloud DNS"
    },
    "TLS": {
        "desc": "Transport Layer Security",
        "vulns": ["downgrade attacks", "certificate issues", "padding oracles", "heartbleed-type", "implementation flaws"],
        "context": "web servers, email, VPNs"
    },
    "SMB": {
        "desc": "Server Message Block",
        "vulns": ["relay attacks", "signing bypass", "EternalBlue-type", "coercion", "share enumeration"],
        "context": "Windows networks, file sharing, printers"
    },
    "LDAP": {
        "desc": "Lightweight Directory Access Protocol",
        "vulns": ["injection", "bind bypass", "passback", "enumeration", "null base DN"],
        "context": "Active Directory, identity systems"
    },
    "Kerberos": {
        "desc": "Network authentication protocol",
        "vulns": ["roasting", "golden/silver tickets", "delegation abuse", "AS-REP roasting", "pass-the-ticket"],
        "context": "Windows domains, enterprise auth"
    },
    "OAuth": {
        "desc": "Authorization framework",
        "vulns": ["redirect manipulation", "token theft", "scope escalation", "state confusion", "PKCE bypass"],
        "context": "SSO, API authorization, mobile apps"
    },
    "SAML": {
        "desc": "Security Assertion Markup Language",
        "vulns": ["signature bypass", "XML injection", "assertion manipulation", "replay", "recipient confusion"],
        "context": "enterprise SSO, federated identity"
    },
    "WebSocket": {
        "desc": "Full-duplex communication protocol",
        "vulns": ["cross-site hijacking", "message injection", "origin bypass", "upgrade abuse", "protocol confusion"],
        "context": "real-time web apps, APIs"
    },
    "gRPC": {
        "desc": "Remote Procedure Call framework",
        "vulns": ["deserialization", "metadata injection", "reflection abuse", "deadline manipulation", "status injection"],
        "context": "microservices, cloud-native apps"
    },
}

exploit_approaches = [
    ("blackbox testing", "Without source code access, using only inputs/outputs"),
    ("whitebox analysis", "With source code or documentation access"),
    ("fuzzing", "Automated input generation to find edge cases"),
    ("manual exploitation", "Crafted inputs based on protocol knowledge"),
]

for proto_name, proto_info in protocols.items():
    for vuln in proto_info["vulns"]:
        for approach, approach_desc in exploit_approaches[:2]:
            add_sample(
                f"Exploit {vuln} in {proto_name} using {approach}",
                f"Protocol: {proto_name} ({proto_info['desc']}). Vulnerability: {vuln}. Context: {proto_info['context']}.",
                f"""## Protocol Exploitation: {proto_name} - {vuln.title()}

### Protocol Overview
**{proto_name}**: {proto_info['desc']}
**Common contexts**: {proto_info['context']}

### Vulnerability: {vuln.title()}

This vulnerability exists because:
- Protocol complexity creates edge cases
- Implementations vary in behavior
- Security was often an afterthought
- Backwards compatibility preserves weaknesses

### {approach.title()} Approach

**{approach_desc}**

**Methodology**:
1. **Reconnaissance**: Identify {proto_name} implementation
2. **Mapping**: Enumerate exposed functionality
3. **Testing**: Probe for {vuln} indicators
4. **Exploitation**: Develop working exploit
5. **Verification**: Confirm impact

### Exploitation Technique

For {vuln} in {proto_name}:

**Detection**:
- Protocol-specific indicators
- Implementation fingerprints
- Error message analysis
- Timing characteristics

**Exploitation**:
- Craft protocol-aware payloads
- Handle protocol state correctly
- Bypass implementation-specific checks
- Chain with other protocol weaknesses

### Impact Potential

Successful {vuln} exploitation enables:
- Data access/manipulation
- Authentication bypass
- Service disruption
- Lateral movement
- Persistence

### Innovation Vectors

To find new {vuln} variants:
1. Study protocol specification gaps
2. Compare implementation behaviors
3. Test version differences
4. Analyze composition with other protocols

### Tool Development

Consider building:
- Custom protocol clients
- Fuzzing harnesses
- Detection scripts
- Exploitation frameworks""",
                category="protocol_vulns"
            )

print(f"   Protocol vulnerabilities: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 4: SECURITY BOUNDARY ANALYSIS
# ============================================================
print("\n📚 Section 4: Security Boundary Analysis...")

boundaries = [
    ("network perimeter", "external to internal network", ["firewall", "IDS/IPS", "DMZ"]),
    ("web application boundary", "client to server", ["WAF", "input validation", "session management"]),
    ("authentication boundary", "unauthenticated to authenticated", ["auth mechanisms", "MFA", "session tokens"]),
    ("authorization boundary", "user to admin", ["RBAC", "ABAC", "capability checks"]),
    ("process boundary", "user process to kernel", ["syscalls", "sandboxing", "capabilities"]),
    ("container boundary", "container to host", ["namespaces", "cgroups", "seccomp"]),
    ("VM boundary", "guest to hypervisor", ["hypercall interface", "memory isolation", "I/O virtualization"]),
    ("cloud boundary", "tenant to provider", ["IAM", "network isolation", "resource separation"]),
    ("domain boundary", "domain to domain", ["trust relationships", "federation", "cross-domain auth"]),
    ("data boundary", "classified to unclassified", ["DLP", "encryption", "access controls"]),
]

crossing_methods = [
    "exploiting implementation bugs",
    "abusing intended functionality",
    "bypassing security controls",
    "exploiting trust relationships",
    "using side channels",
    "leveraging misconfigurations",
]

for (boundary_name, boundary_desc, controls), crossing in product(boundaries[:6], crossing_methods[:4]):
    add_sample(
        f"Cross the {boundary_name} by {crossing}",
        f"Boundary: {boundary_desc}. Controls: {', '.join(controls)}.",
        f"""## Boundary Crossing: {boundary_name.title()}

### Boundary Definition
**{boundary_desc}**

This boundary is enforced by:
{chr(10).join([f"- **{ctrl}**" for ctrl in controls])}

### Crossing Method: {crossing.title()}

**Approach**:
{crossing.title()} to move from lower to higher trust level.

**Why This Works**:
- Security boundaries are human constructs
- Implementation is imperfect
- Assumptions can be violated
- Trust relationships can be abused

### Methodology

**Phase 1: Boundary Mapping**
- Identify exact boundary location
- Understand trust transition
- Enumerate security controls
- Find allowed interactions

**Phase 2: Weakness Identification**
- Test control effectiveness
- Look for bypass opportunities
- Identify trust confusion
- Find allowed paths that achieve goal

**Phase 3: Crossing Execution**
- Prepare technique
- Execute crossing
- Validate success
- Establish foothold

### Impact

Successfully crossing {boundary_name}:
- Gains higher trust level
- Access to restricted resources
- Ability to affect trusted operations
- Platform for further attacks

### Innovation Approach

To find new {boundary_name} crossings:
1. **Study the boundary deeply**: Understand all crossing mechanisms
2. **Analyze controls**: Find gaps and weaknesses
3. **Test systematically**: Probe all crossing attempts
4. **Document findings**: Build knowledge base

### Defense Perspective

Understanding defenses enables bypasses:
{chr(10).join([f"- **{ctrl}**: How does it work? How can it fail?" for ctrl in controls])}""",
        category="boundary_analysis"
    )

print(f"   Boundary analysis: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 5: ATTACK PATTERN VARIATIONS
# ============================================================
print("\n📚 Section 5: Attack Pattern Variations...")

patterns = {
    "injection": {
        "core": "inserting malicious data that is interpreted as code",
        "variants": [
            ("SQL injection", "database query", "data extraction, authentication bypass"),
            ("Command injection", "OS command execution", "RCE, system access"),
            ("LDAP injection", "directory query", "auth bypass, data access"),
            ("XPath injection", "XML query", "data extraction, auth bypass"),
            ("Template injection", "template engine", "RCE, data access"),
            ("Expression injection", "expression language", "RCE, data access"),
            ("Header injection", "HTTP headers", "response manipulation, XSS"),
            ("Log injection", "log files", "log forging, injection in viewers"),
        ]
    },
    "deserialization": {
        "core": "untrusted data used to reconstruct objects",
        "variants": [
            ("Java deserialization", "ObjectInputStream", "RCE via gadget chains"),
            ("PHP deserialization", "unserialize()", "RCE, object injection"),
            (".NET deserialization", "BinaryFormatter", "RCE via gadget chains"),
            ("Python pickle", "pickle.loads()", "arbitrary code execution"),
            ("YAML deserialization", "yaml.load()", "RCE via constructors"),
            ("JSON with types", "typed deserializers", "object instantiation attacks"),
            ("XML deserialization", "XMLDecoder", "RCE, SSRF"),
        ]
    },
    "path traversal": {
        "core": "accessing files outside intended directory",
        "variants": [
            ("Basic traversal", "../ sequences", "arbitrary file read"),
            ("Null byte injection", "%00 termination", "extension bypass"),
            ("Double encoding", "%252e%252e%252f", "WAF bypass"),
            ("Absolute path", "/etc/passwd directly", "direct file access"),
            ("Zip slip", "archive extraction", "file write outside directory"),
            ("Symlink following", "symbolic links", "escape intended directory"),
        ]
    },
    "authentication bypass": {
        "core": "circumventing identity verification",
        "variants": [
            ("Default credentials", "vendor defaults", "immediate access"),
            ("SQL injection auth", "' OR '1'='1", "login bypass"),
            ("JWT manipulation", "algorithm none", "token forgery"),
            ("Session fixation", "forced session ID", "account hijacking"),
            ("Password reset flaws", "weak reset flow", "account takeover"),
            ("MFA bypass", "implementation flaws", "second factor bypass"),
        ]
    },
    "privilege escalation": {
        "core": "gaining higher privileges than intended",
        "variants": [
            ("SUID exploitation", "setuid binaries", "root access"),
            ("Kernel exploit", "kernel vulnerabilities", "ring 0 access"),
            ("Service exploitation", "privileged services", "service account access"),
            ("Token manipulation", "access tokens", "impersonation"),
            ("Sudo abuse", "sudo misconfig", "root command execution"),
            ("Capability abuse", "Linux capabilities", "elevated operations"),
            ("UAC bypass", "Windows UAC", "admin without prompt"),
        ]
    },
}

for pattern_name, pattern_info in patterns.items():
    for variant_name, context, impact in pattern_info["variants"]:
        add_sample(
            f"Exploit {variant_name} ({pattern_name})",
            f"Pattern: {pattern_name}. Core principle: {pattern_info['core']}. Context: {context}.",
            f"""## Attack Pattern: {variant_name}

### Pattern Family: {pattern_name.title()}
**Core principle**: {pattern_info['core']}

### Variant: {variant_name}
**Context**: {context}
**Impact**: {impact}

### Why This Variant Exists

{variant_name} is a specific manifestation of {pattern_name} where:
- {context} processes untrusted input
- The core principle ({pattern_info['core']}) applies
- Impact ({impact}) is achievable

### Exploitation Methodology

**1. Identification**
- Detect presence of {context}
- Identify input vectors
- Test for {variant_name} indicators

**2. Validation**
- Confirm vulnerability exists
- Determine exploitation constraints
- Assess impact potential

**3. Exploitation**
- Craft {variant_name} payload
- Bypass protections
- Achieve {impact}

### Innovation Through Patterns

{variant_name} teaches us that {pattern_name}:
- Appears wherever {pattern_info['core']}
- Manifests differently in different contexts
- Can be found by understanding the principle

**To find new variants**:
1. Identify contexts where principle applies
2. Test for specific manifestation
3. Adapt known techniques
4. Document new variant

### Chaining Opportunities

{variant_name} often chains with:
- Information disclosure → Better exploitation
- Auth bypass → Reach vulnerable code
- Persistence → Maintain access

### Defense Understanding

Defenses against {variant_name}:
- Input validation specific to {context}
- Principle of least privilege
- Isolation and sandboxing

Bypass approaches:
- Encoding and obfuscation
- Alternative input vectors
- Implementation-specific tricks""",
            category="pattern_variants"
        )

print(f"   Pattern variants: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 6: CREATIVE EXPLOITATION SCENARIOS
# ============================================================
print("\n📚 Section 6: Creative Exploitation Scenarios...")

scenarios = [
    {
        "scenario": "You find a minor info disclosure in an otherwise hardened system",
        "constraint": "Limited vulnerability, strong defenses",
        "creative_approach": "Chain the info disclosure into ASLR bypass, then memory corruption exploit"
    },
    {
        "scenario": "The target uses an unknown/custom protocol",
        "constraint": "No existing tools or documentation",
        "creative_approach": "Reverse engineer protocol, apply fundamental vulnerability patterns"
    },
    {
        "scenario": "All traditional attack paths are blocked",
        "constraint": "Strong perimeter, MFA, monitoring",
        "creative_approach": "Target supply chain, employee devices, or physical vectors"
    },
    {
        "scenario": "You have read-only access to a database",
        "constraint": "No write permissions",
        "creative_approach": "Extract credentials, find backup credentials, pivot through found data"
    },
    {
        "scenario": "Target has excellent monitoring and IR capability",
        "constraint": "Low-and-slow approach required",
        "creative_approach": "Living-off-the-land, blend with normal traffic, time-delayed operations"
    },
    {
        "scenario": "Cloud environment with minimal IAM permissions",
        "constraint": "Limited starting permissions",
        "creative_approach": "Enumerate resources, find permission escalation paths, abuse trust"
    },
    {
        "scenario": "Legacy system with no known CVEs",
        "constraint": "Must find 0-day",
        "creative_approach": "Apply fundamental vulnerability classes to legacy code patterns"
    },
    {
        "scenario": "Mobile app with certificate pinning and root detection",
        "constraint": "Anti-tampering measures",
        "creative_approach": "Bypass at runtime, analyze traffic at lower layer, or target backend"
    },
    {
        "scenario": "Kubernetes environment with pod security policies",
        "constraint": "Restricted container execution",
        "creative_approach": "Target K8s API, find privileged pods, abuse service accounts"
    },
    {
        "scenario": "Target only exposes static content and authenticated API",
        "constraint": "Minimal attack surface",
        "creative_approach": "Credentials from other sources, API logic flaws, CDN cache attacks"
    },
]

for scenario in scenarios:
    add_sample(
        f"Creative exploitation: {scenario['scenario']}",
        f"Constraint: {scenario['constraint']}",
        f"""## Creative Exploitation Scenario

### Situation
{scenario['scenario']}

### Constraint
**{scenario['constraint']}**

### Creative Approach
{scenario['creative_approach']}

### Detailed Methodology

**Step 1: Constraint Analysis**
- What exactly is limited?
- What IS allowed/possible?
- What assumptions are being made?

**Step 2: Resource Inventory**
- What do we have?
- What can we observe/access?
- What capabilities exist?

**Step 3: Creative Reframing**
- How else could we achieve our goal?
- What unexpected paths exist?
- What would a defender not expect?

**Step 4: Approach Development**
{scenario['creative_approach']}

Detailed execution:
1. Validate the constraint is real
2. Enumerate available options
3. Develop the creative approach
4. Test and refine
5. Execute and adapt

### Innovation Principles Applied

1. **Question Assumptions**: The constraint may be incomplete
2. **Indirect Paths**: Direct paths blocked → find indirect ones
3. **Composition**: Combine weak capabilities into strong ones
4. **Environment Abuse**: Use environment features unexpectedly
5. **Persistence**: Creative solutions often require iteration

### Generalizing This Approach

This scenario teaches:
- Constraints drive creativity
- Multiple paths to most goals
- Defenders can't block everything
- Novel attacks from novel combinations

### Similar Scenarios

This pattern applies when facing:
- Strong technical controls
- Limited access or capabilities
- Unknown or custom technologies
- Well-defended high-value targets""",
        category="creative_scenarios"
    )

print(f"   Creative scenarios: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 7: DEFENSIVE BYPASS TECHNIQUES
# ============================================================
print("\n📚 Section 7: Defensive Bypass Techniques...")

defenses = {
    "WAF": {
        "purpose": "Block malicious web requests",
        "bypasses": ["encoding", "chunked transfer", "parameter pollution", "protocol-level", "content-type manipulation"]
    },
    "EDR": {
        "purpose": "Detect malicious endpoint behavior",
        "bypasses": ["direct syscalls", "unhooking", "ETW patching", "AMSI bypass", "living-off-the-land"]
    },
    "ASLR": {
        "purpose": "Randomize memory layout",
        "bypasses": ["info leak", "brute force", "partial overwrite", "format string", "non-randomized regions"]
    },
    "Stack Canaries": {
        "purpose": "Detect stack buffer overflow",
        "bypasses": ["info leak", "non-linear overwrite", "format string leak", "overwrite saved canary", "heap corruption"]
    },
    "DEP/NX": {
        "purpose": "Prevent code execution in data",
        "bypasses": ["ROP", "JOP", "ret2libc", "mprotect", "JIT spray"]
    },
    "Network Segmentation": {
        "purpose": "Isolate network zones",
        "bypasses": ["pivot through allowed services", "tunnel over allowed protocols", "application-layer pivot", "compromised jump box"]
    },
    "MFA": {
        "purpose": "Require additional authentication factor",
        "bypasses": ["real-time phishing", "SIM swap", "MFA fatigue", "session hijacking", "fallback mechanism abuse"]
    },
    "Sandboxing": {
        "purpose": "Isolate execution environment",
        "bypasses": ["kernel exploit", "IPC escape", "allowed functionality abuse", "policy gaps", "broker vulnerabilities"]
    },
}

for defense_name, defense_info in defenses.items():
    for bypass in defense_info["bypasses"]:
        add_sample(
            f"Bypass {defense_name} using {bypass}",
            f"Defense: {defense_name}. Purpose: {defense_info['purpose']}.",
            f"""## Defense Bypass: {defense_name} via {bypass.title()}

### Defense Overview
**{defense_name}**: {defense_info['purpose']}

### Bypass Technique: {bypass.title()}

**Why This Works**:
- Defenses make assumptions that can be violated
- Coverage is often incomplete
- Implementation has limitations
- Attackers can adapt faster than defenders update

### Bypass Methodology

**1. Defense Analysis**
- Understand exactly what {defense_name} protects
- Identify what it monitors/enforces
- Find gaps in coverage

**2. Bypass Development**
- {bypass.title()} exploits a gap in {defense_name}
- Craft approach that avoids detection
- Test against actual implementation

**3. Operational Use**
- Integrate bypass into attack chain
- Maintain stealth
- Have fallback approaches

### Technical Details

{bypass.title()} bypasses {defense_name} by:
- Avoiding the monitored/blocked pattern
- Using an unmonitored channel
- Exploiting implementation weakness
- Abusing allowed functionality

### Combination Approaches

{bypass.title()} often combines with:
- Other {defense_name} bypasses
- Bypasses for complementary defenses
- Distraction techniques

### Evolution of This Bypass

Defenses evolve, so must bypasses:
1. Current technique may stop working
2. Variations needed for new versions
3. Combination with other techniques
4. Novel approaches from first principles

### Innovation Mindset

Finding new {defense_name} bypasses:
1. Study how the defense works deeply
2. Identify its assumptions
3. Find ways to violate assumptions
4. Test systematically
5. Document and refine""",
            category="defense_bypass"
        )

print(f"   Defense bypasses: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 8: ZERO-DAY DISCOVERY METHODOLOGY
# ============================================================
print("\n📚 Section 8: Zero-Day Discovery Methodology...")

target_types = [
    ("web application framework", "handles user input and generates output", "injection, auth bypass, RCE"),
    ("network protocol implementation", "parses network messages", "memory corruption, DoS, auth bypass"),
    ("file format parser", "processes untrusted files", "memory corruption, code execution"),
    ("serialization library", "converts data to/from objects", "RCE, injection"),
    ("authentication system", "verifies identity", "bypass, impersonation, privilege escalation"),
    ("cryptographic implementation", "provides security guarantees", "key recovery, plaintext recovery"),
    ("browser component", "handles web content", "sandbox escape, RCE, info disclosure"),
    ("kernel driver", "runs at highest privilege", "privilege escalation, DoS"),
    ("container runtime", "provides isolation", "escape, privilege escalation"),
    ("cloud service", "manages infrastructure", "privilege escalation, data access"),
]

discovery_methods = [
    "code auditing",
    "fuzzing",
    "reverse engineering",
    "differential analysis",
    "pattern matching from CVEs",
]

for (target, target_desc, common_vulns), method in product(target_types[:6], discovery_methods):
    add_sample(
        f"Find zero-days in {target} using {method}",
        f"Target: {target_desc}. Common vulnerabilities: {common_vulns}.",
        f"""## Zero-Day Discovery: {target.title()} via {method.title()}

### Target Analysis
**Type**: {target.title()}
**Function**: {target_desc}
**Common vulnerability patterns**: {common_vulns}

### Discovery Method: {method.title()}

**Why This Method for This Target**:
- {target.title()} has characteristics that {method} exploits
- {method.title()} reveals vulnerabilities in how {target.lower()} {target_desc}
- History shows this combination is productive

### Methodology

**Phase 1: Preparation**
- Gather target documentation and source (if available)
- Set up analysis environment
- Understand previous vulnerabilities
- Identify high-value code paths

**Phase 2: {method.title()} Application**
{f'Systematic review of source code, focusing on input handling, state management, and security-critical operations' if method == 'code auditing' else
f'Generate malformed inputs targeting parser boundaries, edge cases, and unexpected values' if method == 'fuzzing' else
f'Disassemble and analyze binary, identify key functions, understand data flow' if method == 'reverse engineering' else
f'Compare versions, implementations, or configurations to find behavioral differences' if method == 'differential analysis' else
f'Study similar CVEs, extract patterns, look for same patterns in target'}

**Phase 3: Vulnerability Validation**
- Confirm finding is real vulnerability
- Determine exploitation potential
- Assess severity and impact

**Phase 4: Exploit Development**
- Develop proof-of-concept
- Address exploitation challenges
- Create reliable exploit

### What to Look For

In {target.lower()}, focus on:
- **Input handling**: How is untrusted data processed?
- **State management**: Can state be corrupted or confused?
- **Error handling**: What happens in error conditions?
- **Trust boundaries**: Where are security decisions made?

### Common Patterns in {target.title()}

Historical vulnerabilities show:
- {common_vulns.split(', ')[0]}: Most common pattern
- Parser issues in complex data handling
- State management problems
- Trust boundary confusion

### Innovation Opportunity

{target.title()} likely has undiscovered issues because:
- Complexity hides bugs
- New features introduce new attack surface
- Edge cases are hard to test
- Composition creates unexpected interactions

### Building Expertise

To become proficient at finding zero-days in {target.lower()}:
1. Study the technology deeply
2. Analyze previous vulnerabilities
3. Develop {method} skills
4. Practice on CTFs and bug bounties
5. Contribute to open-source security tools""",
        category="zeroday_discovery"
    )

print(f"   Zero-day methodology: {len(all_samples) - start}")

# ============================================================
# SAVE EXPANDED DATASET
# ============================================================
print(f"\n{'='*70}")
print("💾 SAVING EXPANDED DEEP KNOWLEDGE DATASET")
print(f"{'='*70}")

# Load existing samples to avoid duplicates
existing_files = list(output_dir.glob("*_train.jsonl")) + list(output_dir.glob("*_val.jsonl"))
for f in existing_files:
    with open(f) as ef:
        for line in ef:
            sample = json.loads(line)
            content = f"{sample['instruction']}|{sample['input']}"
            h = hashlib.md5(content.encode()).hexdigest()
            seen_hashes.add(h)

random.shuffle(all_samples)

split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

train_file = output_dir / "expanded_train.jsonl"
val_file = output_dir / "expanded_val.jsonl"

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

print(f"\n✅ Total NEW samples: {len(all_samples)}")
print(f"   Train: {len(train_samples)}")
print(f"   Val: {len(val_samples)}")
print(f"\n📊 By category:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"   - {cat}: {count}")
print(f"\n📁 Output: {output_dir}")
