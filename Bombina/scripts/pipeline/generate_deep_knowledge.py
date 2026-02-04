#!/usr/bin/env python3
"""
Bombina Deep Knowledge Dataset Generator
Creates training data for INNOVATION and DEEP UNDERSTANDING
Focus: Attack primitives, vulnerability theory, protocol internals
"""

import json
import hashlib
import random
from pathlib import Path

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
print("🧠 GENERATING DEEP KNOWLEDGE DATASET FOR ATTACK INNOVATION")
print("="*70)

# ============================================================
# PART 1: ATTACK PRIMITIVES - The Building Blocks
# ============================================================
print("\n📚 Part 1: Attack Primitives...")

# 1.1 Memory Corruption Primitives
memory_primitives = [
    ("buffer overflow", "writing beyond allocated memory bounds", 
     "overwrites adjacent memory, can corrupt return addresses, function pointers, or heap metadata"),
    ("use-after-free", "accessing memory after deallocation",
     "dangling pointer dereference, can lead to arbitrary read/write if memory is reallocated"),
    ("double-free", "freeing the same memory twice",
     "corrupts heap metadata, can lead to arbitrary write primitive"),
    ("integer overflow", "arithmetic exceeding data type bounds",
     "wraps around, can bypass size checks, lead to undersized allocations"),
    ("type confusion", "treating data as wrong type",
     "misinterpreting memory layout, can leak pointers or corrupt vtables"),
    ("uninitialized memory", "using memory before initialization",
     "may contain sensitive data from previous operations, info leak"),
    ("format string", "user-controlled format specifiers",
     "arbitrary read via %x/%s, arbitrary write via %n, info disclosure"),
    ("race condition", "timing-dependent behavior",
     "TOCTOU bugs, can bypass checks if state changes between check and use"),
]

exploitation_contexts = ["userland", "kernel", "browser", "embedded", "mobile"]
goals = ["code execution", "privilege escalation", "information disclosure", "denial of service"]

for prim, mechanism, effect in memory_primitives:
    for context in exploitation_contexts:
        for goal in goals:
            add_sample(
                f"Explain the {prim} primitive and how it enables {goal}",
                f"Context: {context} exploitation. Mechanism: {mechanism}",
                f"""## Attack Primitive: {prim.title()}

### Fundamental Mechanism
{mechanism.capitalize()}. This primitive {effect}.

### Why This Enables {goal.title()}

**Root Cause**: The underlying issue is a violation of memory safety assumptions. When code {mechanism}, it breaks the contract between the program and the memory allocator.

**Exploitation Chain**:
1. **Trigger**: Find code path that causes {prim}
2. **Control**: Shape memory/timing to control the corruption
3. **Primitive**: Convert corruption into useful primitive (read/write/execute)
4. **Payload**: Use primitive to achieve {goal}

### {context.title()} Specific Considerations

{'Userland exploitation typically requires bypassing ASLR, stack canaries, and DEP/NX. Modern mitigations like CFI make exploitation harder but not impossible.' if context == 'userland' else
'Kernel exploitation is more valuable (ring 0) but harder. Must consider SMEP, SMAP, KASLR, and kernel heap hardening.' if context == 'kernel' else
'Browser exploitation requires sandbox escape after initial code execution. JIT compilation adds attack surface but also mitigations.' if context == 'browser' else
'Embedded systems often lack modern mitigations, making exploitation easier. But limited debugging and diverse architectures add complexity.' if context == 'embedded' else
'Mobile exploitation must consider app sandboxing, SELinux/sandbox profiles, and platform-specific mitigations.'}

### Innovation Opportunity
To discover new instances of {prim}:
- Look for {mechanism} patterns in code review
- Fuzz inputs that influence memory operations
- Analyze similar vulnerabilities in related codebases
- Consider uncommon code paths and error handlers

### Converting to {goal.title()}
{'Code execution requires controlling instruction pointer (RIP/EIP/PC). Chain: corrupt return address/function pointer → redirect to controlled code/ROP gadgets → execute payload.' if goal == 'code execution' else
'Privilege escalation requires corrupting security-relevant data: credentials, capability structures, or code running at higher privilege.' if goal == 'privilege escalation' else
'Information disclosure requires reading out-of-bounds or from freed memory. Useful for bypassing ASLR or leaking secrets.' if goal == 'information disclosure' else
'DoS is often the easiest outcome - any corruption can crash. But controlled DoS (without crash) requires careful exploitation.'}""",
                category="memory_primitives"
            )

print(f"   Memory primitives: {len(all_samples)}")
start = len(all_samples)

# 1.2 Authentication Primitives
auth_primitives = [
    ("credential theft", "obtaining valid credentials", ["passwords", "tokens", "keys", "certificates"]),
    ("credential forgery", "creating valid-looking credentials", ["JWT manipulation", "ticket forging", "certificate generation"]),
    ("session hijacking", "taking over authenticated sessions", ["cookie theft", "token replay", "session fixation"]),
    ("authentication bypass", "circumventing auth checks", ["logic flaws", "default credentials", "null authentication"]),
    ("privilege confusion", "exploiting trust relationships", ["delegation abuse", "impersonation", "role confusion"]),
]

for prim, desc, techniques in auth_primitives:
    for technique in techniques:
        add_sample(
            f"Explain the {prim} primitive using {technique}",
            f"Technique: {technique}. Goal: Gain unauthorized access.",
            f"""## Authentication Primitive: {prim.title()}

### Core Concept
{desc.capitalize()}. This primitive allows an attacker to assume the identity or privileges of another entity.

### Technique: {technique.title()}

**How It Works**:
{technique.title()} exploits weaknesses in how authentication state is created, stored, validated, or transferred.

**Attack Pattern**:
1. **Identify**: Locate where {technique.lower()} can be performed
2. **Extract/Forge**: Obtain or create the authentication material
3. **Replay/Present**: Use the material to authenticate
4. **Persist**: Maintain access without re-authentication

### Why This Works (Root Cause)

Authentication systems must verify:
- **Something you know** (passwords, PINs)
- **Something you have** (tokens, keys)
- **Something you are** (biometrics)

{technique.title()} works because:
- The verification can be bypassed or fooled
- The authentication material can be obtained or forged
- The trust chain has weaknesses

### Innovation Vectors

To discover new {prim} attacks:
1. **Map the auth flow**: Understand every step of authentication
2. **Identify trust boundaries**: Where is identity verified? Where is it assumed?
3. **Find state storage**: How is auth state stored and validated?
4. **Analyze transitions**: What happens during login, logout, session refresh?

### Combining Primitives
{prim.title()} often chains with:
- Information disclosure (leak credentials)
- Man-in-the-middle (intercept auth)
- Logic flaws (bypass validation)
- Cryptographic weaknesses (forge tokens)""",
            category="auth_primitives"
        )

print(f"   Auth primitives: {len(all_samples) - start}")
start = len(all_samples)

# 1.3 Logic Primitives
logic_primitives = [
    ("TOCTOU", "time-of-check to time-of-use", "state changes between security check and action"),
    ("state confusion", "unexpected state transitions", "reaching states that bypass security checks"),
    ("order dependency", "operation sequence matters", "performing operations in unexpected order"),
    ("boundary confusion", "trust boundary violations", "crossing security boundaries unexpectedly"),
    ("assumption violation", "breaking implicit assumptions", "inputs or states that code doesn't expect"),
    ("resource exhaustion", "depleting limited resources", "causing denial or degraded security"),
]

for prim, short_desc, mechanism in logic_primitives:
    add_sample(
        f"Explain the {prim} logic primitive for finding vulnerabilities",
        f"Description: {short_desc}. Mechanism: {mechanism}.",
        f"""## Logic Primitive: {prim.upper()}

### Fundamental Concept
**{short_desc.title()}**: {mechanism}.

### Why This Creates Vulnerabilities

Software makes assumptions about:
- **Order**: Operations happen in expected sequence
- **Timing**: State doesn't change during critical sections
- **Boundaries**: Trust decisions are enforced correctly
- **Resources**: Sufficient resources are available

{prim.upper()} exploits violations of these assumptions.

### Pattern Recognition

**Where to Look**:
1. Multi-step operations (transactions, wizards, workflows)
2. Concurrent access (multi-threaded, multi-process)
3. Distributed systems (eventual consistency, race conditions)
4. State machines (login flows, payment processing)

**Indicators**:
- Security check separated from action
- Mutable state between operations
- Missing atomicity guarantees
- Implicit ordering assumptions

### Exploitation Methodology

1. **Map the Logic**: Understand the intended flow
2. **Identify Assumptions**: What must be true for security?
3. **Violate Assumptions**: How can you break them?
4. **Exploit the Gap**: What can you achieve?

### Innovation Approach

To find novel {prim} vulnerabilities:
```
For each security-relevant operation:
  1. What state is checked?
  2. What state is used?
  3. Can they differ?
  4. What's the impact if they differ?
```

### Real-World Impact
{prim.upper()} bugs often lead to:
- Authentication bypass
- Authorization failures  
- Data integrity violations
- Privilege escalation""",
        category="logic_primitives"
    )

print(f"   Logic primitives: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 2: VULNERABILITY THEORY - Why Things Break
# ============================================================
print("\n📚 Part 2: Vulnerability Theory...")

# 2.1 Vulnerability Classes
vuln_classes = [
    {
        "class": "Injection",
        "root_cause": "mixing code and data in the same channel",
        "examples": ["SQL injection", "command injection", "LDAP injection", "XPath injection"],
        "principle": "never trust user input to be data-only when it's interpreted as code"
    },
    {
        "class": "Broken Access Control", 
        "root_cause": "failing to enforce authorization on all paths",
        "examples": ["IDOR", "privilege escalation", "path traversal", "forced browsing"],
        "principle": "authorization must be checked at every access point, not just entry points"
    },
    {
        "class": "Cryptographic Failures",
        "root_cause": "misusing or weakening cryptographic protections",
        "examples": ["weak algorithms", "improper key management", "missing encryption", "oracle attacks"],
        "principle": "cryptography must be used correctly end-to-end with proper key lifecycle"
    },
    {
        "class": "Security Misconfiguration",
        "root_cause": "insecure default or improper setup",
        "examples": ["default credentials", "exposed admin interfaces", "verbose errors", "missing hardening"],
        "principle": "secure by default, explicit configuration for any relaxation"
    },
    {
        "class": "Vulnerable Components",
        "root_cause": "using software with known vulnerabilities",
        "examples": ["outdated libraries", "unpatched systems", "abandoned dependencies"],
        "principle": "continuous inventory and patching of all components"
    },
    {
        "class": "Authentication Failures",
        "root_cause": "weak identity verification mechanisms",
        "examples": ["credential stuffing", "brute force", "session fixation", "weak recovery"],
        "principle": "strong authentication with defense in depth and monitoring"
    },
    {
        "class": "Software Integrity Failures",
        "root_cause": "accepting untrusted code or data",
        "examples": ["insecure deserialization", "unsigned updates", "CI/CD compromise"],
        "principle": "verify integrity of all code and data from external sources"
    },
    {
        "class": "SSRF",
        "root_cause": "server making requests to attacker-controlled destinations",
        "examples": ["cloud metadata access", "internal port scanning", "protocol smuggling"],
        "principle": "allowlist destinations, validate URLs, sandbox network access"
    },
]

for vc in vuln_classes:
    add_sample(
        f"Explain the {vc['class']} vulnerability class from first principles",
        f"Root cause: {vc['root_cause']}. Examples: {', '.join(vc['examples'][:3])}.",
        f"""## Vulnerability Class: {vc['class']}

### Root Cause Analysis
**Fundamental Issue**: {vc['root_cause'].capitalize()}.

This class exists because software systems must process external input, but that input can be crafted to violate security assumptions.

### Why This Pattern Repeats

{vc['class']} vulnerabilities appear repeatedly because:

1. **Complexity**: Modern systems have many input paths and trust boundaries
2. **Composition**: Combining secure components can create insecure systems
3. **Evolution**: New features introduce new attack surface
4. **Human factors**: Developers focus on functionality over security

### The Principle
**{vc['principle'].capitalize()}.**

### Examples and Variations

{chr(10).join([f"- **{ex.title()}**: Specific manifestation targeting particular technology/protocol" for ex in vc['examples']])}

### Finding New Instances

To discover novel {vc['class'].lower()} vulnerabilities:

1. **Identify Input Points**: Where does external data enter?
2. **Trace Data Flow**: How is it processed, transformed, used?
3. **Find Trust Transitions**: Where are security decisions made?
4. **Test Boundaries**: What happens with unexpected input?

### Pattern for Innovation

```
For each input path:
  - What security assumption does processing make?
  - Can attacker control data that violates this assumption?
  - What's the worst-case outcome?
```

### Defense Understanding

Understanding defenses helps find bypasses:
- Input validation: Can it be evaded?
- Output encoding: Is it context-appropriate?
- Access controls: Are they complete?
- Monitoring: What's not logged?""",
        category="vuln_theory"
    )

# 2.2 Exploitation Theory
exploitation_theory = [
    ("memory safety", "Why memory corruption leads to code execution",
     """Memory corruption primitives become code execution through controlling program flow:

**The Chain**:
1. **Write Primitive**: Ability to write attacker-controlled data
2. **Target Selection**: Find security-critical data to corrupt
3. **Control Flow**: Redirect execution (return address, function pointer, vtable)
4. **Payload Execution**: Execute attacker code or ROP chain

**Why It Works**:
- CPUs don't distinguish code from data
- Memory layout is predictable or leakable
- Control flow data is stored in writable memory
- Mitigations have bypasses"""),
    
    ("trust boundaries", "How trust boundary violations enable attacks",
     """Trust boundaries define where security decisions are made and enforced.

**Exploitation Pattern**:
1. **Map Boundaries**: Identify where trust transitions occur
2. **Find Gaps**: Look for paths that bypass checks
3. **Cross Boundary**: Move from untrusted to trusted context
4. **Exploit Trust**: Abuse capabilities in trusted context

**Common Weaknesses**:
- Incomplete mediation (not all paths checked)
- Confused deputy (trusted component misused)
- Trust inheritance (child inherits parent's trust)
- Transitive trust (A trusts B, B trusts C, A trusts C?)"""),

    ("attack surface", "Understanding and expanding attack surface",
     """Attack surface is the sum of all points where an attacker can interact with a system.

**Components**:
- **Input vectors**: Network, files, IPC, hardware
- **Code paths**: Reachable functionality
- **Data paths**: Where attacker data flows
- **State**: Persistent attacker influence

**Expansion Techniques**:
1. Enable disabled features
2. Reach error handlers
3. Trigger rare code paths
4. Chain multiple components
5. Abuse debugging/admin interfaces"""),

    ("privilege levels", "Exploiting privilege hierarchies",
     """Systems implement privilege levels to contain compromise. Exploitation targets these boundaries.

**Common Hierarchies**:
- User → Root/Admin → Kernel → Hypervisor → Firmware
- Guest → User → Admin → Domain Admin → Enterprise Admin
- Anonymous → Authenticated → Privileged → Service Account

**Escalation Patterns**:
1. **Vertical**: User to admin to kernel
2. **Horizontal**: User A to User B
3. **Diagonal**: Combine both

**Why Escalation Works**:
- Privileged code has bugs too
- Trust relationships are exploitable
- Isolation is imperfect
- Side channels leak information"""),
]

for title, short_desc, content in exploitation_theory:
    add_sample(
        f"Explain {title} from an offensive security perspective",
        f"Topic: {short_desc}",
        f"""## Exploitation Theory: {title.title()}

### {short_desc}

{content}

### Innovation Application

Understanding {title} enables finding new vulnerabilities:

1. **First Principles**: What must be true for security?
2. **Assumptions**: What does the system assume?
3. **Violations**: How can assumptions be broken?
4. **Impact**: What can attacker achieve?

### Practical Methodology

When analyzing a target:
```
1. Map the {title} characteristics
2. Identify weaknesses in the model
3. Develop hypothesis for exploitation
4. Test and refine approach
5. Chain with other primitives if needed
```""",
        category="exploitation_theory"
    )

print(f"   Vulnerability theory: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 3: ATTACK COMPOSITION - Combining Techniques
# ============================================================
print("\n📚 Part 3: Attack Composition...")

# 3.1 Attack Chaining Principles
chain_principles = [
    ("primitive stacking", "combining multiple primitives for greater impact",
     ["info leak + memory corruption = ASLR bypass + code execution",
      "auth bypass + IDOR = access any user's data",
      "SSRF + cloud metadata = credential theft"]),
    ("stage progression", "using each stage to enable the next",
     ["recon → initial access → persistence → privilege escalation → objective",
      "phishing → beacon → domain recon → lateral movement → DC compromise",
      "web shell → pivot → internal scan → database access → exfiltration"]),
    ("defense evasion composition", "layering evasion techniques",
     ["encoding + encryption + fragmentation = bypass multiple controls",
      "living-off-the-land + timestomping + log clearing = forensic resistance",
      "process injection + unhooking + direct syscalls = EDR bypass"]),
    ("multi-vector attacks", "attacking through multiple paths simultaneously",
     ["phishing + watering hole + supply chain = increased success probability",
      "network attack + physical access + social engineering = defense saturation",
      "web + API + mobile = exploit weakest link"]),
]

for principle, description, examples in chain_principles:
    for example in examples:
        add_sample(
            f"Explain attack composition using {principle}",
            f"Principle: {description}. Example: {example}.",
            f"""## Attack Composition: {principle.title()}

### Principle
**{description.capitalize()}.**

### Example Analysis: {example}

**Decomposition**:
{chr(10).join([f"- Stage {i+1}: {part.strip()}" for i, part in enumerate(example.split('+' if '+' in example else '→'))])}

**Why This Works**:
Each component addresses a specific challenge:
- Early stages provide access or information
- Middle stages expand capabilities
- Final stages achieve objectives

**Composition Logic**:
```
GIVEN: Primitive A provides capability X
AND:   Primitive B requires capability X
THEN:  A enables B
CHAIN: A → B achieves combined effect
```

### Innovation Through Composition

To create novel attack chains:

1. **Inventory Primitives**: What individual capabilities do you have?
2. **Map Dependencies**: What does each primitive require and provide?
3. **Find Connections**: How can outputs feed into inputs?
4. **Optimize Path**: What's the most efficient chain?

### Composition Patterns

**Serial Composition**: A → B → C
- Each stage enables the next
- Failure at any stage stops the chain

**Parallel Composition**: A + B → C
- Multiple primitives combined
- Redundancy or combined effect

**Conditional Composition**: if A then B else C
- Adapt based on results
- Handle different scenarios

### Creating New Attacks

Novel attacks often come from:
1. New primitive combinations
2. Applying known chains to new targets
3. Finding unexpected connections
4. Automating complex chains""",
            category="attack_composition"
        )

print(f"   Attack composition: {len(all_samples) - start}")
start = len(all_samples)

# 3.2 Attack Innovation Samples
innovation_scenarios = [
    {
        "scenario": "You discover a new info leak in a browser",
        "known_primitives": ["ASLR bypass", "heap spray", "type confusion"],
        "innovation_process": "Chain info leak with existing primitives for full exploit"
    },
    {
        "scenario": "Target has unknown authentication system",
        "known_primitives": ["timing attacks", "error oracle", "state manipulation"],
        "innovation_process": "Apply fundamental auth weaknesses to unknown implementation"
    },
    {
        "scenario": "Cloud environment with custom IAM",
        "known_primitives": ["privilege enumeration", "role chaining", "metadata access"],
        "innovation_process": "Map trust relationships and find escalation paths"
    },
    {
        "scenario": "IoT device with proprietary protocol",
        "known_primitives": ["protocol fuzzing", "firmware analysis", "side channels"],
        "innovation_process": "Reverse engineer protocol, apply known vulnerability patterns"
    },
    {
        "scenario": "AI/ML system accepting user input",
        "known_primitives": ["prompt injection", "training data poisoning", "model extraction"],
        "innovation_process": "Understand trust boundaries in AI pipeline, find injection points"
    },
]

for scenario in innovation_scenarios:
    add_sample(
        "Create a novel attack approach for an unknown target",
        f"Scenario: {scenario['scenario']}. Available primitives: {', '.join(scenario['known_primitives'])}.",
        f"""## Attack Innovation Exercise

### Scenario
{scenario['scenario']}

### Available Primitives
{chr(10).join([f"- {p}" for p in scenario['known_primitives']])}

### Innovation Process

**Step 1: Understand the Target**
- What is the system trying to do?
- What are the trust boundaries?
- Where does user input flow?
- What security assumptions exist?

**Step 2: Map to Known Patterns**
{scenario['innovation_process']}

Even unknown systems follow patterns:
- Authentication has common weaknesses
- Memory management has known pitfalls
- Trust relationships can be abused
- Input handling is often flawed

**Step 3: Hypothesis Generation**
Based on primitives and target understanding:
```
Hypothesis 1: {scenario['known_primitives'][0]} may reveal internal structure
Hypothesis 2: {scenario['known_primitives'][1]} could bypass intended flow
Hypothesis 3: Combining primitives may achieve greater impact
```

**Step 4: Experimentation**
- Start with least detectable techniques
- Validate each hypothesis
- Document findings for chain building
- Iterate based on results

**Step 5: Chain Construction**
Once primitives are validated:
1. Order by dependency (what enables what)
2. Identify failure points and alternatives
3. Build end-to-end attack path
4. Optimize for reliability/stealth

### Innovation Principles Applied

1. **First Principles**: Understand WHY systems are vulnerable
2. **Pattern Recognition**: Apply known patterns to new contexts
3. **Composition**: Combine primitives creatively
4. **Iteration**: Refine through experimentation

### Novel Attack Creation

The attack is "new" because:
- Target is unknown/custom
- Specific chain is unique
- But underlying primitives are well-understood

**Innovation = Known Primitives + New Context + Creative Composition**""",
        category="attack_innovation"
    )

print(f"   Attack innovation: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 4: PROTOCOL DEEP DIVES - How Systems Work
# ============================================================
print("\n📚 Part 4: Protocol Deep Dives...")

protocols = [
    {
        "name": "Kerberos",
        "purpose": "Network authentication protocol",
        "components": ["KDC", "TGT", "TGS", "Service Ticket", "PAC"],
        "attack_surface": ["AS-REQ/AS-REP", "TGS-REQ/TGS-REP", "AP-REQ/AP-REP", "Ticket encryption", "PAC validation"],
        "known_attacks": ["Kerberoasting", "AS-REP Roasting", "Golden Ticket", "Silver Ticket", "Delegation abuse"],
        "innovation_areas": ["New ticket manipulation", "PAC-based attacks", "Cross-realm abuse", "Clock skew exploitation"]
    },
    {
        "name": "NTLM",
        "purpose": "Challenge-response authentication",
        "components": ["LM hash", "NT hash", "NTLM challenge", "NTLM response", "NTLMv2"],
        "attack_surface": ["Hash extraction", "Challenge/response", "Session signing", "Relay", "Downgrade"],
        "known_attacks": ["Pass-the-hash", "NTLM relay", "Responder poisoning", "NTLMv1 downgrade"],
        "innovation_areas": ["New relay scenarios", "Coercion methods", "Cross-protocol relay", "Hash extraction techniques"]
    },
    {
        "name": "OAuth 2.0 / OIDC",
        "purpose": "Authorization and authentication framework",
        "components": ["Authorization server", "Resource server", "Client", "Tokens", "Scopes"],
        "attack_surface": ["Redirect URI", "State parameter", "Token storage", "Implicit flow", "PKCE"],
        "known_attacks": ["Authorization code injection", "Token theft", "Scope escalation", "Open redirect"],
        "innovation_areas": ["Novel redirect bypasses", "Token binding attacks", "Cross-origin issues", "Mobile flow attacks"]
    },
    {
        "name": "TLS/SSL",
        "purpose": "Transport layer security",
        "components": ["Handshake", "Certificates", "Cipher suites", "Session resumption", "Extensions"],
        "attack_surface": ["Certificate validation", "Cipher negotiation", "Key exchange", "Protocol version", "Extensions"],
        "known_attacks": ["Downgrade attacks", "Certificate forgery", "Padding oracles", "Implementation bugs"],
        "innovation_areas": ["New cipher attacks", "Implementation-specific bugs", "Interception techniques", "Side channels"]
    },
    {
        "name": "DNS",
        "purpose": "Domain name resolution",
        "components": ["Resolvers", "Authoritative servers", "Records", "Caching", "DNSSEC"],
        "attack_surface": ["Query/response", "Cache", "Zone transfers", "Dynamic updates", "Recursion"],
        "known_attacks": ["Cache poisoning", "DNS tunneling", "Subdomain takeover", "NXDOMAIN attacks"],
        "innovation_areas": ["New cache attacks", "Covert channels", "Trust exploitation", "Cloud DNS abuse"]
    },
    {
        "name": "SMB/CIFS",
        "purpose": "File and printer sharing",
        "components": ["Authentication", "Sessions", "Shares", "Named pipes", "RPC over SMB"],
        "attack_surface": ["Authentication negotiation", "Share permissions", "Named pipe access", "RPC interfaces"],
        "known_attacks": ["Relay attacks", "Share enumeration", "Named pipe abuse", "RPC exploitation"],
        "innovation_areas": ["New coercion", "Protocol confusion", "Cross-version attacks", "Signing bypass"]
    },
    {
        "name": "LDAP",
        "purpose": "Directory access protocol",
        "components": ["Bind", "Search", "Modify", "Schema", "Controls"],
        "attack_surface": ["Authentication", "Query injection", "Access controls", "Replication", "LDAPS"],
        "known_attacks": ["LDAP injection", "Pass-back attacks", "Credential extraction", "AD enumeration"],
        "innovation_areas": ["New injection contexts", "Control abuse", "Replication attacks", "Trust exploitation"]
    },
    {
        "name": "HTTP/2 and HTTP/3",
        "purpose": "Modern web transport",
        "components": ["Streams", "HPACK/QPACK", "Server push", "Multiplexing", "QUIC"],
        "attack_surface": ["Header compression", "Stream handling", "Priority", "Flow control", "Connection pooling"],
        "known_attacks": ["Request smuggling", "Header injection", "Stream reset", "Resource exhaustion"],
        "innovation_areas": ["H2/H3 specific smuggling", "Compression attacks", "Stream confusion", "QUIC exploitation"]
    },
]

for protocol in protocols:
    add_sample(
        f"Deep dive into {protocol['name']} protocol security",
        f"Protocol: {protocol['name']}. Purpose: {protocol['purpose']}.",
        f"""## Protocol Deep Dive: {protocol['name']}

### Overview
**Purpose**: {protocol['purpose']}

### Core Components
{chr(10).join([f"- **{comp}**" for comp in protocol['components']])}

### Attack Surface Analysis

{protocol['name']} exposes these attack vectors:
{chr(10).join([f"- {surface}" for surface in protocol['attack_surface']])}

### Known Attack Techniques

Well-documented attacks against {protocol['name']}:
{chr(10).join([f"- **{attack}**" for attack in protocol['known_attacks']])}

### Why These Attacks Work

{protocol['name']} vulnerabilities stem from:
1. **Complexity**: Multiple components with subtle interactions
2. **Legacy**: Backwards compatibility preserves weaknesses
3. **Implementation variance**: Different vendors, different bugs
4. **Trust assumptions**: Protocol design made assumptions that don't hold

### Innovation Opportunities

Areas for discovering new {protocol['name']} attacks:
{chr(10).join([f"- {area}" for area in protocol['innovation_areas']])}

### Research Methodology

To find new vulnerabilities in {protocol['name']}:

1. **Study the RFC/Specification**
   - Understand intended behavior
   - Note ambiguities and edge cases
   - Identify security considerations

2. **Analyze Implementations**
   - Compare different implementations
   - Look for specification violations
   - Find implementation-specific features

3. **Identify Trust Boundaries**
   - Where are security decisions made?
   - What data crosses boundaries?
   - How is authentication handled?

4. **Fuzz and Test**
   - Protocol-aware fuzzing
   - State machine testing
   - Interoperability testing

### Composition with Other Protocols

{protocol['name']} often interacts with other protocols. Attacks can span:
- Protocol boundaries (cross-protocol attacks)
- Layer transitions (network to application)
- Trust domains (internal to external)

### Building Expertise

To deeply understand {protocol['name']}:
1. Read the specification completely
2. Implement a basic client/server
3. Study existing vulnerability research
4. Analyze real-world traffic
5. Build testing tools""",
        category="protocol_deepdive"
    )

print(f"   Protocol deep dives: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 5: SYSTEM INTERNALS - How Computers Work
# ============================================================
print("\n📚 Part 5: System Internals...")

system_topics = [
    {
        "topic": "Windows Security Architecture",
        "components": ["LSASS", "SAM", "Security Descriptors", "Access Tokens", "Privileges", "Integrity Levels"],
        "attack_relevance": "Understanding Windows security enables credential attacks, privilege escalation, and defense evasion"
    },
    {
        "topic": "Linux Security Model",
        "components": ["UIDs/GIDs", "Capabilities", "SELinux/AppArmor", "Namespaces", "Seccomp", "cgroups"],
        "attack_relevance": "Understanding Linux security enables container escapes, privilege escalation, and sandbox bypasses"
    },
    {
        "topic": "Memory Management",
        "components": ["Virtual memory", "Heap allocators", "Stack layout", "Memory protections", "ASLR"],
        "attack_relevance": "Understanding memory enables exploitation of corruption vulnerabilities"
    },
    {
        "topic": "Process and Thread Security",
        "components": ["Process isolation", "Thread context", "Handles", "IPC mechanisms", "Job objects"],
        "attack_relevance": "Understanding processes enables injection, hijacking, and sandbox escapes"
    },
    {
        "topic": "Network Stack",
        "components": ["Sockets", "Protocol handlers", "Firewall integration", "Driver model", "Raw access"],
        "attack_relevance": "Understanding networking enables traffic interception, spoofing, and protocol attacks"
    },
    {
        "topic": "Cryptographic Subsystems",
        "components": ["Key storage", "Crypto providers", "Certificate stores", "Random number generation", "HSM integration"],
        "attack_relevance": "Understanding crypto systems enables key extraction, algorithm attacks, and authentication bypass"
    },
]

for topic in system_topics:
    add_sample(
        f"Explain {topic['topic']} for offensive security",
        f"Topic: {topic['topic']}. Components: {', '.join(topic['components'][:3])}.",
        f"""## System Internals: {topic['topic']}

### Security Relevance
{topic['attack_relevance']}.

### Core Components
{chr(10).join([f"- **{comp}**" for comp in topic['components']])}

### Offensive Understanding

**Why This Matters**:
Deep understanding of {topic['topic'].lower()} enables:
1. Finding vulnerabilities others miss
2. Developing reliable exploits
3. Evading security controls
4. Creating novel attack techniques

### Component Analysis

Each component has attack potential:
{chr(10).join([f"- **{comp}**: Can be abused, bypassed, or exploited" for comp in topic['components']])}

### Common Weaknesses

{topic['topic']} commonly has issues with:
- **Complexity**: More components = more attack surface
- **Defaults**: Secure configurations often not default
- **Compatibility**: Legacy support introduces weaknesses
- **Trust**: Components trust each other inappropriately

### Research Approach

To find vulnerabilities in {topic['topic'].lower()}:

1. **Documentation Study**
   - Official documentation
   - Internal implementation details
   - Undocumented features

2. **Dynamic Analysis**
   - Debugger exploration
   - API tracing
   - Behavioral analysis

3. **Static Analysis**
   - Binary reverse engineering
   - Source code review (if available)
   - Configuration analysis

4. **Attack Modeling**
   - What security properties should hold?
   - How can they be violated?
   - What's the impact?

### Innovation Through Understanding

Deep knowledge of {topic['topic'].lower()} enables:
- Discovering 0-day vulnerabilities
- Developing novel attack techniques
- Bypassing security controls
- Creating reliable exploits

The attacker who understands the system best has the advantage.""",
        category="system_internals"
    )

print(f"   System internals: {len(all_samples) - start}")

# ============================================================
# SAVE DATASET
# ============================================================
print(f"\n{'='*70}")
print("💾 SAVING DEEP KNOWLEDGE DATASET")
print(f"{'='*70}")

random.shuffle(all_samples)

# Split 95/5
split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

# Save
train_file = output_dir / "deep_knowledge_train.jsonl"
val_file = output_dir / "deep_knowledge_val.jsonl"

with open(train_file, "w") as f:
    for s in train_samples:
        f.write(json.dumps(s) + "\n")

with open(val_file, "w") as f:
    for s in val_samples:
        f.write(json.dumps(s) + "\n")

# Statistics
categories = {}
for s in all_samples:
    cat = s.get("category", "unknown")
    categories[cat] = categories.get(cat, 0) + 1

print(f"\n✅ Total samples: {len(all_samples)}")
print(f"   Train: {len(train_samples)}")
print(f"   Val: {len(val_samples)}")
print(f"\n📊 By category:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"   - {cat}: {count}")
print(f"\n📁 Output: {output_dir}")
