#!/usr/bin/env python3
"""
Bombina Advanced Attack Composition Dataset
Teaches how to CREATE NEW ATTACKS through primitive combination
Focus: Innovation, creativity, novel attack chains
"""

import json
import hashlib
import random
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "deep_knowledge"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output, category="composition"):
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
print("🔗 GENERATING ATTACK COMPOSITION & INNOVATION DATASET")
print("="*70)

# ============================================================
# ATTACK PRIMITIVE COMBINATIONS
# ============================================================
print("\n📚 Attack Primitive Combinations...")

primitives = {
    "info_leak": ["ASLR bypass", "credential disclosure", "configuration exposure", "internal network mapping", "user enumeration"],
    "memory_corruption": ["buffer overflow", "use-after-free", "type confusion", "integer overflow", "format string"],
    "auth_bypass": ["authentication bypass", "session hijacking", "token forgery", "credential theft", "MFA bypass"],
    "privilege_escalation": ["kernel exploit", "sudo abuse", "service account compromise", "capability abuse", "ACL manipulation"],
    "lateral_movement": ["pass-the-hash", "RDP hijacking", "WMI execution", "PSRemoting", "SSH pivoting"],
    "persistence": ["scheduled task", "registry modification", "DLL hijacking", "bootkit", "web shell"],
    "defense_evasion": ["process injection", "AMSI bypass", "log tampering", "timestomping", "living-off-the-land"],
    "data_access": ["database query", "file system access", "memory dumping", "API abuse", "cloud storage access"],
}

# Generate combination samples
import itertools
primitive_types = list(primitives.keys())

for combo in itertools.combinations(primitive_types, 2):
    type1, type2 = combo
    for prim1 in primitives[type1][:2]:  # Take top 2 from each
        for prim2 in primitives[type2][:2]:
            add_sample(
                f"Design an attack chain combining {prim1} with {prim2}",
                f"Primitives: {type1.replace('_', ' ')} ({prim1}) + {type2.replace('_', ' ')} ({prim2})",
                f"""## Attack Chain: {prim1.title()} → {prim2.title()}

### Primitive Analysis

**Primitive 1: {prim1.title()}** ({type1.replace('_', ' ').title()})
- Provides: Initial capability or information
- Requires: Access to vulnerable component
- Output: {'Memory layout information' if 'leak' in type1 else 'Access or capability' if 'auth' in type1 or 'priv' in type1 else 'Position or persistence' if 'lateral' in type1 or 'persist' in type1 else 'Control or access'}

**Primitive 2: {prim2.title()}** ({type2.replace('_', ' ').title()})
- Provides: {'Exploitation capability' if 'memory' in type2 else 'Elevated access' if 'priv' in type2 else 'Network position' if 'lateral' in type2 else 'Sustained access' if 'persist' in type2 else 'Stealth' if 'evasion' in type2 else 'Objective completion'}
- Requires: {'Memory primitive' if 'memory' in type2 else 'Valid credentials or access' if 'auth' in type2 or 'priv' in type2 else 'Network access' if 'lateral' in type2 else 'System access' if 'persist' in type2 else 'Code execution'}
- Depends on: Output from Primitive 1

### Chain Design

```
Phase 1: {prim1.title()}
├── Objective: Obtain {type1.replace('_', ' ')} capability
├── Technique: {prim1}
├── Output: Foundation for next phase
└── OPSEC: {'Low risk - passive information gathering' if 'leak' in type1 else 'Medium risk - active but legitimate-looking' if 'auth' in type1 else 'Higher risk - active exploitation'}

Phase 2: {prim2.title()}
├── Prerequisite: Successful Phase 1
├── Technique: {prim2}
├── Objective: {type2.replace('_', ' ').title()}
└── Impact: Combined attack achieves greater effect
```

### Why This Chain Works

1. **Dependency Satisfaction**: {prim1} provides what {prim2} needs
2. **Capability Building**: Each stage increases attacker capability
3. **Defense Bypass**: Combined approach addresses multiple controls
4. **Objective Achievement**: Final state achieves attacker goal

### Innovation Potential

This chain can be enhanced by:
- Adding intermediate stages for reliability
- Implementing parallel paths for redundancy
- Adapting to specific target characteristics
- Combining with additional primitives

### Detection Considerations

**Primitive 1 Detection**:
- {'Memory access patterns, crash logs' if 'memory' in type1 else 'Authentication logs, failed attempts' if 'auth' in type1 else 'Network traffic anomalies' if 'leak' in type1 else 'Process monitoring, EDR alerts'}

**Primitive 2 Detection**:
- {'Memory protection violations' if 'memory' in type2 else 'Privilege changes, token events' if 'priv' in type2 else 'Lateral movement indicators' if 'lateral' in type2 else 'Persistence artifacts' if 'persist' in type2 else 'Behavioral anomalies'}

**Chain Detection**:
- Correlation of Primitive 1 and 2 indicators
- Timing analysis between stages
- Behavioral baseline deviation""",
                category="primitive_combination"
            )

print(f"   Primitive combinations: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# CREATIVE ATTACK SCENARIOS
# ============================================================
print("\n📚 Creative Attack Scenarios...")

creative_scenarios = [
    {
        "scenario": "Create an attack against a system you've never seen before",
        "approach": "Apply universal vulnerability patterns to unknown technology",
        "reasoning": """When facing unknown systems, apply fundamental vulnerability patterns:

1. **Input Handling**: Every system takes input. Where does it go? How is it processed?
   - Test for injection at every input point
   - Look for parsing vulnerabilities
   - Check boundary conditions

2. **Authentication**: How does it verify identity?
   - Default credentials
   - Auth bypass via logic flaws
   - Session management weaknesses

3. **Authorization**: How does it enforce access?
   - IDOR patterns
   - Privilege boundaries
   - Trust relationships

4. **State Management**: How does it maintain state?
   - Race conditions
   - State confusion
   - Incomplete transitions

5. **Error Handling**: What happens when things fail?
   - Information disclosure
   - Fail-open conditions
   - Recovery weaknesses"""
    },
    {
        "scenario": "Develop a novel authentication bypass for custom protocol",
        "approach": "Analyze protocol for fundamental auth weaknesses",
        "reasoning": """Custom protocols often repeat classic mistakes:

1. **Replay Attacks**: Can captured auth be reused?
   - Check for nonces, timestamps, sequence numbers
   - Test credential replay across sessions

2. **Crypto Weaknesses**: Is crypto implemented correctly?
   - Weak algorithms, short keys
   - IV reuse, predictable random
   - Padding oracles, timing attacks

3. **State Manipulation**: Can auth state be manipulated?
   - Modify tokens/tickets
   - Skip protocol steps
   - Inject into established sessions

4. **Trust Confusion**: Where is identity checked vs assumed?
   - Internal vs external boundaries
   - Service-to-service trust
   - Delegation chains

5. **Implementation Bugs**: Protocol vs implementation
   - Parsing differences
   - Edge case handling
   - Error conditions"""
    },
    {
        "scenario": "Design a zero-day discovery methodology for web applications",
        "approach": "Systematic approach to finding novel vulnerabilities",
        "reasoning": """Zero-day discovery in web apps requires systematic methodology:

1. **Technology Fingerprinting**
   - Identify all frameworks, libraries, versions
   - Map custom vs third-party components
   - Note uncommon or custom implementations

2. **Attack Surface Enumeration**
   - Every input vector (params, headers, cookies, files)
   - All endpoints including hidden/debug
   - API surface including undocumented

3. **Logic Flow Analysis**
   - Map authentication and authorization flows
   - Identify business logic and rules
   - Trace data through the application

4. **Vulnerability Hypothesis**
   - For each input: what vulnerabilities are possible?
   - For each flow: what logic flaws could exist?
   - For each component: what CVEs affect similar code?

5. **Systematic Testing**
   - Automate common cases (fuzzing)
   - Manual testing for logic flaws
   - Chain findings into attacks"""
    },
    {
        "scenario": "Create a novel privilege escalation in a hardened environment",
        "approach": "Find overlooked trust relationships and boundaries",
        "reasoning": """Hardened environments still have privilege escalation paths:

1. **Trust Relationships**
   - What trusts what? Service accounts, scheduled tasks, automated processes
   - Cross-boundary trust: network, cloud, containers
   - Implicit trust: localhost, same-user, parent-child

2. **Overlooked Components**
   - Third-party tools and agents
   - Monitoring and management software
   - Temporary or debugging features

3. **Configuration Gaps**
   - Hardening misses or exceptions
   - Legacy compatibility requirements
   - User-controlled components

4. **Race Conditions**
   - TOCTOU in privilege checks
   - Concurrent operations
   - Cleanup timing

5. **Capability Chains**
   - Combine limited privileges
   - Abuse delegated access
   - Pivot through intermediate accounts"""
    },
    {
        "scenario": "Develop an attack against AI/ML security system",
        "approach": "Target the unique attack surface of ML systems",
        "reasoning": """AI/ML systems have unique vulnerability patterns:

1. **Input Manipulation**
   - Adversarial examples: inputs that fool the model
   - Prompt injection: manipulate LLM behavior
   - Evasion: craft inputs that bypass detection

2. **Training Data Attacks**
   - Data poisoning: corrupt training to affect model
   - Backdoor insertion: hidden triggers in model
   - Model stealing: extract model through queries

3. **Pipeline Vulnerabilities**
   - Data ingestion: injection during preprocessing
   - Model serving: traditional web vulnerabilities
   - Output handling: unsafe use of model output

4. **Trust Boundaries**
   - Where is user input trusted?
   - How is model output used?
   - What can the model access?

5. **Emergent Behaviors**
   - Unexpected capabilities from training
   - Jailbreaking and guardrail bypasses
   - Context manipulation"""
    },
]

for scenario in creative_scenarios:
    add_sample(
        scenario["scenario"],
        f"Approach: {scenario['approach']}",
        f"""## Creative Attack Development

### Challenge
{scenario['scenario']}

### Strategic Approach
{scenario['approach']}

### Reasoning Framework

{scenario['reasoning']}

### Innovation Methodology

**Step 1: Understand the Target**
- What is it trying to do?
- What security properties must hold?
- What assumptions does it make?

**Step 2: Identify Attack Surface**
- Where can attacker influence system?
- What data/commands can be injected?
- What state can be manipulated?

**Step 3: Generate Hypotheses**
- Based on patterns, what vulnerabilities are likely?
- What would be high-impact if vulnerable?
- What's been overlooked?

**Step 4: Test and Validate**
- Start with low-risk tests
- Validate hypotheses systematically
- Document findings

**Step 5: Build Attack Chain**
- How do findings combine?
- What's the most impactful chain?
- How to ensure reliability?

### Key Innovation Principles

1. **First Principles**: Understand WHY things are vulnerable
2. **Pattern Recognition**: Apply known patterns to new contexts
3. **Composition**: Combine primitives creatively
4. **Persistence**: Most novel attacks require iteration
5. **Documentation**: Record insights for future attacks""",
        category="creative_attack"
    )

print(f"   Creative scenarios: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# ATTACK INNOVATION TEMPLATES
# ============================================================
print("\n📚 Attack Innovation Templates...")

innovation_templates = [
    {
        "title": "Protocol Variant Attack",
        "description": "Apply known protocol attack to different protocol",
        "example": "HTTP request smuggling principles applied to custom binary protocol",
        "methodology": """
1. Understand the original attack deeply
2. Identify the underlying principle
3. Find analogous structures in target protocol
4. Adapt technique to new context
5. Account for protocol-specific defenses"""
    },
    {
        "title": "Environment Transplant",
        "description": "Apply attack from one environment to another",
        "example": "Windows privilege escalation concepts applied to cloud IAM",
        "methodology": """
1. Abstract the attack to its core principle
2. Map equivalent components in new environment
3. Identify environment-specific variations
4. Adapt exploitation technique
5. Test in new context"""
    },
    {
        "title": "Primitive Inversion",
        "description": "Use defensive mechanism offensively",
        "example": "Use backup systems to exfiltrate data, use monitoring to map network",
        "methodology": """
1. Identify security/operational mechanisms
2. Consider: what if attacker controlled this?
3. Determine attacker benefits from mechanism
4. Develop technique to abuse mechanism
5. Consider detection and evasion"""
    },
    {
        "title": "Trust Chain Exploitation",
        "description": "Find and abuse chains of trust relationships",
        "example": "DevOps pipeline → production, vendor update → customer systems",
        "methodology": """
1. Map all trust relationships in environment
2. Identify weakest links in trust chains
3. Determine how to compromise weak link
4. Trace impact through trust chain
5. Develop end-to-end attack path"""
    },
    {
        "title": "Timing and Race Innovation",
        "description": "Find race conditions in unexpected places",
        "example": "Race condition in cloud resource provisioning, CI/CD timing attacks",
        "methodology": """
1. Identify multi-step operations
2. Determine security-relevant state changes
3. Find windows where state is inconsistent
4. Develop technique to win the race
5. Make exploitation reliable"""
    },
    {
        "title": "Side Channel Discovery",
        "description": "Find information leakage through indirect channels",
        "example": "Timing-based user enumeration, error message information disclosure",
        "methodology": """
1. Identify operations with measurable side effects
2. Determine what information affects side effects
3. Develop measurement technique
4. Correlate measurements to information
5. Extract useful intelligence"""
    },
    {
        "title": "Assumption Violation",
        "description": "Find and violate implicit security assumptions",
        "example": "Assume input is HTTP but send HTTP/2, assume user can't control header order",
        "methodology": """
1. List all assumptions system makes
2. Determine which are enforced vs assumed
3. Find ways to violate unenforced assumptions
4. Determine security impact of violation
5. Develop exploitation technique"""
    },
]

for template in innovation_templates:
    add_sample(
        f"Use the {template['title']} pattern to innovate attacks",
        f"Pattern: {template['description']}. Example: {template['example']}.",
        f"""## Attack Innovation Pattern: {template['title']}

### Pattern Description
{template['description']}

### Illustrative Example
{template['example']}

### Methodology
{template['methodology']}

### Applying This Pattern

**Step 1: Pattern Recognition**
Identify situations where this pattern applies:
- What known attacks use the underlying principle?
- What targets have analogous structures?
- Where is this pattern overlooked?

**Step 2: Adaptation**
Modify the attack for new context:
- What's the same between contexts?
- What's different?
- How do differences affect the attack?

**Step 3: Validation**
Test the adapted attack:
- Does the principle hold in new context?
- What modifications are needed?
- Is the attack reliable?

**Step 4: Refinement**
Improve and document:
- Optimize for reliability/stealth
- Document the adaptation
- Identify further applications

### Innovation Mindset

This pattern works because:
1. **Principles are universal**: Core vulnerabilities repeat
2. **Contexts vary**: Same principle, different manifestation
3. **Defenders are focused**: May not see cross-context applications
4. **Attackers can abstract**: See patterns others miss

### Practice Exercises

1. Take a known attack from one domain
2. Abstract it to its core principle
3. Find 3 other domains where it could apply
4. Develop adapted attack for each
5. Identify detection and evasion considerations""",
        category="innovation_template"
    )

print(f"   Innovation templates: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# VULNERABILITY CLASS DEEP ANALYSIS
# ============================================================
print("\n📚 Vulnerability Class Analysis...")

vuln_deep = [
    {
        "class": "Injection",
        "root_principle": "Mixing code and data in same channel",
        "variations": ["SQL", "Command", "LDAP", "XPath", "Template", "Header", "Log"],
        "innovation_vectors": [
            "New contexts where injection applies",
            "Polyglot payloads across contexts",
            "Second-order injection (stored then executed)",
            "Blind injection in new scenarios"
        ]
    },
    {
        "class": "Deserialization",
        "root_principle": "Trusting serialized data to recreate objects safely",
        "variations": ["Java", "PHP", ".NET", "Python Pickle", "YAML", "JSON (with type hints)"],
        "innovation_vectors": [
            "New gadget chains in libraries",
            "Language-specific deserialization quirks",
            "Partial/hybrid deserialization attacks",
            "Deserialization in unexpected formats"
        ]
    },
    {
        "class": "Path Traversal",
        "root_principle": "User input controlling file system paths",
        "variations": ["Directory traversal", "Null byte injection", "Encoding bypass", "Symlink following"],
        "innovation_vectors": [
            "Cloud storage path traversal",
            "Archive extraction traversal (zip slip)",
            "Virtual filesystem traversal",
            "API path parameter manipulation"
        ]
    },
    {
        "class": "SSRF",
        "root_principle": "Server making requests to attacker-influenced destinations",
        "variations": ["Basic SSRF", "Blind SSRF", "Partial SSRF", "Protocol smuggling"],
        "innovation_vectors": [
            "Cloud metadata access variations",
            "Internal service discovery",
            "Cross-protocol attacks",
            "SSRF in PDF/image processing"
        ]
    },
    {
        "class": "Race Condition",
        "root_principle": "Security-relevant state changes between operations",
        "variations": ["TOCTOU", "Double-fetch", "Symlink races", "Resource races"],
        "innovation_vectors": [
            "Cloud/distributed system races",
            "Microservice timing attacks",
            "Container and orchestration races",
            "Database transaction races"
        ]
    },
]

for vuln in vuln_deep:
    add_sample(
        f"Deep analysis of {vuln['class']} vulnerabilities for attack innovation",
        f"Root principle: {vuln['root_principle']}. Variations: {', '.join(vuln['variations'][:3])}.",
        f"""## Vulnerability Class Deep Dive: {vuln['class']}

### Root Principle
**{vuln['root_principle']}**

This is the fundamental issue that all {vuln['class'].lower()} vulnerabilities share. Understanding this principle enables finding new instances.

### Known Variations
{chr(10).join([f"- **{var}**: Specific manifestation in that context" for var in vuln['variations']])}

### Why New Variations Keep Appearing

1. **New Technologies**: Each new framework/language can have this issue
2. **Complex Interactions**: Combining systems creates new attack surface
3. **Developer Assumptions**: Same mistakes made in new contexts
4. **Mitigation Bypasses**: Defenses are often incomplete

### Innovation Vectors

Where to find new {vuln['class'].lower()} vulnerabilities:
{chr(10).join([f"- {vector}" for vector in vuln['innovation_vectors']])}

### Discovery Methodology

**Step 1: Identify Root Pattern**
- Where does the root principle apply?
- What systems have this architectural pattern?
- Where is mitigation likely incomplete?

**Step 2: Find Variations**
- How is this implemented in target?
- What's unique about this implementation?
- What defenses are in place?

**Step 3: Develop Exploitation**
- How to trigger the vulnerability?
- How to achieve desired impact?
- How to bypass defenses?

### From Principle to Novel Attack

```
ROOT PRINCIPLE: {vuln['root_principle']}
         ↓
TARGET ANALYSIS: Where does this pattern appear?
         ↓
VARIATION DISCOVERY: What's unique about this instance?
         ↓
EXPLOITATION: How to abuse this specific case?
         ↓
NOVEL ATTACK: New {vuln['class'].lower()} variant documented
```

### Composition Opportunities

{vuln['class']} often chains with:
- Information disclosure → Better exploitation
- Authentication bypass → Reach vulnerable code
- Privilege escalation → Greater impact
- Persistence → Maintain access

### Practice Finding New Instances

1. Pick a technology you know well
2. Ask: does it have the root pattern?
3. If yes, analyze the implementation
4. Look for gaps in mitigations
5. Develop and test exploitation""",
        category="vuln_analysis"
    )

print(f"   Vulnerability analysis: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# ATTACK DEVELOPMENT WORKFLOW
# ============================================================
print("\n📚 Attack Development Workflows...")

workflows = [
    {
        "goal": "Develop zero-day exploit from vulnerability",
        "phases": [
            ("Vulnerability Analysis", "Deeply understand the bug, root cause, trigger conditions"),
            ("Exploitation Strategy", "Determine how to convert bug into useful primitive"),
            ("Environment Setup", "Build reliable reproduction environment"),
            ("Primitive Development", "Achieve initial exploitation primitive (crash, info leak, write)"),
            ("Capability Enhancement", "Extend primitive to useful capability (code exec, priv esc)"),
            ("Reliability Engineering", "Make exploit work consistently"),
            ("Weaponization", "Package for operational use with evasion")
        ]
    },
    {
        "goal": "Discover new attack technique",
        "phases": [
            ("Research Phase", "Study target technology, documentation, existing research"),
            ("Hypothesis Generation", "Based on patterns, what vulnerabilities might exist?"),
            ("Attack Surface Mapping", "Enumerate all potential entry points"),
            ("Systematic Testing", "Test hypotheses methodically"),
            ("Finding Validation", "Confirm vulnerabilities are real and exploitable"),
            ("Chain Development", "Connect findings into attack paths"),
            ("Documentation", "Document technique for reproduction and adaptation")
        ]
    },
    {
        "goal": "Bypass security control",
        "phases": [
            ("Control Analysis", "Understand exactly how the control works"),
            ("Detection Logic", "What does it look for? What triggers alerts?"),
            ("Gap Identification", "What doesn't it cover? What's the threshold?"),
            ("Bypass Development", "Craft approach that evades detection"),
            ("Testing", "Verify bypass in realistic conditions"),
            ("Refinement", "Improve reliability and reduce indicators"),
            ("Operational Integration", "Incorporate into attack workflow")
        ]
    },
]

for workflow in workflows:
    phases_text = ""
    for i, (phase, description) in enumerate(workflow['phases'], 1):
        phases_text += f"""
**Phase {i}: {phase}**
{description}
- Key activities for this phase
- Success criteria before proceeding
- Common pitfalls to avoid
"""
    
    add_sample(
        f"Develop a structured approach to: {workflow['goal']}",
        f"Goal: {workflow['goal']}. Phases: {len(workflow['phases'])}.",
        f"""## Attack Development Workflow

### Goal
{workflow['goal']}

### Phased Approach
{phases_text}

### Workflow Principles

1. **Sequential Dependency**: Each phase builds on previous
2. **Validation Gates**: Confirm success before proceeding
3. **Documentation**: Record findings throughout
4. **Iteration**: Return to earlier phases if needed

### Success Factors

- **Deep Understanding**: Know the target thoroughly
- **Systematic Approach**: Don't skip steps
- **Persistence**: Novel attacks require iteration
- **Documentation**: Enable reproduction and adaptation

### Common Failure Modes

- Skipping analysis phases (leads to unreliable results)
- Insufficient environment setup (can't reproduce)
- Premature weaponization (reliability issues)
- Poor documentation (can't adapt or reproduce)

### Applying to New Targets

This workflow is general-purpose:
1. Adapt phases to specific target
2. Adjust depth based on complexity
3. Iterate based on findings
4. Document for future similar targets""",
        category="workflow"
    )

print(f"   Workflows: {len(all_samples) - start}")

# ============================================================
# SAVE DATASET
# ============================================================
print(f"\n{'='*70}")
print("💾 SAVING COMPOSITION DATASET")
print(f"{'='*70}")

random.shuffle(all_samples)

split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

train_file = output_dir / "composition_train.jsonl"
val_file = output_dir / "composition_val.jsonl"

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
print(f"\n📊 By category:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"   - {cat}: {count}")
print(f"\n📁 Output: {output_dir}")
