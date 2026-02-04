#!/usr/bin/env python3
"""
Bombina Attack Innovation Master Dataset
Teaches HOW TO CREATE and INNOVATE new attacks
Focus: First principles, creative thinking, novel attack development
"""

import json
import hashlib
import random
from pathlib import Path
from itertools import combinations, product

output_dir = Path(__file__).parent.parent / "data" / "deep_knowledge"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output, category="innovation"):
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
print("💡 BOMBINA ATTACK INNOVATION MASTER DATASET")
print("="*70)

# ============================================================
# SECTION 1: FIRST PRINCIPLES OF VULNERABILITY
# ============================================================
print("\n📚 Section 1: First Principles of Vulnerability...")

principles = [
    {
        "principle": "All software has bugs",
        "implication": "Any sufficiently complex system will have exploitable flaws",
        "action": "Focus effort on finding bugs, not assuming they don't exist"
    },
    {
        "principle": "Security is about economics",
        "implication": "Attackers choose paths with best cost/benefit ratio",
        "action": "Find overlooked paths that defenders undervalue"
    },
    {
        "principle": "Complexity is the enemy of security",
        "implication": "More complexity = more potential for vulnerabilities",
        "action": "Target the most complex parts of systems"
    },
    {
        "principle": "Trust must be verified, not assumed",
        "implication": "Implicit trust relationships create exploitation opportunities",
        "action": "Map trust relationships and identify unverified trust"
    },
    {
        "principle": "Defense must be complete, attack needs one path",
        "implication": "Defenders must cover everything, attackers need one gap",
        "action": "Search systematically for the one gap defenders missed"
    },
    {
        "principle": "Systems fail at boundaries",
        "implication": "Interfaces between components are vulnerability hotspots",
        "action": "Focus on parsing, API boundaries, and trust transitions"
    },
    {
        "principle": "Backwards compatibility preserves vulnerabilities",
        "implication": "Legacy support often means legacy weaknesses",
        "action": "Force systems into legacy modes with weaker security"
    },
    {
        "principle": "Side effects reveal information",
        "implication": "Observable behavior differences leak security-relevant data",
        "action": "Measure timing, errors, responses for side-channel information"
    },
]

for p in principles:
    add_sample(
        f"Apply the principle '{p['principle']}' to finding new vulnerabilities",
        f"Implication: {p['implication']}",
        f"""## First Principle: {p['principle']}

### Principle Explanation
**{p['principle']}**

This is a fundamental truth about security that persists across technologies and time.

### Security Implication
{p['implication']}

This means that every system you encounter has potential weaknesses that follow from this principle.

### Practical Application
**{p['action']}**

### Using This Principle for Innovation

**Step 1: Recognize Where It Applies**
- Look at any system through the lens of this principle
- Ask: how does this principle manifest here?
- Identify specific instances

**Step 2: Generate Attack Hypotheses**
Based on this principle:
- What vulnerabilities are likely to exist?
- What have defenders probably missed?
- What would be high-impact if vulnerable?

**Step 3: Test Systematically**
- Develop tests for hypotheses
- Document findings
- Iterate based on results

### Example Applications

**Web Application**: {p['implication']} means...
- Input handling likely has gaps
- Complex features have more bugs
- Error paths are less tested

**Network Protocol**: {p['implication']} means...
- Parser edge cases exist
- State machine has unexpected transitions
- Trust assumptions can be violated

**Operating System**: {p['implication']} means...
- Kernel has exploitable bugs
- Privilege boundaries have gaps
- Legacy code has legacy problems

### Building Intuition

Internalizing this principle means:
- You always expect vulnerabilities to exist
- You know where to focus your search
- You have a framework for discovering new issues

### Combining Principles

This principle is most powerful when combined with others:
- Multiple principles point to same weakness = high confidence
- Principles guide systematic vulnerability research
- Innovation comes from applying principles to new contexts""",
        category="first_principles"
    )

print(f"   First principles: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# SECTION 2: ATTACK INNOVATION FRAMEWORKS
# ============================================================
print("\n📚 Section 2: Attack Innovation Frameworks...")

frameworks = [
    {
        "name": "OODA Loop for Hackers",
        "steps": ["Observe", "Orient", "Decide", "Act"],
        "description": "Continuous cycle of observation and action",
        "application": "Rapid iteration through attack approaches, adapting based on feedback"
    },
    {
        "name": "Attack Tree Methodology",
        "steps": ["Define goal", "Enumerate paths", "Analyze feasibility", "Select optimal"],
        "description": "Systematic decomposition of attack objectives",
        "application": "Finding non-obvious paths to objectives through systematic enumeration"
    },
    {
        "name": "STRIDE Inversion",
        "steps": ["Spoofing", "Tampering", "Repudiation", "Info disclosure", "DoS", "Escalation"],
        "description": "Use threat model categories as attack checklist",
        "application": "Systematically check each category against target"
    },
    {
        "name": "Kill Chain Analysis",
        "steps": ["Recon", "Weaponize", "Deliver", "Exploit", "Install", "C2", "Actions"],
        "description": "Attack lifecycle framework",
        "application": "Ensure complete attack chain, find gaps defenders leave"
    },
    {
        "name": "Assumption Mapping",
        "steps": ["List assumptions", "Classify as enforced/implicit", "Test implicit", "Exploit violations"],
        "description": "Finding security assumptions that aren't enforced",
        "application": "Systematic discovery of logic vulnerabilities"
    },
    {
        "name": "Primitive Building",
        "steps": ["Identify capability", "Find enabling vulnerability", "Build primitive", "Chain to objective"],
        "description": "Building attack capabilities from basic primitives",
        "application": "Constructing complex attacks from simple building blocks"
    },
]

for fw in frameworks:
    add_sample(
        f"Use the {fw['name']} framework to innovate attacks",
        f"Steps: {' → '.join(fw['steps'])}. Description: {fw['description']}",
        f"""## Attack Innovation Framework: {fw['name']}

### Framework Overview
**{fw['description']}**

### Steps
{chr(10).join([f"{i+1}. **{step}**" for i, step in enumerate(fw['steps'])])}

### Application for Attack Innovation
{fw['application']}

### Detailed Methodology

{chr(10).join([f'''**Step: {step}**
- What this step accomplishes
- How to execute effectively
- Common pitfalls to avoid
- Output feeds into next step
''' for step in fw['steps']])}

### Why This Framework Enables Innovation

1. **Systematic Approach**: Covers all angles, finds what others miss
2. **Structured Thinking**: Prevents tunnel vision
3. **Reproducible**: Can be applied to any target
4. **Comprehensive**: Ensures thorough analysis

### Example Application

**Target**: Unknown web application

{chr(10).join([f"**{step}**: Apply to web app context..." for step in fw['steps']])}

**Outcome**: Novel attack path discovered through systematic analysis

### Combining with Other Frameworks

{fw['name']} works well with:
- First principles analysis
- Other frameworks at different abstraction levels
- Tool-assisted automation

### Practice Exercise

Apply {fw['name']} to:
1. A technology you know well
2. A technology you're learning
3. A CTF challenge or bug bounty target

Document your process and findings.""",
        category="innovation_frameworks"
    )

print(f"   Innovation frameworks: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 3: NOVEL ATTACK CREATION METHODOLOGY
# ============================================================
print("\n📚 Section 3: Novel Attack Creation...")

creation_methods = [
    {
        "method": "Cross-Domain Transfer",
        "description": "Apply attack from one domain to another",
        "example": "Windows privilege escalation patterns → Cloud IAM privilege escalation",
        "process": ["Identify source attack", "Abstract to principle", "Find target analogy", "Adapt technique"]
    },
    {
        "method": "Primitive Composition",
        "description": "Combine basic capabilities into new attacks",
        "example": "Info leak + memory corruption = ASLR bypass + code execution",
        "process": ["Inventory available primitives", "Identify required primitives", "Find composition path", "Build chain"]
    },
    {
        "method": "Defense Inversion",
        "description": "Use defensive mechanisms offensively",
        "example": "Backup systems for exfiltration, monitoring for reconnaissance",
        "process": ["Identify defense mechanism", "Consider attacker control", "Find offensive use", "Develop technique"]
    },
    {
        "method": "Assumption Mining",
        "description": "Find and violate implicit security assumptions",
        "example": "Assuming HTTP headers can't be controlled by attacker",
        "process": ["List all assumptions", "Find unenforced ones", "Develop violation technique", "Exploit the gap"]
    },
    {
        "method": "Edge Case Hunting",
        "description": "Find vulnerabilities in rarely-tested code paths",
        "example": "Error handlers, concurrent access, resource exhaustion",
        "process": ["Map all code paths", "Identify edge cases", "Test systematically", "Exploit findings"]
    },
    {
        "method": "Interface Fuzzing",
        "description": "Find vulnerabilities through interface boundary testing",
        "example": "API parameters, file formats, network protocols",
        "process": ["Identify interface", "Generate malformed inputs", "Monitor for anomalies", "Develop exploits"]
    },
    {
        "method": "Trust Chain Analysis",
        "description": "Find weakest link in trust relationships",
        "example": "Developer laptop → CI/CD → production",
        "process": ["Map trust chain", "Identify links", "Find weakest point", "Exploit for chain access"]
    },
    {
        "method": "Timing Exploitation",
        "description": "Exploit race conditions and timing dependencies",
        "example": "TOCTOU, authentication race, resource races",
        "process": ["Identify multi-step operations", "Find timing windows", "Develop race technique", "Win the race"]
    },
]

for method in creation_methods:
    add_sample(
        f"Create novel attacks using {method['method']}",
        f"Description: {method['description']}. Example: {method['example']}",
        f"""## Novel Attack Creation: {method['method']}

### Method Overview
**{method['description']}**

### Illustrative Example
{method['example']}

### Creation Process

{chr(10).join([f"**Step {i+1}: {step}**" for i, step in enumerate(method['process'])])}

### Detailed Methodology

**Step 1: {method['process'][0]}**
- What to look for
- How to systematically identify
- Documentation approach

**Step 2: {method['process'][1]}**
- Analysis techniques
- Pattern recognition
- Gap identification

**Step 3: {method['process'][2]}**
- Development approach
- Testing methodology
- Iteration process

**Step 4: {method['process'][3]}**
- Final technique refinement
- Reliability engineering
- Documentation for reuse

### Why {method['method']} Works

This method produces novel attacks because:
1. It exploits patterns that repeat across systems
2. It targets areas defenders often overlook
3. It applies systematic thinking to creativity
4. It builds on known principles in new ways

### Practice Exercise

Apply {method['method']} to find a novel attack:

1. **Choose target**: Pick a technology or system
2. **Apply method**: Follow the process steps
3. **Document findings**: What did you discover?
4. **Develop technique**: Can you exploit it?
5. **Generalize**: Where else might this apply?

### Combining Methods

{method['method']} is most powerful when combined:
- Use multiple methods on same target
- Let findings from one inform another
- Build comprehensive attack portfolio

### Innovation Mindset

Practicing {method['method']} builds:
- Pattern recognition skills
- Creative thinking ability
- Systematic approach to novelty
- Expertise through repetition""",
        category="novel_creation"
    )

print(f"   Novel creation methods: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 4: ATTACK SURFACE EXPANSION TECHNIQUES
# ============================================================
print("\n📚 Section 4: Attack Surface Expansion...")

expansion_techniques = [
    ("Enable hidden features", "Find and enable disabled functionality", "debug modes, admin panels, beta features"),
    ("Trigger error handlers", "Cause errors to reach less-tested code", "malformed input, resource exhaustion, timeout"),
    ("Access alternate interfaces", "Find additional entry points", "APIs, admin ports, management interfaces"),
    ("Chain through services", "Use one service to reach another", "SSRF, internal APIs, service mesh"),
    ("Abuse debugging capabilities", "Leverage debugging for exploitation", "debug endpoints, stack traces, profilers"),
    ("Force legacy modes", "Downgrade to older, weaker versions", "protocol downgrade, feature flags, compatibility"),
    ("Exploit documentation", "Use docs to find attack surface", "API docs, config files, comments"),
    ("Social engineering", "Expand surface through people", "phishing, pretexting, physical access"),
    ("Supply chain vectors", "Attack through dependencies", "libraries, updates, third-party services"),
    ("Physical access", "Expand attack surface physically", "USB, console access, hardware implants"),
]

for technique, description, examples in expansion_techniques:
    add_sample(
        f"Expand attack surface by: {technique}",
        f"Method: {description}. Examples: {examples}.",
        f"""## Attack Surface Expansion: {technique.title()}

### Technique Overview
**{description}**

### Examples
{examples}

### Why This Expands Attack Surface

Every system has more attack surface than is immediately visible:
- Some functionality is disabled but present
- Some paths are rarely exercised
- Some interfaces are not publicly documented
- Some access requires specific conditions

{technique.title()} reveals this hidden attack surface.

### Methodology

**Step 1: Reconnaissance**
- Enumerate visible attack surface
- Identify indicators of hidden functionality
- Research target for known hidden features

**Step 2: Discovery**
- Probe for {examples.split(', ')[0]}
- Test for {examples.split(', ')[1]}
- Attempt {examples.split(', ')[2]}

**Step 3: Validation**
- Confirm access to new attack surface
- Assess exploitability
- Map new capabilities

**Step 4: Exploitation**
- Target newly discovered surface
- Combine with other techniques
- Achieve objectives

### Common Indicators

Signs that this technique might work:
- References in documentation or code
- Error messages revealing functionality
- Configuration options suggesting features
- Historical research on similar targets

### Innovation Application

Use this technique to find vulnerabilities others miss:
1. Assume hidden attack surface exists
2. Systematically search for it
3. Test thoroughly when found
4. Document for future use

### Combination Strategies

{technique.title()} combines well with:
- Fuzzing new interfaces
- Applying known exploits to new surface
- Chaining through expanded surface
- Persistence via hidden features""",
        category="surface_expansion"
    )

print(f"   Surface expansion: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 5: VULNERABILITY PATTERN GENERALIZATION
# ============================================================
print("\n📚 Section 5: Vulnerability Pattern Generalization...")

generalization_patterns = [
    {
        "specific": "SQL injection in web login form",
        "pattern": "Injection where user input is concatenated into queries",
        "generalizations": [
            "Any query language with user input (LDAP, XPath, GraphQL)",
            "Any interpreter with user input (shell, eval)",
            "Any template engine with user input (SSTI)",
            "Any log processor with user input (log injection)"
        ]
    },
    {
        "specific": "Buffer overflow in strcpy",
        "pattern": "Memory corruption from unbounded copy",
        "generalizations": [
            "Any string operation without bounds checking",
            "Any memory copy with user-controlled length",
            "Any array access with user-controlled index",
            "Any format string with user-controlled format"
        ]
    },
    {
        "specific": "CSRF in form submission",
        "pattern": "State-changing request without origin verification",
        "generalizations": [
            "Any authenticated action triggerable cross-origin",
            "Any API endpoint without proper CORS",
            "Any WebSocket without origin check",
            "Any GraphQL mutation without CSRF protection"
        ]
    },
    {
        "specific": "Path traversal in file download",
        "pattern": "User input controlling file system paths",
        "generalizations": [
            "Any file operation with user-influenced path",
            "Archive extraction with path in archive",
            "URL fetching with user-controlled URL",
            "Template inclusion with user-controlled name"
        ]
    },
    {
        "specific": "XXE in XML parser",
        "pattern": "External entity processing in document formats",
        "generalizations": [
            "Any XML parser with default settings",
            "Any document format with include/import",
            "Any template with include functionality",
            "Any configuration with external references"
        ]
    },
]

for gp in generalization_patterns:
    for generalization in gp['generalizations']:
        add_sample(
            f"Generalize '{gp['specific']}' to find new vulnerabilities",
            f"Core pattern: {gp['pattern']}. Generalization: {generalization}.",
            f"""## Vulnerability Pattern Generalization

### Specific Instance
**{gp['specific']}**

### Underlying Pattern
**{gp['pattern']}**

This is the abstract vulnerability that manifests in many forms.

### Generalization
**{generalization}**

### Why Generalization Works

The same fundamental weakness appears across technologies:
1. Core pattern remains the same
2. Only the context changes
3. Understanding the pattern enables finding new instances
4. Each new instance is a potential novel vulnerability

### Finding New Instances

**Step 1: Understand the Pattern**
{gp['pattern']} is the root cause. Understand WHY it's vulnerable.

**Step 2: Identify Analogous Contexts**
{generalization} is one place this pattern appears. Find others.

**Step 3: Test for Vulnerability**
Apply the pattern knowledge to test new contexts.

**Step 4: Develop Exploitation**
Create exploits specific to the new context.

### Pattern → Instance Mapping

```
Pattern: {gp['pattern']}
    ↓
Context: {generalization.split('with')[0].strip() if 'with' in generalization else generalization}
    ↓
Vulnerability: Specific exploitable instance
    ↓
Exploit: Context-appropriate technique
```

### Building Pattern Library

To become expert at finding vulnerabilities:
1. Study specific vulnerabilities deeply
2. Extract underlying patterns
3. Practice finding new instances
4. Build personal pattern library
5. Apply patterns to new targets

### Innovation Through Patterns

Novel attacks often come from:
- Applying known patterns to new technologies
- Combining patterns in unexpected ways
- Finding patterns in emerging technologies
- Discovering new fundamental patterns""",
            category="pattern_generalization"
        )

print(f"   Pattern generalization: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 6: ADVANCED ATTACK COMPOSITION
# ============================================================
print("\n📚 Section 6: Advanced Attack Composition...")

composition_scenarios = [
    {
        "goal": "Remote code execution on hardened server",
        "available": ["SSRF", "path traversal", "information disclosure"],
        "composition": "SSRF → access internal service → path traversal → read credentials → info disclosure → leak memory → chain to RCE"
    },
    {
        "goal": "Compromise cloud infrastructure",
        "available": ["web shell", "metadata access", "IAM enumeration"],
        "composition": "web shell → access instance metadata → get credentials → enumerate IAM → find escalation path → compromise infrastructure"
    },
    {
        "goal": "Domain admin in enterprise network",
        "available": ["phishing foothold", "local admin", "credential dumping"],
        "composition": "phishing → foothold → local privesc → dump creds → identify DA path → kerberoast/delegation → domain admin"
    },
    {
        "goal": "Exfiltrate data from air-gapped network",
        "available": ["USB access", "covert channel", "encoding techniques"],
        "composition": "USB → establish foothold → collect data → encode → covert channel → bridge air gap → exfiltrate"
    },
    {
        "goal": "Persistent access to SaaS tenant",
        "available": ["OAuth token", "API access", "service account"],
        "composition": "OAuth token → API enumeration → find service accounts → create backdoor → establish persistence → maintain access"
    },
]

for scenario in composition_scenarios:
    add_sample(
        f"Compose attack to achieve: {scenario['goal']}",
        f"Available capabilities: {', '.join(scenario['available'])}.",
        f"""## Advanced Attack Composition

### Objective
**{scenario['goal']}**

### Available Capabilities
{chr(10).join([f"- {cap}" for cap in scenario['available']])}

### Composition Strategy
{scenario['composition']}

### Detailed Composition Analysis

**Why This Composition Works**:
1. Each capability enables the next
2. Combined effect exceeds individual capabilities
3. Addresses multiple defensive layers
4. Achieves objective that no single capability could

**Capability Chain**:
```
{scenario['available'][0]}
    ↓ enables
{scenario['available'][1]}
    ↓ enables
{scenario['available'][2]}
    ↓ achieves
{scenario['goal']}
```

### Composition Methodology

**Step 1: Define Objective**
What is the ultimate goal? {scenario['goal']}

**Step 2: Inventory Capabilities**
What can we currently do? {', '.join(scenario['available'])}

**Step 3: Identify Gaps**
What capabilities are missing? What's needed to reach the goal?

**Step 4: Find Bridges**
How can available capabilities provide missing ones?

**Step 5: Build Chain**
Construct the composition: {scenario['composition']}

**Step 6: Execute and Adapt**
Run the chain, handle failures, adapt as needed.

### Innovation in Composition

Novel attacks often come from:
- New combinations of known capabilities
- Unexpected bridges between capabilities
- Creative gap-filling
- Adapting chains to specific targets

### Failure Handling

Composition must handle failures:
- What if step N fails?
- Alternative paths available?
- Fallback capabilities?
- Detection and retry logic?

### Composition Patterns

Common composition patterns:
1. **Linear**: A → B → C → goal
2. **Parallel**: A + B → C → goal
3. **Conditional**: if A then B else C → goal
4. **Iterative**: repeat (A → B) until C → goal

### Practice Exercise

Given your capabilities, compose an attack:
1. Define an objective beyond current reach
2. Identify capability gaps
3. Find bridges to fill gaps
4. Construct composition
5. Analyze and refine""",
        category="advanced_composition"
    )

print(f"   Advanced composition: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 7: EXPLOIT DEVELOPMENT THINKING
# ============================================================
print("\n📚 Section 7: Exploit Development Thinking...")

exploit_thinking = [
    {
        "stage": "Vulnerability to Primitive",
        "challenge": "Converting a bug into a useful capability",
        "approach": "Understand what the bug provides (read, write, control flow) and how to weaponize it",
        "questions": ["What memory is corrupted?", "What values can be written?", "What pointers can be controlled?", "What code paths can be reached?"]
    },
    {
        "stage": "Primitive to Capability",
        "challenge": "Using a primitive to achieve something useful",
        "approach": "Chain primitives together to build more powerful capabilities",
        "questions": ["What can this primitive enable?", "What other primitives are needed?", "How can primitives be combined?", "What's the minimal chain to the goal?"]
    },
    {
        "stage": "Bypassing Mitigations",
        "challenge": "Working around security controls",
        "approach": "Understand mitigations deeply and find gaps or bypasses",
        "questions": ["What mitigations are present?", "What do they actually protect?", "Where are the gaps?", "Can they be disabled?"]
    },
    {
        "stage": "Reliability Engineering",
        "challenge": "Making exploits work consistently",
        "approach": "Address sources of non-determinism and failure modes",
        "questions": ["What can vary between runs?", "How to stabilize heap/stack?", "How to handle failures?", "What are the reliability blockers?"]
    },
    {
        "stage": "Weaponization",
        "challenge": "Packaging exploit for operational use",
        "approach": "Make exploit deliverable, evade detection, ensure operational security",
        "questions": ["How will it be delivered?", "What detection exists?", "How to evade detection?", "What's the operational context?"]
    },
]

for stage in exploit_thinking:
    add_sample(
        f"Master exploit development: {stage['stage']}",
        f"Challenge: {stage['challenge']}",
        f"""## Exploit Development Thinking: {stage['stage']}

### The Challenge
**{stage['challenge']}**

### Approach
{stage['approach']}

### Key Questions
{chr(10).join([f"- {q}" for q in stage['questions']])}

### Detailed Methodology

**Understanding the Stage**:
{stage['stage']} is critical because it bridges the gap between finding a vulnerability and achieving impact.

**Systematic Approach**:
1. Answer each key question thoroughly
2. Document findings and constraints
3. Develop approach based on answers
4. Test and iterate

**Common Challenges**:
- Constraints limiting exploitation
- Non-determinism in behavior
- Mitigations blocking techniques
- Target environment variations

### Questions Deep Dive

{chr(10).join([f'''**{q}**
- Why this matters for {stage['stage'].lower()}
- How to find the answer
- What the answer enables
''' for q in stage['questions']])}

### Building Expertise

To master {stage['stage'].lower()}:
1. Study existing exploits at this stage
2. Practice on CTF challenges
3. Develop tools for this stage
4. Build intuition through repetition

### Innovation Opportunity

{stage['stage']} is where novel techniques emerge:
- New ways to convert vulnerabilities to primitives
- New primitive compositions
- New mitigation bypasses
- New reliability techniques

### Integration with Other Stages

{stage['stage']} connects to other stages:
- Receives input from previous stage
- Provides output to next stage
- Constraints propagate through stages
- Success requires all stages to work""",
        category="exploit_thinking"
    )

print(f"   Exploit thinking: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# SECTION 8: CREATIVE CONSTRAINT EXPLOITATION
# ============================================================
print("\n📚 Section 8: Creative Constraint Exploitation...")

constraints = [
    {
        "constraint": "No outbound network access",
        "standard_approach": "Use reverse shell",
        "creative_solutions": ["DNS tunneling", "ICMP tunneling", "abuse allowed protocols", "out-of-band via email/SMS", "physical exfiltration"]
    },
    {
        "constraint": "No code execution possible",
        "standard_approach": "Find RCE vulnerability",
        "creative_solutions": ["data exfiltration only", "credential theft", "business logic abuse", "denial of service", "pivot to other targets"]
    },
    {
        "constraint": "All traffic is inspected",
        "standard_approach": "Use encryption",
        "creative_solutions": ["steganography", "protocol mimicry", "timing-based covert channels", "abuse allowed encrypted channels", "slow exfiltration"]
    },
    {
        "constraint": "Target is air-gapped",
        "standard_approach": "Physical access",
        "creative_solutions": ["supply chain attack", "removable media", "acoustic/electromagnetic side channels", "social engineering", "insider threat"]
    },
    {
        "constraint": "Limited privileges (low user)",
        "standard_approach": "Privilege escalation exploit",
        "creative_solutions": ["accomplish goals at current privilege", "find data accessible at this level", "social engineer higher access", "wait for opportunity", "pivot to softer target"]
    },
    {
        "constraint": "Strong monitoring and IR team",
        "standard_approach": "Avoid detection",
        "creative_solutions": ["living-off-the-land", "time operations during maintenance", "blend with normal traffic", "distributed low-and-slow", "compromise monitoring itself"]
    },
]

for c in constraints:
    add_sample(
        f"Overcome constraint: {c['constraint']}",
        f"Standard approach: {c['standard_approach']}. But what if that's blocked?",
        f"""## Creative Constraint Exploitation

### Constraint
**{c['constraint']}**

### Standard Approach
{c['standard_approach']}

But what if the standard approach is blocked?

### Creative Solutions

{chr(10).join([f"{i+1}. **{sol}**" for i, sol in enumerate(c['creative_solutions'])])}

### Why Constraints Drive Creativity

Constraints force attackers to:
1. Think beyond standard techniques
2. Find unexpected paths
3. Develop novel approaches
4. Innovate under pressure

### Detailed Solution Analysis

{chr(10).join([f'''**Solution: {sol}**
- How it bypasses the constraint
- Requirements and prerequisites
- Trade-offs and risks
- When to use this approach
''' for sol in c['creative_solutions'][:3]])}

### Constraint Analysis Framework

When facing any constraint:
1. **Understand the constraint exactly**: What specifically is blocked?
2. **Identify what's allowed**: What CAN you do?
3. **Find the gap**: How can allowed actions achieve the goal?
4. **Develop technique**: Build the creative solution
5. **Test and refine**: Validate it works

### Innovation Mindset

Constraints are innovation opportunities:
- Standard techniques blocked = need for novel approaches
- Novel approaches = potential for research contribution
- Research contribution = expertise development
- Expertise = ability to overcome future constraints

### Combining Creative Solutions

Often multiple creative solutions combine:
- Use several in parallel for redundancy
- Chain for greater effect
- Adapt based on target response

### Building Constraint-Breaking Skills

Practice constraint exploitation:
1. Artificially constrain yourself in CTFs
2. Study how APTs overcome constraints
3. Develop novel techniques
4. Share and learn from community""",
        category="constraint_exploitation"
    )

print(f"   Constraint exploitation: {len(all_samples) - start}")

# ============================================================
# SAVE INNOVATION DATASET
# ============================================================
print(f"\n{'='*70}")
print("💾 SAVING ATTACK INNOVATION DATASET")
print(f"{'='*70}")

random.shuffle(all_samples)

split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

train_file = output_dir / "innovation_train.jsonl"
val_file = output_dir / "innovation_val.jsonl"

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
