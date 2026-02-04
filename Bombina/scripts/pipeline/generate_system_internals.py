#!/usr/bin/env python3
"""
Bombina Advanced Protocol & System Internals Dataset
Deep technical knowledge for understanding HOW things work
Focus: Protocols, architectures, internals that enable sophisticated attacks
"""

import json
import hashlib
import random
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "deep_knowledge"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output, category="internals"):
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
print("⚙️ GENERATING PROTOCOL & SYSTEM INTERNALS DATASET")
print("="*70)

# ============================================================
# PART 1: WINDOWS INTERNALS FOR EXPLOITATION
# ============================================================
print("\n📚 Part 1: Windows Internals...")

windows_internals = [
    {
        "topic": "LSASS and Credential Storage",
        "description": "How Windows stores and protects credentials",
        "attack_relevance": "Credential dumping, pass-the-hash, mimikatz",
        "deep_dive": """LSASS (Local Security Authority Subsystem Service) is the core credential handler:

**Credential Storage Locations**:
- SAM database: Local accounts (SYSTEM hive protected)
- LSASS memory: Cached credentials, Kerberos tickets, NTLM hashes
- Credential Manager: Stored web/domain credentials
- DPAPI: User data protection (tied to user password)

**Protection Mechanisms**:
- LSASS runs as Protected Process Light (PPL) on newer systems
- Credential Guard uses virtualization-based security (VBS)
- LSA protection prevents unsigned code loading
- RunAsPPL registry setting

**Attack Approaches**:
1. Memory access: Read LSASS memory (requires admin + bypass PPL)
2. SAM extraction: Offline attack on SAM/SYSTEM hives
3. DCSync: Domain replication to extract hashes
4. Over-pass-the-hash: Use hash to get Kerberos ticket

**Innovation Vectors**:
- New PPL bypass techniques
- Credential Guard escape
- Novel memory access methods
- Alternative credential sources"""
    },
    {
        "topic": "Windows Access Tokens",
        "description": "How Windows tracks identity and privileges",
        "attack_relevance": "Token impersonation, privilege escalation, UAC bypass",
        "deep_dive": """Access tokens are the core identity mechanism in Windows:

**Token Structure**:
- User SID: Identity
- Group SIDs: Group memberships
- Privileges: What the token can do (SeDebugPrivilege, etc.)
- Integrity Level: Untrusted/Low/Medium/High/System
- Token Type: Primary (process) or Impersonation (thread)

**Token Operations**:
- CreateProcessAsUser: Run as different user
- ImpersonateLoggedOnUser: Take another user's identity
- DuplicateToken: Copy and modify tokens
- SetThreadToken: Change thread identity

**Attack Approaches**:
1. Token theft: Steal token from another process
2. Token impersonation: Use stolen token to act as user
3. Privilege enabling: Enable disabled privileges
4. Integrity manipulation: Elevate from medium to high

**Innovation Vectors**:
- New token theft techniques
- Novel privilege abuse
- Integrity level manipulation
- Cross-session token attacks"""
    },
    {
        "topic": "Windows Service Architecture",
        "description": "How Windows services work and can be abused",
        "attack_relevance": "Service exploitation, privilege escalation, persistence",
        "deep_dive": """Windows services provide persistent, privileged execution:

**Service Components**:
- SCM (Service Control Manager): Manages all services
- Service executable: The actual program
- Service account: Identity service runs as
- Service configuration: Registry under HKLM\\SYSTEM\\CurrentControlSet\\Services

**Privilege Levels**:
- LocalSystem: Highest privilege, no network identity
- LocalService: Limited, anonymous network
- NetworkService: Limited, machine network identity
- Domain accounts: Configurable privileges

**Attack Approaches**:
1. Unquoted service paths: Path traversal in service binaries
2. Weak permissions: Modify service configuration or binary
3. DLL hijacking: Missing DLLs in service search path
4. Service account abuse: Compromise service account credentials

**Innovation Vectors**:
- New service misconfiguration patterns
- Service-specific vulnerabilities
- Novel DLL injection techniques
- Cross-service attacks"""
    },
    {
        "topic": "Windows RPC and DCOM",
        "description": "Remote procedure calls and distributed COM",
        "attack_relevance": "Remote exploitation, lateral movement, privilege escalation",
        "deep_dive": """RPC/DCOM enables Windows remote communication:

**Architecture**:
- MSRPC: Microsoft's DCE-RPC implementation
- DCOM: COM over network
- NDR: Network Data Representation (marshaling)
- Interfaces: Defined by UUID and version

**Exposed Attack Surface**:
- Anonymous access: Some interfaces accessible unauthenticated
- Privileged operations: Many run as SYSTEM
- Complex parsing: NDR deserialization bugs
- Trust confusion: Client/server trust issues

**Attack Approaches**:
1. Interface enumeration: Find accessible interfaces
2. Method fuzzing: Test for parsing vulnerabilities
3. Coercion: Force NTLM authentication
4. Relay: Relay RPC authentication to other services

**Innovation Vectors**:
- Undocumented interface discovery
- New coercion methods (PrintNightmare, etc.)
- Novel relay scenarios
- Interface-specific vulnerabilities"""
    },
    {
        "topic": "Windows Networking Stack",
        "description": "How Windows handles network protocols",
        "attack_relevance": "Network attacks, MITM, protocol exploitation",
        "deep_dive": """Windows networking is complex and attackable:

**Protocol Stack**:
- SMB/CIFS: File sharing (port 445)
- NetBIOS: Name resolution (137-139)
- LLMNR/NBT-NS/mDNS: Local name resolution
- Kerberos: Domain authentication (88)
- LDAP: Directory access (389/636)

**Attack Surface**:
- Name resolution poisoning: LLMNR/NBT-NS/mDNS
- Relay attacks: SMB/HTTP → LDAP/SMB/etc
- Protocol vulnerabilities: EternalBlue, etc
- Coercion: Force outbound authentication

**Attack Approaches**:
1. Responder: Poison name resolution, capture hashes
2. ntlmrelayx: Relay captured authentication
3. SMB attacks: Exploits, signing bypass, capture
4. Kerberos attacks: Roasting, delegation abuse

**Innovation Vectors**:
- New coercion triggers
- Novel relay chains
- Cross-protocol attacks
- Protocol implementation bugs"""
    },
]

for item in windows_internals:
    add_sample(
        f"Explain {item['topic']} for offensive security",
        f"Topic: {item['topic']}. Attack relevance: {item['attack_relevance']}.",
        f"""## Windows Internals: {item['topic']}

### Overview
{item['description']}

### Attack Relevance
**{item['attack_relevance']}**

### Deep Technical Dive
{item['deep_dive']}

### Practical Application

**Reconnaissance**:
- What information reveals this attack surface?
- How to enumerate configuration?
- What indicates vulnerability?

**Exploitation**:
- What tools exist for this attack?
- What custom techniques are needed?
- How to achieve reliable exploitation?

**Post-Exploitation**:
- What capabilities does this provide?
- How to maintain access?
- What to look for next?

### Building Expertise

To master {item['topic'].lower()}:
1. Study Windows documentation and internals books
2. Use debugging tools (WinDbg, Process Monitor)
3. Practice on lab systems
4. Study existing tools and exploits
5. Develop custom techniques""",
        category="windows_internals"
    )

print(f"   Windows internals: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# PART 2: LINUX INTERNALS FOR EXPLOITATION
# ============================================================
print("\n📚 Part 2: Linux Internals...")

linux_internals = [
    {
        "topic": "Linux Privilege Model",
        "description": "UIDs, capabilities, and privilege management",
        "attack_relevance": "Privilege escalation, capability abuse, setuid exploitation",
        "deep_dive": """Linux privilege is more nuanced than just root:

**Identity Model**:
- Real UID: Actual user
- Effective UID: Privilege level for access checks
- Saved UID: Remembered UID for switching
- File system UID: For file system access

**Capabilities**:
- Break root into 40+ capabilities
- CAP_SYS_ADMIN: Catch-all admin capability
- CAP_NET_RAW: Raw sockets
- CAP_DAC_OVERRIDE: Bypass file permissions
- Inherited, permitted, effective, bounding sets

**Attack Vectors**:
1. Setuid binaries: Execute as owner (often root)
2. Capability abuse: Leverage granted capabilities
3. Sudo misconfig: NOPASSWD, env_keep, etc
4. Polkit/dbus: Privilege escalation via services

**Innovation Vectors**:
- New setuid vulnerabilities
- Capability combination attacks
- Sudo bypass techniques
- Policy kit exploitation"""
    },
    {
        "topic": "Linux Kernel Attack Surface",
        "description": "How to attack the Linux kernel",
        "attack_relevance": "Kernel exploitation, container escape, privilege escalation",
        "deep_dive": """The kernel is the ultimate privilege target:

**Attack Surface**:
- Syscalls: 400+ system calls
- Device drivers: Huge code base, varying quality
- Filesystems: Parsing of untrusted data
- Networking: Protocol handlers
- eBPF: JIT compilation, verifier

**Vulnerability Types**:
- Memory corruption in kernel code
- Race conditions
- Use-after-free in kernel objects
- Type confusion
- Logic bugs

**Exploitation Challenges**:
- KASLR: Kernel address randomization
- SMEP/SMAP: Supervisor mode restrictions
- KPTI: Page table isolation
- CFI: Control flow integrity

**Attack Approaches**:
1. Namespace/cgroup escape: Break container isolation
2. Driver exploitation: Target loaded drivers
3. Syscall exploitation: Fuzz syscall interfaces
4. eBPF: JIT bugs, verifier bypasses

**Innovation Vectors**:
- New kernel primitives
- Novel KASLR bypasses
- Container escape techniques
- eBPF exploitation"""
    },
    {
        "topic": "Container Security Boundaries",
        "description": "How container isolation works and breaks",
        "attack_relevance": "Container escape, host compromise, lateral movement",
        "deep_dive": """Containers use multiple isolation mechanisms:

**Isolation Mechanisms**:
- Namespaces: Separate views of system resources
- Cgroups: Resource limits
- Seccomp: Syscall filtering
- AppArmor/SELinux: Mandatory access control
- Capabilities: Dropped by default

**Common Weaknesses**:
- Privileged containers: Full host access
- Dangerous capabilities: CAP_SYS_ADMIN, etc
- Host mounts: Access to host filesystem
- Shared namespaces: Network, PID, etc
- Socket exposure: Docker socket, kubelet

**Escape Techniques**:
1. Privileged: Direct host access
2. Capability abuse: CAP_SYS_ADMIN → mount
3. Kernel exploit: Shared kernel
4. Socket abuse: Docker/K8s API access

**Innovation Vectors**:
- New namespace escapes
- Novel capability chains
- Cloud-specific escapes
- Orchestrator exploitation"""
    },
    {
        "topic": "Linux Filesystem Security",
        "description": "File permissions, ACLs, and filesystem attacks",
        "attack_relevance": "Privilege escalation, data access, persistence",
        "deep_dive": """Filesystem security is foundational:

**Permission Model**:
- Traditional: Owner/group/other, rwx
- ACLs: Extended access control lists
- Extended attributes: Security labels, capabilities
- File capabilities: setcap for fine-grained privilege

**Special Files**:
- Setuid/setgid: Execute with owner/group privileges
- World-writable: /tmp, /var/tmp risks
- Symlinks: Can be used for attacks
- Device files: Hardware access

**Attack Vectors**:
1. Path traversal: Access unintended files
2. Symlink attacks: Race conditions, redirects
3. Permission issues: World-writable configs
4. File capability abuse: Binaries with capabilities

**Innovation Vectors**:
- New path traversal contexts
- Symlink race conditions
- Mount namespace abuse
- Overlay filesystem attacks"""
    },
]

for item in linux_internals:
    add_sample(
        f"Explain {item['topic']} for offensive security",
        f"Topic: {item['topic']}. Attack relevance: {item['attack_relevance']}.",
        f"""## Linux Internals: {item['topic']}

### Overview
{item['description']}

### Attack Relevance
**{item['attack_relevance']}**

### Deep Technical Dive
{item['deep_dive']}

### Practical Application

**Enumeration**:
- What reveals this attack surface?
- Key files, commands, APIs to check?
- Indicators of vulnerability?

**Exploitation**:
- Common tools and techniques?
- Manual exploitation steps?
- Reliability considerations?

**Post-Exploitation**:
- What does success provide?
- How to persist?
- Next steps?

### Building Expertise

To master {item['topic'].lower()}:
1. Study Linux source code and documentation
2. Practice on intentionally vulnerable systems
3. Use debugging and tracing tools
4. Study published exploits
5. Develop custom techniques""",
        category="linux_internals"
    )

print(f"   Linux internals: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 3: WEB APPLICATION INTERNALS
# ============================================================
print("\n📚 Part 3: Web Application Internals...")

web_internals = [
    {
        "topic": "HTTP Protocol Deep Dive",
        "components": ["Request/Response structure", "Headers", "Methods", "Status codes", "Connections"],
        "attack_surface": "Request smuggling, header injection, method confusion, keep-alive abuse",
        "deep_knowledge": """HTTP is the foundation of web attacks:

**Request Structure**:
```
METHOD /path?query HTTP/1.1
Host: target.com
Header: Value

Body
```

**Critical Headers for Attacks**:
- Host: Virtual host routing, SSRF
- Content-Length/Transfer-Encoding: Smuggling
- Cookie: Session hijacking
- Authorization: Token theft
- X-Forwarded-*: Trust boundary confusion

**HTTP/1.1 vs HTTP/2 vs HTTP/3**:
- H1: Text-based, keep-alive, pipelining
- H2: Binary, multiplexed streams, HPACK compression
- H3: QUIC-based, UDP, QPACK compression

**Attack Patterns**:
1. Smuggling: CL/TE desync between servers
2. Header injection: CRLF to inject headers
3. Host header attacks: Routing manipulation
4. Method override: X-HTTP-Method-Override abuse"""
    },
    {
        "topic": "Session Management Internals",
        "components": ["Cookies", "Tokens", "Server-side sessions", "JWTs"],
        "attack_surface": "Session hijacking, token forgery, fixation, prediction",
        "deep_knowledge": """Session management is identity for web:

**Cookie Security**:
- HttpOnly: No JavaScript access (bypass via XSS in other ways)
- Secure: HTTPS only
- SameSite: CSRF protection
- Domain/Path: Scope control

**Token Types**:
- Session ID: Opaque reference to server state
- JWT: Self-contained, signed (optional encrypted)
- OAuth tokens: Access and refresh tokens

**JWT Vulnerabilities**:
- Algorithm confusion: None, HS256/RS256 mix
- Key issues: Weak secrets, key exposure
- Claim manipulation: Sub, exp, aud
- Implementation bugs

**Attack Approaches**:
1. Prediction: Weak random generation
2. Fixation: Force known session
3. Theft: XSS, network capture
4. Forgery: Create valid tokens"""
    },
    {
        "topic": "Browser Security Model",
        "components": ["Same-Origin Policy", "CORS", "CSP", "Sandboxing"],
        "attack_surface": "XSS, CSRF, clickjacking, SOP bypass, CSP bypass",
        "deep_knowledge": """Browsers are security boundaries:

**Same-Origin Policy**:
- Origin = scheme + host + port
- Restricts cross-origin data access
- Applies to: DOM, cookies, storage, requests

**CORS (Cross-Origin Resource Sharing)**:
- Relaxes SOP for legitimate use cases
- Misconfig: Access-Control-Allow-Origin: *
- Credential issues: Access-Control-Allow-Credentials
- Preflight: OPTIONS request for complex cases

**CSP (Content Security Policy)**:
- Controls resource loading
- XSS mitigation
- Bypasses: Unsafe-inline, unsafe-eval, JSONP, CDN

**Attack Approaches**:
1. XSS: Execute arbitrary JavaScript
2. CSRF: Force authenticated actions
3. CSP bypass: Find allowed vectors
4. Clickjacking: UI redressing"""
    },
    {
        "topic": "Web Framework Internals",
        "components": ["Routing", "Template engines", "ORM", "Authentication"],
        "attack_surface": "SSTI, ORM injection, mass assignment, deserialization",
        "deep_knowledge": """Frameworks have common vulnerability patterns:

**Template Engines**:
- Server-side rendering
- Expression evaluation
- SSTI: User input in template = code execution
- Common: Jinja2, Twig, Freemarker, Velocity

**ORM/Query Builders**:
- Object-Relational Mapping
- Can still have injection via:
  - Raw queries
  - Unsafe operations
  - Order by/group by

**Mass Assignment**:
- Automatic parameter binding to objects
- Can modify unintended fields
- Especially dangerous: isAdmin, role, permissions

**Framework-Specific**:
- Spring: SpEL injection, actuator exposure
- Django: Admin, debug mode
- Rails: Mass assignment, YAML deserialization
- Node/Express: Prototype pollution"""
    },
]

for item in web_internals:
    add_sample(
        f"Explain {item['topic']} for web application attacks",
        f"Components: {', '.join(item['components'][:3])}. Attack surface: {item['attack_surface']}.",
        f"""## Web Internals: {item['topic']}

### Components
{chr(10).join([f"- **{comp}**" for comp in item['components']])}

### Attack Surface
{item['attack_surface']}

### Deep Technical Knowledge
{item['deep_knowledge']}

### Exploitation Approach

**Reconnaissance**:
- Identify technology stack
- Enumerate configuration
- Find misconfigurations

**Vulnerability Discovery**:
- Test each component for issues
- Look for known CVEs
- Custom fuzzing

**Exploitation**:
- Develop working exploit
- Chain vulnerabilities
- Achieve impact

### Innovation Opportunities

To find new vulnerabilities in this area:
1. Study framework/protocol source code
2. Compare implementations
3. Test edge cases
4. Look for composition issues
5. Analyze recent CVEs""",
        category="web_internals"
    )

print(f"   Web internals: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 4: CLOUD ARCHITECTURE INTERNALS
# ============================================================
print("\n📚 Part 4: Cloud Architecture...")

cloud_internals = [
    {
        "topic": "AWS IAM Deep Dive",
        "attack_surface": "Privilege escalation, policy abuse, role assumption, credential theft",
        "details": """IAM is the foundation of AWS security:

**Identity Types**:
- Users: Long-term credentials
- Roles: Temporary credentials via assumption
- Groups: Policy aggregation
- Service-linked roles: AWS-managed

**Policy Structure**:
- Effect: Allow/Deny
- Action: Service:Operation
- Resource: ARN specification
- Condition: Context requirements

**Dangerous Permissions**:
- iam:*: Full IAM control = privilege escalation
- sts:AssumeRole: Role chaining
- PassRole: Attach role to services
- CreateAccessKey: Persist access

**Attack Paths**:
1. Role chain: Assume role to assume role
2. Service pivot: Use service role for escalation
3. Policy manipulation: Modify policies
4. Credential persistence: Create keys, add users"""
    },
    {
        "topic": "Kubernetes Security Model",
        "attack_surface": "RBAC bypass, container escape, service account abuse, secrets",
        "details": """Kubernetes security is complex:

**Authentication**:
- Service accounts: Pod identity
- OIDC: External identity providers
- Certificates: Client certs

**Authorization (RBAC)**:
- Roles/ClusterRoles: Permissions
- RoleBindings/ClusterRoleBindings: Assignment
- Aggregated roles: Combined permissions

**Pod Security**:
- Security contexts: Container restrictions
- Pod Security Standards: Privileged/baseline/restricted
- Network policies: Pod-to-pod communication

**Attack Paths**:
1. Service account abuse: Mount tokens, enumerate RBAC
2. Secret access: Read secrets, mount ConfigMaps
3. Container escape: Kernel exploit, socket access
4. etcd access: Direct database access"""
    },
    {
        "topic": "Cloud Metadata Services",
        "attack_surface": "SSRF to metadata, credential theft, instance identity",
        "details": """Metadata services are high-value targets:

**AWS IMDS**:
- v1: GET http://169.254.169.254/latest/meta-data/
- v2: Requires PUT for token first (IMDSv2)
- Credentials at: /iam/security-credentials/role-name

**Azure IMDS**:
- http://169.254.169.254/metadata/instance
- Requires Metadata: true header
- Managed identity tokens at /identity/oauth2/token

**GCP Metadata**:
- http://metadata.google.internal/computeMetadata/
- Requires Metadata-Flavor: Google header
- Service account tokens available

**Attack Patterns**:
1. SSRF: Application fetches metadata URL
2. Container escape: Access node metadata
3. Cloud function: Lambda/function has role
4. Credential leakage: Logs, debug endpoints"""
    },
]

for item in cloud_internals:
    add_sample(
        f"Explain {item['topic']} for cloud attacks",
        f"Attack surface: {item['attack_surface']}",
        f"""## Cloud Internals: {item['topic']}

### Attack Surface
{item['attack_surface']}

### Deep Technical Details
{item['details']}

### Exploitation Methodology

**Enumeration**:
- What credentials/access do you have?
- What permissions are granted?
- What resources exist?
- What can you reach?

**Privilege Escalation**:
- What paths lead to higher privileges?
- What services can be abused?
- What misconfigurations exist?

**Lateral Movement**:
- What other resources can be accessed?
- What trust relationships exist?
- How to pivot between services?

### Innovation Vectors

New cloud attacks emerge from:
1. New service features
2. Policy complexity
3. Trust relationship abuse
4. Cross-service interactions
5. API quirks""",
        category="cloud_internals"
    )

print(f"   Cloud internals: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# PART 5: CRYPTOGRAPHIC INTERNALS
# ============================================================
print("\n📚 Part 5: Cryptographic Internals...")

crypto_internals = [
    {
        "topic": "Symmetric Cryptography Attacks",
        "primitives": ["AES", "Block cipher modes", "Stream ciphers", "MACs"],
        "attacks": """Symmetric crypto attacks:

**Block Cipher Mode Issues**:
- ECB: Pattern preservation
- CBC: Padding oracle, IV manipulation
- CTR: Nonce reuse = keystream recovery
- GCM: Nonce reuse = authentication bypass

**Padding Oracle**:
- When server reveals padding validity
- Byte-by-byte decryption possible
- Works on CBC mode
- POODLE, Lucky13, etc.

**Implementation Issues**:
- Timing attacks on comparison
- Key management failures
- IV/nonce reuse
- Weak random generation"""
    },
    {
        "topic": "Asymmetric Cryptography Attacks",
        "primitives": ["RSA", "ECDSA", "Diffie-Hellman", "Certificates"],
        "attacks": """Asymmetric crypto attacks:

**RSA Weaknesses**:
- Textbook RSA: No padding = malleable
- PKCS#1 v1.5: Bleichenbacher padding oracle
- Small exponent: e=3 with small message
- Common modulus: Shared n between keys
- Factorization: Weak key generation

**ECDSA Issues**:
- Nonce reuse: Private key recovery
- Biased nonce: Lattice attack
- Invalid curve: Point not on curve

**Certificate Attacks**:
- Self-signed acceptance
- Hostname validation bypass
- Certificate pinning bypass
- CA compromise implications"""
    },
    {
        "topic": "Hash and Token Attacks",
        "primitives": ["MD5", "SHA-1", "SHA-256", "HMAC", "JWT"],
        "attacks": """Hash and token weaknesses:

**Hash Collisions**:
- MD5: Practical collisions
- SHA-1: Theoretical breaks
- Use in: Certificates, signatures, checksums

**Length Extension**:
- MD5, SHA-1, SHA-256 vulnerable
- Append data to existing hash
- Counter: Use HMAC instead

**JWT Attacks**:
- Algorithm none: No signature required
- Algorithm confusion: HS256 with RS256 public key
- Key injection: jwk/jku in header
- Weak secrets: Brute force HS256"""
    },
]

for item in crypto_internals:
    add_sample(
        f"Explain {item['topic']} for security testing",
        f"Primitives: {', '.join(item['primitives'][:3])}",
        f"""## Cryptographic Internals: {item['topic']}

### Primitives
{chr(10).join([f"- **{prim}**" for prim in item['primitives']])}

### Known Attacks
{item['attacks']}

### Finding Crypto Vulnerabilities

**Identification**:
- What crypto is in use?
- How is it configured?
- What mode/parameters?
- How are keys managed?

**Testing**:
- Check for known weaknesses
- Test implementation quality
- Look for side channels
- Analyze key handling

### Innovation in Crypto Attacks

Most crypto attacks come from:
1. Implementation errors
2. Protocol misuse
3. Side channels
4. Mathematical advances
5. Key management failures

### Practical Approach

When testing crypto:
1. Identify what's being used
2. Check for known issues
3. Test implementation quality
4. Look for protocol-level issues
5. Consider side channels""",
        category="crypto_internals"
    )

print(f"   Crypto internals: {len(all_samples) - start}")

# ============================================================
# SAVE DATASET
# ============================================================
print(f"\n{'='*70}")
print("💾 SAVING INTERNALS DATASET")
print(f"{'='*70}")

random.shuffle(all_samples)

split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

train_file = output_dir / "internals_train.jsonl"
val_file = output_dir / "internals_val.jsonl"

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
