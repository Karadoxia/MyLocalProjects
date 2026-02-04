#!/usr/bin/env python3
"""
OWASP Data Extractor for Bombina
Extracts web security reasoning from OWASP resources
Generates training samples for web attack categories

Usage: python extract_owasp.py
"""

import json
import re
from pathlib import Path
from typing import Dict, List
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "datasets"

# OWASP Top 10 2021 with detailed reasoning
OWASP_TOP_10 = [
    {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
        "attack_vectors": [
            "Violation of the principle of least privilege or deny by default",
            "Bypassing access control checks by modifying the URL, internal application state, or the HTML page",
            "Permitting viewing or editing someone else's account by providing its unique identifier (insecure direct object references)",
            "Accessing API with missing access controls for POST, PUT and DELETE",
            "Elevation of privilege acting as a user without being logged in or acting as an admin when logged in as a user",
            "Metadata manipulation such as replaying or tampering with a JWT access control token",
            "CORS misconfiguration allows API access from unauthorized/untrusted origins",
            "Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user"
        ],
        "prevention": [
            "Implement access control mechanisms once and re-use them throughout the application",
            "Model access controls should enforce record ownership rather than accepting that the user can create, read, update, or delete any record",
            "Disable web server directory listing and ensure file metadata and backup files are not present within web roots",
            "Log access control failures and alert admins when appropriate",
            "Rate limit API and controller access to minimize the harm from automated attack tooling",
            "Invalidate JWT tokens on the server after logout"
        ]
    },
    {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "The first thing is to determine the protection needs of data in transit and at rest. Passwords, credit card numbers, health records, personal information, and business secrets require extra protection if that data falls under privacy laws or regulations.",
        "attack_vectors": [
            "Is any data transmitted in clear text including HTTP, SMTP, FTP with TLS upgrades like STARTTLS",
            "Are any old or weak cryptographic algorithms or protocols used by default or in older code",
            "Are default crypto keys in use, weak crypto keys generated or re-used, or is proper key management missing",
            "Is encryption not enforced with missing security directives or headers",
            "Is the received server certificate and the trust chain properly validated",
            "Are initialization vectors ignored, reused, or not generated sufficiently secure",
            "Is deprecated hash functions such as MD5 or SHA1 in use, or are non-cryptographic hash functions used when cryptographic hash functions are needed",
            "Are deprecated cryptographic padding methods such as PKCS number 1 v1.5 in use"
        ],
        "prevention": [
            "Classify data processed, stored, or transmitted by an application and identify which data is sensitive",
            "Don't store sensitive data unnecessarily and discard it as soon as possible",
            "Make sure to encrypt all sensitive data at rest",
            "Ensure up-to-date and strong standard algorithms, protocols, and keys are in place",
            "Encrypt all data in transit with secure protocols such as TLS with forward secrecy ciphers",
            "Disable caching for responses that contain sensitive data",
            "Store passwords using strong adaptive and salted hashing functions with a work factor"
        ]
    },
    {
        "id": "A03:2021",
        "name": "Injection",
        "description": "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized by the application, dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter, or hostile data is used within ORM search parameters.",
        "attack_vectors": [
            "SQL injection through unsanitized user input in database queries",
            "NoSQL injection in document databases like MongoDB",
            "OS command injection through system calls with user input",
            "LDAP injection in directory service queries",
            "Expression Language injection in template engines",
            "XPath injection in XML processing",
            "Header injection in HTTP responses",
            "ORM injection through search parameters"
        ],
        "prevention": [
            "Use a safe API which avoids using the interpreter entirely, provides a parameterized interface, or migrates to ORMs",
            "Use positive server-side input validation - this is not a complete defense as many applications require special characters",
            "For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter",
            "Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection"
        ]
    },
    {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design. Insecure design is not the source for all other Top 10 risk categories. There is a difference between insecure design and insecure implementation.",
        "attack_vectors": [
            "Missing threat modeling during design phase",
            "Lack of security requirements and reference architecture",
            "Business logic flaws due to missing validation",
            "Insufficient rate limiting allowing resource exhaustion",
            "Missing account lockout mechanisms",
            "Predictable resource identifiers enabling enumeration",
            "Trust boundary violations in multi-tier architectures",
            "Missing segregation of duties in critical operations"
        ],
        "prevention": [
            "Establish and use a secure development lifecycle with AppSec professionals",
            "Use threat modeling for critical authentication, access control, business logic, and key flows",
            "Integrate security language and controls into user stories",
            "Integrate plausibility checks at each tier of your application",
            "Write unit and integration tests to validate that all critical flows are resistant to the threat model",
            "Segregate tier layers on the system and network layers depending on the exposure and protection needs"
        ]
    },
    {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "The application might be vulnerable if the application is missing appropriate security hardening across any part of the application stack or improperly configured permissions on cloud services, or unnecessary features are enabled or installed.",
        "attack_vectors": [
            "Missing appropriate security hardening across the application stack",
            "Improperly configured permissions on cloud services",
            "Unnecessary features enabled or installed including ports, services, pages, accounts, or privileges",
            "Default accounts and their passwords are still enabled and unchanged",
            "Error handling reveals stack traces or overly informative error messages to users",
            "Latest security features are disabled or not configured securely for upgraded systems",
            "Security settings in application servers, frameworks, libraries, databases are not set to secure values",
            "Server does not send security headers or directives, or they are not set to secure values"
        ],
        "prevention": [
            "A repeatable hardening process makes it fast and easy to deploy another environment that is appropriately locked down",
            "A minimal platform without any unnecessary features, components, documentation, and samples",
            "A task to review and update the configurations appropriate to all security notes, updates, and patches as part of the patch management process",
            "A segmented application architecture provides effective and secure separation between components or tenants",
            "Sending security directives to clients such as security headers",
            "An automated process to verify the effectiveness of the configurations and settings in all environments"
        ]
    },
    {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "You are likely vulnerable if you do not know the versions of all components you use, if the software is vulnerable unsupported or out of date, if you do not scan for vulnerabilities regularly and subscribe to security bulletins related to the components you use.",
        "attack_vectors": [
            "Running components with known vulnerabilities that have public exploits",
            "Using unsupported or end-of-life software versions",
            "Not knowing all component versions including nested dependencies",
            "Not scanning for vulnerabilities on a regular basis",
            "Not fixing or upgrading the underlying platform, frameworks, and dependencies in a timely fashion",
            "Not testing compatibility of updated libraries",
            "Not securing component configurations"
        ],
        "prevention": [
            "Remove unused dependencies, unnecessary features, components, files, and documentation",
            "Continuously inventory the versions of both client-side and server-side components and their dependencies",
            "Only obtain components from official sources over secure links and prefer signed packages",
            "Monitor for libraries and components that are unmaintained or do not create security patches for older versions",
            "Every organization must ensure an ongoing plan for monitoring, triaging, and applying updates or configuration changes"
        ]
    },
    {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. There may be authentication weaknesses if the application permits automated attacks such as credential stuffing.",
        "attack_vectors": [
            "Permits automated attacks such as credential stuffing, where the attacker has a list of valid usernames and passwords",
            "Permits brute force or other automated attacks",
            "Permits default, weak, or well-known passwords such as Password1 or admin/admin",
            "Uses weak or ineffective credential recovery and forgot-password processes",
            "Uses plain text, encrypted, or weakly hashed password data stores",
            "Has missing or ineffective multi-factor authentication",
            "Exposes session identifier in the URL",
            "Reuses session identifier after successful login",
            "Does not correctly invalidate Session IDs during logout or inactivity"
        ],
        "prevention": [
            "Implement multi-factor authentication to prevent automated credential stuffing, brute force, and stolen credential reuse attacks",
            "Do not ship or deploy with any default credentials, particularly for admin users",
            "Implement weak password checks against a list of the top 10000 worst passwords",
            "Align password length, complexity, and rotation policies with NIST 800-63b guidelines",
            "Ensure registration, credential recovery, and API pathways are hardened against account enumeration attacks",
            "Limit or increasingly delay failed login attempts while being careful not to create a denial of service scenario",
            "Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login"
        ]
    },
    {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and CDNs.",
        "attack_vectors": [
            "Applications that rely upon plugins, libraries, or modules from untrusted sources, repositories, and CDNs",
            "An insecure CI/CD pipeline that can introduce potential for unauthorized access, malicious code, or system compromise",
            "Auto-update functionality where updates are downloaded without sufficient integrity verification",
            "Objects or data encoded or serialized into a structure that an attacker can see and modify are vulnerable to insecure deserialization",
            "Supply chain attacks through compromised dependencies",
            "Unsigned or unverified software packages"
        ],
        "prevention": [
            "Use digital signatures or similar mechanisms to verify the software or data is from the expected source and has not been altered",
            "Ensure libraries and dependencies are consuming trusted repositories",
            "Ensure that a software supply chain security tool is used to verify that components do not contain known vulnerabilities",
            "Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced",
            "Ensure that your CI/CD pipeline has proper segregation, configuration, and access control",
            "Ensure that unsigned or unencrypted serialized data is not sent to untrusted clients without some form of integrity check"
        ]
    },
    {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "This category helps detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time auditable events are not logged.",
        "attack_vectors": [
            "Auditable events such as logins, failed logins, and high-value transactions are not logged",
            "Warnings and errors generate no, inadequate, or unclear log messages",
            "Logs of applications and APIs are not monitored for suspicious activity",
            "Logs are only stored locally",
            "Appropriate alerting thresholds and response escalation processes are not in place or effective",
            "Penetration testing and scans by DAST tools do not trigger alerts",
            "The application cannot detect, escalate, or alert for active attacks in real-time or near real-time"
        ],
        "prevention": [
            "Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts",
            "Ensure that logs are generated in a format that log management solutions can easily consume",
            "Ensure log data is encoded correctly to prevent injections or attacks on the logging or monitoring systems",
            "Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion",
            "DevSecOps teams should establish effective monitoring and alerting so suspicious activities are detected and responded to quickly",
            "Establish or adopt an incident response and recovery plan"
        ]
    },
    {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network ACL.",
        "attack_vectors": [
            "Fetching a URL from an external service without validation",
            "Accessing internal services through the vulnerable application",
            "Reading local files through file:// protocol",
            "Accessing cloud metadata services like 169.254.169.254",
            "Port scanning internal hosts through the vulnerable server",
            "Accessing internal APIs that trust requests from localhost",
            "Bypassing access controls to reach protected admin interfaces"
        ],
        "prevention": [
            "Segment remote resource access functionality in separate networks to reduce the impact of SSRF",
            "Enforce URL schemas, ports, and destinations with a positive allow list",
            "Disable HTTP redirections",
            "Do not send raw responses to clients",
            "Be aware of the URL consistency to avoid attacks such as DNS rebinding and TOCTOU race conditions",
            "Do not mitigate SSRF via the use of a deny list or regular expression"
        ]
    }
]

# CWE (Common Weakness Enumeration) - Top 25 with reasoning
CWE_TOP_25 = [
    {
        "id": "CWE-787",
        "name": "Out-of-bounds Write",
        "description": "The software writes data past the end, or before the beginning, of the intended buffer.",
        "reasoning": "Out-of-bounds write vulnerabilities allow attackers to corrupt memory, potentially leading to code execution. In penetration testing, these are high-value targets in binary exploitation. Detection is difficult without source code access, but fuzzing and memory analysis tools can identify them. Exploitation requires understanding of memory layout and often bypassing protections like ASLR and stack canaries."
    },
    {
        "id": "CWE-79",
        "name": "Cross-site Scripting (XSS)",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "reasoning": "XSS is prevalent because developers often trust user input or fail to properly encode output. Testing involves injecting script payloads into all input vectors. Reflected XSS requires social engineering for exploitation, while stored XSS persists and affects all users viewing the content. DOM-based XSS requires analyzing client-side JavaScript. Impact ranges from session hijacking to complete account takeover."
    },
    {
        "id": "CWE-89",
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        "reasoning": "SQL injection remains common despite decades of awareness because developers still concatenate user input into queries. Testing involves identifying injection points and determining database type. Blind SQLi requires boolean or time-based techniques when output is not visible. Union-based attacks extract data directly. The goal progression is: detect > identify DBMS > enumerate > extract data > potentially achieve code execution via xp_cmdshell or similar."
    },
    {
        "id": "CWE-416",
        "name": "Use After Free",
        "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        "reasoning": "Use-after-free vulnerabilities are complex to exploit but powerful when successful. They occur when memory is accessed after being deallocated. Exploitation involves controlling what gets allocated in the freed memory region. Modern browsers and applications are common targets. Heap grooming techniques are essential for reliable exploitation. These bugs often lead to remote code execution in browser and kernel contexts."
    },
    {
        "id": "CWE-78",
        "name": "OS Command Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
        "reasoning": "Command injection occurs when applications pass user input to system shells. Testing involves injecting shell metacharacters like semicolons, pipes, and backticks. The impact is typically immediate code execution with the application's privileges. Blind command injection requires out-of-band techniques like DNS callbacks or time delays. Always test both Unix and Windows syntax as applications may run on either platform."
    },
    {
        "id": "CWE-20",
        "name": "Improper Input Validation",
        "description": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
        "reasoning": "Input validation failures underlie many other vulnerability classes. Testing involves sending unexpected data types, lengths, formats, and encodings. Edge cases like null bytes, unicode normalization issues, and type confusion are valuable attack vectors. Defense requires both syntactic validation (format) and semantic validation (business logic). Client-side validation alone is never sufficient."
    },
    {
        "id": "CWE-125",
        "name": "Out-of-bounds Read",
        "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
        "reasoning": "Out-of-bounds reads can leak sensitive information from memory, including cryptographic keys, passwords, and memory addresses useful for bypassing ASLR. Heartbleed is the most famous example. While less severe than write primitives, these bugs are often stepping stones to full exploitation by revealing memory layout."
    },
    {
        "id": "CWE-22",
        "name": "Path Traversal",
        "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
        "reasoning": "Path traversal attacks use sequences like ../ to escape intended directories. Testing involves trying various encodings: URL encoding, double encoding, unicode, and null bytes. Common targets are file download features, template engines, and log viewers. Successful exploitation can lead to source code disclosure, configuration file access, or writing to sensitive locations."
    },
    {
        "id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        "reasoning": "CSRF forces authenticated users to perform unintended actions. Testing involves identifying state-changing requests without proper tokens. Modern frameworks include CSRF protection, but custom implementations often fail. SameSite cookies have reduced CSRF prevalence but bypass techniques exist. Impact depends on what actions the victim can perform - admin CSRF is particularly valuable."
    },
    {
        "id": "CWE-434",
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
        "reasoning": "File upload vulnerabilities can lead to code execution if the server processes uploaded files as executable. Testing involves bypassing extension filters (double extensions, null bytes, case variations), content-type validation, and magic byte checks. Even if execution is prevented, uploads to web roots enable stored XSS via HTML/SVG files."
    }
]

# CAPEC (Common Attack Pattern Enumeration) - Attack patterns with reasoning
CAPEC_PATTERNS = [
    {
        "id": "CAPEC-66",
        "name": "SQL Injection",
        "category": "web_attacks",
        "phases": ["Explore", "Experiment", "Exploit"],
        "reasoning": "SQL injection follows a methodical approach: First, identify injection points by testing for errors with single quotes. Second, determine the database type through error messages or behavioral differences. Third, enumerate the schema using information_schema or equivalent. Fourth, extract data using UNION queries or blind techniques. Fifth, attempt privilege escalation through database-specific features like xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL)."
    },
    {
        "id": "CAPEC-86",
        "name": "XSS Through HTTP Headers",
        "category": "web_attacks",
        "phases": ["Explore", "Experiment", "Exploit"],
        "reasoning": "HTTP headers are often reflected without proper encoding. Test User-Agent, Referer, X-Forwarded-For, and custom headers. Log poisoning attacks inject XSS payloads into server logs that are later viewed by administrators. Detection requires analyzing all response locations where headers might be reflected, including error pages and admin interfaces."
    },
    {
        "id": "CAPEC-112",
        "name": "Brute Force",
        "category": "initial_access",
        "phases": ["Explore", "Exploit"],
        "reasoning": "Brute force attacks require balancing speed against detection. Account lockout policies dictate maximum attempt rates. Distributed attacks across multiple IPs evade rate limiting. Password spraying (few passwords across many accounts) avoids lockouts better than focused attacks. Response time analysis can reveal valid usernames even without successful authentication."
    },
    {
        "id": "CAPEC-94",
        "name": "Man in the Middle Attack",
        "category": "lateral_movement",
        "phases": ["Explore", "Experiment", "Exploit"],
        "reasoning": "MITM attacks require network positioning through ARP spoofing, DNS poisoning, or rogue access points. SSL stripping downgrades HTTPS connections. Certificate warnings are often ignored by users. Modern HSTS preload lists limit effectiveness against major sites. Internal networks without proper segmentation are most vulnerable."
    },
    {
        "id": "CAPEC-98",
        "name": "Phishing",
        "category": "initial_access",
        "phases": ["Explore", "Experiment", "Exploit"],
        "reasoning": "Phishing effectiveness depends on pretext quality and target research. Spear phishing requires OSINT gathering on specific targets. Domain typosquatting and lookalike domains increase credibility. MFA bypass requires real-time relay attacks or session token capture. Success metrics include click rates, credential submission, and payload execution."
    },
    {
        "id": "CAPEC-125",
        "name": "Flooding",
        "category": "failure_analysis",
        "phases": ["Exploit"],
        "reasoning": "Denial of service testing requires authorization and careful scoping. Application-layer attacks (Slowloris, RUDY) are more efficient than volumetric attacks. Amplification attacks leverage UDP protocols with spoofed sources. Testing focuses on identifying resource exhaustion points rather than actually causing outages."
    },
    {
        "id": "CAPEC-169",
        "name": "Footprinting",
        "category": "initial_access",
        "phases": ["Explore"],
        "reasoning": "Reconnaissance establishes the attack surface before active testing. OSINT sources include DNS records, WHOIS, certificate transparency logs, and web archives. Passive techniques avoid detection but provide less detail. Active scanning should be carefully timed and sourced to avoid alerting defenders."
    },
    {
        "id": "CAPEC-186",
        "name": "Malicious Software Update",
        "category": "persistence",
        "phases": ["Explore", "Experiment", "Exploit"],
        "reasoning": "Supply chain attacks through software updates are highly effective because users trust update mechanisms. Compromising update servers or signing keys enables mass distribution. Testing involves verifying update integrity checks, certificate pinning, and code signing validation. Nation-state actors increasingly use this vector."
    }
]


def generate_owasp_samples() -> List[Dict]:
    """Generate training samples from OWASP Top 10."""
    samples = []
    
    for vuln in OWASP_TOP_10:
        # Sample 1: Attack planning
        samples.append({
            "instruction": f"You are testing a web application for {vuln['name']} vulnerabilities.",
            "input": f"The application is a typical enterprise web app. How would you approach testing for {vuln['id']}?",
            "output": f"{vuln['description']} Testing approach: Focus on these attack vectors: {'; '.join(vuln['attack_vectors'][:4])}. Each vector requires different testing techniques and has different detection risks. Prioritize based on application architecture and visible functionality."
        })
        
        # Sample 2: Detection awareness
        samples.append({
            "instruction": f"Assess detection risk when testing for {vuln['name']}.",
            "input": "Target has WAF and SIEM monitoring. Need to test thoroughly while minimizing alerts.",
            "output": f"Testing for {vuln['id']} ({vuln['name']}) requires careful approach under monitoring. High-risk actions: automated scanning, obvious payloads. Lower-risk approach: manual testing with obfuscated payloads, time-delayed requests, testing during high-traffic periods. Focus on: {vuln['attack_vectors'][0]} - often less monitored. Defenders typically watch for: {vuln['prevention'][0][:100]}..."
        })
        
        # Sample 3: Remediation perspective (blue team)
        samples.append({
            "instruction": f"As a defender, how would you protect against {vuln['name']}?",
            "input": f"Building security controls for {vuln['id']}. What are the key mitigations?",
            "output": f"Defense against {vuln['name']} requires multiple layers: {' '.join(vuln['prevention'][:3])}. Detection capabilities should monitor for attack patterns while prevention controls block known techniques. Balance security with usability - overly restrictive controls lead to workarounds that introduce new vulnerabilities."
        })
        
        # Sample 4: Failure analysis
        if len(vuln['attack_vectors']) > 3:
            samples.append({
                "instruction": f"Your initial testing for {vuln['name']} found no vulnerabilities. What alternatives should you consider?",
                "input": f"Standard {vuln['id']} testing techniques failed. Application seems hardened.",
                "output": f"When standard testing fails, consider: 1) Different attack vectors - {vuln['attack_vectors'][3]} may be overlooked. 2) Encoding variations and filter bypasses. 3) Chaining with other vulnerabilities. 4) Logic flaws in the specific implementation rather than generic patterns. 5) Second-order vulnerabilities where payload executes in different context. The absence of obvious vulnerabilities doesn't mean the application is secure - it means testing must go deeper."
            })
    
    return samples


def generate_cwe_samples() -> List[Dict]:
    """Generate training samples from CWE Top 25."""
    samples = []
    
    for weakness in CWE_TOP_25:
        # Sample 1: Technical analysis
        samples.append({
            "instruction": f"Explain how to identify and test for {weakness['name']} ({weakness['id']}).",
            "input": "You're conducting a security assessment and need to test for this weakness class.",
            "output": f"{weakness['description']} {weakness['reasoning']}"
        })
        
        # Sample 2: Exploitation reasoning
        samples.append({
            "instruction": f"What is the exploitation potential of {weakness['name']}?",
            "input": f"Found potential {weakness['id']} in target application. Assess risk and approach.",
            "output": f"Exploitation analysis for {weakness['name']}: {weakness['reasoning']} Impact assessment depends on context - consider data sensitivity, system privileges, and downstream effects. Always document findings thoroughly for responsible disclosure."
        })
    
    return samples


def generate_capec_samples() -> List[Dict]:
    """Generate training samples from CAPEC attack patterns."""
    samples = []
    
    for pattern in CAPEC_PATTERNS:
        # Sample 1: Attack methodology
        samples.append({
            "instruction": f"Describe the methodology for {pattern['name']} attacks.",
            "input": f"Planning a test involving {pattern['id']}. What phases and considerations apply?",
            "output": f"Attack pattern {pattern['name']} follows these phases: {', '.join(pattern['phases'])}. {pattern['reasoning']} This pattern is relevant for {pattern['category']} testing scenarios."
        })
        
        # Sample 2: Decision making
        samples.append({
            "instruction": f"When should you use {pattern['name']} techniques in an engagement?",
            "input": "Determining appropriate attack patterns for current phase of assessment.",
            "output": f"Consider {pattern['name']} when: {pattern['reasoning']} The technique fits the {pattern['category']} category. Phases involved: {', '.join(pattern['phases'])}. Always validate scope authorization before proceeding with active testing."
        })
    
    return samples


def generate_scenario_samples() -> List[Dict]:
    """Generate scenario-based training samples combining multiple concepts."""
    scenarios = [
        {
            "instruction": "Plan a web application penetration test approach.",
            "input": "Target is an e-commerce application with user accounts, payment processing, and admin panel. Standard LAMP stack suspected.",
            "output": "Phased approach recommended: 1) Reconnaissance - identify technology stack, entry points, and authentication mechanisms. 2) Authentication testing - test for weak passwords, credential stuffing resilience, session management flaws. 3) Authorization testing - IDOR on user resources, privilege escalation to admin. 4) Injection testing - SQLi on search/filter functions, command injection on any file processing. 5) Payment logic - test for race conditions, price manipulation, replay attacks. 6) Admin panel - often less hardened, focus authentication bypass and functionality abuse. Prioritize based on business impact - payment vulnerabilities are typically critical."
        },
        {
            "instruction": "Assess an API for security vulnerabilities.",
            "input": "REST API with JWT authentication. Need comprehensive security assessment.",
            "output": "API testing methodology: 1) Authentication - test JWT signature validation, algorithm confusion (none/HS256), expiration enforcement, token revocation. 2) Authorization - BOLA/IDOR on all endpoints changing resource IDs, function-level access control testing admin endpoints with user tokens. 3) Input validation - test all parameters for injection (SQLi, NoSQLi, command injection), mass assignment vulnerabilities. 4) Rate limiting - assess throttling on sensitive endpoints. 5) Information disclosure - verbose errors, stack traces, internal IDs. 6) Business logic - test intended vs actual workflow, state manipulation. APIs often lack the security controls of traditional web apps because developers assume limited exposure."
        },
        {
            "instruction": "You discovered a potential SQL injection but it appears to be blind. How do you proceed?",
            "input": "No error messages returned. Behavior changes slightly with certain inputs but no data is directly visible.",
            "output": "Blind SQLi exploitation approach: 1) Confirm vulnerability - use time-based payloads (SLEEP/WAITFOR DELAY) or boolean-based (AND 1=1 vs AND 1=2) to verify injection exists. 2) Identify DBMS - syntax differences in time functions identify MySQL vs MSSQL vs PostgreSQL vs Oracle. 3) Enumerate schema - use boolean extraction or time-based extraction to pull table/column names character by character. 4) Extract data - same technique for actual data. 5) Optimization - binary search reduces requests (127 chars = 7 requests vs 127). 6) Consider out-of-band - DNS exfiltration or HTTP callbacks can be faster than boolean/time methods. Tool support: sqlmap with appropriate tampering scripts. Manual testing validates findings and bypasses WAF better. Document payload patterns that work for the report."
        },
        {
            "instruction": "Testing finds that the application has Content Security Policy. How does this affect XSS testing?",
            "input": "CSP header present: default-src 'self'; script-src 'self' 'unsafe-inline'",
            "output": "CSP analysis: This policy allows 'unsafe-inline' for scripts which significantly weakens protection - inline script injection is still viable. Testing approach: 1) Inline handlers (onclick, onerror) are blocked by default-src but enabled by script-src unsafe-inline - test both. 2) Script injection with inline code should work. 3) External script loading is limited to 'self' - host payload on same origin if possible (file upload?). 4) Bypass techniques: JSONP endpoints on same origin, Angular template injection if framework present, base tag injection for relative URLs. 5) Report the CSP weakness itself - 'unsafe-inline' defeats much of CSP's purpose. The policy provides partial protection but the unsafe-inline directive is a significant gap."
        },
        {
            "instruction": "You've gained initial access to a Linux server. Plan your privilege escalation approach.",
            "input": "Low-privilege shell as www-data user. Ubuntu 20.04 server, appears to be a web server.",
            "output": "Linux privesc methodology: 1) Situational awareness - uname -a, cat /etc/os-release, id, sudo -l (check for NOPASSWD entries). 2) Quick wins - sudo misconfiguration, SUID binaries (find / -perm -4000), capabilities (getcap -r /), writable /etc/passwd. 3) Service enumeration - running processes (ps aux), listening services (netstat -tlnp), potential credentials in config files. 4) Cron jobs - check /etc/crontab, /etc/cron.*, user crontabs - look for writable scripts or path hijacking. 5) Web server context - www-data often has access to database credentials, session files, or other sensitive data. Check /var/www/, .env files, config.php. 6) Kernel exploits - last resort due to stability risk, check kernel version against known exploits. Automate enumeration with linPEAS but understand each finding. Document the path for the report."
        },
        {
            "instruction": "Explain how to approach Active Directory penetration testing.",
            "input": "Internal network assessment. Windows domain environment with multiple DCs, workstations, and servers.",
            "output": "AD pentest methodology: 1) Reconnaissance - identify DCs (DNS SRV records), domain functional level, trust relationships. 2) User enumeration - null sessions if available, RPC enumeration, Kerberos user enumeration. 3) Initial access techniques - LLMNR/NBT-NS poisoning for hash capture, password spraying against identified accounts, Kerberoasting for service account hashes. 4) Credential attacks - AS-REP roasting for accounts without preauth, targeted Kerberoasting, hash cracking offline. 5) Lateral movement - pass-the-hash, over-pass-the-hash, pass-the-ticket with captured credentials. 6) Privilege escalation - BloodHound for attack path analysis, ACL abuse, delegation attacks, ADCS exploitation. 7) Domain dominance - DCSync with sufficient privileges, Golden Ticket for persistence. Key insight: AD attacks are about finding paths, not individual exploits. BloodHound visualizes these paths. Always consider detection - most techniques generate distinctive log events."
        }
    ]
    
    return scenarios


def save_samples(samples: List[Dict], category: str, source: str):
    """Save samples to appropriate category file."""
    output_dir = OUTPUT_DIR / category
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{source}_samples.jsonl"
    
    with open(output_file, 'w') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"  📁 {category}: {len(samples)} samples → {output_file.name}")
    return len(samples)


def main():
    """Main extraction function."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA OWASP/CWE/CAPEC EXTRACTOR
   Generating web security training samples
═══════════════════════════════════════════════════════════════════
""")
    
    total = 0
    
    # Generate OWASP samples
    print("📂 Generating OWASP Top 10 samples...")
    owasp_samples = generate_owasp_samples()
    total += save_samples(owasp_samples, "web_attacks", "owasp")
    
    # Generate CWE samples
    print("\n📂 Generating CWE Top 25 samples...")
    cwe_samples = generate_cwe_samples()
    total += save_samples(cwe_samples, "web_attacks", "cwe")
    
    # Generate CAPEC samples
    print("\n📂 Generating CAPEC attack pattern samples...")
    capec_samples = generate_capec_samples()
    
    # Split CAPEC by category
    capec_by_category = {}
    for sample in capec_samples:
        cat = sample.get("_category", "initial_access")
        if cat not in capec_by_category:
            capec_by_category[cat] = []
        # Remove internal category marker
        clean_sample = {k: v for k, v in sample.items() if not k.startswith("_")}
        capec_by_category[cat].append(clean_sample)
    
    for category in ["initial_access", "lateral_movement", "failure_analysis", "persistence"]:
        if category in capec_by_category:
            total += save_samples(capec_by_category[category], category, "capec")
    total += save_samples(capec_samples, "initial_access", "capec")
    
    # Generate scenario samples
    print("\n📂 Generating scenario-based samples...")
    scenario_samples = generate_scenario_samples()
    total += save_samples(scenario_samples, "initial_access", "scenarios")
    
    print(f"""
═══════════════════════════════════════════════════════════════
✅ OWASP/CWE/CAPEC EXTRACTION COMPLETE

Total new samples: {total}

Run quality scorer next:
  python quality_scorer.py
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
