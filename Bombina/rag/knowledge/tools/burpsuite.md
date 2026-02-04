# Burp Suite - Web Application Testing

## Overview
Industry-standard web application security testing platform.

## Proxy Configuration

### Browser Setup
1. Configure browser proxy: 127.0.0.1:8080
2. Install Burp CA certificate for HTTPS interception
3. Enable intercept in Proxy tab

### Intercept Controls
- Intercept is on/off: Toggle request interception
- Forward: Send request to server
- Drop: Block request
- Action: Send to other tools

## Key Tools

### Target
- Site map: Visual representation of discovered content
- Scope: Define in-scope targets
- Issues: Discovered vulnerabilities

### Proxy
```
HTTP History - All requests/responses
WebSockets history - WebSocket messages
Options - Proxy settings, match/replace rules
```

### Intruder (Automated attacks)

#### Attack Types
- **Sniper**: Single payload, one position at a time
- **Battering ram**: Same payload in all positions
- **Pitchfork**: Multiple payloads, synchronized
- **Cluster bomb**: Multiple payloads, all combinations

#### Common Uses
```
Brute force login
Parameter fuzzing
ID enumeration
SQL injection
XSS testing
```

### Repeater
Manual request modification and resending.
- Modify any part of request
- Compare responses
- Track request history

### Scanner (Pro)
Automated vulnerability scanning:
- Active scanning (sends payloads)
- Passive scanning (analyzes traffic)
- Audit configurations

### Decoder
Encode/decode data:
- URL encoding
- Base64
- HTML entities
- Hex
- ASCII hex

### Comparer
Compare two items:
- Requests
- Responses
- Words or bytes

## Common Workflows

### Authentication Testing
1. Capture login request
2. Send to Intruder
3. Mark password field
4. Load wordlist
5. Start attack
6. Analyze response lengths/codes

### Parameter Tampering
1. Capture request in Proxy
2. Send to Repeater
3. Modify parameters
4. Analyze response
5. Test for IDOR, injection, etc.

### SQL Injection Testing
1. Identify parameters
2. Send to Intruder
3. Use SQLi payloads
4. Look for errors, time delays, different responses

## Useful Extensions
- Logger++: Enhanced logging
- Autorize: Authorization testing
- JSON Beautifier: Format JSON
- Turbo Intruder: Fast fuzzing
- Param Miner: Find hidden parameters
- Retire.js: Vulnerable JavaScript libraries

## Scope Configuration
```
Target > Scope > Add
Include: .*\.target\.com$
Exclude: .*\.google\.com$
```

## Match and Replace Rules
```
Proxy > Options > Match and Replace
Match: User-Agent: .*
Replace: User-Agent: Custom-Agent
```

## Detection Considerations
- Use delays between requests
- Rotate User-Agents
- Throttle Intruder attacks
- Avoid scanning login pages repeatedly (lockouts)
