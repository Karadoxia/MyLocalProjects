# Nmap - Network Scanner

## Overview
Nmap (Network Mapper) is the de facto standard for network discovery and security auditing.

## Common Scan Types

### Host Discovery
```bash
nmap -sn 192.168.1.0/24          # Ping scan (no port scan)
nmap -Pn TARGET                   # Skip host discovery
nmap -PS22,80,443 TARGET          # TCP SYN discovery
nmap -PA80,443 TARGET             # TCP ACK discovery
nmap -PU53 TARGET                 # UDP discovery
```

### Port Scanning
```bash
nmap -sS TARGET                   # SYN scan (stealth, requires root)
nmap -sT TARGET                   # TCP connect scan
nmap -sU TARGET                   # UDP scan (slow)
nmap -sA TARGET                   # ACK scan (firewall detection)
nmap -sW TARGET                   # Window scan
nmap -sN TARGET                   # Null scan
nmap -sF TARGET                   # FIN scan
nmap -sX TARGET                   # Xmas scan
```

### Port Specification
```bash
nmap -p 22 TARGET                 # Single port
nmap -p 22,80,443 TARGET          # Multiple ports
nmap -p 1-1000 TARGET             # Port range
nmap -p- TARGET                   # All 65535 ports
nmap --top-ports 100 TARGET       # Top 100 ports
nmap -p U:53,T:22,80 TARGET       # UDP and TCP
```

### Service/Version Detection
```bash
nmap -sV TARGET                   # Version detection
nmap -sV --version-intensity 5    # Aggressive version detection
nmap -A TARGET                    # Aggressive (OS, version, scripts, traceroute)
nmap -O TARGET                    # OS detection
```

### NSE Scripts
```bash
nmap -sC TARGET                   # Default scripts
nmap --script=vuln TARGET         # Vulnerability scripts
nmap --script=safe TARGET         # Safe scripts only
nmap --script=smb-enum* TARGET    # SMB enumeration
nmap --script=http-* TARGET       # HTTP scripts
```

### Timing and Performance
```bash
nmap -T0 TARGET                   # Paranoid (IDS evasion)
nmap -T1 TARGET                   # Sneaky
nmap -T2 TARGET                   # Polite
nmap -T3 TARGET                   # Normal (default)
nmap -T4 TARGET                   # Aggressive
nmap -T5 TARGET                   # Insane (fast, noisy)
nmap --min-rate 1000 TARGET       # Minimum packet rate
nmap --max-retries 1 TARGET       # Reduce retries
```

### Output Options
```bash
nmap -oN scan.txt TARGET          # Normal output
nmap -oX scan.xml TARGET          # XML output
nmap -oG scan.gnmap TARGET        # Grepable output
nmap -oA scan TARGET              # All formats
```

## Detection Risk
- **Low**: -sS with -T2 or lower
- **Medium**: -sS with -T3, service detection
- **High**: -A, -T4+, aggressive scripts, full port scans

## Common Workflows

### Quick Network Sweep
```bash
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | cut -d" " -f2
```

### Full Service Enumeration
```bash
nmap -sS -sV -sC -O -p- -T4 TARGET -oA full_scan
```

### Stealth Scan
```bash
nmap -sS -T2 -f --data-length 24 -D RND:5 TARGET
```

### Vulnerability Assessment
```bash
nmap -sV --script=vuln TARGET
```
