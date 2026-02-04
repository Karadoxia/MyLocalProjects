# MITRE ATT&CK Framework Reference

## Initial Access (TA0001)

| Technique | ID | Description |
|-----------|-----|-------------|
| Drive-by Compromise | T1189 | Malicious website exploits browser |
| Exploit Public-Facing App | T1190 | Exploit vulnerability in internet-facing app |
| External Remote Services | T1133 | Use VPN, RDP, Citrix for access |
| Hardware Additions | T1200 | Physical device insertion |
| Phishing | T1566 | Spearphishing attachment/link/service |
| Replication Through Removable Media | T1091 | Malware via USB |
| Supply Chain Compromise | T1195 | Compromise software supply chain |
| Trusted Relationship | T1199 | Abuse third-party access |
| Valid Accounts | T1078 | Use compromised credentials |

## Execution (TA0002)

| Technique | ID | Description |
|-----------|-----|-------------|
| Command/Scripting Interpreter | T1059 | PowerShell, cmd, bash, Python |
| Container Admin Command | T1609 | Execute via kubectl, docker |
| Deploy Container | T1610 | Deploy malicious container |
| Exploitation for Client Execution | T1203 | Exploit apps like Office, browsers |
| Inter-Process Communication | T1559 | DDE, COM |
| Native API | T1106 | Use OS APIs directly |
| Scheduled Task/Job | T1053 | Cron, at, scheduled tasks |
| Shared Modules | T1129 | Load shared libraries |
| Software Deployment Tools | T1072 | SCCM, Ansible misuse |
| System Services | T1569 | Service execution |
| User Execution | T1204 | Trick user to execute |
| Windows Management Instrumentation | T1047 | WMI for execution |

## Persistence (TA0003)

| Technique | ID | Description |
|-----------|-----|-------------|
| Account Manipulation | T1098 | SSH keys, MFA changes |
| BITS Jobs | T1197 | Background transfer jobs |
| Boot/Logon Autostart Execution | T1547 | Registry run keys, startup folder |
| Boot/Logon Initialization Scripts | T1037 | Logon scripts |
| Browser Extensions | T1176 | Malicious extensions |
| Compromise Client Software Binary | T1554 | Modify client binaries |
| Create Account | T1136 | Local or domain accounts |
| Create/Modify System Process | T1543 | Services, systemd |
| Event Triggered Execution | T1546 | WMI, AppInit DLLs |
| External Remote Services | T1133 | Persistent VPN/RDP access |
| Hijack Execution Flow | T1574 | DLL hijacking, PATH |
| Implant Internal Image | T1525 | Container image backdoors |
| Modify Authentication Process | T1556 | SSP, LSASS |
| Office Application Startup | T1137 | Office templates, add-ins |
| Pre-OS Boot | T1542 | Bootkit, UEFI |
| Scheduled Task/Job | T1053 | Persistent scheduled execution |
| Server Software Component | T1505 | Web shells, SQL stored procedures |
| Traffic Signaling | T1205 | Port knocking |
| Valid Accounts | T1078 | Maintain compromised accounts |

## Privilege Escalation (TA0004)

| Technique | ID | Description |
|-----------|-----|-------------|
| Abuse Elevation Control Mechanism | T1548 | UAC bypass, sudo abuse |
| Access Token Manipulation | T1134 | Token impersonation, theft |
| Boot/Logon Autostart Execution | T1547 | Run with elevated context |
| Create/Modify System Process | T1543 | Weak service permissions |
| Domain Policy Modification | T1484 | GPO abuse |
| Escape to Host | T1611 | Container escape |
| Event Triggered Execution | T1546 | Accessibility features |
| Exploitation for Privilege Escalation | T1068 | Kernel exploits |
| Hijack Execution Flow | T1574 | DLL search order hijacking |
| Process Injection | T1055 | DLL injection, process hollowing |
| Scheduled Task/Job | T1053 | Elevated scheduled tasks |
| Valid Accounts | T1078 | Use privileged accounts |

## Defense Evasion (TA0005)

| Technique | ID | Description |
|-----------|-----|-------------|
| Abuse Elevation Control Mechanism | T1548 | Bypass security controls |
| Access Token Manipulation | T1134 | Modify tokens |
| BITS Jobs | T1197 | Stealthy file transfer |
| Deobfuscate/Decode Files | T1140 | Decode payloads at runtime |
| Direct Volume Access | T1006 | Raw disk access |
| Domain Policy Modification | T1484 | Disable security via GPO |
| Execution Guardrails | T1480 | Environment checks |
| Exploitation for Defense Evasion | T1211 | Exploit security software |
| File/Path Exclusions | T1564 | Hidden files, ADS |
| Hide Artifacts | T1564 | Hidden files, NTFS ADS |
| Hijack Execution Flow | T1574 | DLL hijacking |
| Impair Defenses | T1562 | Disable AV, firewall |
| Indicator Removal | T1070 | Clear logs, timestomp |
| Indirect Command Execution | T1202 | Use trusted binaries |
| Masquerading | T1036 | Rename files, spoof names |
| Modify Authentication Process | T1556 | Bypass authentication |
| Modify Cloud Compute Infrastructure | T1578 | Cloud resource modification |
| Modify Registry | T1112 | Registry modifications |
| Modify System Image | T1601 | Firmware modifications |
| Network Boundary Bridging | T1599 | Network tunneling |
| Obfuscated Files/Information | T1027 | Encoding, encryption |
| Plist File Modification | T1647 | macOS plist abuse |
| Pre-OS Boot | T1542 | Bootkit persistence |
| Process Injection | T1055 | Code injection |
| Reflective Code Loading | T1620 | In-memory execution |
| Rogue Domain Controller | T1207 | DCShadow |
| Rootkit | T1014 | Kernel-level hiding |
| Subvert Trust Controls | T1553 | Code signing bypass |
| System Binary Proxy Execution | T1218 | LOLBAS execution |
| Template Injection | T1221 | Document template abuse |
| Traffic Signaling | T1205 | Covert signaling |
| Trusted Developer Utilities | T1127 | MSBuild, InstallUtil |
| Unused/Unsupported Cloud Regions | T1535 | Hide in unused regions |
| Use Alternate Authentication Material | T1550 | Pass the hash/ticket |
| Valid Accounts | T1078 | Blend with legitimate activity |
| Virtualization/Sandbox Evasion | T1497 | Detect analysis environment |
| Weaken Encryption | T1600 | Downgrade encryption |
| XSL Script Processing | T1220 | MSXSL.exe abuse |

## Credential Access (TA0006)

| Technique | ID | Description |
|-----------|-----|-------------|
| Adversary-in-the-Middle | T1557 | LLMNR/NBT-NS poisoning |
| Brute Force | T1110 | Password guessing/spraying |
| Credentials from Password Stores | T1555 | Browser, keychain |
| Exploitation for Credential Access | T1212 | Credential vulnerabilities |
| Forced Authentication | T1187 | Capture NTLM hashes |
| Forge Web Credentials | T1606 | SAML token forgery |
| Input Capture | T1056 | Keylogging |
| Modify Authentication Process | T1556 | SSP, Skeleton Key |
| Multi-Factor Authentication Interception | T1111 | MFA bypass |
| Multi-Factor Authentication Request Generation | T1621 | MFA fatigue |
| Network Sniffing | T1040 | Capture credentials on wire |
| OS Credential Dumping | T1003 | LSASS, SAM, NTDS.dit |
| Steal Application Access Token | T1528 | OAuth, API tokens |
| Steal or Forge Kerberos Tickets | T1558 | Kerberoasting, Golden/Silver |
| Steal Web Session Cookie | T1539 | Session hijacking |
| Unsecured Credentials | T1552 | Files, registry, history |

## Lateral Movement (TA0008)

| Technique | ID | Description |
|-----------|-----|-------------|
| Exploitation of Remote Services | T1210 | Exploit internal services |
| Internal Spearphishing | T1534 | Phish internal users |
| Lateral Tool Transfer | T1570 | Move tools internally |
| Remote Service Session Hijacking | T1563 | RDP, SSH hijacking |
| Remote Services | T1021 | SMB, RDP, SSH, WinRM |
| Replication Through Removable Media | T1091 | USB propagation |
| Software Deployment Tools | T1072 | SCCM, Ansible |
| Taint Shared Content | T1080 | Modify shared files |
| Use Alternate Authentication Material | T1550 | PtH, PtT, web cookies |

## Collection (TA0009)

| Technique | ID | Description |
|-----------|-----|-------------|
| Adversary-in-the-Middle | T1557 | Collect via interception |
| Archive Collected Data | T1560 | Compress before exfil |
| Audio Capture | T1123 | Microphone recording |
| Automated Collection | T1119 | Scripted data gathering |
| Browser Session Hijacking | T1185 | Man-in-the-browser |
| Clipboard Data | T1115 | Clipboard monitoring |
| Data from Cloud Storage | T1530 | S3, blob storage |
| Data from Configuration Repository | T1602 | Network device configs |
| Data from Information Repositories | T1213 | SharePoint, wikis |
| Data from Local System | T1005 | Local files |
| Data from Network Shared Drive | T1039 | File shares |
| Data from Removable Media | T1025 | USB data |
| Data Staged | T1074 | Stage before exfil |
| Email Collection | T1114 | Mailbox access |
| Input Capture | T1056 | Keylogging |
| Screen Capture | T1113 | Screenshots |
| Video Capture | T1125 | Webcam recording |

## Exfiltration (TA0010)

| Technique | ID | Description |
|-----------|-----|-------------|
| Automated Exfiltration | T1020 | Scripted exfil |
| Data Transfer Size Limits | T1030 | Chunk data |
| Exfiltration Over Alternative Protocol | T1048 | DNS, ICMP tunneling |
| Exfiltration Over C2 Channel | T1041 | Use C2 for exfil |
| Exfiltration Over Other Network Medium | T1011 | Bluetooth, RF |
| Exfiltration Over Physical Medium | T1052 | USB exfil |
| Exfiltration Over Web Service | T1567 | Cloud storage upload |
| Scheduled Transfer | T1029 | Timed exfiltration |
| Transfer Data to Cloud Account | T1537 | Move to cloud storage |
