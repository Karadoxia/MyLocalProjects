# BloodHound - Active Directory Attack Path Analysis

## Overview
BloodHound uses graph theory to reveal hidden relationships in Active Directory environments.

## Components
- **SharpHound**: Data collector (runs on Windows)
- **BloodHound**: GUI for analysis
- **Neo4j**: Graph database backend

## Installation

```bash
# Install Neo4j
sudo apt install neo4j

# Start Neo4j
sudo neo4j start
# Access: http://localhost:7474
# Default: neo4j/neo4j (change on first login)

# Install BloodHound
sudo apt install bloodhound
# Or download from GitHub releases
```

## Data Collection (SharpHound)

### From Windows (Preferred)
```powershell
# Download SharpHound
.\SharpHound.exe -c All

# Collection methods
.\SharpHound.exe -c DCOnly          # DC only, fast
.\SharpHound.exe -c All             # Everything
.\SharpHound.exe -c Session         # Sessions only
.\SharpHound.exe -c LoggedOn        # Logged on users
.\SharpHound.exe -c Trusts          # Domain trusts
.\SharpHound.exe -c ACL             # ACLs
.\SharpHound.exe -c ObjectProps     # Object properties

# Stealth options
.\SharpHound.exe -c All --stealth   # Avoid detection
.\SharpHound.exe -c All --excludedcs  # Skip DCs
```

### From Linux (bloodhound-python)
```bash
pip install bloodhound

bloodhound-python -u user -p password -d domain.local -c All -ns DC_IP

# Options
-c All,DCOnly,Session,Trusts,ACL
--dns-tcp         # Use TCP for DNS
-w 1              # Workers (stealth)
```

## BloodHound GUI

### Starting
```bash
bloodhound --no-sandbox
```

### Import Data
1. Upload JSON/ZIP files from SharpHound
2. Drag and drop or use Upload button

### Pre-Built Queries
```
- Find all Domain Admins
- Find Shortest Paths to Domain Admins
- Find Principals with DCSync Rights
- Find Computers where Domain Users are Local Admin
- Shortest Paths to High Value Targets
- Find Kerberoastable Users
- Find AS-REP Roastable Users
- Find Computers with Unsupported OS
- Shortest Paths from Owned Principals
```

### Custom Cypher Queries

```cypher
# Find all Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u

# Find users with DCSync rights
MATCH (n1)-[r:MemberOf|GetChanges*1..]->(u:Domain) RETURN n1

# Find computers where Domain Users can RDP
MATCH p=(m:Group)-[r:CanRDP]->(n:Computer) 
WHERE m.name =~ 'DOMAIN USERS@.*' RETURN p

# Find shortest path from owned to DA
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p

# Find all GPOs
MATCH (g:GPO) RETURN g.name
```

### Mark Nodes
- Right-click > Mark as Owned
- Right-click > Mark as High Value
- Owned nodes show attack paths FROM them
- High Value nodes show attack paths TO them

## Key Attack Paths

### Generic All
Full control over object - can reset password, add to groups

### GenericWrite
Can modify object attributes - set SPN for Kerberoasting

### WriteDacl
Can modify ACL - grant yourself more permissions

### WriteOwner
Can change owner - then modify permissions

### ForceChangePassword
Reset password without knowing current

### AddMember
Add principals to group

### ReadLAPSPassword
Read local admin password from AD

### ReadGMSAPassword
Read Group Managed Service Account password

### DCSync
Replicate domain data (get all hashes)

### Constrained Delegation
Impersonate users to specific services

### Unconstrained Delegation
Capture and reuse TGTs

## Tips
- Always collect fresh data before attacks
- Mark owned principals for path analysis
- Check "Shortest Paths" from owned to targets
- Look for misconfigurations, not just vulnerabilities
