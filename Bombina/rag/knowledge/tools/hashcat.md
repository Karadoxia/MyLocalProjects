# Hashcat - Password Recovery

## Overview
World's fastest password recovery tool supporting 300+ hash types.

## Basic Syntax
```bash
hashcat -m HASH_TYPE -a ATTACK_MODE hash.txt wordlist.txt
```

## Common Hash Types (-m)

### Windows
```
1000    NTLM
3000    LM
5500    NetNTLMv1
5600    NetNTLMv2
```

### Linux
```
500     md5crypt ($1$)
1800    sha512crypt ($6$)
7400    sha256crypt ($5$)
```

### Web/Database
```
0       MD5
100     SHA1
1400    SHA256
1700    SHA512
3200    bcrypt
```

### Kerberos
```
13100   Kerberos 5 TGS-REP (Kerberoasting)
18200   Kerberos 5 AS-REP (AS-REP Roasting)
19600   Kerberos 5 TGS-REP (AES128)
19700   Kerberos 5 TGS-REP (AES256)
```

### Other
```
1500    descrypt
2500    WPA/WPA2
22000   WPA-PBKDF2-PMKID+EAPOL
16800   WPA-PMKID-PBKDF2
```

## Attack Modes (-a)

```
0       Dictionary (wordlist)
1       Combination (word1+word2)
3       Brute-force/Mask
6       Hybrid Wordlist + Mask
7       Hybrid Mask + Wordlist
9       Association
```

## Mask Attack (-a 3)

### Charsets
```
?l      Lowercase (a-z)
?u      Uppercase (A-Z)
?d      Digits (0-9)
?s      Special (!@#$%...)
?a      All (?l?u?d?s)
?b      Hex (0x00-0xff)
```

### Examples
```bash
# 8 character lowercase
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l

# Common pattern: Word + 4 digits
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?l?d?d?d?d

# Custom charset
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1
```

## Rule-Based Attack

```bash
# Use rules file
hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule

# Multiple rules
hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule -r rules/toggles1.rule

# Built-in rules
-r /usr/share/hashcat/rules/best64.rule
-r /usr/share/hashcat/rules/rockyou-30000.rule
-r /usr/share/hashcat/rules/d3ad0ne.rule
-r /usr/share/hashcat/rules/dive.rule
```

## Useful Options

```bash
--status                # Show status
--status-timer=10       # Status every 10 seconds
-w 3                    # Workload profile (1-4)
-O                      # Optimized kernels (faster, limited password length)
--force                 # Ignore warnings
--show                  # Show cracked passwords
--username              # Hash file includes username
-o cracked.txt          # Output file
--increment             # Increment mask length
--increment-min=4       # Minimum length
--increment-max=8       # Maximum length
--session=session1      # Name session
--restore               # Restore session
--potfile-disable       # Don't use potfile
```

## Common Workflows

### Crack NTLM with Wordlist
```bash
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt
```

### Crack NTLM with Rules
```bash
hashcat -m 1000 ntlm.txt rockyou.txt -r best64.rule
```

### Kerberoasting
```bash
hashcat -m 13100 kerberoast.txt rockyou.txt
```

### NetNTLMv2
```bash
hashcat -m 5600 netntlmv2.txt rockyou.txt
```

### Brute Force Short Passwords
```bash
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a --increment
```

### Hybrid Attack
```bash
# Wordlist + 4 digits
hashcat -m 0 hash.txt -a 6 wordlist.txt ?d?d?d?d
```

## Performance Tips
- Use GPU (CUDA/OpenCL)
- `-w 3` or `-w 4` for dedicated cracking
- `-O` for faster cracking (limited to 32 chars)
- Use rules instead of pure brute force
- Start with common passwords, escalate

## Hash Identification
```bash
hashid hash_value
hash-identifier
```
