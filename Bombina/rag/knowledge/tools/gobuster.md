# Gobuster - Directory/DNS Brute Force

## Overview
Fast directory/file & DNS busting tool written in Go.

## Directory Brute Force (dir mode)

### Basic Usage
```bash
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt
```

### Common Options
```bash
gobuster dir -u URL -w WORDLIST \
    -t 50                    # Threads (default 10)
    -x php,txt,html,bak      # Extensions to check
    -s "200,204,301,302"     # Status codes to show
    -b "404,403"             # Status codes to hide
    -r                       # Follow redirects
    -k                       # Skip TLS verification
    -c "PHPSESSID=abc123"    # Cookie
    -H "Authorization: Bearer token"  # Header
    -a "Mozilla/5.0..."      # User agent
    -o output.txt            # Output file
    --timeout 10s            # Request timeout
    --delay 100ms            # Delay between requests
    -q                       # Quiet mode
    --no-error               # Don't show errors
```

### Examples
```bash
# Basic with extensions
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt

# Authenticated scan
gobuster dir -u http://target.com -w wordlist.txt -c "session=abc123" -H "X-Auth: token"

# Stealth mode
gobuster dir -u http://target.com -w wordlist.txt -t 5 --delay 500ms -a "Mozilla/5.0"
```

## DNS Subdomain Enumeration (dns mode)

```bash
gobuster dns -d TARGET.COM -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Options
-r 8.8.8.8                   # DNS resolver
-c                           # Show CNAME records
-i                           # Show IP addresses
--wildcard                   # Force wildcard processing
```

## Virtual Host Enumeration (vhost mode)

```bash
gobuster vhost -u http://TARGET -w wordlist.txt

# Options
--append-domain              # Append domain to wordlist
-r                           # Follow redirects
```

## S3 Bucket Enumeration (s3 mode)

```bash
gobuster s3 -w bucket-names.txt
```

## Recommended Wordlists
- `/usr/share/seclists/Discovery/Web-Content/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

## Detection Risk
- **Low**: Low threads, delays, common user agent
- **Medium**: Default settings
- **High**: High threads, no delays, aggressive scanning
