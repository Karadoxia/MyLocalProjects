# Common Ports and Services

## Well-Known Ports (0-1023)

| Port | Service | Notes |
|------|---------|-------|
| 20 | FTP Data | File transfer data |
| 21 | FTP Control | File transfer control, check anonymous access |
| 22 | SSH | Secure shell, check for weak passwords |
| 23 | Telnet | Insecure, credentials in cleartext |
| 25 | SMTP | Email, check for open relay |
| 53 | DNS | Domain resolution, zone transfer |
| 67/68 | DHCP | Dynamic IP assignment |
| 69 | TFTP | Trivial FTP, no auth |
| 80 | HTTP | Web server |
| 88 | Kerberos | AD authentication |
| 110 | POP3 | Email retrieval |
| 111 | RPC | Remote procedure call, rpcinfo |
| 119 | NNTP | News |
| 123 | NTP | Time sync |
| 135 | MSRPC | Windows RPC |
| 137 | NetBIOS-NS | Name service |
| 138 | NetBIOS-DGM | Datagram |
| 139 | NetBIOS-SSN | Session, SMB over NetBIOS |
| 143 | IMAP | Email |
| 161/162 | SNMP | Network management, community strings |
| 389 | LDAP | Directory services |
| 443 | HTTPS | Encrypted web |
| 445 | SMB | File sharing, common target |
| 464 | Kpasswd | Kerberos password change |
| 500 | IKE | VPN |
| 514 | Syslog | Logging |
| 515 | LPD | Printing |
| 520 | RIP | Routing |
| 523 | IBM DB2 | Database |
| 548 | AFP | Apple file sharing |
| 554 | RTSP | Streaming |
| 587 | SMTP Submission | Email submission |
| 636 | LDAPS | LDAP over SSL |
| 873 | Rsync | File sync |
| 993 | IMAPS | IMAP over SSL |
| 995 | POP3S | POP3 over SSL |

## Registered Ports (1024-49151)

| Port | Service | Notes |
|------|---------|-------|
| 1080 | SOCKS Proxy | Proxy server |
| 1099 | Java RMI | Remote method invocation |
| 1433 | MSSQL | Microsoft SQL Server |
| 1434 | MSSQL Browser | SQL Server discovery |
| 1521 | Oracle | Oracle database |
| 1723 | PPTP | VPN |
| 2049 | NFS | Network file system |
| 2121 | FTP Proxy | Alternative FTP |
| 2375 | Docker | Docker API (unencrypted!) |
| 2376 | Docker TLS | Docker API (encrypted) |
| 3000 | Development | Node.js, Grafana, etc. |
| 3128 | Squid Proxy | HTTP proxy |
| 3268 | Global Catalog | AD Global Catalog |
| 3269 | Global Catalog SSL | AD GC over SSL |
| 3306 | MySQL | MySQL database |
| 3389 | RDP | Remote Desktop |
| 3632 | distccd | Distributed compiler |
| 4369 | EPMD | Erlang Port Mapper |
| 4443 | HTTPS Alt | Alternative HTTPS |
| 4444 | Metasploit | Default MSF handler |
| 5000 | Development | Flask, Docker Registry |
| 5432 | PostgreSQL | PostgreSQL database |
| 5555 | Android ADB | Android Debug Bridge |
| 5601 | Kibana | Elasticsearch UI |
| 5672 | RabbitMQ | Message queue |
| 5800 | VNC Web | VNC over HTTP |
| 5900 | VNC | Virtual Network Computing |
| 5984 | CouchDB | NoSQL database |
| 5985 | WinRM HTTP | Windows Remote Management |
| 5986 | WinRM HTTPS | WinRM over SSL |
| 6379 | Redis | In-memory database |
| 6443 | Kubernetes API | K8s API server |
| 6667 | IRC | Internet Relay Chat |
| 7001 | WebLogic | Oracle WebLogic |
| 8000 | Development | Django, various |
| 8080 | HTTP Proxy | Tomcat, Jenkins |
| 8081 | HTTP Alt | Alternative HTTP |
| 8443 | HTTPS Alt | Tomcat, various |
| 8888 | HTTP Alt | Jupyter, various |
| 9000 | PHP-FPM | SonarQube |
| 9090 | Prometheus | Monitoring |
| 9200 | Elasticsearch | Search engine |
| 9300 | Elasticsearch | Cluster communication |
| 10000 | Webmin | Web admin panel |
| 10250 | Kubelet | Kubernetes node |
| 11211 | Memcached | Caching |
| 27017 | MongoDB | NoSQL database |
| 27018 | MongoDB | Shard server |
| 28017 | MongoDB Web | MongoDB web interface |

## Service-Specific Testing

### Port 21 - FTP
```bash
nmap -sV -sC -p21 TARGET
ftp TARGET  # Try anonymous
```

### Port 22 - SSH
```bash
nmap -sV -sC -p22 TARGET
ssh-audit TARGET
hydra -l user -P wordlist.txt ssh://TARGET
```

### Port 25 - SMTP
```bash
nmap -sV --script smtp-* -p25 TARGET
# Check open relay
# User enumeration: VRFY, EXPN
```

### Port 53 - DNS
```bash
dig axfr @TARGET domain.com  # Zone transfer
dnsrecon -d domain.com
```

### Port 80/443 - HTTP/HTTPS
```bash
nmap -sV --script http-* -p80,443 TARGET
nikto -h TARGET
gobuster dir -u http://TARGET -w wordlist.txt
```

### Port 139/445 - SMB
```bash
nmap -sV --script smb-* -p139,445 TARGET
smbclient -L //TARGET -N
enum4linux -a TARGET
crackmapexec smb TARGET
```

### Port 389/636 - LDAP
```bash
nmap -sV --script ldap-* -p389 TARGET
ldapsearch -x -H ldap://TARGET -b "DC=domain,DC=com"
```

### Port 1433 - MSSQL
```bash
nmap -sV --script ms-sql-* -p1433 TARGET
sqsh -S TARGET -U sa
```

### Port 3306 - MySQL
```bash
nmap -sV --script mysql-* -p3306 TARGET
mysql -h TARGET -u root
```

### Port 3389 - RDP
```bash
nmap -sV --script rdp-* -p3389 TARGET
xfreerdp /v:TARGET /u:user
```

### Port 5432 - PostgreSQL
```bash
nmap -sV --script pgsql-* -p5432 TARGET
psql -h TARGET -U postgres
```
