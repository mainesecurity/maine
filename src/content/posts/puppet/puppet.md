---
title: puppet
published: 2026-01-08
description: 'Certificate'
image: './puppet.png'
tags: [Certificate]
category: ''
draft: false 
lang: ''
---
*Note: I will provide the unredacted copy upon request*

Puppet Pro Lab presents an opportunity to practice working with C2 as a red teamer.


### Scenario
You are tasked with performing a red team engagement on Puppet Inc. The company does not allow data leaving the internal network, so a c2 server has been set up internally and an employee executed a payload in order to simulate a successful social engineering attack.

Puppet is a small active directory scenario in which you start with an already running Sliver C2 beacon on an internal system. It is designed to practice operating through a C2 framework in a modern, challenging hybrid environment.

Puppet is designed for penetration testers and red teamers in search of a quick and challenging lab that has c2 infrastructure already set up in order to practice c2 operations.

This **Red Team Operator I** lab will expose players to:

- Enumeration
- Active Directory enumeration and attacks
- Exploiting DevOps infrastructure
- Lateral movement
- Local privilege escalation
- Situational awareness
- C2 Operations

### Review
The main goal in this lab is introduce us to C2 red teaming operations, in this case, the C2 of choice by the Puppet Inc is Sliver C2.

At first, as soon as I got the beacon after connecting to C2 server, I instantly fell back in my old habit by just popping a shell on the compromised server every time I needed to enumerate the target host. Then I realized, I should not do that though I can, rather,the goal is to only rely on Sliver C2 features to carry out this operation.

Although I was already familiar with Sliver C2, yet just relying on Sliver C2 features and built-in BOFs was still a learning curve. That was a great experience.