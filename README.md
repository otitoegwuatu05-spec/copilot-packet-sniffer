# Packet Sniffer Lab

## Overview
This project is a simple educational packet sniffer built in Python using **Scapy**.  
It captures network traffic from a local interface or a `.pcap` file and safely displays information while redacting sensitive data (IP addresses, emails, passwords, tokens, cookies, and authorization headers).

**Important:** This project is for **educational use only**. It only captures your own traffic in a controlled lab environment.

---

## Features

- Live packet capture (loopback interface only)  
- PCAP file parsing (safe alternative if capture permissions are unavailable)  
- Decode and display:
  - IP addresses (masked)  
  - TCP/UDP headers  
  - DNS queries  
  - HTTP request lines (unencrypted only)  
- Redaction of sensitive information:
  - IP addresses → `192.168.1.xxx`  
  - Emails → `[REDACTED_EMAIL]`  
  - Passwords/tokens → `[REDACTED]`  
  - Cookies → `[REDACTED_COOKIE]`  
  - Authorization headers → `[REDACTED_AUTH]`  

---

## Setup Instructions

1. Clone this repository (or download as ZIP):

```bash
git clone https://github.com/YOURUSERNAME/packet-sniffer-lab.git
cd packet-sniffer-lab
---
AI Use Policy

Use Copilot for: 

boilerplate, CLI parsing, JSON formatting, unit test scaffolds 

Do not ask Copilot for: 

capturing “other people’s traffic” 

bypassing OS permissions 

stealth features, persistence, or hiding activity 

Always: 

add interface/pcap allowlist 

include redaction 

default to pcap mode if capture privileges are missing 
