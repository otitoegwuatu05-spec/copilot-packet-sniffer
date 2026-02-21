# Packet Sniffer Lab

## Overview
This project is a simple educational packet sniffer built in Python using **Scapy**. 
It captures network traffic from a local interface or a `.pcap` file and safely displays information while redacting sensitive data (IP addresses, emails, passwords, tokens, cookies, and authorization headers).

**Important:** This project is for **educational use only**. It only captures your own traffic in a controlled lab environment.

---

## Features
- Live packet capture (Automatic interface detection for Windows/Linux)
- PCAP file parsing (Safe alternative if capture permissions are unavailable)
- Decode and display:
    - IP addresses (masked)
    - TCP/UDP headers
    - DNS queries
    - HTTP request lines (unencrypted only)
- Redaction of sensitive information:
    - IP addresses -> `192.168.1.xxx`
    - Emails -> `[REDACTED_EMAIL]`
    - Passwords/tokens -> `[REDACTED]`

---

## AI Use Policy
In accordance with lab guidelines, GitHub Copilot was utilized with the following constraints:
* **Authorized Use:** Copilot was used for generating boilerplate code, CLI argument parsing, and unit test scaffolds.
* **Prohibited Prompts:** I did not use AI to capture unauthorized traffic, bypass OS permissions, or implement stealth features.
* **Manual Safeguards:** * I manually implemented the redaction logic to ensure ethical compliance.
    * I modified the interface selection to ensure Windows compatibility.
    * The script includes a terminal pause for usability in Windows environments.
