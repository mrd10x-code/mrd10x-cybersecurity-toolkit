# 🔒 MR.D10X Cybersecurity Toolkit

Advanced Linux-based cybersecurity assessment toolkit for educational purposes and authorized penetration testing.

## 🚀 Quick Install
```bash
# One-command install
curl -sSL https://raw.githubusercontent.com/mrd10x-code/mrd10x-cybersecurity-toolkit/main/install.sh | bash

# Manual install
git clone https://github.com/mrd10x-code/mrd10x-cybersecurity-toolkit.git
cd mrd10x-toolkit
pip3 install -r requirements.txt
python3 mrd10x.py

✨ Features

🔍 Network Assessment

· Port Scanner: Comprehensive TCP port scanning with service detection
· Network Discovery: Host discovery and network mapping
· Ping Sweep: ICMP-based host availability checking
· Traceroute: Network path analysis

🌐 Web Security

· DNS Enumeration: Domain information gathering
· Subdomain Discovery: Automated subdomain finding
· Security Headers Analysis: HTTP security headers assessment
· WHOIS Lookup: Domain registration information

🔐 Security Tools

· Password Analyzer: Strength assessment and entropy calculation
· Hash Generator: Multiple algorithm support (MD5, SHA1, SHA256, SHA512)
· File Integrity Checker: Checksum verification and file hashing
· System Security Audit: Basic security configuration checking

💻 System Information

· Hardware Inventory: System specifications gathering
· Network Configuration: Interface and routing information
· User Account Audit: Local user enumeration
· Service Detection: Running services identification

🛠️ Usage

Basic Usage

```bash
python3 mrd10x.py
```

Command Line Options

```bash
# Scan specific target
python3 mrd10x.py --target example.com

# Custom port range
python3 mrd10x.py --ports 1-1000

# Silent mode (output to file)
python3 mrd10x.py --silent --output scan_results.txt
```
