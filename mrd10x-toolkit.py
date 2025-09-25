#!/usr/bin/env python3
"""
MR.D10X Cybersecurity Toolkit
Linux-based multi-tool for security assessment
Created for educational purposes only!
"""

import os
import sys
import time
import argparse
import socket
import threading
import subprocess
import hashlib
import requests
import random
import re
import json
from datetime import datetime

class MRD10XToolkit:
    def __init__(self):
        self.version = "v4.0"
        self.author = "MR.D10X Security Team"
        self.tools = {
            '1': 'Network Scanner',
            '2': 'Port Scanner', 
            '3': 'DNS Lookup',
            '4': 'Whois Checker',
            '5': 'Subdomain Finder',
            '6': 'Password Analyzer',
            '7': 'Hash Generator',
            '8': 'File Integrity Checker',
            '9': 'Website Security Scanner',
            '10': 'System Information'
        }
        
    def show_banner(self):
        """Show MR.D10X ASCII Art Banner"""
        banner = r"""
███╗   ███╗██████╗    ██████╗  ██╗ ██████╗ ██╗  ██╗
████╗ ████║██╔══██╗   ██╔══██╗███║██╔═████╗╚██╗██╔╝
██╔████╔██║██████╔╝   ██║  ██║╚██║██║██╔██║ ╚███╔╝ 
██║╚██╔╝██║██╔══██╗   ██║  ██║ ██║████╔╝██║ ██╔██╗ 
██║ ╚═╝ ██║██║  ██║██╗██████╔╝ ██║╚██████╔╝██╔╝ ██╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═════╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
                                                    
░█▀▀░█▀▀░█▀▀░▀█▀░█▀█░█▀█░█░░░█░█░▀█▀░▀█▀
░▀▀█░█▀▀░█░░░░█░░█░█░█░█░█░░░█▀▄░░█░░░█░
░▀▀▀░▀▀▀░▀▀▀░░▀░░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░
"""
        print(f"\033[1;32m{banner}\033[0m")
        print(f"🚀 MR.D10X Cybersecurity Toolkit {self.version}")
        print(f"👤 Created by: {self.author}")
        print("⚠️  FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!")
        print("="*60)
    
    def show_menu(self):
        """Show main menu"""
        print("\n🛠️  **MR.D10X TOOLKIT MENU**")
        print("="*45)
        
        for key, value in self.tools.items():
            print(f"🔸 [{key}] {value}")
        
        print("\n🔸 [99] About MR.D10X")
        print("🔸 [0] Exit Toolkit")
        print("="*45)
    
    def network_scanner(self, target):
        """Network Scanner dengan ping sweep"""
        print(f"\n🔍 Network Scanning: {target}")
        print("-" * 50)
        
        try:
            # Single target scan
            if not '/' in target:
                ip = socket.gethostbyname(target)
                print(f"📍 Target IP: {ip}")
                
                # Ping test
                response = os.system(f"ping -c 3 -W 2 {ip} > /dev/null 2>&1")
                if response == 0:
                    print("🟢 Status: ONLINE")
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        print(f"🏷️  Hostname: {hostname}")
                    except:
                        print("🏷️  Hostname: Not resolvable")
                    
                    # Traceroute
                    print(f"\n🛣️  Traceroute (first 5 hops):")
                    os.system(f"traceroute -m 5 -w 1 {ip} 2>/dev/null | head -10")
                else:
                    print("🔴 Status: OFFLINE")
            
            # Network range scan
            else:
                print(f"🌐 Scanning network range: {target}")
                print("Scanning... This may take a while...")
                os.system(f"nmap -sn {target} 2>/dev/null | grep -E 'Nmap scan|MAC Address' | head -20")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def port_scanner(self, target, ports="1-1000"):
        """Advanced Port Scanner dengan multi-threading"""
        print(f"\n🎯 Port Scanning: {target}")
        print("-" * 50)
        
        open_ports = []
        start_time = time.time()
        
        def scan_port(ip, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self.get_service_name(port)
                        open_ports.append((port, service))
            except:
                pass
        
        try:
            target_ip = socket.gethostbyname(target)
            start_port, end_port = map(int, ports.split('-'))
            
            print(f"📍 Target IP: {target_ip}")
            print(f"🎯 Port Range: {start_port}-{end_port}")
            print(f"⏰ Starting scan at: {datetime.now().strftime('%H:%M:%S')}")
            print("\nScanning...\n")
            
            # Scan dengan progress indicator
            total_ports = end_port - start_port + 1
            current = 0
            
            threads = []
            for port in range(start_port, end_port + 1):
                thread = threading.Thread(target=scan_port, args=(target_ip, port))
                threads.append(thread)
                thread.start()
                
                current += 1
                if current % 100 == 0:
                    progress = (current / total_ports) * 100
                    print(f"📊 Progress: {progress:.1f}% ({current}/{total_ports} ports)")
            
            # Wait for all threads
            for thread in threads:
                thread.join()
            
            scan_time = time.time() - start_time
            
            # Display results
            print(f"\n{'='*50}")
            print("📊 SCAN RESULTS")
            print(f"{'='*50}")
            print(f"Target: {target} ({target_ip})")
            print(f"Open ports: {len(open_ports)}")
            print(f"Scan duration: {scan_time:.2f} seconds")
            print(f"{'='*50}")
            
            if open_ports:
                print("\n🔓 OPEN PORTS:")
                for port, service in sorted(open_ports):
                    risk = self.assess_port_risk(port)
                    print(f"   Port {port}/TCP - {service} - {risk}")
            else:
                print("✅ No open ports found")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 3389: "RDP", 1433: "MSSQL",
            3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"
        }
        return services.get(port, "Unknown")
    
    def assess_port_risk(self, port):
        """Assess security risk of open port"""
        high_risk = [21, 23, 135, 139, 445, 3389]  # FTP, Telnet, SMB, RDP
        medium_risk = [22, 25, 53, 110, 143]  # SSH, SMTP, DNS, POP3, IMAP
        
        if port in high_risk:
            return "🔴 HIGH RISK"
        elif port in medium_risk:
            return "🟡 MEDIUM RISK"
        else:
            return "🟢 LOW RISK"
    
    def dns_lookup(self, domain):
        """Comprehensive DNS Lookup"""
        print(f"\n🌐 DNS Lookup: {domain}")
        print("-" * 50)
        
        try:
            # A records
            print("📍 A Records:")
            try:
                a_records = socket.getaddrinfo(domain, None)
                for record in a_records[:5]:
                    print(f"  {record[4][0]}")
            except:
                print("  Not found")
            
            # MX records
            print("\n📧 MX Records:")
            try:
                mx_records = socket.getaddrinfo(f"mail.{domain}", None)
                for record in mx_records[:3]:
                    print(f"  {record[4][0]}")
            except:
                print("  Not found")
            
            # NS records menggunakan nslookup
            print("\n🌍 Name Servers:")
            os.system(f"nslookup -type=NS {domain} 2>/dev/null | grep 'nameserver' | head -5")
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def whois_checker(self, domain):
        """WHOIS Information Lookup"""
        print(f"\n📋 WHOIS Lookup: {domain}")
        print("-" * 50)
        
        try:
            # Gunakan whois command
            result = os.popen(f"whois {domain} 2>/dev/null").read()
            
            # Filter informasi penting
            important_info = [
                "Registrar:",
                "Creation Date:",
                "Updated Date:",
                "Expiration Date:",
                "Name Server:",
                "Status:"
            ]
            
            lines = result.split('\n')
            found_info = []
            
            for line in lines:
                for info in important_info:
                    if info in line:
                        found_info.append(line.strip())
                        break
            
            if found_info:
                for info in found_info[:10]:  # Batasi output
                    print(f"  {info}")
            else:
                print("  WHOIS information not available")
                print("  Try: pip install python-whois")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def subdomain_finder(self, domain):
        """Subdomain Discovery Tool"""
        print(f"\n🔎 Subdomain Finder: {domain}")
        print("-" * 50)
        
        # Common subdomains list
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'dev',
            'test', 'staging', 'admin', 'forum', 'shop', 'store', 'app', 'apps', 'cdn',
            'static', 'media', 'img', 'images', 'js', 'css', 'files', 'download', 'docs'
        ]
        
        found_subs = []
        
        print("Scanning common subdomains...\n")
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                found_subs.append((full_domain, ip))
                print(f"✅ Found: {full_domain} -> {ip}")
            except:
                pass
        
        threads = []
        for sub in common_subs:
            thread = threading.Thread(target=check_subdomain, args=(sub,))
            threads.append(thread)
            thread.start()
            time.sleep(0.05)  # Rate limiting
        
        for thread in threads:
            thread.join()
        
        print(f"\n📊 Found {len(found_subs)} subdomains")
    
    def password_analyzer(self, password):
        """Advanced Password Strength Analyzer"""
        print(f"\n🔐 Password Strength Analysis")
        print("-" * 50)
        
        score = 0
        max_score = 10
        feedback = []
        
        # Length check
        length = len(password)
        if length >= 16:
            score += 3
            feedback.append("✅ Length: Excellent (16+ characters)")
        elif length >= 12:
            score += 2
            feedback.append("✅ Length: Good (12+ characters)")
        elif length >= 8:
            score += 1
            feedback.append("⚠️  Length: Acceptable (8+ characters)")
        else:
            feedback.append("❌ Length: Too short (min 8 characters)")
        
        # Complexity checks
        checks = [
            (r'[A-Z]', 'Uppercase letters', 1),
            (r'[a-z]', 'Lowercase letters', 1),
            (r'[0-9]', 'Numbers', 1),
            (r'[^A-Za-z0-9]', 'Special characters', 2),
            (r'.{3,}', 'No repeated patterns', 1)  # Basic pattern check
        ]
        
        for pattern, description, points in checks:
            if re.search(pattern, password):
                score += points
                feedback.append(f"✅ {description}: Yes")
            else:
                feedback.append(f"❌ {description}: No")
        
        # Common password check
        common_passwords = ['password', '123456', 'password123', 'admin', 'qwerty']
        if password.lower() in common_passwords:
            score = 0
            feedback.append("❌ CRITICAL: Very common password!")
        
        # Entropy calculation (basic)
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^A-Za-z0-9]', password): charset_size += 32
        
        if charset_size > 0:
            entropy = length * (charset_size ** 0.5)
            feedback.append(f"📊 Estimated entropy: {entropy:.1f}")
        
        # Display results
        strength_percent = (score / max_score) * 100
        
        print(f"Password: {'*' * len(password)}")
        print(f"Length: {length} characters")
        print(f"\nStrength Score: {score}/{max_score} ({strength_percent:.1f}%)")
        
        if strength_percent >= 80:
            print("💪 Strength: EXCELLENT")
        elif strength_percent >= 60:
            print("⚠️  Strength: GOOD")
        elif strength_percent >= 40:
            print("🔴 Strength: WEAK")
        else:
            print("💀 Strength: VERY WEAK")
        
        print("\nDetailed Analysis:")
        for item in feedback:
            print(f"  {item}")
        
        # Recommendations
        print(f"\n💡 Recommendations:")
        if strength_percent >= 80:
            print("  ✅ Your password is strong! Use a password manager to keep it safe.")
        else:
            print("  🔧 Use a mix of uppercase, lowercase, numbers, and symbols")
            print("  📏 Make it at least 12 characters long")
            print("  🚫 Avoid common words and patterns")
            print("  🔄 Use unique passwords for different accounts")
    
    def hash_generator(self, text):
        """Multi-algorithm Hash Generator"""
        print(f"\n🔑 Hash Generator")
        print("-" * 50)
        
        print(f"Input: {text}")
        print(f"Length: {len(text)} characters\n")
        
        # Various hash algorithms
        algorithms = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512,
            'BLAKE2b': hashlib.blake2b
        }
        
        for name, algorithm in algorithms.items():
            try:
                hash_obj = algorithm(text.encode())
                print(f"{name:>8}: {hash_obj.hexdigest()}")
            except:
                print(f"{name:>8}: Not available")
    
    def file_integrity_checker(self, filename):
        """File Integrity Checker dengan berbagai hash"""
        print(f"\n📁 File Integrity Check: {filename}")
        print("-" * 50)
        
        try:
            if not os.path.exists(filename):
                print("❌ File not found!")
                return
            
            file_size = os.path.getsize(filename)
            print(f"📏 File Size: {file_size} bytes")
            
            # Read file in chunks untuk file besar
            print("\nCalculating hashes...")
            
            hashers = {
                'MD5': hashlib.md5(),
                'SHA1': hashlib.sha1(),
                'SHA256': hashlib.sha256(),
                'SHA512': hashlib.sha512()
            }
            
            with open(filename, 'rb') as f:
                while chunk := f.read(8192):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            
            print("\n🔐 File Hashes:")
            for name, hasher in hashers.items():
                print(f"{name:>8}: {hasher.hexdigest()}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def website_security_scanner(self, url):
        """Website Security Headers Checker"""
        print(f"\n🌐 Website Security Scan: {url}")
        print("-" * 50)
        
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'Forces HTTPS',
                'Content-Security-Policy': 'Prevents XSS',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'X-Frame-Options': 'Prevents clickjacking',
                'X-XSS-Protection': 'XSS protection',
                'Referrer-Policy': 'Controls referrer info'
            }
            
            found = 0
            total = len(security_headers)
            
            print("🔍 Checking security headers...\n")
            
            for header, description in security_headers.items():
                if header in headers:
                    print(f"✅ {header}: {headers[header]}")
                    print(f"   📝 {description}")
                    found += 1
                else:
                    print(f"❌ {header}: MISSING")
                    print(f"   📝 {description}")
                print()
            
            score = (found / total) * 100
            print(f"📊 Security Score: {score:.1f}% ({found}/{total} headers)")
            
            if score >= 80:
                print("🟢 Security: EXCELLENT")
            elif score >= 60:
                print("🟡 Security: GOOD")
            elif score >= 40:
                print("🟠 Security: FAIR")
            else:
                print("🔴 Security: POOR")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def system_information(self):
        """Comprehensive System Information"""
        print(f"\n💻 System Information")
        print("-" * 50)
        
        try:
            # OS Info
            print("🖥️  OS Information:")
            print(f"  System: {os.uname().sysname}")
            print(f"  Hostname: {os.uname().nodename}")
            print(f"  Release: {os.uname().release}")
            print(f"  Version: {os.uname().version}")
            
            # Network Info
            print(f"\n🌐 Network Information:")
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"  Local IP: {local_ip}")
            
            # Public IP (try to get)
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=5).text
                print(f"  Public IP: {public_ip}")
            except:
                print("  Public IP: Unable to determine")
            
            # User Info
            print(f"\n👤 User Information:")
            print(f"  Username: {os.getlogin()}")
            print(f"  Home Directory: {os.path.expanduser('~')}")
            
            # Security Info
            print(f"\n🔒 Security Status:")
            # Check if running as root
            if os.geteuid() == 0:
                print("  ⚠️  Running as ROOT - Be careful!")
            else:
                print("  ✅ Running as regular user")
            
            # Check sudo privileges
            result = os.system("sudo -n true 2>/dev/null")
            if result == 0:
                print("  ✅ Sudo privileges available")
            else:
                print("  ❌ No sudo privileges")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def about(self):
        """About MR.D10X"""
        print(f"\n" + "="*60)
        print("🤖 ABOUT MR.D10X CYBERSECURITY TOOLKIT")
        print("="*60)
        print(f"Version: {self.version}")
        print(f"Author: {self.author}")
        print(f"License: Educational Use Only")
        
        print(f"\n📌 FEATURES:")
        for key, tool in self.tools.items():
            print(f"  🔸 {tool}")
        
        print(f"\n⚡ PERFORMANCE:")
        print("  Multi-threaded scanning")
        print("  Real-time progress indicators")
        print("  Comprehensive security assessments")
        
        print(f"\n⚠️  DISCLAIMER:")
        print("  This toolkit is for EDUCATIONAL purposes only!")
        print("  Use only on systems you own or have permission to test.")
        print("  The author is not responsible for misuse.")
        
        print(f"\n🔒 Stay Ethical, Stay Secure!")
        print("="*60)

def main():
    toolkit = MRD10XToolkit()
    
    # Clear screen and show banner
    os.system('clear' if os.name == 'posix' else 'cls')
    toolkit.show_banner()
    
    while True:
        toolkit.show_menu()
        
        try:
            choice = input("\n🎯 Select tool [0-10] or [99]: ").strip()
            
            if choice == '0':
                print("\n👋 Thank you for using MR.D10X Toolkit!")
                print("🔒 Stay secure and ethical!\n")
                break
                
            elif choice == '1':
                target = input("Enter target (IP/domain/network): ")
                toolkit.network_scanner(target)
                
            elif choice == '2':
                target = input("Enter target (IP/domain): ")
                ports = input("Port range [default: 1-1000]: ") or "1-1000"
                toolkit.port_scanner(target, ports)
                
            elif choice == '3':
                domain = input("Enter domain: ")
                toolkit.dns_lookup(domain)
                
            elif choice == '4':
                domain = input("Enter domain: ")
                toolkit.whois_checker(domain)
                
            elif choice == '5':
                domain = input("Enter domain: ")
                toolkit.subdomain_finder(domain)
                
            elif choice == '6':
                password = input("Enter password to analyze: ")
                toolkit.password_analyzer(password)
                
            elif choice == '7':
                text = input("Enter text to hash: ")
                toolkit.hash_generator(text)
                
            elif choice == '8':
                filename = input("Enter filename: ")
                toolkit.file_integrity_checker(filename)
                
            elif choice == '9':
                url = input("Enter website URL: ")
                toolkit.website_security_scanner(url)
                
            elif choice == '10':
                toolkit.system_info()
                
            elif choice == '99':
                toolkit.about()
                
            else:
                print("❌ Invalid choice! Please select 0-10 or 99")
            
            input("\nPress Enter to continue...")
            os.system('clear' if os.name == 'posix' else 'cls')
            toolkit.show_banner()
            
        except KeyboardInterrupt:
            print("\n\n👋 Tool terminated by user. Stay secure!")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    # Check if running on Linux
    if os.name != 'posix':
        print("⚠️  This toolkit is optimized for Linux systems!")
        input("Press Enter to continue anyway...")
    
    main()