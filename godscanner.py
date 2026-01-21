#!/usr/bin/env python3
"""
GodScanner - CloudFlare Proxy Scanner
Find IP addresses that proxy traffic through CloudFlare CDN
but are NOT official CloudFlare IPs.

These IPs can be used as relay for VLESS/VMess WS TLS fronting.
"""

import ssl
import socket
import http.client
import threading
import ipaddress
import json
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional, List

__version__ = "1.0.0"
__author__ = "GodScanner Team"

# ============== COLORS ==============
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    WHITE = '\033[97m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def colored(text: str, color: str) -> str:
    return f"{color}{text}{Colors.END}"

# ============== OFFICIAL CLOUDFLARE IPs (EXCLUDED) ==============
CLOUDFLARE_IPV4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CF_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV4]

def is_cloudflare_ip(ip: str) -> bool:
    """Check if IP is official CloudFlare IP"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in CF_NETWORKS:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return False

# ============== VPS PROVIDERS ==============
VPS_PROVIDERS = {
    "1": {
        "name": "Contabo",
        "ranges": [
            "144.91.64.0/18",
            "167.86.64.0/18",
            "62.171.128.0/17",
            "161.97.64.0/18",
            "207.180.192.0/18",
            "45.136.28.0/22",
            "45.94.208.0/22",
        ]
    },
    "2": {
        "name": "Hetzner",
        "ranges": [
            "95.216.0.0/16",
            "135.181.0.0/16",
            "65.108.0.0/16",
            "65.109.0.0/16",
            "167.235.0.0/16",
            "168.119.0.0/16",
        ]
    },
    "3": {
        "name": "OVH",
        "ranges": [
            "51.68.0.0/16",
            "51.75.0.0/16",
            "51.77.0.0/16",
            "51.79.0.0/16",
            "51.81.0.0/16",
            "51.83.0.0/16",
            "51.89.0.0/16",
            "51.91.0.0/16",
            "54.36.0.0/16",
            "54.37.0.0/16",
            "54.38.0.0/16",
        ]
    },
    "4": {
        "name": "DigitalOcean",
        "ranges": [
            "134.209.0.0/16",
            "157.245.0.0/16",
            "159.65.0.0/16",
            "159.89.0.0/16",
            "161.35.0.0/16",
            "164.90.0.0/16",
            "164.92.0.0/16",
            "165.22.0.0/16",
            "165.227.0.0/16",
            "167.71.0.0/16",
            "167.99.0.0/16",
            "178.62.0.0/16",
            "178.128.0.0/16",
            "188.166.0.0/16",
            "206.189.0.0/16",
        ]
    },
    "5": {
        "name": "Vultr",
        "ranges": [
            "45.32.0.0/16",
            "45.63.0.0/16",
            "45.76.0.0/16",
            "45.77.0.0/16",
            "66.42.0.0/16",
            "78.141.192.0/18",
            "95.179.128.0/17",
            "104.156.224.0/19",
            "108.61.0.0/16",
            "136.244.64.0/18",
            "140.82.0.0/16",
            "149.28.0.0/16",
            "155.138.128.0/17",
            "207.148.0.0/17",
            "209.250.224.0/19",
            "216.128.128.0/17",
        ]
    },
    "6": {
        "name": "Linode/Akamai",
        "ranges": [
            "45.33.0.0/17",
            "45.56.64.0/18",
            "45.79.0.0/16",
            "50.116.0.0/18",
            "69.164.192.0/18",
            "96.126.96.0/19",
            "139.144.0.0/16",
            "139.162.0.0/16",
            "143.42.0.0/16",
            "172.104.0.0/15",
            "178.79.128.0/17",
        ]
    },
    "7": {
        "name": "Scaleway",
        "ranges": [
            "51.15.0.0/16",
            "51.158.0.0/15",
            "62.210.0.0/16",
            "163.172.0.0/16",
            "195.154.0.0/16",
            "212.47.224.0/19",
        ]
    },
    "8": {
        "name": "Oracle Cloud",
        "ranges": [
            "129.146.0.0/16",
            "129.151.0.0/16",
            "130.61.0.0/16",
            "132.145.0.0/16",
            "140.238.0.0/16",
            "144.24.0.0/16",
            "150.136.0.0/16",
            "152.67.0.0/16",
            "152.70.0.0/16",
            "158.101.0.0/16",
            "168.138.0.0/16",
            "193.122.0.0/16",
            "193.123.0.0/16",
        ]
    },
    "9": {
        "name": "Google Cloud",
        "ranges": [
            "34.64.0.0/11",
            "35.184.0.0/13",
            "35.192.0.0/12",
            "35.208.0.0/13",
            "35.216.0.0/15",
        ]
    },
    "10": {
        "name": "Azure",
        "ranges": [
            "13.64.0.0/11",
            "20.33.0.0/16",
            "20.34.0.0/15",
            "20.36.0.0/14",
            "20.40.0.0/13",
            "20.48.0.0/12",
            "40.64.0.0/10",
            "51.104.0.0/15",
            "52.224.0.0/11",
        ]
    },
    "11": {
        "name": "AWS Lightsail",
        "ranges": [
            "3.8.0.0/14",
            "13.48.0.0/15",
            "15.160.0.0/16",
            "18.130.0.0/16",
            "18.185.0.0/16",
            "35.156.0.0/14",
            "52.28.0.0/16",
            "52.56.0.0/16",
            "52.57.0.0/16",
        ]
    },
    "12": {
        "name": "HostHatch",
        "ranges": [
            "23.160.192.0/24",
            "103.114.160.0/22",
            "185.213.24.0/22",
            "193.148.248.0/22",
        ]
    },
}

@dataclass
class ScanResult:
    ip: str
    port: int
    is_cf_proxy: bool
    cf_ray: Optional[str] = None
    server: Optional[str] = None
    status_code: Optional[int] = None
    cert_cn: Optional[str] = None
    response_time_ms: Optional[int] = None
    error: Optional[str] = None


class Scanner:
    def __init__(self, threads: int = 200, timeout: float = 5.0, port: int = 443):
        self.threads = threads
        self.timeout = timeout
        self.port = port
        self.results: List[ScanResult] = []
        self.scanned = 0
        self.found = 0
        self.total = 0
        self.lock = threading.Lock()
        self.stop_flag = False

    def check_ip(self, ip: str) -> Optional[ScanResult]:
        """Check single IP for CF proxy"""
        if self.stop_flag:
            return None
            
        if is_cloudflare_ip(ip):
            return None

        start_time = time.time()
        result = ScanResult(ip=ip, port=self.port, is_cf_proxy=False)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                with ctx.wrap_socket(sock, server_hostname="www.cloudflare.com") as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        result.cert_cn = subject.get('commonName', '')

            conn = http.client.HTTPSConnection(ip, self.port, timeout=self.timeout, context=ctx)
            conn.request("GET", "/", headers={"Host": "check.example.com", "User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()
            result.status_code = resp.status
            
            headers = {k.lower(): v for k, v in resp.getheaders()}
            result.cf_ray = headers.get('cf-ray')
            result.server = headers.get('server', '')
            conn.close()

            is_cf = False
            if result.cf_ray:
                is_cf = True
            if 'cloudflare' in result.server.lower():
                is_cf = True
            if result.cert_cn and 'cloudflare' in result.cert_cn.lower():
                is_cf = True

            result.is_cf_proxy = is_cf
            result.response_time_ms = int((time.time() - start_time) * 1000)

            return result if is_cf else None

        except Exception as e:
            result.error = str(e)[:50]
            return None

    def scan(self, ips: List[str], callback=None):
        """Scan list of IPs"""
        self.total = len(ips)
        self.scanned = 0
        self.found = 0
        self.results = []
        self.stop_flag = False

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_ip, ip): ip for ip in ips}

            for future in as_completed(futures):
                if self.stop_flag:
                    break
                    
                with self.lock:
                    self.scanned += 1

                try:
                    result = future.result()
                    if result and result.is_cf_proxy:
                        with self.lock:
                            self.found += 1
                            self.results.append(result)
                        if callback:
                            callback(result)
                except Exception:
                    pass

        return self.results

    def stop(self):
        self.stop_flag = True


class GodScanner:
    def __init__(self):
        self.scanner = Scanner()
        self.results: List[ScanResult] = []
        self.settings = {
            'threads': 200,
            'timeout': 5.0,
            'port': 443,
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
   ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
  ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██║  ███╗██║   ██║██║  ██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║   ██║██║   ██║██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ╚██████╔╝╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
   ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Colors.END}
{Colors.WHITE}  CloudFlare Proxy Scanner v{__version__}{Colors.END}
{Colors.DIM}  Find non-official IPs that relay traffic through CloudFlare CDN{Colors.END}
{Colors.DIM}  ════════════════════════════════════════════════════════════════════{Colors.END}
"""
        print(banner)

    def print_main_menu(self):
        found_count = len(self.results)
        print(f"""
{Colors.BOLD}╔════════════════════════════════════════════════════════════════════╗
║                         MAIN MENU                                  ║
╠════════════════════════════════════════════════════════════════════╣{Colors.END}
║                                                                    ║
║  {Colors.GREEN}[1]{Colors.END}  🔍  Scan by Provider                                        ║
║  {Colors.GREEN}[2]{Colors.END}  🎯  Scan Custom CIDR Range                                  ║
║  {Colors.GREEN}[3]{Colors.END}  📝  Check Single IP                                         ║
║  {Colors.GREEN}[4]{Colors.END}  📁  Scan from File                                          ║
║  {Colors.GREEN}[5]{Colors.END}  🌐  Scan ALL Providers {Colors.RED}(takes long time){Colors.END}                   ║
║                                                                    ║
║  {Colors.YELLOW}[6]{Colors.END}  ⚙️   Settings                                               ║
║  {Colors.YELLOW}[7]{Colors.END}  📊  View Results {Colors.CYAN}({found_count} found){Colors.END}                                 ║
║  {Colors.YELLOW}[8]{Colors.END}  💾  Save Results                                            ║
║  {Colors.YELLOW}[9]{Colors.END}  📋  Generate VLESS Configs                                  ║
║                                                                    ║
║  {Colors.RED}[0]{Colors.END}  ❌  Exit                                                     ║
║                                                                    ║
{Colors.BOLD}╚════════════════════════════════════════════════════════════════════╝{Colors.END}
""")

    def print_provider_menu(self):
        print(f"""
{Colors.BOLD}╔════════════════════════════════════════════════════════════════════╗
║                      SELECT PROVIDER                               ║
╠════════════════════════════════════════════════════════════════════╣{Colors.END}""")
        
        for key, provider in VPS_PROVIDERS.items():
            total_ips = sum(ipaddress.ip_network(r, strict=False).num_addresses for r in provider['ranges'])
            name = provider['name']
            print(f"║  {Colors.GREEN}[{key:>2}]{Colors.END}  {name:<22} {Colors.DIM}(~{total_ips:>12,} IPs){Colors.END}           ║")
        
        print(f"""║                                                                    ║
║  {Colors.RED}[0]{Colors.END}   ← Back                                                      ║
{Colors.BOLD}╚════════════════════════════════════════════════════════════════════╝{Colors.END}
""")

    def print_settings_menu(self):
        print(f"""
{Colors.BOLD}╔════════════════════════════════════════════════════════════════════╗
║                         SETTINGS                                   ║
╠════════════════════════════════════════════════════════════════════╣{Colors.END}
║                                                                    ║
║  {Colors.GREEN}[1]{Colors.END}  Threads:      {Colors.CYAN}{self.settings['threads']:>6}{Colors.END}                                    ║
║  {Colors.GREEN}[2]{Colors.END}  Timeout:      {Colors.CYAN}{self.settings['timeout']:>6.1f}s{Colors.END}                                   ║
║  {Colors.GREEN}[3]{Colors.END}  Port:         {Colors.CYAN}{self.settings['port']:>6}{Colors.END}                                    ║
║                                                                    ║
║  {Colors.RED}[0]{Colors.END}  ← Back                                                      ║
{Colors.BOLD}╚════════════════════════════════════════════════════════════════════╝{Colors.END}
""")

    def print_subnet_menu(self, provider_name: str, ranges: List[str]):
        print(f"""
{Colors.BOLD}╔════════════════════════════════════════════════════════════════════╗
║              {provider_name.upper():^24} - SUBNETS                   ║
╠════════════════════════════════════════════════════════════════════╣{Colors.END}""")
        
        for i, cidr in enumerate(ranges, 1):
            network = ipaddress.ip_network(cidr, strict=False)
            print(f"║  {Colors.GREEN}[{i:>2}]{Colors.END}  {cidr:<28} {Colors.DIM}({network.num_addresses:>10,} IPs){Colors.END}    ║")
        
        print(f"""║                                                                    ║
║  {Colors.YELLOW}[A]{Colors.END}   Scan ALL subnets                                          ║
║  {Colors.RED}[0]{Colors.END}   ← Back                                                      ║
{Colors.BOLD}╚════════════════════════════════════════════════════════════════════╝{Colors.END}
""")

    def on_found(self, result: ScanResult):
        """Callback when CF proxy found"""
        print(f"\r{Colors.GREEN}[+] FOUND: {result.ip}:{result.port}{Colors.END} | CF-RAY: {result.cf_ray} | {result.response_time_ms}ms")

    def do_scan(self, ips: List[str], description: str):
        """Execute scan with progress display"""
        print(f"\n{Colors.CYAN}[*] {description}{Colors.END}")
        print(f"{Colors.DIM}[*] Total IPs: {len(ips)} | Threads: {self.settings['threads']} | Timeout: {self.settings['timeout']}s{Colors.END}")
        print(f"{Colors.DIM}[*] Press Ctrl+C to stop scan{Colors.END}\n")
        
        self.scanner = Scanner(
            threads=self.settings['threads'],
            timeout=self.settings['timeout'],
            port=self.settings['port']
        )
        
        start = time.time()
        scan_done = threading.Event()
        
        def scan_thread():
            self.scanner.scan(ips, callback=self.on_found)
            scan_done.set()
        
        t = threading.Thread(target=scan_thread)
        t.start()
        
        try:
            while not scan_done.is_set():
                time.sleep(0.3)
                if self.scanner.total > 0:
                    pct = (self.scanner.scanned / self.scanner.total) * 100
                    bar_len = 30
                    filled = int(bar_len * self.scanner.scanned / self.scanner.total)
                    bar = '█' * filled + '░' * (bar_len - filled)
                    print(f"\r{Colors.DIM}[{bar}] {pct:5.1f}% | {self.scanner.scanned}/{self.scanner.total} | Found: {Colors.GREEN}{self.scanner.found}{Colors.END}   ", end="", flush=True)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Stopping scan...{Colors.END}")
            self.scanner.stop()
        
        t.join()
        
        elapsed = time.time() - start
        self.results.extend(self.scanner.results)
        
        print(f"\n\n{Colors.GREEN}{'═'*60}{Colors.END}")
        print(f"{Colors.GREEN}[✓] Scan completed in {elapsed:.1f}s{Colors.END}")
        print(f"{Colors.GREEN}[✓] Found CF proxies: {self.scanner.found}{Colors.END}")
        print(f"{Colors.GREEN}[✓] Total results: {len(self.results)}{Colors.END}")
        print(f"{Colors.GREEN}{'═'*60}{Colors.END}")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")

    def scan_by_provider(self):
        """Provider selection menu"""
        while True:
            clear_screen()
            self.print_banner()
            self.print_provider_menu()
            
            choice = input(f"{Colors.BOLD}Select provider: {Colors.END}").strip()
            
            if choice == '0':
                return
            
            if choice in VPS_PROVIDERS:
                provider = VPS_PROVIDERS[choice]
                self.scan_provider_subnets(provider['name'], provider['ranges'])

    def scan_provider_subnets(self, provider_name: str, ranges: List[str]):
        """Subnet selection for provider"""
        while True:
            clear_screen()
            self.print_banner()
            self.print_subnet_menu(provider_name, ranges)
            
            choice = input(f"{Colors.BOLD}Select subnet: {Colors.END}").strip().upper()
            
            if choice == '0':
                return
            
            if choice == 'A':
                all_ips = []
                for cidr in ranges:
                    network = ipaddress.ip_network(cidr, strict=False)
                    all_ips.extend([str(ip) for ip in network.hosts()])
                self.do_scan(all_ips, f"Scanning all {provider_name} subnets")
                
            elif choice.isdigit() and 1 <= int(choice) <= len(ranges):
                cidr = ranges[int(choice) - 1]
                network = ipaddress.ip_network(cidr, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                self.do_scan(ips, f"Scanning {cidr}")

    def scan_custom_cidr(self):
        """Custom CIDR input"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Custom CIDR Range ═══{Colors.END}\n")
        print(f"{Colors.DIM}Examples: 144.91.64.0/24, 10.0.0.0/16, 192.168.1.0/24{Colors.END}\n")
        
        cidr = input(f"Enter CIDR: ").strip()
        
        if not cidr:
            return
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            
            print(f"\n{Colors.CYAN}Range: {cidr}{Colors.END}")
            print(f"{Colors.CYAN}Total IPs: {len(ips):,}{Colors.END}")
            
            if len(ips) > 100000:
                print(f"\n{Colors.YELLOW}[!] WARNING: Large range, this will take a while!{Colors.END}")
            
            confirm = input(f"\nStart scan? [Y/n]: ").strip().lower()
            if confirm != 'n':
                self.do_scan(ips, f"Scanning {cidr}")
        except ValueError as e:
            print(f"{Colors.RED}[!] Invalid CIDR: {e}{Colors.END}")
            input(f"\n{Colors.DIM}Press Enter...{Colors.END}")

    def scan_single_ip(self):
        """Check single IP"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Check Single IP ═══{Colors.END}\n")
        ip = input("Enter IP address: ").strip()
        
        if not ip:
            return
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"{Colors.RED}[!] Invalid IP address{Colors.END}")
            input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
            return
        
        print(f"\n{Colors.CYAN}[*] Checking {ip}...{Colors.END}\n")
        
        # Check if official CF
        if is_cloudflare_ip(ip):
            print(f"{Colors.YELLOW}[!] This is an OFFICIAL CloudFlare IP{Colors.END}")
            print(f"{Colors.DIM}Official CF IPs cannot be used as relay{Colors.END}")
            input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[✓] Not official CloudFlare IP{Colors.END}")
        print(f"{Colors.DIM}[*] Testing connection...{Colors.END}\n")
        
        scanner = Scanner(threads=1, timeout=self.settings['timeout'], port=self.settings['port'])
        result = scanner.check_ip(ip)
        
        if result and result.is_cf_proxy:
            print(f"{Colors.GREEN}{'═'*50}{Colors.END}")
            print(f"{Colors.GREEN}[✓] CF PROXY DETECTED!{Colors.END}")
            print(f"{Colors.GREEN}{'═'*50}{Colors.END}")
            print(f"  IP:        {result.ip}")
            print(f"  Port:      {result.port}")
            print(f"  CF-RAY:    {result.cf_ray}")
            print(f"  Server:    {result.server}")
            print(f"  Cert CN:   {result.cert_cn}")
            print(f"  Latency:   {result.response_time_ms}ms")
            print(f"{Colors.GREEN}{'═'*50}{Colors.END}")
            
            save = input(f"\nAdd to results? [Y/n]: ").strip().lower()
            if save != 'n':
                self.results.append(result)
                print(f"{Colors.GREEN}[✓] Added to results{Colors.END}")
        else:
            print(f"{Colors.RED}{'═'*50}{Colors.END}")
            print(f"{Colors.RED}[✗] Not a CF proxy{Colors.END}")
            print(f"{Colors.RED}{'═'*50}{Colors.END}")
            print(f"{Colors.DIM}This IP does not proxy traffic through CloudFlare{Colors.END}")
        
        input(f"\n{Colors.DIM}Press Enter...{Colors.END}")

    def scan_from_file(self):
        """Scan from file"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Scan from File ═══{Colors.END}\n")
        print(f"{Colors.DIM}File should contain one IP per line{Colors.END}\n")
        
        filepath = input("File path: ").strip()
        
        if not filepath:
            return
        
        if not os.path.exists(filepath):
            print(f"{Colors.RED}[!] File not found{Colors.END}")
            input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
            return
        
        with open(filepath) as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"\n{Colors.CYAN}Loaded IPs: {len(ips)}{Colors.END}")
        
        confirm = input(f"\nStart scan? [Y/n]: ").strip().lower()
        if confirm != 'n':
            self.do_scan(ips, f"Scanning from {filepath}")

    def scan_all_providers(self):
        """Scan all providers"""
        clear_screen()
        self.print_banner()
        
        total_ips = 0
        for provider in VPS_PROVIDERS.values():
            for cidr in provider['ranges']:
                network = ipaddress.ip_network(cidr, strict=False)
                total_ips += network.num_addresses
        
        print(f"\n{Colors.BOLD}═══ Scan ALL Providers ═══{Colors.END}\n")
        print(f"{Colors.RED}[!] WARNING: This will take a VERY long time!{Colors.END}")
        print(f"{Colors.CYAN}Total IPs to scan: ~{total_ips:,}{Colors.END}\n")
        
        print("Providers to scan:")
        for provider in VPS_PROVIDERS.values():
            print(f"  • {provider['name']}")
        
        confirm = input(f"\nAre you sure? [y/N]: ").strip().lower()
        if confirm != 'y':
            return
        
        for key, provider in VPS_PROVIDERS.items():
            print(f"\n{Colors.BOLD}{'═'*60}{Colors.END}")
            print(f"{Colors.BOLD}Provider: {provider['name']}{Colors.END}")
            print(f"{Colors.BOLD}{'═'*60}{Colors.END}")
            
            all_ips = []
            for cidr in provider['ranges']:
                network = ipaddress.ip_network(cidr, strict=False)
                all_ips.extend([str(ip) for ip in network.hosts()])
            
            self.do_scan(all_ips, f"Scanning {provider['name']}")

    def show_settings(self):
        """Settings menu"""
        while True:
            clear_screen()
            self.print_banner()
            self.print_settings_menu()
            
            choice = input(f"{Colors.BOLD}Select setting: {Colors.END}").strip()
            
            if choice == '0':
                return
            elif choice == '1':
                try:
                    val = int(input("Number of threads (1-1000): "))
                    if 1 <= val <= 1000:
                        self.settings['threads'] = val
                        print(f"{Colors.GREEN}[✓] Threads set to {val}{Colors.END}")
                    else:
                        print(f"{Colors.RED}[!] Value must be between 1 and 1000{Colors.END}")
                except ValueError:
                    print(f"{Colors.RED}[!] Invalid number{Colors.END}")
                input(f"{Colors.DIM}Press Enter...{Colors.END}")
            elif choice == '2':
                try:
                    val = float(input("Timeout in seconds (1-30): "))
                    if 1 <= val <= 30:
                        self.settings['timeout'] = val
                        print(f"{Colors.GREEN}[✓] Timeout set to {val}s{Colors.END}")
                    else:
                        print(f"{Colors.RED}[!] Value must be between 1 and 30{Colors.END}")
                except ValueError:
                    print(f"{Colors.RED}[!] Invalid number{Colors.END}")
                input(f"{Colors.DIM}Press Enter...{Colors.END}")
            elif choice == '3':
                try:
                    val = int(input("Port (1-65535): "))
                    if 1 <= val <= 65535:
                        self.settings['port'] = val
                        print(f"{Colors.GREEN}[✓] Port set to {val}{Colors.END}")
                    else:
                        print(f"{Colors.RED}[!] Value must be between 1 and 65535{Colors.END}")
                except ValueError:
                    print(f"{Colors.RED}[!] Invalid number{Colors.END}")
                input(f"{Colors.DIM}Press Enter...{Colors.END}")

    def show_results(self):
        """Display results"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Results ({len(self.results)} found) ═══{Colors.END}\n")
        
        if not self.results:
            print(f"{Colors.DIM}No results yet. Run a scan first!{Colors.END}")
        else:
            # Sort by latency
            sorted_results = sorted(self.results, key=lambda x: x.response_time_ms or 9999)
            
            print(f"{'IP':<20} {'Port':<6} {'Latency':<10} {'CF-RAY':<30}")
            print("─" * 70)
            
            for r in sorted_results:
                latency = f"{r.response_time_ms}ms" if r.response_time_ms else "N/A"
                cf_ray = r.cf_ray[:27] + "..." if r.cf_ray and len(r.cf_ray) > 30 else (r.cf_ray or "N/A")
                print(f"{r.ip:<20} {r.port:<6} {latency:<10} {cf_ray:<30}")
            
            print(f"\n{Colors.DIM}Sorted by latency (fastest first){Colors.END}")
        
        input(f"\n{Colors.DIM}Press Enter...{Colors.END}")

    def save_results(self):
        """Save results to file"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Save Results ═══{Colors.END}\n")
        
        if not self.results:
            print(f"{Colors.RED}[!] No results to save{Colors.END}")
            input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
            return
        
        print(f"  {Colors.GREEN}[1]{Colors.END}  JSON file (full details)")
        print(f"  {Colors.GREEN}[2]{Colors.END}  Text file (IP list only)")
        print(f"  {Colors.GREEN}[3]{Colors.END}  CSV file")
        print(f"  {Colors.RED}[0]{Colors.END}  Cancel")
        
        choice = input(f"\nFormat: ").strip()
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        if choice == '1':
            filename = f"godscanner_results_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump([asdict(r) for r in self.results], f, indent=2)
            print(f"{Colors.GREEN}[✓] Saved: {filename}{Colors.END}")
            
        elif choice == '2':
            filename = f"godscanner_ips_{timestamp}.txt"
            with open(filename, 'w') as f:
                for r in self.results:
                    f.write(f"{r.ip}\n")
            print(f"{Colors.GREEN}[✓] Saved: {filename}{Colors.END}")
            
        elif choice == '3':
            filename = f"godscanner_results_{timestamp}.csv"
            with open(filename, 'w') as f:
                f.write("ip,port,cf_ray,server,latency_ms,cert_cn\n")
                for r in self.results:
                    f.write(f"{r.ip},{r.port},{r.cf_ray},{r.server},{r.response_time_ms},{r.cert_cn}\n")
            print(f"{Colors.GREEN}[✓] Saved: {filename}{Colors.END}")
        else:
            return
        
        input(f"\n{Colors.DIM}Press Enter...{Colors.END}")

    def generate_vless(self):
        """Generate VLESS configs"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Generate VLESS Configs ═══{Colors.END}\n")
        
        if not self.results:
            print(f"{Colors.RED}[!] No results. Run a scan first!{Colors.END}")
            input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
            return
        
        print(f"{Colors.CYAN}Found {len(self.results)} CF proxy IPs{Colors.END}")
        print(f"{Colors.DIM}Enter your VLESS parameters below{Colors.END}\n")
        
        # UUID
        print(f"{Colors.BOLD}[1/6] UUID{Colors.END}")
        print(f"{Colors.DIM}Your VLESS server UUID{Colors.END}")
        uuid = input(f"  UUID: ").strip()
        if not uuid:
            print(f"{Colors.YELLOW}  Using placeholder: YOUR-UUID-HERE{Colors.END}")
            uuid = "YOUR-UUID-HERE"
        
        # Host
        print(f"\n{Colors.BOLD}[2/6] Host Header{Colors.END}")
        print(f"{Colors.DIM}Domain for Host header (your CF domain){Colors.END}")
        host = input(f"  Host: ").strip()
        if not host:
            print(f"{Colors.YELLOW}  Using placeholder: YOUR-HOST.com{Colors.END}")
            host = "YOUR-HOST.com"
        
        # SNI
        print(f"\n{Colors.BOLD}[3/6] SNI (Server Name Indication){Colors.END}")
        print(f"{Colors.DIM}TLS SNI domain (usually same as Host){Colors.END}")
        print(f"{Colors.DIM}Press Enter to use same as Host: {host}{Colors.END}")
        sni = input(f"  SNI: ").strip()
        if not sni:
            sni = host
            print(f"{Colors.GREEN}  Using: {sni}{Colors.END}")
        
        # Path
        print(f"\n{Colors.BOLD}[4/6] WebSocket Path{Colors.END}")
        print(f"{Colors.DIM}Path on your VLESS server (e.g., /ws, /vless){Colors.END}")
        path = input(f"  Path [/]: ").strip() or "/"
        if not path.startswith('/'):
            path = '/' + path
        
        # 0-RTT (Early Data)
        print(f"\n{Colors.BOLD}[5/6] 0-RTT Early Data{Colors.END}")
        print(f"{Colors.DIM}Reduces latency by sending data in TLS handshake{Colors.END}")
        print(f"{Colors.DIM}Recommended: Yes{Colors.END}")
        add_ed = input(f"  Add 0-RTT (?ed=2048)? [Y/n]: ").strip().lower()
        use_early_data = add_ed != 'n'
        
        if use_early_data:
            # Add ?ed=2048 to path
            if '?' in path:
                path = path + "&ed=2048"
            else:
                path = path + "?ed=2048"
            print(f"{Colors.GREEN}  Path with 0-RTT: {path}{Colors.END}")
        
        # Fragment
        print(f"\n{Colors.BOLD}[6/6] TLS Fragment{Colors.END}")
        print(f"{Colors.DIM}Splits TLS ClientHello to bypass DPI{Colors.END}")
        print(f"{Colors.DIM}Format: length,interval,packets (e.g., 3,1,tlshello){Colors.END}")
        add_frag = input(f"  Add fragment? [y/N]: ").strip().lower()
        use_fragment = add_frag == 'y'
        
        fragment_value = ""
        if use_fragment:
            print(f"{Colors.DIM}  Common values: 1-3,1-1,tlshello or 10-50,10-30,tlshello{Colors.END}")
            fragment_value = input(f"  Fragment value [1-3,1-1,tlshello]: ").strip() or "1-3,1-1,tlshello"
            print(f"{Colors.GREEN}  Fragment: {fragment_value}{Colors.END}")
        
        # Config name prefix
        print(f"\n{Colors.BOLD}[Optional] Config Name{Colors.END}")
        print(f"{Colors.DIM}Prefix for config names (e.g., MyVPN, Speed){Colors.END}")
        name_prefix = input(f"  Name prefix [GodScanner]: ").strip() or "GodScanner"
        
        # URL encode path
        import urllib.parse
        encoded_path = urllib.parse.quote(path, safe='')
        
        # Generate configs
        print(f"\n{Colors.BOLD}{'═'*60}{Colors.END}")
        print(f"{Colors.BOLD}           GENERATED VLESS CONFIGS{Colors.END}")
        print(f"{Colors.BOLD}{'═'*60}{Colors.END}\n")
        
        configs = []
        sorted_results = sorted(self.results, key=lambda x: x.response_time_ms or 9999)
        
        for i, r in enumerate(sorted_results, 1):
            # Build config URL
            params = [
                "encryption=none",
                "type=ws",
                f"host={host}",
                f"path={encoded_path}",
                "security=tls",
                "fp=chrome",
                f"sni={sni}",
                "allowInsecure=false",
            ]
            
            if use_fragment:
                params.append(f"fragment={fragment_value}")
            
            # Config name with emoji flag and latency
            latency = r.response_time_ms or 0
            config_name = f"{name_prefix}-{i}-{latency}ms"
            encoded_name = urllib.parse.quote(config_name, safe='')
            
            config = f"vless://{uuid}@{r.ip}:{r.port}?{'&'.join(params)}#{encoded_name}"
            configs.append(config)
            
            # Print with color
            print(f"{Colors.GREEN}#{i}{Colors.END} {Colors.CYAN}[{latency}ms]{Colors.END} {r.ip}")
            print(f"{Colors.DIM}{config}{Colors.END}\n")
        
        print(f"{Colors.BOLD}{'═'*60}{Colors.END}")
        print(f"{Colors.GREEN}Total configs: {len(configs)}{Colors.END}")
        print(f"{Colors.BOLD}{'═'*60}{Colors.END}")
        
        # Summary
        print(f"\n{Colors.BOLD}Configuration Summary:{Colors.END}")
        print(f"  • UUID: {Colors.CYAN}{uuid[:8]}...{Colors.END}" if len(uuid) > 8 else f"  • UUID: {Colors.CYAN}{uuid}{Colors.END}")
        print(f"  • Host: {Colors.CYAN}{host}{Colors.END}")
        print(f"  • SNI: {Colors.CYAN}{sni}{Colors.END}")
        print(f"  • Path: {Colors.CYAN}{path}{Colors.END}")
        print(f"  • 0-RTT: {Colors.GREEN}Yes{Colors.END}" if use_early_data else f"  • 0-RTT: {Colors.RED}No{Colors.END}")
        print(f"  • Fragment: {Colors.GREEN}{fragment_value}{Colors.END}" if use_fragment else f"  • Fragment: {Colors.RED}No{Colors.END}")
        
        # Save
        print(f"\n{Colors.BOLD}Save Options:{Colors.END}")
        print(f"  {Colors.GREEN}[1]{Colors.END}  Save to file")
        print(f"  {Colors.GREEN}[2]{Colors.END}  Copy to clipboard (if available)")
        print(f"  {Colors.RED}[0]{Colors.END}  Skip")
        
        save_choice = input(f"\nChoice: ").strip()
        
        if save_choice == '1':
            filename = f"vless_{name_prefix.lower()}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for c in configs:
                    f.write(c + "\n")
            print(f"{Colors.GREEN}[✓] Saved: {filename}{Colors.END}")
            
        elif save_choice == '2':
            try:
                import subprocess
                all_configs = "\n".join(configs)
                # Try xclip (Linux)
                try:
                    subprocess.run(['xclip', '-selection', 'clipboard'], input=all_configs.encode(), check=True)
                    print(f"{Colors.GREEN}[✓] Copied to clipboard!{Colors.END}")
                except FileNotFoundError:
                    # Try xsel (Linux)
                    try:
                        subprocess.run(['xsel', '--clipboard', '--input'], input=all_configs.encode(), check=True)
                        print(f"{Colors.GREEN}[✓] Copied to clipboard!{Colors.END}")
                    except FileNotFoundError:
                        # Try pbcopy (macOS)
                        try:
                            subprocess.run(['pbcopy'], input=all_configs.encode(), check=True)
                            print(f"{Colors.GREEN}[✓] Copied to clipboard!{Colors.END}")
                        except FileNotFoundError:
                            print(f"{Colors.YELLOW}[!] Clipboard tool not found. Install xclip or xsel.{Colors.END}")
                            # Fallback to file
                            filename = f"vless_{name_prefix.lower()}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                            with open(filename, 'w') as f:
                                for c in configs:
                                    f.write(c + "\n")
                            print(f"{Colors.GREEN}[✓] Saved to file instead: {filename}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Clipboard error: {e}{Colors.END}")
        
        input(f"\n{Colors.DIM}Press Enter...{Colors.END}")

    def run(self):
        """Main loop"""
        while True:
            clear_screen()
            self.print_banner()
            self.print_main_menu()
            
            choice = input(f"{Colors.BOLD}Select option: {Colors.END}").strip()
            
            if choice == '0':
                clear_screen()
                print(f"\n{Colors.CYAN}Thanks for using GodScanner!{Colors.END}")
                print(f"{Colors.DIM}github.com/yourusername/godscanner{Colors.END}\n")
                sys.exit(0)
            elif choice == '1':
                self.scan_by_provider()
            elif choice == '2':
                self.scan_custom_cidr()
            elif choice == '3':
                self.scan_single_ip()
            elif choice == '4':
                self.scan_from_file()
            elif choice == '5':
                self.scan_all_providers()
            elif choice == '6':
                self.show_settings()
            elif choice == '7':
                self.show_results()
            elif choice == '8':
                self.save_results()
            elif choice == '9':
                self.generate_vless()


def main():
    try:
        app = GodScanner()
        app.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.CYAN}Interrupted by user{Colors.END}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
