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

    def check_ip(self, ip: str, sni: str = "") -> Optional[ScanResult]:
        """
        Check if IP is a CloudFlare proxy.
        Tries BOTH port 80 (HTTP) and port 443 (HTTPS) automatically.
        
        Args:
            ip: IP address to check
            sni: SNI domain (used for port 443)
        """
        if self.stop_flag:
            return None
            
        if is_cloudflare_ip(ip):
            return None

        start_time = time.time()
        
        # ===== Try PORT 80 first (faster, no TLS) =====
        try:
            conn = http.client.HTTPConnection(ip, 80, timeout=self.timeout)
            conn.request("HEAD", "/", headers={
                "Host": sni if sni else ip,
                "User-Agent": "Mozilla/5.0",
                "Connection": "close"
            })
            resp = conn.getresponse()
            
            headers = {k.lower(): v for k, v in resp.getheaders()}
            cf_ray = headers.get('cf-ray')
            server = headers.get('server', '')
            conn.close()
            
            # Check for CF indicators
            if cf_ray or (server and 'cloudflare' in server.lower()):
                return ScanResult(
                    ip=ip, 
                    port=80, 
                    is_cf_proxy=True,
                    cf_ray=cf_ray,
                    server=server,
                    status_code=resp.status,
                    response_time_ms=int((time.time() - start_time) * 1000)
                )
        except:
            pass
        
        # ===== Try PORT 443 (TLS) =====
        if not sni:
            return None
            
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, 443), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    
                    if not cert:
                        return None
                    
                    # Get certificate info
                    subject = dict(x[0] for x in cert.get('subject', []))
                    cert_cn = subject.get('commonName', '')
                    
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    issuer_o = issuer.get('organizationName', '').lower()
                    
                    is_cf_cert = False
                    
                    # Check 1: CN contains cloudflare
                    if cert_cn:
                        cn_lower = cert_cn.lower()
                        if 'cloudflare' in cn_lower or 'sni.cloudflaressl.com' == cn_lower:
                            is_cf_cert = True
                    
                    # Check 2: Issuer is Cloudflare
                    if 'cloudflare' in issuer_o:
                        is_cf_cert = True
                    
                    # Check 3: Raw certificate
                    if not is_cf_cert and cert_bin:
                        try:
                            cert_str = cert_bin.decode('latin-1', errors='ignore').lower()
                            if 'cloudflare' in cert_str and ('sni.cloudflaressl' in cert_str or 'cloudflare inc' in cert_str):
                                is_cf_cert = True
                        except:
                            pass
                    
                    # Check 4: Subject Alt Names
                    if not is_cf_cert:
                        for san_type, san_value in cert.get('subjectAltName', []):
                            if san_type == 'DNS' and 'cloudflare' in san_value.lower():
                                is_cf_cert = True
                                break
                    
                    if not is_cf_cert:
                        return None
                    
                    # Try to get CF-RAY
                    cf_ray = None
                    server = None
                    status_code = None
                    try:
                        conn = http.client.HTTPSConnection(ip, 443, timeout=min(self.timeout, 2), context=ctx)
                        conn.request("HEAD", "/", headers={
                            "Host": sni,
                            "User-Agent": "Mozilla/5.0",
                            "Connection": "close"
                        })
                        resp = conn.getresponse()
                        status_code = resp.status
                        headers = {k.lower(): v for k, v in resp.getheaders()}
                        cf_ray = headers.get('cf-ray')
                        server = headers.get('server', '')
                        conn.close()
                    except:
                        pass
                    
                    return ScanResult(
                        ip=ip,
                        port=443,
                        is_cf_proxy=True,
                        cf_ray=cf_ray,
                        server=server,
                        cert_cn=cert_cn,
                        status_code=status_code,
                        response_time_ms=int((time.time() - start_time) * 1000)
                    )
                        
        except:
            pass
            
        return None

    def scan(self, ips: List[str], sni: str, callback=None):
        """Scan list of IPs with specified SNI"""
        self.total = len(ips)
        self.scanned = 0
        self.found = 0
        self.results = []
        self.stop_flag = False
        
        # SNI required only for port 443+
        if self.port != 80 and not sni:
            return self.results
        
        # Process in batches to avoid memory issues
        batch_size = min(self.threads * 10, 10000)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for batch_start in range(0, len(ips), batch_size):
                if self.stop_flag:
                    break
                    
                batch = ips[batch_start:batch_start + batch_size]
                futures = {executor.submit(self.check_ip, ip, sni): ip for ip in batch}
                
                for future in as_completed(futures):
                    if self.stop_flag:
                        for f in futures:
                            f.cancel()
                        break
                    
                    with self.lock:
                        self.scanned += 1
                    
                    try:
                        result = future.result(timeout=0.1)
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
            'threads': 300,
            'timeout': 3.0,
            'sni': '',           # User's CF domain for SNI (port 443)
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
        sni_status = f"{Colors.GREEN}✓ {self.settings['sni']}{Colors.END}" if self.settings['sni'] else f"{Colors.RED}✗ NOT SET{Colors.END}"
        print(f"""
{Colors.BOLD}╔════════════════════════════════════════════════════════════════════╗
║                         MAIN MENU                                  ║
╠════════════════════════════════════════════════════════════════════╣{Colors.END}
║  SNI Domain: {sni_status:<56}║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  {Colors.GREEN}[1]{Colors.END}  🔍  Scan by Provider                                        ║
║  {Colors.GREEN}[2]{Colors.END}  🎯  Scan Custom CIDR Range                                  ║
║  {Colors.GREEN}[3]{Colors.END}  📝  Check Single IP                                         ║
║  {Colors.GREEN}[4]{Colors.END}  📁  Scan from File                                          ║
║  {Colors.GREEN}[5]{Colors.END}  🌐  Scan ALL Providers {Colors.RED}(takes long time){Colors.END}                   ║
║  {Colors.GREEN}[6]{Colors.END}  🏢  Scan by ASN                                             ║
║                                                                    ║
║  {Colors.YELLOW}[7]{Colors.END}  ⚙️   Settings                                               ║
║  {Colors.YELLOW}[8]{Colors.END}  📊  View Results {Colors.CYAN}({found_count} found){Colors.END}                                 ║
║  {Colors.YELLOW}[9]{Colors.END}  💾  Save Results                                            ║
║  {Colors.YELLOW}[10]{Colors.END} 📋  Generate VLESS Configs                                  ║
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
        sni_display = self.settings['sni'] if self.settings['sni'] else f"{Colors.RED}NOT SET (port 80 only){Colors.END}"
        print(f"""
{Colors.BOLD}╔════════════════════════════════════════════════════════════════════╗
║                         SETTINGS                                   ║
╠════════════════════════════════════════════════════════════════════╣{Colors.END}
║                                                                    ║
║  {Colors.GREEN}[1]{Colors.END}  SNI Domain:   {Colors.CYAN}{sni_display:<43}{Colors.END} ║
║  {Colors.GREEN}[2]{Colors.END}  Threads:      {Colors.CYAN}{self.settings['threads']:<6}{Colors.END}                                    ║
║  {Colors.GREEN}[3]{Colors.END}  Timeout:      {Colors.CYAN}{self.settings['timeout']:<6.1f}s{Colors.END}                                   ║
║                                                                    ║
║  {Colors.DIM}Scanning checks BOTH port 80 (HTTP) and 443 (HTTPS){Colors.END}             ║
║  {Colors.DIM}SNI is required only for port 443 detection{Colors.END}                     ║
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
        """Callback when potential proxy found"""
        cf_ray = f" | CF-RAY: {result.cf_ray}" if result.cf_ray else ""
        print(f"\r{Colors.GREEN}[+] FOUND: {result.ip}:{result.port}{Colors.END} | {result.response_time_ms}ms{cf_ray}")

    def do_scan(self, ips: List[str], description: str):
        """Execute scan with progress display"""
        
        print(f"\n{Colors.CYAN}[*] {description}{Colors.END}")
        print(f"{Colors.DIM}[*] Checking both port 80 (HTTP) and 443 (HTTPS){Colors.END}")
        if self.settings['sni']:
            print(f"{Colors.DIM}[*] SNI for 443: {self.settings['sni']}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}[*] No SNI set - only port 80 will be checked{Colors.END}")
        print(f"{Colors.DIM}[*] Total IPs: {len(ips):,} | Threads: {self.settings['threads']} | Timeout: {self.settings['timeout']}s{Colors.END}")
        
        # Estimate time
        estimated_time = (len(ips) / self.settings['threads']) * self.settings['timeout']
        if estimated_time > 60:
            print(f"{Colors.YELLOW}[*] Estimated time: {estimated_time/60:.1f} minutes{Colors.END}")
        else:
            print(f"{Colors.DIM}[*] Estimated time: {estimated_time:.0f} seconds{Colors.END}")
        
        print(f"{Colors.DIM}[*] Press Ctrl+C to stop scan{Colors.END}\n")
        
        self.scanner = Scanner(
            threads=self.settings['threads'],
            timeout=self.settings['timeout'],
            port=443  # Ignored now, check_ip tries both
        )
        
        start = time.time()
        scan_done = threading.Event()
        scan_error = [None]
        
        def scan_thread():
            try:
                self.scanner.scan(ips, self.settings['sni'], callback=self.on_found)
            except Exception as e:
                scan_error[0] = e
            finally:
                scan_done.set()
        
        t = threading.Thread(target=scan_thread, daemon=True)
        t.start()
        
        interrupted = False
        last_scanned = 0
        stall_count = 0
        
        try:
            while not scan_done.is_set():
                time.sleep(0.5)
                if self.scanner.total > 0:
                    pct = (self.scanner.scanned / self.scanner.total) * 100
                    bar_len = 30
                    filled = int(bar_len * self.scanner.scanned / self.scanner.total)
                    bar = '█' * filled + '░' * (bar_len - filled)
                    
                    # Calculate speed
                    elapsed = time.time() - start
                    speed = self.scanner.scanned / elapsed if elapsed > 0 else 0
                    
                    # ETA
                    remaining = self.scanner.total - self.scanner.scanned
                    eta = remaining / speed if speed > 0 else 0
                    eta_str = f"{eta:.0f}s" if eta < 60 else f"{eta/60:.1f}m"
                    
                    print(f"\r{Colors.DIM}[{bar}] {pct:5.1f}% | {self.scanner.scanned:,}/{self.scanner.total:,} | Found: {Colors.GREEN}{self.scanner.found}{Colors.DIM} | {speed:.0f}/s | ETA: {eta_str}{Colors.END}   ", end="", flush=True)
                    
                    # Check for stall
                    if self.scanner.scanned == last_scanned:
                        stall_count += 1
                        if stall_count > 20:
                            print(f"\n{Colors.YELLOW}[!] Scan appears stalled. Consider Ctrl+C and lowering timeout.{Colors.END}")
                            stall_count = 0
                    else:
                        stall_count = 0
                    last_scanned = self.scanner.scanned
                    
        except KeyboardInterrupt:
            interrupted = True
            print(f"\n\n{Colors.YELLOW}[!] Stopping scan...{Colors.END}")
            self.scanner.stop()
            t.join(timeout=3)
        
        if not interrupted:
            t.join()
        
        elapsed = time.time() - start
        self.results.extend(self.scanner.results)
        
        print(f"\n\n{Colors.GREEN}{'═'*60}{Colors.END}")
        if interrupted:
            print(f"{Colors.YELLOW}[!] Scan interrupted after {elapsed:.1f}s{Colors.END}")
        else:
            print(f"{Colors.GREEN}[✓] Scan completed in {elapsed:.1f}s{Colors.END}")
        print(f"{Colors.GREEN}[✓] Scanned: {self.scanner.scanned:,} IPs ({self.scanner.scanned/elapsed:.0f}/s){Colors.END}")
        print(f"{Colors.GREEN}[✓] Found potential proxies: {self.scanner.found}{Colors.END}")
        print(f"{Colors.GREEN}[✓] Total results: {len(self.results)}{Colors.END}")
        print(f"{Colors.GREEN}{'═'*60}{Colors.END}")
        
        if self.scanner.found > 0:
            print(f"\n{Colors.CYAN}These IPs accepted TLS with your SNI.{Colors.END}")
            print(f"{Colors.DIM}Test them with your VLESS client to verify they work.{Colors.END}")
        
        try:
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
        except KeyboardInterrupt:
            pass

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
        """Check single IP - tries both port 80 and 443"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Check Single IP ═══{Colors.END}\n")
        print(f"{Colors.DIM}Will check both port 80 (HTTP) and 443 (HTTPS){Colors.END}")
        if self.settings['sni']:
            print(f"{Colors.DIM}SNI for 443: {self.settings['sni']}{Colors.END}\n")
        else:
            print(f"{Colors.YELLOW}No SNI set - only port 80 will be checked{Colors.END}\n")
        
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
        print(f"{Colors.DIM}[*] Testing port 80 (HTTP) and 443 (HTTPS)...{Colors.END}\n")
        
        scanner = Scanner(threads=1, timeout=self.settings['timeout'], port=443)
        result = scanner.check_ip(ip, self.settings['sni'])
        
        if result and result.is_cf_proxy:
            print(f"{Colors.GREEN}{'═'*50}{Colors.END}")
            print(f"{Colors.GREEN}[✓] CF PROXY FOUND!{Colors.END}")
            print(f"{Colors.GREEN}{'═'*50}{Colors.END}")
            print(f"  IP:        {result.ip}")
            print(f"  Port:      {result.port}")
            print(f"  Latency:   {result.response_time_ms}ms")
            print(f"  CF-RAY:    {result.cf_ray or 'N/A'}")
            print(f"  Server:    {result.server or 'N/A'}")
            if result.cert_cn:
                print(f"  Cert CN:   {result.cert_cn}")
            print(f"{Colors.GREEN}{'═'*50}{Colors.END}")
            print(f"\n{Colors.CYAN}This is a CloudFlare proxy!{Colors.END}")
            print(f"{Colors.DIM}Test it with your VLESS/VMess client.{Colors.END}")
            
            save = input(f"\nAdd to results? [Y/n]: ").strip().lower()
            if save != 'n':
                self.results.append(result)
                print(f"{Colors.GREEN}[✓] Added to results{Colors.END}")
        else:
            print(f"{Colors.RED}{'═'*50}{Colors.END}")
            print(f"{Colors.RED}[✗] Not a CF proxy{Colors.END}")
            print(f"{Colors.RED}{'═'*50}{Colors.END}")
            print(f"{Colors.DIM}No CloudFlare found on port 80 or 443{Colors.END}")
        
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
        
        try:
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
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            return

    def scan_by_asn(self):
        """Scan by ASN number"""
        clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}═══ Scan by ASN ═══{Colors.END}\n")
        print(f"{Colors.DIM}Enter ASN number to fetch IP ranges and scan{Colors.END}")
        print(f"{Colors.DIM}Examples: AS13335 (Cloudflare), AS51167 (Contabo), AS24940 (Hetzner){Colors.END}\n")
        
        # Popular ASNs reference
        print(f"{Colors.BOLD}Popular ASNs:{Colors.END}")
        popular_asns = [
            ("AS51167", "Contabo"),
            ("AS24940", "Hetzner"),
            ("AS16276", "OVH"),
            ("AS14061", "DigitalOcean"),
            ("AS20473", "Vultr"),
            ("AS63949", "Linode"),
            ("AS12876", "Scaleway"),
            ("AS31898", "Oracle Cloud"),
            ("AS15169", "Google Cloud"),
            ("AS8075", "Microsoft Azure"),
            ("AS16509", "Amazon AWS"),
            ("AS13335", "Cloudflare (will be excluded)"),
        ]
        
        for asn, name in popular_asns:
            print(f"  {Colors.CYAN}{asn:<10}{Colors.END} - {name}")
        
        print()
        asn_input = input(f"Enter ASN (e.g., AS51167 or 51167): ").strip().upper()
        
        if not asn_input:
            return
        
        # Normalize ASN format
        if not asn_input.startswith("AS"):
            asn_input = "AS" + asn_input
        
        asn_number = asn_input.replace("AS", "")
        
        print(f"\n{Colors.CYAN}[*] Fetching IP ranges for {asn_input}...{Colors.END}")
        
        try:
            # Method 1: Try bgp.he.net (Hurricane Electric)
            import urllib.request
            import urllib.error
            import re
            
            ranges = []
            
            # Try multiple sources
            sources = [
                f"https://api.bgpview.io/asn/{asn_number}/prefixes",
                f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_input}",
            ]
            
            # Try BGPView API first
            try:
                print(f"{Colors.DIM}[*] Trying BGPView API...{Colors.END}")
                req = urllib.request.Request(
                    f"https://api.bgpview.io/asn/{asn_number}/prefixes",
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = json.loads(response.read().decode())
                    
                    if data.get("status") == "ok" and data.get("data"):
                        ipv4_prefixes = data["data"].get("ipv4_prefixes", [])
                        for prefix in ipv4_prefixes:
                            cidr = prefix.get("prefix")
                            if cidr:
                                ranges.append(cidr)
                        
                        print(f"{Colors.GREEN}[✓] Found {len(ranges)} IPv4 ranges from BGPView{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!] BGPView failed: {e}{Colors.END}")
            
            # Try RIPE Stat if BGPView failed
            if not ranges:
                try:
                    print(f"{Colors.DIM}[*] Trying RIPE Stat API...{Colors.END}")
                    req = urllib.request.Request(
                        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_input}",
                        headers={"User-Agent": "Mozilla/5.0"}
                    )
                    with urllib.request.urlopen(req, timeout=15) as response:
                        data = json.loads(response.read().decode())
                        
                        prefixes = data.get("data", {}).get("prefixes", [])
                        for prefix in prefixes:
                            cidr = prefix.get("prefix")
                            if cidr and ":" not in cidr:  # Skip IPv6
                                ranges.append(cidr)
                        
                        print(f"{Colors.GREEN}[✓] Found {len(ranges)} IPv4 ranges from RIPE{Colors.END}")
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] RIPE Stat failed: {e}{Colors.END}")
            
            if not ranges:
                print(f"{Colors.RED}[!] Could not fetch IP ranges for {asn_input}{Colors.END}")
                print(f"{Colors.DIM}Try entering CIDR ranges manually with option [2]{Colors.END}")
                input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
                return
            
            # Remove duplicates and sort
            ranges = sorted(list(set(ranges)))
            
            # Calculate total IPs
            total_ips = 0
            for cidr in ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    total_ips += network.num_addresses
                except:
                    pass
            
            print(f"\n{Colors.BOLD}═══ {asn_input} IP Ranges ═══{Colors.END}\n")
            print(f"Total ranges: {len(ranges)}")
            print(f"Total IPs: ~{total_ips:,}\n")
            
            # Show ranges
            print(f"{Colors.BOLD}Ranges:{Colors.END}")
            for i, cidr in enumerate(ranges[:20], 1):  # Show first 20
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    print(f"  {i:>2}. {cidr:<20} ({network.num_addresses:>10,} IPs)")
                except:
                    print(f"  {i:>2}. {cidr}")
            
            if len(ranges) > 20:
                print(f"  ... and {len(ranges) - 20} more ranges")
            
            # Scan options
            print(f"\n{Colors.BOLD}Scan Options:{Colors.END}")
            print(f"  {Colors.GREEN}[A]{Colors.END}  Scan ALL ranges")
            print(f"  {Colors.GREEN}[S]{Colors.END}  Select specific ranges")
            print(f"  {Colors.GREEN}[L]{Colors.END}  Scan only /24 and smaller (faster)")
            print(f"  {Colors.RED}[0]{Colors.END}  Cancel")
            
            choice = input(f"\nChoice: ").strip().upper()
            
            if choice == '0':
                return
            
            elif choice == 'A':
                # Scan all
                all_ips = []
                for cidr in ranges:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        all_ips.extend([str(ip) for ip in network.hosts()])
                    except:
                        pass
                
                if all_ips:
                    # Warn if large scan and suggest lower timeout
                    if len(all_ips) > 10000:
                        print(f"\n{Colors.YELLOW}[!] Large scan: {len(all_ips):,} IPs{Colors.END}")
                        print(f"{Colors.DIM}Current timeout: {self.settings['timeout']}s{Colors.END}")
                        print(f"{Colors.DIM}Recommended timeout for large scans: 2-3s{Colors.END}")
                        
                        lower = input(f"\nLower timeout to 2s for faster scan? [Y/n]: ").strip().lower()
                        if lower != 'n':
                            old_timeout = self.settings['timeout']
                            self.settings['timeout'] = 2.0
                            print(f"{Colors.GREEN}[✓] Timeout set to 2s{Colors.END}")
                            self.do_scan(all_ips, f"Scanning {asn_input} - All ranges")
                            self.settings['timeout'] = old_timeout  # Restore
                        else:
                            self.do_scan(all_ips, f"Scanning {asn_input} - All ranges")
                    else:
                        self.do_scan(all_ips, f"Scanning {asn_input} - All ranges")
            
            elif choice == 'L':
                # Scan only small ranges (/24 and smaller)
                small_ranges = []
                for cidr in ranges:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if network.prefixlen >= 24:
                            small_ranges.append(cidr)
                    except:
                        pass
                
                if not small_ranges:
                    print(f"{Colors.YELLOW}[!] No /24 or smaller ranges found{Colors.END}")
                    input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
                    return
                
                all_ips = []
                for cidr in small_ranges:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        all_ips.extend([str(ip) for ip in network.hosts()])
                    except:
                        pass
                
                print(f"\n{Colors.CYAN}Scanning {len(small_ranges)} small ranges ({len(all_ips):,} IPs){Colors.END}")
                self.do_scan(all_ips, f"Scanning {asn_input} - Small ranges only")
            
            elif choice == 'S':
                # Select specific ranges
                print(f"\n{Colors.DIM}Enter range numbers separated by comma (e.g., 1,3,5){Colors.END}")
                print(f"{Colors.DIM}Or enter range (e.g., 1-10){Colors.END}")
                
                selection = input(f"Selection: ").strip()
                
                selected_indices = set()
                for part in selection.split(','):
                    part = part.strip()
                    if '-' in part:
                        try:
                            start, end = part.split('-')
                            for i in range(int(start), int(end) + 1):
                                selected_indices.add(i)
                        except:
                            pass
                    else:
                        try:
                            selected_indices.add(int(part))
                        except:
                            pass
                
                selected_ranges = []
                for i in selected_indices:
                    if 1 <= i <= len(ranges):
                        selected_ranges.append(ranges[i - 1])
                
                if not selected_ranges:
                    print(f"{Colors.RED}[!] No valid ranges selected{Colors.END}")
                    input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
                    return
                
                all_ips = []
                for cidr in selected_ranges:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        all_ips.extend([str(ip) for ip in network.hosts()])
                    except:
                        pass
                
                print(f"\n{Colors.CYAN}Scanning {len(selected_ranges)} ranges ({len(all_ips):,} IPs){Colors.END}")
                self.do_scan(all_ips, f"Scanning {asn_input} - Selected ranges")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            return
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
            try:
                input(f"\n{Colors.DIM}Press Enter...{Colors.END}")
            except KeyboardInterrupt:
                pass

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
                print(f"\n{Colors.BOLD}SNI Domain{Colors.END}")
                print(f"{Colors.DIM}Enter a CloudFlare-backed domain for scanning.{Colors.END}")
                print(f"{Colors.DIM}This domain is used as SNI when connecting to IPs.{Colors.END}")
                print(f"\n{Colors.YELLOW}If your domain is blocked, use a popular unblocked CF domain:{Colors.END}")
                
                # Popular CF domains that are usually not blocked
                popular_snis = [
                    "speed.cloudflare.com",
                    "www.visa.com",
                    "www.mastercard.com", 
                    "www.who.int",
                    "www.unicef.org",
                    "www.spotify.com",
                    "www.udemy.com",
                    "www.canva.com",
                    "www.medium.com",
                    "www.notion.so",
                ]
                
                print(f"\n{Colors.CYAN}Popular CF domains (try these if yours is blocked):{Colors.END}")
                for i, domain in enumerate(popular_snis, 1):
                    print(f"  {i:>2}. {domain}")
                
                print(f"\n{Colors.DIM}Enter domain name, number (1-{len(popular_snis)}), or 'clear' to remove{Colors.END}")
                
                val = input(f"\nSNI Domain: ").strip()
                
                if val == 'clear' or val == '':
                    self.settings['sni'] = ''
                    print(f"{Colors.YELLOW}[✓] SNI cleared{Colors.END}")
                elif val.isdigit() and 1 <= int(val) <= len(popular_snis):
                    self.settings['sni'] = popular_snis[int(val) - 1]
                    print(f"{Colors.GREEN}[✓] SNI set to: {self.settings['sni']}{Colors.END}")
                else:
                    # Remove protocol if present
                    val = val.lower().replace('https://', '').replace('http://', '').split('/')[0]
                    self.settings['sni'] = val
                    print(f"{Colors.GREEN}[✓] SNI set to: {val}{Colors.END}")
                input(f"{Colors.DIM}Press Enter...{Colors.END}")
            elif choice == '2':
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
            elif choice == '3':
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
            try:
                clear_screen()
                self.print_banner()
                self.print_main_menu()
                
                choice = input(f"{Colors.BOLD}Select option: {Colors.END}").strip()
                
                if choice == '0':
                    clear_screen()
                    print(f"\n{Colors.CYAN}Thanks for using GodScanner!{Colors.END}")
                    print(f"{Colors.DIM}github.com/useruserdev/godscanner{Colors.END}\n")
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
                    self.scan_by_asn()
                elif choice == '7':
                    self.show_settings()
                elif choice == '8':
                    self.show_results()
                elif choice == '9':
                    self.save_results()
                elif choice == '10':
                    self.generate_vless()
            except KeyboardInterrupt:
                # Ctrl+C in main menu = exit
                clear_screen()
                print(f"\n{Colors.CYAN}Thanks for using GodScanner!{Colors.END}")
                print(f"{Colors.DIM}github.com/useruserdev/godscanner{Colors.END}\n")
                sys.exit(0)


def main():
    try:
        app = GodScanner()
        app.run()
    except KeyboardInterrupt:
        clear_screen()
        print(f"\n{Colors.CYAN}Thanks for using GodScanner!{Colors.END}")
        print(f"{Colors.DIM}github.com/useruserdev/godscanner{Colors.END}\n")
        sys.exit(0)
    except EOFError:
        # Handle Ctrl+D
        print(f"\n{Colors.CYAN}Goodbye!{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {e}{Colors.END}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
