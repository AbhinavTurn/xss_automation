#!/usr/bin/env python3

import argparse
import json
import logging
import os
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Constants
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
]

# Evasion techniques to bypass WAFs
ENCODING_TECHNIQUES = {
    "basic": lambda p: p,
    "url_encode": lambda p: urllib.parse.quote(p),
    "double_url_encode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    "html_entities": lambda p: p.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;"),
    "hex_encode": lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
    "unicode_encode": lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
    "split_payload": lambda p: p.replace("script", "scr\nip\nt"),
    "case_randomization": lambda p: ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in p),
    "null_byte_injection": lambda p: p.replace("<", "%00<").replace(">", "%00>"),
}


class XSSScanner:
    def __init__(self, target_url: str, payloads_file: str, output_file: str = None, 
                 depth: int = 2, cookies: str = None, timeout: int = 10):
        # Setup logging first to avoid the 'logger' attribute error
        self.logger = self._setup_logging()
        
        self.target_url = self._normalize_url(target_url)
        self.depth = depth
        self.timeout = timeout
        self.urls_to_scan: Set[str] = set()
        self.visited_urls: Set[str] = set()
        self.vulnerable_urls: List[Dict] = []
        self.forms_to_test: List[Dict] = []
        
        self.logger.info(f"Initializing scanner for target: {self.target_url}")
        
        # Load payloads after logger is initialized
        self.payloads: List[str] = self._load_payloads(payloads_file)
        self.output_file = output_file or f"xss_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.cookies = self._parse_cookies(cookies) if cookies else {}
        
        # Session setup
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed certificates
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging to both console and file."""
        logger = logging.getLogger("XSSScanner")
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers if any
        if logger.handlers:
            logger.handlers.clear()
        
        # Create log directory if it doesn't exist
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Log file
        log_file = os.path.join(log_dir, f"xss_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Format
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def _load_payloads(self, payloads_file: str) -> List[str]:
        """Load XSS payloads from a file."""
        try:
            with open(payloads_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(payloads)} payloads from {payloads_file}")
            return payloads
        except Exception as e:
            self.logger.error(f"Failed to load payloads from {payloads_file}: {e}")
            sys.exit(1)
    
    def _parse_cookies(self, cookies_str: str) -> Dict[str, str]:
        """Parse cookies string into a dictionary."""
        cookies = {}
        for cookie in cookies_str.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies
    
    def _random_user_agent(self) -> str:
        """Return a random user agent."""
        return random.choice(USER_AGENTS)
    
    def _create_request_headers(self) -> Dict[str, str]:
        """Create randomized request headers to evade detection."""
        headers = {
            'User-Agent': self._random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'X-Forwarded-For': f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        }
        
        # Add random headers to further evade detection
        if random.choice([True, False]):
            headers['Sec-Fetch-Dest'] = 'document'
            headers['Sec-Fetch-Mode'] = 'navigate'
            headers['Sec-Fetch-Site'] = 'none'
            headers['Sec-Fetch-User'] = '?1'
        
        return headers
    
    def _get_request(self, url: str) -> Optional[requests.Response]:
        """Make a GET request with error handling."""
        try:
            headers = self._create_request_headers()
            response = self.session.get(
                url, 
                headers=headers,
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=True
            )
            return response
        except RequestException as e:
            self.logger.error(f"Request error on {url}: {e}")
            return None
    
    def _post_request(self, url: str, data: Dict) -> Optional[requests.Response]:
        """Make a POST request with error handling."""
        try:
            headers = self._create_request_headers()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = self.session.post(
                url, 
                data=data,
                headers=headers,
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=True
            )
            return response
        except RequestException as e:
            self.logger.error(f"POST request error on {url}: {e}")
            return None
    
    def extract_urls(self, response: requests.Response) -> List[str]:
        """Extract URLs from a webpage."""
        if not response or not response.text:
            return []
        
        base_url = response.url
        parsed_base = urllib.parse.urlparse(base_url)
        base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            urls = []
            
            # Extract links from <a> tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                abs_url = self._make_absolute_url(href, base_url, base_domain)
                if abs_url and self._is_valid_url(abs_url, base_domain):
                    urls.append(abs_url)
            
            # Extract links from <form> tags
            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                abs_url = self._make_absolute_url(action, base_url, base_domain)
                if abs_url and self._is_valid_url(abs_url, base_domain):
                    urls.append(abs_url)
            
            return list(set(urls))  # Remove duplicates
        except Exception as e:
            self.logger.error(f"Error extracting URLs from {base_url}: {e}")
            return []
    
    def _make_absolute_url(self, href: str, base_url: str, base_domain: str) -> Optional[str]:
        """Convert relative URLs to absolute URLs."""
        try:
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                return None
                
            # Handle absolute URLs
            if href.startswith(('http://', 'https://')):
                return href
                
            # Handle relative URLs
            return urllib.parse.urljoin(base_url, href)
        except Exception:
            return None
    
    def _is_valid_url(self, url: str, base_domain: str) -> bool:
        """Check if a URL is valid for crawling."""
        try:
            parsed = urllib.parse.urlparse(url)
            # Only crawl URLs in the same domain
            return (parsed.netloc == urllib.parse.urlparse(base_domain).netloc and
                    not url.endswith(('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', 
                                     '.css', '.js', '.zip', '.tar', '.gz', '.mp3', '.mp4')))
        except Exception:
            return False
    
    def extract_forms(self, url: str, response: requests.Response) -> List[Dict]:
        """Extract forms and their details from a webpage."""
        if not response or not response.text:
            return []
        
        forms = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_details = {
                    'source_url': url,
                    'action': self._make_absolute_url(form.get('action', ''), response.url, self.target_url) or response.url,
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                # Get all input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name', '')
                    
                    # Skip submit buttons and hidden fields
                    if input_type == 'submit' or not input_name:
                        continue
                        
                    input_value = input_tag.get('value', '')
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
                    
                if form_details['inputs']:
                    forms.append(form_details)
            
            return forms
        except Exception as e:
            self.logger.error(f"Error extracting forms from {response.url}: {e}")
            return []
    
    def extract_url_parameters(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            return params
        except Exception:
            return {}
    
    def _apply_evasion_technique(self, payload: str, technique_name: str) -> str:
        """Apply an evasion technique to a payload."""
        technique = ENCODING_TECHNIQUES.get(technique_name)
        if not technique:
            return payload
        return technique(payload)
    
    def _check_reflection(self, payload: str, response_text: str) -> bool:
        """Check if a payload is reflected in the response."""
        # Clean payload for reflection check (removing most common transformations)
        clean_payload = payload
        for char in ['<', '>', '"', "'", '&']:
            clean_payload = clean_payload.replace(char, '')
        
        # Check for specific patterns that might indicate successful XSS
        if re.search(r'<script[^>]*>[^<]*' + re.escape(clean_payload), response_text, re.I):
            return True
        if payload in response_text:
            return True
        if clean_payload and clean_payload in response_text:
            return True
            
        return False
    
    def _check_xss_response(self, original_response: str, injected_response: str, payload: str) -> bool:
        """Advanced check to detect successful XSS injection."""
        # If the payload is directly reflected
        if self._check_reflection(payload, injected_response):
            return True
            
        # Check if the structure of the page has been modified in a way that suggests XSS success
        orig_soup = BeautifulSoup(original_response, 'html.parser')
        inj_soup = BeautifulSoup(injected_response, 'html.parser')
        
        # Count script tags, as successful XSS might add one
        orig_script_count = len(orig_soup.find_all('script'))
        inj_script_count = len(inj_soup.find_all('script'))
        
        if inj_script_count > orig_script_count:
            return True
            
        # Check for event handlers which might have been injected
        inj_events = len(re.findall(r'on\w+\s*=\s*["\'][^"\']*["\']', injected_response, re.I))
        orig_events = len(re.findall(r'on\w+\s*=\s*["\'][^"\']*["\']', original_response, re.I))
        
        if inj_events > orig_events:
            return True
            
        return False
    
    def test_url_params(self, url: str) -> List[Dict]:
        """Test URL parameters for XSS vulnerabilities."""
        results = []
        params = self.extract_url_parameters(url)
        
        if not params:
            return results
            
        # Get the original response for comparison
        original_response = self._get_request(url)
        if not original_response:
            return results
            
        original_content = original_response.text
        
        self.logger.info(f"Testing {len(params)} parameters in URL: {url}")
        
        # Test each parameter
        for param_name, param_value in params.items():
            self.logger.info(f"Testing parameter: {param_name}")
            
            # Test with different payloads
            for payload in self.payloads:
                # Try different evasion techniques
                for technique_name in ENCODING_TECHNIQUES.keys():
                    encoded_payload = self._apply_evasion_technique(payload, technique_name)
                    
                    # Create a modified URL with the payload
                    new_params = params.copy()
                    new_params[param_name] = encoded_payload
                    query_string = urllib.parse.urlencode(new_params, doseq=True)
                    
                    parsed = urllib.parse.urlparse(url)
                    new_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        query_string,
                        parsed.fragment
                    ))
                    
                    # Add a small delay to avoid overwhelming the server
                    time.sleep(random.uniform(0.1, 0.5))
                    
                    # Make the request with the payload
                    response = self._get_request(new_url)
                    if not response:
                        continue
                        
                    # Check if the payload was successful
                    if self._check_xss_response(original_content, response.text, payload):
                        vuln_info = {
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "encoded_payload": encoded_payload,
                            "encoding_technique": technique_name,
                            "type": "GET parameter",
                            "evidence": self._extract_evidence(response.text, encoded_payload)
                        }
                        results.append(vuln_info)
                        self.logger.warning(f"Found XSS in parameter {param_name} at {url}")
                        
                        # Break out after finding vulnerability to avoid excessive testing
                        break
                
                # If vulnerability found, move to next parameter
                if any(r["parameter"] == param_name for r in results):
                    break
        
        return results
    
    def test_form(self, form: Dict) -> List[Dict]:
        """Test form inputs for XSS vulnerabilities."""
        results = []
        url = form['source_url']
        
        # Get the original form response for comparison
        original_response = self._get_request(url)
        if not original_response:
            return results
            
        original_content = original_response.text
        
        self.logger.info(f"Testing form at {url} with {len(form['inputs'])} inputs")
        
        # Test each input field
        for input_field in form['inputs']:
            field_name = input_field['name']
            field_type = input_field['type']
            
            # Skip testing on certain input types
            if field_type in ['checkbox', 'radio', 'file', 'submit', 'image', 'button']:
                continue
                
            self.logger.info(f"Testing form input: {field_name}")
            
            # Test with different payloads
            for payload in self.payloads:
                # Try different evasion techniques
                for technique_name in ENCODING_TECHNIQUES.keys():
                    encoded_payload = self._apply_evasion_technique(payload, technique_name)
                    
                    # Create form data
                    form_data = {}
                    for inp in form['inputs']:
                        if inp['name'] == field_name:
                            form_data[inp['name']] = encoded_payload
                        else:
                            # Use default values for other fields
                            if inp['type'] == 'text':
                                form_data[inp['name']] = 'test'
                            else:
                                form_data[inp['name']] = inp['value']
                    
                    # Add a small delay to avoid overwhelming the server
                    time.sleep(random.uniform(0.2, 0.7))
                    
                    # Submit the form
                    if form['method'] == 'post':
                        response = self._post_request(form['action'], form_data)
                    else:  # GET method
                        query_string = urllib.parse.urlencode(form_data, doseq=True)
                        form_url = f"{form['action']}?{query_string}"
                        response = self._get_request(form_url)
                        
                    if not response:
                        continue
                        
                    # Check if the payload was successful
                    if self._check_xss_response(original_content, response.text, payload):
                        vuln_info = {
                            "url": url,
                            "form_action": form['action'],
                            "method": form['method'],
                            "parameter": field_name,
                            "payload": payload,
                            "encoded_payload": encoded_payload,
                            "encoding_technique": technique_name,
                            "type": f"{form['method'].upper()} form parameter",
                            "evidence": self._extract_evidence(response.text, encoded_payload)
                        }
                        results.append(vuln_info)
                        self.logger.warning(f"Found XSS in form input {field_name} at {url}")
                        
                        # Break out after finding vulnerability to avoid excessive testing
                        break
                
                # If vulnerability found, move to next parameter
                if any(r["parameter"] == field_name for r in results):
                    break
        
        return results
    
    def _extract_evidence(self, response_text: str, payload: str) -> str:
        """Extract a snippet of code around the payload as evidence."""
        try:
            # Find the payload in the response
            index = response_text.find(payload)
            if index == -1:
                # Try with HTML entities
                clean_payload = payload
                for char, entity in [('<', '&lt;'), ('>', '&gt;'), ('"', '&quot;'), ("'", '&#39;')]:
                    clean_payload = clean_payload.replace(char, entity)
                index = response_text.find(clean_payload)
                
            if index != -1:
                # Extract context (30 chars before and after)
                start = max(0, index - 30)
                end = min(len(response_text), index + len(payload) + 30)
                evidence = response_text[start:end]
                return evidence.replace('\n', ' ').strip()
            return "Evidence not found"
        except Exception:
            return "Error extracting evidence"
    
    def crawl_website(self, url: str, current_depth: int = 0) -> None:
        """Crawl the website to collect all URLs first."""
        if current_depth > self.depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.logger.info(f"Crawling: {url} (depth: {current_depth}/{self.depth})")
        
        # Get the page
        response = self._get_request(url)
        if not response:
            return
        
        # Add URL to scan list if it has parameters
        if "?" in url and self.extract_url_parameters(url):
            self.urls_to_scan.add(url)
        
        # Extract and store forms for later testing
        forms = self.extract_forms(url, response)
        if forms:
            self.forms_to_test.extend(forms)
        
        # Continue crawling if depth allows
        if current_depth < self.depth:
            extracted_urls = self.extract_urls(response)
            for new_url in extracted_urls:
                if new_url not in self.visited_urls:
                    # Add a small delay between requests
                    time.sleep(random.uniform(0.3, 0.8))
                    self.crawl_website(new_url, current_depth + 1)
    
    def save_results(self) -> None:
        """Save scan results to a file."""
        result_data = {
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_url": self.target_url,
            "scan_depth": self.depth,
            "urls_crawled": len(self.visited_urls),
            "urls_crawled_list": list(self.visited_urls),
            "vulnerabilities_found": len(self.vulnerable_urls),
            "vulnerabilities": self.vulnerable_urls
        }
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=4)
            self.logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
    
    def run(self) -> None:
        """Run the XSS scanner in two phases: crawl, then test."""
        self.logger.info(f"Starting XSS scan on {self.target_url}")
        start_time = time.time()
        
        # PHASE 1: Crawl the entire website first
        self.logger.info("=== PHASE 1: Crawling website to collect all URLs ===")
        self.crawl_website(self.target_url)
        self.logger.info(f"Crawling complete. Found {len(self.visited_urls)} URLs.")
        self.logger.info(f"URLs with parameters to test: {len(self.urls_to_scan)}")
        self.logger.info(f"Forms to test: {len(self.forms_to_test)}")
        
        # Add URLs without parameters but have forms
        for url in self.visited_urls:
            if url not in self.urls_to_scan:
                response = self._get_request(url)
                if response and self.extract_forms(url, response):
                    self.urls_to_scan.add(url)
        
        # PHASE 2: Test all collected URLs for XSS vulnerabilities
        self.logger.info("=== PHASE 2: Testing all URLs for XSS vulnerabilities ===")
        
        # Test URL parameters
        for url in self.urls_to_scan:
            self.logger.info(f"Testing URL: {url}")
            url_results = self.test_url_params(url)
            if url_results:
                self.vulnerable_urls.extend(url_results)
        
        # Test all forms
        for form in self.forms_to_test:
            form_results = self.test_form(form)
            if form_results:
                self.vulnerable_urls.extend(form_results)
        
        # Save results
        self.save_results()
        
        # Log summary
        elapsed_time = time.time() - start_time
        self.logger.info("="*50)
        self.logger.info("Scan Summary:")
        self.logger.info(f"Target URL: {self.target_url}")
        self.logger.info(f"URLs crawled: {len(self.visited_urls)}")
        self.logger.info(f"URLs tested: {len(self.urls_to_scan)}")
        self.logger.info(f"Forms tested: {len(self.forms_to_test)}")
        self.logger.info(f"Vulnerabilities found: {len(self.vulnerable_urls)}")
        self.logger.info(f"Scan duration: {elapsed_time:.2f} seconds")
        self.logger.info(f"Results saved to {self.output_file}")
        self.logger.info("="*50)
        
        if self.vulnerable_urls:
            self.logger.warning("XSS vulnerabilities were found! Check the output file for details.")
        else:
            self.logger.info("No XSS vulnerabilities were detected.")


def main() -> None:
    """Main function to parse arguments and run the scanner."""
    parser = argparse.ArgumentParser(description="Advanced XSS Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-p", "--payloads", required=True, help="Path to file containing XSS payloads")
    parser.add_argument("-o", "--output", help="Output file path for results (JSON format)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--cookies", help="Cookies to include with requests (format: name1=value1; name2=value2)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    try:
        scanner = XSSScanner(
            target_url=args.url,
            payloads_file=args.payloads,
            output_file=args.output,
            depth=args.depth,
            cookies=args.cookies,
            timeout=args.timeout
        )
        scanner.run()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Saving partial results...")
        if hasattr(scanner, 'save_results'):
            scanner.save_results()
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
