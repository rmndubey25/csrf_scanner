#!/usr/bin/env python3
"""
CSRF Security Testing Tool

This tool is designed for security professionals to test for CSRF vulnerabilities
in web applications they are authorized to test. Always obtain proper permission
before conducting security testing.

Features:
- Customizable request parameters
- Token extraction and analysis
- Proxy support for testing environments
- Detailed reporting
- Logging for audit purposes
"""

import argparse
import logging
import random
import re
import string
import sys
import time
from typing import Dict, List, Optional, Tuple, Union
import json
import os

import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("csrf_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("csrf_tester")

class CSRFTester:
    def __init__(self, target_url: str, auth_url: Optional[str] = None,
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 proxy: Optional[Dict] = None, user_agent: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize the CSRF tester with required parameters
        
        Args:
            target_url: The URL to test for CSRF vulnerabilities
            auth_url: Optional URL for authentication
            cookies: Optional cookies to include
            headers: Optional headers to include
            proxy: Optional proxy configuration
            user_agent: Optional user agent string
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.target_url = target_url
        self.auth_url = auth_url
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.proxy = proxy
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # Add default user agent if not provided
        if user_agent:
            self.headers['User-Agent'] = user_agent
        else:
            self.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        
        # Configure session
        self.session.headers.update(self.headers)
        if cookies:
            self.session.cookies.update(cookies)
        
        if proxy:
            self.session.proxies.update(proxy)
        
        self.authenticated = False
        self.csrf_tokens = {}
        self.test_results = []
        
        logger.info(f"Initialized CSRF tester for target: {target_url}")

    def authenticate(self, username: str, password: str, auth_form_data: Optional[Dict] = None) -> bool:
        """
        Authenticate to the target application
        
        Args:
            username: Username for authentication
            password: Password for authentication
            auth_form_data: Additional form data needed for authentication
            
        Returns:
            bool: True if authentication was successful
        """
        if not self.auth_url:
            logger.error("Authentication URL not provided")
            return False
            
        logger.info(f"Attempting to authenticate to {self.auth_url}")
        
        # Get the login page to extract any CSRF tokens
        try:
            response = self.session.get(self.auth_url, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
            
            # Extract CSRF token if it exists
            csrf_token = self._extract_csrf_token(response.text, response.url)
            
            # Prepare authentication data
            auth_data = auth_form_data or {}
            auth_data.update({
                'username': username,
                'password': password
            })
            
            if csrf_token:
                csrf_field_name = csrf_token.get('name', 'csrf_token')
                auth_data[csrf_field_name] = csrf_token.get('value', '')
            
            # Submit authentication request
            auth_response = self.session.post(
                self.auth_url,
                data=auth_data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            # Check if authentication was successful (this logic may need to be customized)
            if auth_response.status_code == 200 and 'login' not in auth_response.url.lower():
                self.authenticated = True
                logger.info("Authentication successful")
                return True
            else:
                logger.warning("Authentication failed")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Authentication error: {e}")
            return False

    def scan_for_csrf_vulnerabilities(self, forms_data: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Scan for CSRF vulnerabilities in the target application
        
        Args:
            forms_data: Optional predefined forms to test
            
        Returns:
            List of test results with vulnerability information
        """
        logger.info(f"Starting CSRF vulnerability scan on {self.target_url}")
        
        try:
            # Get the target page
            response = self.session.get(
                self.target_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            # If forms_data is not provided, extract forms from the page
            if not forms_data:
                forms_data = self._extract_forms(response.text)
            
            if not forms_data:
                logger.warning("No forms found to test for CSRF vulnerabilities")
                return []
            
            # Test each form for CSRF vulnerabilities
            for form in forms_data:
                self._test_form_for_csrf(form)
            
            logger.info(f"Completed CSRF vulnerability scan. Found {sum(1 for r in self.test_results if r['vulnerable'])} vulnerable forms.")
            return self.test_results
            
        except requests.RequestException as e:
            logger.error(f"Error during CSRF scan: {e}")
            return self.test_results

    def _test_form_for_csrf(self, form: Dict) -> None:
        """
        Test a specific form for CSRF vulnerabilities
        
        Args:
            form: Dictionary containing form information
        """
        form_url = form.get('action', self.target_url)
        form_method = form.get('method', 'POST').upper()
        form_id = form.get('id', 'unknown_form')
        
        logger.info(f"Testing form '{form_id}' with method {form_method} at {form_url}")
        
        # Check if the form has a CSRF token
        has_csrf_token = False
        csrf_token_field = None
        
        for field in form.get('fields', []):
            field_name = field.get('name', '').lower()
            if 'csrf' in field_name or 'token' in field_name:
                has_csrf_token = True
                csrf_token_field = field
                break
        
        # Prepare test result
        test_result = {
            'form_id': form_id,
            'url': form_url,
            'method': form_method,
            'has_csrf_token': has_csrf_token,
            'vulnerable': False,
            'details': '',
            'mitigation': '',
            'timestamp': time.time()
        }
        
        # If the form has no CSRF token, it might be vulnerable
        if not has_csrf_token:
            test_result['vulnerable'] = True
            test_result['details'] = "Form does not contain a CSRF token"
            test_result['mitigation'] = "Implement CSRF tokens for this form"
        else:
            # Test if the CSRF token is properly validated
            test_result['vulnerable'] = self._test_csrf_token_validation(form, csrf_token_field)
            if test_result['vulnerable']:
                test_result['details'] = "CSRF token exists but validation may be insufficient"
                test_result['mitigation'] = "Ensure server-side validation of CSRF tokens"
        
        self.test_results.append(test_result)
        
        if test_result['vulnerable']:
            logger.warning(f"Potential CSRF vulnerability found in form '{form_id}'")
        else:
            logger.info(f"Form '{form_id}' appears to be protected against CSRF")

    def _test_csrf_token_validation(self, form: Dict, csrf_field: Dict) -> bool:
        """
        Test if CSRF token validation is properly implemented
        
        Args:
            form: Dictionary containing form information
            csrf_field: CSRF token field information
            
        Returns:
            bool: True if the form may be vulnerable
        """
        # Strategy: Submit the form with a modified token and see if it's accepted
        form_url = form.get('action', self.target_url)
        form_method = form.get('method', 'POST').upper()
        
        # Prepare form data with all required fields
        form_data = {}
        for field in form.get('fields', []):
            if field.get('required', False) or field.get('name') == csrf_field.get('name'):
                # For non-CSRF fields, use provided value or a generic test value
                if field.get('name') != csrf_field.get('name'):
                    form_data[field.get('name')] = field.get('value', 'test_value')
        
        # Set an invalid CSRF token
        form_data[csrf_field.get('name')] = self._generate_invalid_token(csrf_field.get('value', ''))
        
        try:
            # Submit the form with the invalid token
            if form_method == 'POST':
                response = self.session.post(
                    form_url,
                    data=form_data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
            else:  # GET
                response = self.session.get(
                    form_url,
                    params=form_data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
            
            # If the request was accepted (200 OK) or redirected (302),
            # the CSRF token might not be properly validated
            if response.status_code == 200 or response.status_code == 302:
                # Look for error messages in the response
                error_patterns = ['invalid token', 'csrf', 'security', 'error', 'invalid']
                response_text = response.text.lower()
                
                if not any(pattern in response_text for pattern in error_patterns):
                    return True  # Potentially vulnerable
            
            return False  # Likely not vulnerable
            
        except requests.RequestException:
            # If an error occurred, we can't determine if the form is vulnerable
            return False

    def _generate_invalid_token(self, original_token: str) -> str:
        """
        Generate an invalid CSRF token based on the original token
        
        Args:
            original_token: The original CSRF token
            
        Returns:
            str: An invalid CSRF token
        """
        # If the original token is short, generate a completely new one
        if len(original_token) < 10:
            return ''.join(random.choices(string.ascii_letters + string.digits, k=len(original_token) + 5))
        
        # Otherwise, modify the original token
        if original_token.isalnum():
            # If alphanumeric, change some characters
            token_chars = list(original_token)
            for i in range(min(5, len(token_chars))):
                pos = random.randint(0, len(token_chars) - 1)
                token_chars[pos] = random.choice(string.ascii_letters + string.digits)
            return ''.join(token_chars)
        else:
            # For more complex tokens (possibly base64 or hex), add some random chars
            return original_token + ''.join(random.choices(string.ascii_letters + string.digits, k=5))

    def _extract_forms(self, html_content: str) -> List[Dict]:
        """
        Extract forms from HTML content
        
        Args:
            html_content: HTML content to parse
            
        Returns:
            List of dictionaries containing form information
        """
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form_el in soup.find_all('form'):
            form = {
                'id': form_el.get('id', f"form_{len(forms)}"),
                'action': form_el.get('action', self.target_url),
                'method': form_el.get('method', 'post'),
                'fields': []
            }
            
            # Ensure action URL is absolute
            if not form['action'].startswith(('http://', 'https://')):
                base_url = urlparse(self.target_url)
                if form['action'].startswith('/'):
                    form['action'] = f"{base_url.scheme}://{base_url.netloc}{form['action']}"
                else:
                    path = os.path.dirname(base_url.path)
                    form['action'] = f"{base_url.scheme}://{base_url.netloc}{path}/{form['action']}"
            
            # Extract input fields
            for input_el in form_el.find_all(['input', 'textarea', 'select']):
                field = {
                    'name': input_el.get('name', ''),
                    'type': input_el.get('type', 'text') if input_el.name == 'input' else input_el.name,
                    'value': input_el.get('value', ''),
                    'required': input_el.has_attr('required')
                }
                
                if field['name']:  # Only include fields with names
                    form['fields'].append(field)
            
            forms.append(form)
        
        return forms

    def _extract_csrf_token(self, html_content: str, url: str) -> Optional[Dict]:
        """
        Extract CSRF token from HTML content
        
        Args:
            html_content: HTML content to parse
            url: URL of the page
            
        Returns:
            Dictionary containing CSRF token information or None
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Common CSRF token field names
        csrf_patterns = [
            re.compile(r'csrf', re.I),
            re.compile(r'token', re.I),
            re.compile(r'_token', re.I),
            re.compile(r'nonce', re.I),
            re.compile(r'xsrf', re.I)
        ]
        
        # Look for meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            if any(pattern.search(name) for pattern in csrf_patterns):
                return {
                    'name': meta.get('name'),
                    'value': meta.get('content', ''),
                    'type': 'meta'
                }
        
        # Look for input fields
        for input_tag in soup.find_all('input', type=['hidden', 'text']):
            name = input_tag.get('name', '').lower()
            if any(pattern.search(name) for pattern in csrf_patterns):
                return {
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', ''),
                    'type': 'input'
                }
        
        # Look for data attributes on body or html
        for tag in [soup.html, soup.body]:
            if not tag:
                continue
                
            for attr_name, attr_value in tag.attrs.items():
                if any(pattern.search(attr_name) for pattern in csrf_patterns):
                    return {
                        'name': attr_name,
                        'value': attr_value,
                        'type': 'attribute'
                    }
        
        # Check for CSRF token in JavaScript
        script_patterns = [
            r'csrf[\s]*[=:][\s]*[\'"]([^\'"]+)[\'"]',
            r'token[\s]*[=:][\s]*[\'"]([^\'"]+)[\'"]',
            r'_token[\s]*[=:][\s]*[\'"]([^\'"]+)[\'"]'
        ]
        
        for script in soup.find_all('script'):
            script_content = script.string if script.string else ""
            for pattern in script_patterns:
                match = re.search(pattern, script_content)
                if match:
                    return {
                        'name': 'csrf_token',
                        'value': match.group(1),
                        'type': 'script'
                    }
        
        return None

    def generate_csrf_poc(self, vulnerable_form: Dict) -> str:
        """
        Generate a Proof of Concept (PoC) HTML page for the vulnerable form
        
        Args:
            vulnerable_form: Form information for the vulnerable form
            
        Returns:
            str: HTML content for the PoC
        """
        form_url = vulnerable_form.get('url', self.target_url)
        form_method = vulnerable_form.get('method', 'POST').upper()
        
        poc_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF PoC - For Educational Purposes Only</title>
            <meta charset="UTF-8">
        </head>
        <body>
            <h3>CSRF Vulnerability Demonstration (For authorized security testing only)</h3>
            <p>This page demonstrates a CSRF vulnerability in the target application.</p>
            <p>This is a security testing tool and should only be used on systems you are authorized to test.</p>
            
            <form id="csrf-poc" action="{form_url}" method="{form_method}">
        """
        
        # Add form fields
        for field in vulnerable_form.get('fields', []):
            if not field.get('name', '').lower() in ['csrf', 'token', '_token', 'csrf_token']:
                field_value = field.get('value', 'test_value')
                poc_html += f'    <input type="hidden" name="{field.get("name")}" value="{field_value}">\n'
        
        poc_html += """
            </form>
            
            <p>The form will be automatically submitted. This is only for demonstrating the vulnerability.</p>
            
            <script>
                // Auto-submit the form when the page loads
                window.onload = function() {
                    // Uncomment the line below to enable auto-submission in a real test
                    // document.getElementById('csrf-poc').submit();
                    console.log('CSRF PoC ready. Uncomment the auto-submit line to enable in a real test.');
                };
            </script>
        </body>
        </html>
        """
        
        return poc_html

    def generate_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate a security report based on test results
        
        Args:
            output_file: Optional file path to save the report
            
        Returns:
            str: Report content
        """
        vulnerable_forms = [r for r in self.test_results if r['vulnerable']]
        safe_forms = [r for r in self.test_results if not r['vulnerable']]
        
        report = f"""
        # CSRF Vulnerability Assessment Report
        
        Target: {self.target_url}
        Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
        
        ## Summary
        
        - Total forms tested: {len(self.test_results)}
        - Vulnerable forms: {len(vulnerable_forms)}
        - Protected forms: {len(safe_forms)}
        
        ## Vulnerable Forms
        
        """
        
        if vulnerable_forms:
            for idx, form in enumerate(vulnerable_forms, 1):
                report += f"""
                ### Vulnerable Form {idx}: {form['form_id']}
                
                - URL: {form['url']}
                - Method: {form['method']}
                - Has CSRF Token: {'Yes' if form['has_csrf_token'] else 'No'}
                - Details: {form['details']}
                - Recommended Mitigation: {form['mitigation']}
                
                """
        else:
            report += "No vulnerable forms found.\n"
        
        report += """
        ## Recommendations
        
        1. Implement anti-CSRF tokens for all state-changing forms and requests
        2. Ensure tokens are properly validated on the server side
        3. Use SameSite=Strict cookies where possible
        4. Implement proper Content-Type checks for JSON endpoints
        
        ## Disclaimer
        
        This report was generated by an automated tool and should be verified by a security professional.
        Some vulnerabilities might be false positives, and some might have been missed.
        """
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {output_file}")
            
        return report


def main():
    """Main function to run the CSRF tester from command line"""
    parser = argparse.ArgumentParser(description='CSRF Security Testing Tool')
    parser.add_argument('--target', '-t', required=True, help='Target URL to test')
    parser.add_argument('--auth-url', help='Authentication URL')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--cookie', action='append', help='Cookies in format name=value')
    parser.add_argument('--header', action='append', help='Headers in format name=value')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='User agent string')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    parser.add_argument('--output', '-o', help='Output file for the report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress all output except errors')
    parser.add_argument('--disclaimer', action='store_true', help='Print legal disclaimer and exit')
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.ERROR)
    
    # Show legal disclaimer
    if args.disclaimer:
        print("""
        Legal Disclaimer:
        
        This tool is provided for educational and authorized security testing purposes only.
        Usage of this tool for attacking targets without prior mutual consent is illegal.
        It is the end user's responsibility to obey all applicable local, state, national,
        and international laws. The developers assume no liability and are not responsible
        for any misuse or damage caused by this program.
        
        Only use this tool on systems you are authorized to test.
        """)
        sys.exit(0)
    
    # Parse cookies and headers
    cookies = {}
    if args.cookie:
        for cookie in args.cookie:
            name, value = cookie.split('=', 1)
            cookies[name] = value
    
    headers = {}
    if args.header:
        for header in args.header:
            name, value = header.split('=', 1)
            headers[name] = value
    
    # Configure proxy
    proxy = None
    if args.proxy:
        proxy = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    # Initialize the CSRF tester
    tester = CSRFTester(
        target_url=args.target,
        auth_url=args.auth_url,
        cookies=cookies,
        headers=headers,
        proxy=proxy,
        user_agent=args.user_agent,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl
    )
    
    # Authenticate if credentials are provided
    if args.auth_url and args.username and args.password:
        if not tester.authenticate(args.username, args.password):
            logger.error("Authentication failed. Continuing without authentication.")
    
    # Scan for CSRF vulnerabilities
    tester.scan_for_csrf_vulnerabilities()
    
    # Generate and save the report
    report = tester.generate_report(args.output)
    if not args.quiet and not args.output:
        print(report)
    
    # Print summary
    vulnerable_forms = sum(1 for r in tester.test_results if r['vulnerable'])
    logger.info(f"Testing completed. Found {vulnerable_forms} potentially vulnerable forms out of {len(tester.test_results)} tested.")
    
    if args.output:
        logger.info(f"Detailed report saved to {args.output}")


if __name__ == "__main__":
    print("""
    CSRF Security Testing Tool
    For authorized security testing purposes only.
    
    This tool should only be used on systems you are authorized to test.
    Unauthorized testing may violate computer crime laws.
    """)
    main()