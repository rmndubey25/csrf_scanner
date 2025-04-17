# CSRF Security Testing Tool

An advanced Cross-Site Request Forgery (CSRF) vulnerability assessment tool for security professionals.

## Overview

This tool helps security professionals identify and demonstrate CSRF vulnerabilities in web applications during authorized security assessments. It features advanced detection capabilities, customizable testing parameters, and comprehensive reporting.

## Disclaimer

**This tool is provided for educational and authorized security testing purposes only.**

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

**Only use this tool on systems you are authorized to test.**

## Features

- Automated CSRF vulnerability detection
- Token extraction and validation testing
- Authentication support for protected applications
- Proxy support for testing behind WAFs
- Customizable headers and user agents
- Detailed security reporting
- PoC (Proof of Concept) generation
- Comprehensive logging for audit purposes

## Installation

```bash
# Clone the repository
git clone https://github.com/rmndubey25/csrf_scanner.git
cd csrf-tester

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python csrf_scanner --target https://example.com/vulnerable-form
```

### Advanced Usage

```bash
python csrf_scanner \
  --target https://example.com/vulnerable-form \
  --auth-url https://example.com/login \
  --username test_user \
  --password test_password \
  --cookie "session=abc123" \
  --header "X-Custom-Header=value" \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.110" \
  --timeout 45 \
  --output report.md \
  --verbose
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--target`, `-t` | Target URL to test (required) |
| `--auth-url` | Authentication URL |
| `--username` | Username for authentication |
| `--password` | Password for authentication |
| `--cookie` | Cookies in format name=value (can be used multiple times) |
| `--header` | Headers in format name=value (can be used multiple times) |
| `--proxy` | Proxy URL (e.g., http://127.0.0.1:8080) |
| `--user-agent` | User agent string |
| `--timeout` | Request timeout in seconds (default: 30) |
| `--no-verify-ssl` | Disable SSL verification |
| `--output`, `-o` | Output file for the report |
| `--verbose`, `-v` | Enable verbose output |
| `--quiet`, `-q` | Suppress all output except errors |
| `--disclaimer` | Print legal disclaimer and exit |

## API Usage

You can also use the tool as a library in your Python scripts:

```python
from csrf_tester import CSRFTester

# Initialize the tester
tester = CSRFTester(
    target_url="https://example.com/vulnerable-form",
    auth_url="https://example.com/login",
    cookies={"session": "abc123"},
    headers={"X-Custom-Header": "value"},
    proxy={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"},
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.110",
    timeout=30,
    verify_ssl=True
)

# Authenticate if needed
tester.authenticate("test_user", "test_password")

# Scan for vulnerabilities
results = tester.scan_for_csrf_vulnerabilities()

# Generate a report
report = tester.generate_report("report.md")
```

## Testing Methodology

The tool uses the following methodology to identify CSRF vulnerabilities:

1. Crawl and identify forms on the target website
2. Extract and analyze CSRF tokens if present
3. Test token validation mechanisms
4. Generate reports of potential vulnerabilities
5. Create proof-of-concept demonstrations

## WAF Bypass Considerations

This tool includes techniques for testing applications behind WAFs such as Cloudflare and Akamai:

- Customizable user agents and headers
- Configurable request patterns
- Proxy support for traffic routing
- Timing controls to avoid rate limiting

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/csrf)
