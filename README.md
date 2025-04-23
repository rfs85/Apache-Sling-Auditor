# Apache Sling Auditor

A comprehensive security auditing tool for Apache Sling and Adobe Experience Manager (AEM) instances.

## Features

- Multi-mode scanning (quick, full, stealth)
- Comprehensive vulnerability checks
- Default credential testing
- JCR structure analysis
- OSGI configuration auditing
- Exposed API detection
- Security misconfigurations detection
- Detailed reporting in multiple formats

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Apache-Sling-Auditor.git
cd Apache-Sling-Auditor

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python auditor.py -t http://example.com:4502
```

Full options:
```bash
python auditor.py -t http://example.com:4502 [options]

Options:
  -t, --target TARGET     Target URL (e.g., http://example.com:4502)
  -u, --username USER     Username for authentication
  -p, --password PASS     Password for authentication
  -o, --output FILE      Output file for JSON results
  -T, --timeout SEC      Request timeout in seconds (default: 10)
  -k, --insecure        Allow insecure SSL connections
  -v, --verbose         Enable verbose output
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080)
  --mode {quick,full,stealth}
                        Scan mode (default: full)
```

## Scan Modes

- **Quick**: Basic checks for common vulnerabilities and misconfigurations
- **Full**: Comprehensive security audit including all checks
- **Stealth**: Minimal footprint scanning with reduced requests

## Security Checks

1. Version Detection
   - AEM/Sling version identification
   - Known vulnerability correlation

2. Authentication
   - Default credential testing
   - Authentication bypass attempts
   - Session handling analysis

3. Access Control
   - Path traversal checks
   - Directory listing
   - Sensitive path exposure

4. Configuration
   - OSGI console security
   - Dispatcher configuration
   - Error handling setup
   - Debug mode status

5. Content Security
   - JCR node permissions
   - Replication agents
   - User/group enumeration
   - Content exposure

## Output Formats

Results are provided in multiple formats:
- Console output with severity-based highlighting
- Detailed JSON report
- Summary of critical findings

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is meant for security auditing by authorized individuals only. Always obtain proper authorization before scanning any systems.