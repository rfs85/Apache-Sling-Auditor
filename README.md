# Apache Sling / AEM Auditor

A comprehensive security auditing tool designed for Apache Sling and Adobe Experience Manager (AEM) instances.

This tool helps identify misconfigurations, vulnerabilities, and potential security weaknesses in Sling/AEM environments.

## Features

- **Multi-mode Scanning:** Choose between `quick`, `full`, and `stealth` scan modes to suit your needs.
- **Comprehensive Security Checks:** Includes checks for:
    - Version detection (passive and active)
    - Authentication issues (default credentials, required auth paths)
    - Known vulnerability scanning (based on `config/audit_config.yaml`)
    - Exposed API endpoint enumeration
    - OSGI configuration auditing (including Dispatcher checks)
    - Content security analysis (sensitive path exposure)
    - JCR structure inspection (Planned)
- **Asynchronous Scanning:** Utilizes `asyncio` and `aiohttp` for efficient concurrent requests.
- **Configurable:** Customize scan behavior, paths, credentials, and vulnerabilities via `config/audit_config.yaml`.
- **Wordlist Support:** Use custom or generated wordlists for path enumeration.
- **Detailed Reporting:** Generates reports in multiple formats:
    - Rich console output with color-coded severity levels.
    - Detailed JSON report (`scan_results/<timestamp>/detailed_report.json`).
    - HTML Report (Planned).
    - Executive Summary Report (Planned).
- **Proxy Support:** Route traffic through an HTTP/HTTPS proxy.
- **Customizable:** Set user-agent, cookies, timeout, and concurrency level.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Apache-Sling-Auditor.git
cd Apache-Sling-Auditor

# Create a virtual environment (recommended)
python -m venv venv
# Activate the environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

**Basic Scan (Full Mode):**
```bash
python auditor.py -t http://example.com:4502
```

**Scan with Authentication and Verbose Output:**
```bash
python auditor.py -t https://secure.aem:4503 -u admin -p password -v
```

**Quick Scan:**
```bash
python auditor.py -t http://example.com:4502 --mode quick
```

**Stealth Scan:**
```bash
python auditor.py -t http://example.com:4502 --mode stealth
```

**Using a Wordlist:**
```bash
# First, generate the expanded wordlist (optional)
python wordlists/generate_paths.py

# Run the auditor with the generated wordlist
python auditor.py -t http://example.com:4502 --wordlist wordlists/sling_paths_generated.txt
```

**Full Options:**
```bash
python auditor.py -t <target_url> [options]

Options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target URL (e.g., http://example.com:4502)
  -u USERNAME, --username USERNAME
                        Username for authentication
  -p PASSWORD, --password PASSWORD
                        Password for authentication
  -o OUTPUT, --output OUTPUT
                        Output directory for scan results (default: scan_results)
  -T TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  -k, --insecure        Allow insecure SSL connections
  -v, --verbose         Enable verbose output
  --threads THREADS     Number of concurrent threads (default: 5)
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080)
  --mode {quick,full,stealth}
                        Scan mode: quick, full, or stealth (default: full)
  --user-agent USER_AGENT
                        Custom User-Agent string
  --cookies COOKIES     Cookies to include with requests (e.g., "key1=val1; key2=val2")
  --wordlist WORDLIST   Path to a custom wordlist file for path enumeration
```

## Configuration

The core behavior of the auditor can be customized via the `config/audit_config.yaml` file. This file defines:
- Scan mode settings (request limits, checks enabled)
- Paths to check (core, API, sensitive) with associated severities
- Default credentials to test
- Known vulnerabilities (CVEs, custom checks) with descriptions and remediation steps
- Specific security check configurations (authentication, content security, etc.)
- Reporting options

## Security Checks Detailed

The auditor performs various checks depending on the selected mode:

1.  **Version Detection (`check_version_full`, `check_version`, `check_version_passive`):**
    *   Attempts to identify Sling/AEM version via specific endpoints (`/system/console/productinfo`, `/libs/cq/core/content/welcome.html`).
    *   Passively analyzes server headers (`Server`, `X-Powered-By`).
    *   Correlates findings with known vulnerabilities (based on config).
2.  **Authentication (`check_authentication`, `check_basic_auth`):**
    *   Identifies paths requiring authentication.
    *   Tests default credentials provided in the configuration against authenticated paths.
    *   Checks session handling mechanisms (Planned).
3.  **Vulnerability Scanning (`check_vulnerabilities_full`, `check_critical_vulnerabilities`):**
    *   Probes for known vulnerabilities defined in `config/audit_config.yaml`.
    *   Checks vary based on scan mode (critical only for quick scan).
4.  **API Enumeration (`check_exposed_apis_full`):**
    *   Checks for publicly accessible API endpoints defined in the configuration.
5.  **Configuration Audit (`check_configuration_full`):**
    *   Looks for common misconfigurations like exposed OSGI console access.
    *   Checks for exposed Dispatcher configuration (`/dispatcher/invalidate.cache`).
    *   Analyzes error handling setup (Planned).
    *   Checks debug mode status (Planned).
6.  **Content Security (`check_content_security`, `run_safe_checks`):**
    *   Identifies exposure of sensitive content paths defined in the configuration (e.g., `/etc/passwords.json`).
    *   Performs safe checks for generally accessible endpoints (`/.json`, etc.) in stealth mode.
    *   Analyzes JCR node permissions (Planned).
    *   Checks replication agent configurations (Planned).
    *   Enumerates users/groups (Planned).
7.  **Path Enumeration (via `--wordlist`):**
    *   Uses the provided wordlist (`sling_paths.txt` or `sling_paths_generated.txt` by default) to discover accessible paths and resources.

## Wordlist Generation

The `wordlists/` directory contains:
- `sling_paths.txt`: A base list of common Sling/AEM paths, extensions, and parameters.
- `generate_paths.py`: A script to expand `sling_paths.txt` by creating combinations of paths, extensions, and parameters.
- `sling_paths_generated.txt`: The output of the generator script (created when you run it).

Run `python wordlists/generate_paths.py` to create the expanded wordlist.

## Output Formats

Results are saved in a timestamped directory within `scan_results/` (or the directory specified by `-o`).
- **Console:** Real-time progress and findings with severity highlighting.
- **JSON (`detailed_report.json`):** Comprehensive machine-readable report containing all findings and scan information.
- **HTML (Planned):** User-friendly graphical report.
- **Summary (Planned):** A concise overview of critical and high-severity findings.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a Pull Request. Ensure your code follows standard Python practices and includes relevant tests if applicable.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

**For Educational and Authorized Use Only.**
This tool is intended for security auditing and testing purposes by authorized personnel only. Unauthorized scanning of systems is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this tool. Always obtain explicit permission from the system owner before conducting any security assessments.