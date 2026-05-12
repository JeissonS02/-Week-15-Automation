# Network Automation and Reconnaissance Toolkit

This project was developed as part of a hands-on lab focused on Python-based network automation, concurrent scanning, structured parsing, log analysis, anomaly detection, and integrated reconnaissance workflows.

The toolkit includes:
- A concurrent port scanner
- An Nmap XML parser and enricher
- Authentication log analysis
- Web access log analysis with anomaly detection
- An integrated reconnaissance tool

---

# Python Version

Tested with:

```bash
Python 3.13+
```

---

# Dependencies

Install required tools and dependencies:

```bash
sudo apt update

sudo apt install -y \
    nmap \
    whois \
    dnsutils \
    curl

pip install --upgrade pip
```

This project uses only Python standard library modules:
- argparse
- asyncio
- concurrent.futures
- collections
- datetime
- json
- logging
- pathlib
- re
- socket
- statistics
- subprocess
- xml.etree.ElementTree

No third-party Python packages are required.

---

# Project Structure

```text
.
├── scanner.py
├── parse_scan.py
├── auth_analysis.py
├── log_analysis.py
├── recon.py
├── sample_output
│   ├── audit.log
│   ├── report.md
│   └── results.json
└── README.md
```

---

# Part 1 — Concurrent Port Scanner

File:

```text
scanner.py
```

## Features

- Sequential TCP scanner
- ThreadPoolExecutor implementation
- asyncio + Semaphore implementation
- Configurable concurrency
- Port range parsing
- JSON output support
- CLI interface using argparse

## Example Usage

### Async mode

```bash
python3 scanner.py 127.0.0.1
```

### Threaded mode

```bash
python3 scanner.py 127.0.0.1 --mode threaded
```

### Custom port range

```bash
python3 scanner.py 127.0.0.1 --ports 1-100
```

### Specific ports

```bash
python3 scanner.py 127.0.0.1 --ports 22,80,443
```

### Export results

```bash
python3 scanner.py 127.0.0.1 --output results.json
```

## Design Choices

The scanner was implemented using both threads and asyncio to compare concurrency models for network I/O workloads. A semaphore was used in the asyncio implementation to safely cap concurrent socket operations and avoid resource exhaustion. JSON output was chosen to facilitate automation and integration with other tools.

---

# Part 2 — Nmap XML Parser and Enricher

File:

```text
parse_scan.py
```

## Features

- Parses Nmap XML output
- Extracts:
  - IP addresses
  - hostnames
  - open ports
  - services
  - service versions
- Enriches SSH hosts using ssh-keyscan
- JSON export
- argparse CLI

## Generate XML Scan

```bash
nmap -sV --open -oX scan.xml 127.0.0.1
```

## Example Usage

```bash
python3 parse_scan.py --input scan.xml
```

## Design Choices

The parser uses Python's built-in xml.etree.ElementTree library to avoid external dependencies. SSH enrichment was implemented through subprocess and ssh-keyscan to demonstrate integration with external system tools while maintaining structured output.

---

# Part 3 — Authentication and Web Log Analysis

## Authentication Analysis

File:

```text
auth_analysis.py
```

## Features

- Failed login detection
- Brute-force analysis
- Targeted user analysis
- Failed/success login ratio
- JSON export

## Example Usage

```bash
python3 auth_analysis.py --input auth.log
```

## Design Choices

Regular expressions were used for flexible parsing of SSH authentication logs. Counter objects simplified frequency analysis and brute-force detection.

---

## Web Access Log Analysis

File:

```text
log_analysis.py
```

## Features

- SQL injection detection
- XSS detection
- Path traversal detection
- Command injection detection
- Top IP analysis
- HTTP status distribution
- 3-sigma anomaly detection
- Markdown report generation

## Example Usage

```bash
python3 log_analysis.py --input access.log
```

## Design Choices

Regex-based detection was selected for simplicity and transparency. Statistical anomaly detection was implemented using the 3-sigma rule to identify unusual traffic spikes while keeping the implementation lightweight and dependency-free.

---

# Part 4 — Integrated Reconnaissance Tool

File:

```text
recon.py
```

## Features

### Domain Mode

- WHOIS lookup
- DNS enumeration
- HTTP header collection
- Security header analysis

### IP Mode

- Nmap service scanning
- Reverse DNS lookup
- IP WHOIS analysis

### General Features

- Automatic mode detection
- Structured JSON output
- Markdown reporting
- Audit logging
- Independent failure handling
- Configurable output directory

## Example Usage

### Domain reconnaissance

```bash
python3 recon.py example.com --verbose
```

### IP reconnaissance

```bash
python3 recon.py 127.0.0.1 --verbose
```

## Design Choices

The reconnaissance tool was designed with modular functions to isolate failures and simplify maintenance. Each reconnaissance step executes independently so that one failing command does not terminate the entire workflow. Structured JSON output enables future automation and integration, while Markdown reporting improves readability for analysts and documentation purposes.

---

# Sample Output

The `sample_output/` directory contains:
- `results.json`
- `report.md`
- `audit.log`

generated from a real execution of:

```bash
python3 recon.py example.com --verbose
```

---

# Notes

This project was developed for educational and authorized security testing purposes only.

Always ensure you have permission before scanning or analyzing systems you do not own.
