import argparse
import json
import logging
import subprocess
import re
import xml.etree.ElementTree as ET

from datetime import datetime
from pathlib import Path


# Logging Setup
def setup_logging(output_dir: Path):
    log_file = output_dir / "audit.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.info("Recon tool started")



# Command Runner
def run_command(command):
    logging.info(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )
        logging.info(f"Command completed with return code {result.returncode}")
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        logging.error(f"Command failed: {str(e)}")
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e)
        }


# Parse Nmap XML
def parse_nmap_xml(xml_data):
    hosts = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            address = host.find("address")
            if address is None:
                continue
            ip = address.get("addr")
            open_ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                service_name = None
                version = None
                if service is not None:
                    service_name = service.get("name")
                    product = service.get("product", "")
                    version_number = service.get("version", "")
                    version = f"{product} {version_number}".strip()
                open_ports.append({
                    "port": int(port.get("portid")),
                    "service": service_name,
                    "version": version
                })
            hosts.append({
                "ip": ip,
                "open_ports": open_ports
            })
    except Exception as e:
        logging.error(f"Nmap XML parse failed: {e}")
    return hosts


# Domain Recon
def domain_recon(target):
    results = {}

    # WHOIS
    whois_result = run_command(["whois", target])
    whois_data = {}
    if whois_result["success"]:
        output = whois_result["stdout"]
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiry_date": r"Registry Expiry Date:\s*(.+)",
            "organization": r"Registrant Organization:\s*(.+)"
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_data[key] = match.group(1).strip()
    results["whois"] = whois_data

    # DNS Records
    dns_results = {}
    for record_type in ["A", "MX", "NS", "TXT"]:
        dig_result = run_command(["dig", "+short", target, record_type])
        if dig_result["success"]:
            records = [
                line.strip()
                for line in dig_result["stdout"].splitlines()
                if line.strip()
            ]
            dns_results[record_type] = records
    results["dns"] = dns_results

    # HTTP Headers
    curl_result = run_command(["curl", "-I", f"https://{target}"])
    headers = {}
    if curl_result["success"]:
        for line in curl_result["stdout"].splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
    results["http_headers"] = headers

    return results


# IP Recon
def ip_recon(target):
    results = {}

    # Nmap Scan
    nmap_result = run_command([
        "nmap", "-sV", "--open", "--top-ports", "100", "-oX", "-", target
    ])
    if nmap_result["success"]:
        results["nmap"] = parse_nmap_xml(nmap_result["stdout"])
    else:
        results["nmap"] = {"error": nmap_result["stderr"]}

    # Reverse DNS
    reverse_dns = run_command(["dig", "+short", "-x", target])
    if reverse_dns["success"]:
        results["reverse_dns"] = [
            line.strip()
            for line in reverse_dns["stdout"].splitlines()
            if line.strip()
        ]

    # WHOIS IP
    whois_result = run_command(["whois", target])
    whois_data = {}
    if whois_result["success"]:
        output = whois_result["stdout"]
        patterns = {
            "organization": r"OrgName:\s*(.+)",
            "country": r"Country:\s*(.+)"
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_data[key] = match.group(1).strip()
    results["whois"] = whois_data

    return results


# Markdown Report
def generate_report(mode, target, results):
    report = f"""# Reconnaissance Report

Generated: {datetime.now().isoformat()}

Target: {target}
Mode: {mode}

---

"""

    # Domain Report
    if mode == "domain":
        report += "# WHOIS Information\n\n"
        for key, value in results.get("whois", {}).items():
            report += f"- **{key}**: {value}\n"

        report += "\n# DNS Records\n\n"
        for record_type, records in results.get("dns", {}).items():
            report += f"## {record_type}\n"
            for record in records:
                report += f"- {record}\n"
            report += "\n"

        report += "# HTTP Headers\n\n"
        headers = results.get("http_headers", {})
        for key, value in headers.items():
            report += f"- **{key}**: {value}\n"

        report += "\n# Security Header Analysis\n\n"
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options"
        ]
        missing = []
        for header in required_headers:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing.append(header)
        if missing:
            for header in missing:
                report += f"- Missing: {header}\n"
        else:
            report += "- All important security headers detected\n"

    # IP Report
    elif mode == "ip":
        report += "# Nmap Results\n\n"
        for host in results.get("nmap", []):
            report += f"## Host: {host['ip']}\n\n"
            for port in host.get("open_ports", []):
                report += (
                    f"- Port {port['port']} "
                    f"({port['service']}) "
                    f"- {port['version']}\n"
                )
            report += "\n"

        report += "# Reverse DNS\n\n"
        for entry in results.get("reverse_dns", []):
            report += f"- {entry}\n"

        report += "\n# WHOIS Information\n\n"
        for key, value in results.get("whois", {}).items():
            report += f"- **{key}**: {value}\n"

    return report



# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Integrated Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--mode", choices=["domain", "ip"], default=None, help="Recon mode")
    parser.add_argument("--output", default=None, help="Output directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Auto-detect mode
    if args.mode is None:
        if all(c.isdigit() or c == "." for c in args.target):
            mode = "ip"
        else:
            mode = "domain"
    else:
        mode = args.mode

    # Output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        output_dir = Path(args.output)
    else:
        safe_target = args.target.replace("/", "_")
        output_dir = Path(f"recon_{safe_target}_{timestamp}")

    output_dir.mkdir(exist_ok=True)

    # Logging
    setup_logging(output_dir)
    logging.info(f"Target: {args.target}")
    logging.info(f"Mode: {mode}")

    if args.verbose:
        print(f"[+] Output directory: {output_dir}")
        print(f"[+] Audit log initialized")

    results = {}

    # Domain Mode
    if mode == "domain":
        if args.verbose:
            print(f"[+] Running domain reconnaissance")
        results = domain_recon(args.target)

    # IP Mode
    elif mode == "ip":
        if args.verbose:
            print(f"[+] Running IP reconnaissance")
        results = ip_recon(args.target)

    # Save results.json
    results_file = output_dir / "results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=4)
    logging.info(f"Results written to {results_file}")

    # Generate markdown report
    report = generate_report(mode, args.target, results)
    report_file = output_dir / "report.md"
    with open(report_file, "w") as f:
        f.write(report)
    logging.info(f"Report written to {report_file}")

    print("Recon completed successfully")
