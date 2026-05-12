import argparse
import json
import subprocess
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_file: str):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts_data = []

    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr")

        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname_tag = hostnames.find("hostname")
            if hostname_tag is not None:
                hostname = hostname_tag.get("name")

        open_ports = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None:
                continue
            if state.get("state") != "open":
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

        host_info = {
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports
        }

        ssh_open = any(
            port["port"] == 22
            for port in open_ports
        )
        if ssh_open:
            host_info["ssh_host_key_type"] = get_ssh_key_types(ip)

        hosts_data.append(host_info)

    return hosts_data


def get_ssh_key_types(ip: str):
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", "5", ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        key_types = set()
        for line in result.stdout.splitlines():
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                key_types.add(parts[1])
        return sorted(list(key_types))
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        subprocess.SubprocessError
    ):
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse Nmap XML output"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input XML file"
    )
    parser.add_argument(
        "--output",
        default="hosts.json",
        help="Output JSON file"
    )
    args = parser.parse_args()

    results = parse_nmap_xml(args.input)
    print(json.dumps(results, indent=4))

    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nResults saved to: {args.output}")
