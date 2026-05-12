import socket
import time
import asyncio
import argparse
import json

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def parse_ports(port_string: str):

    ports = set()

    for part in port_string.split(","):

        if "-" in part:

            start, end = part.split("-")

            ports.update(
                range(int(start), int(end) + 1)
            )

        else:
            ports.add(int(part))

    return sorted(ports)


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.settimeout(timeout)

        try:
            s.connect((host, port))
            return True

        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

def threaded_scan(host: str, ports: range, workers: int, timeout: float):

    with ThreadPoolExecutor(max_workers=workers) as executor:

        results = executor.map(
            lambda port: scan_port(host, port, timeout),
            ports
        )

    open_ports = [
        port
        for port, is_open in zip(ports, results)
        if is_open
    ]

    return open_ports

async def async_scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0):

    async with semaphore:

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            writer.close()
            await writer.wait_closed()

            return port

        except (
            asyncio.TimeoutError,
            ConnectionRefusedError,
            OSError
        ):
            return None

async def async_scan_host(host: str, ports: range, max_concurrent: int, timeout: float):

    semaphore = asyncio.Semaphore(max_concurrent)

    tasks = [
        async_scan_port(host, port, semaphore)
        for port in ports
    ]

    results = await asyncio.gather(*tasks)

    open_ports = sorted([
        port for port in results
        if port is not None
    ])

    return open_ports



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Concurrent Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address"
    )

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range or list (example: 1-1024 or 22,80,443)"
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=200,
        help="Maximum concurrent connections"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Per-port timeout"
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file"
    )

    parser.add_argument(
        "--mode",
        choices=["threaded", "async"],
        default="async",
        help="Scanner mode"
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    start = time.perf_counter()

    if args.mode == "threaded":

        open_ports = threaded_scan(
            args.target,
            ports,
            args.rate,
            args.timeout
        )

    else:

        open_ports = asyncio.run(
            async_scan_host(
                args.target,
                ports,
                args.rate,
                args.timeout
            )
        )

    elapsed = time.perf_counter() - start

    results = {
        "target": args.target,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": datetime.now().isoformat(),
        "open_ports": open_ports
    }

    print(json.dumps(results, indent=4))

    if args.output:

        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)

        print(f"\nResults saved to: {args.output}")
