"""
Port scanner — wraps nmap via python-nmap.

Runs in a thread-pool executor so the async scan pipeline is never blocked.
Each call creates its own PortScanner instance (nmap.PortScanner is not
thread-safe when shared).

Scan type:
  -sT (TCP connect) — works without root or any Linux capabilities.
  Set scan_arguments in config to "-sS -T4 -sV --open" to enable SYN
  scanning; that requires NET_RAW capability in Docker (see docker-compose).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Ports that matter for asset-monitoring purposes.
DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,"
    "636,993,995,1433,1521,2222,2375,2376,3000,3306,3389,4443,4848,"
    "5000,5432,5672,5900,5984,6379,7000,7001,7199,8000,8080,8081,"
    "8443,8888,8983,9000,9042,9090,9200,9300,9443,11211,15672,27017,"
    "27018,28017,50000,61616"
)


def _scan_sync(
    host: str,
    ports: str,
    arguments: str,
    timeout: int,
) -> dict:
    """Run one nmap scan synchronously (intended for executor use)."""
    try:
        import nmap  # imported here so import failure surfaces at scan time
    except ImportError:
        logger.error("python-nmap is not installed — port scanning unavailable")
        return _error_result(host, "python-nmap not installed")

    nm = nmap.PortScanner()
    result: dict = {
        "host": host,
        "status": "down",
        "open_ports": [],
        "scan_duration": 0.0,
        "error": None,
    }

    t0 = time.monotonic()
    try:
        nm.scan(hosts=host, ports=ports, arguments=arguments, timeout=timeout)
        result["scan_duration"] = round(time.monotonic() - t0, 2)

        # nmap may resolve hostname to a different key
        hosts_found = nm.all_hosts()
        if not hosts_found:
            result["status"] = "down"
            return result

        host_key = hosts_found[0]
        host_data = nm[host_key]
        result["status"] = host_data.state()

        for proto in host_data.all_protocols():
            for port, port_data in sorted(host_data[proto].items()):
                if port_data["state"] == "open":
                    result["open_ports"].append({
                        "port": int(port),
                        "protocol": proto,
                        "state": port_data["state"],
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                    })

    except Exception as exc:
        result["scan_duration"] = round(time.monotonic() - t0, 2)
        result["error"] = str(exc)
        logger.warning("nmap scan failed for %s: %s", host, exc)

    return result


def _error_result(host: str, msg: str) -> dict:
    return {
        "host": host,
        "status": "error",
        "open_ports": [],
        "scan_duration": 0.0,
        "error": msg,
    }


async def scan_host(
    host: str,
    ports: str = DEFAULT_PORTS,
    arguments: str = "-sT -T4 -sV --version-intensity 2 --open",
    timeout: int = 120,
) -> dict:
    """Async wrapper: runs the nmap scan in the default thread-pool executor.

    Args:
        host:      IP address or hostname to scan.
        ports:     Comma-separated port list or nmap range string.
        arguments: Additional nmap CLI flags.
        timeout:   Max seconds for the nmap process.

    Returns:
        Dict with keys: host, status, open_ports (list), scan_duration, error.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _scan_sync, host, ports, arguments, timeout
    )
