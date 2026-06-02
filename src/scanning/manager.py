"""
Port scan orchestrator.

For each scan cycle:
  1. Collect all live subdomains from the DB.
  2. Scan each FQDN (and any raw IPs stored against it) for open ports.
  3. Compare results against the previous scan for the same host.
  4. Persist new PortScan + OpenPort rows.
  5. Emit PORT_OPENED / PORT_CLOSED ChangeEvent rows for any delta.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from .port_scanner import DEFAULT_PORTS, scan_host

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    # Ports that signal high-value exposure when newly opened
    22: "MEDIUM", 23: "HIGH", 25: "MEDIUM", 3389: "HIGH", 5900: "HIGH",
    5901: "HIGH", 2375: "CRITICAL", 2376: "HIGH",  # Docker daemon
    6379: "HIGH", 11211: "HIGH",  # Redis, Memcached unauthenticated
    27017: "HIGH", 27018: "HIGH",  # MongoDB
    9200: "HIGH", 9300: "HIGH",   # Elasticsearch
    5432: "MEDIUM", 3306: "MEDIUM", 1521: "MEDIUM", 1433: "MEDIUM",
}


def _port_severity(port: int) -> str:
    return _SEVERITY_MAP.get(port, "LOW")


class PortScanManager:
    """Coordinates port scans for all monitored hosts and records changes."""

    def __init__(self, config: "AppConfig", db: "DatabaseManager") -> None:
        self._config = config
        self._db = db

    async def scan_all(self) -> list:
        """Scan every live subdomain and return new ChangeEvent objects."""
        ps_cfg = getattr(self._config, "port_scanning", None)
        if ps_cfg and not getattr(ps_cfg, "enabled", True):
            logger.info("Port scanning disabled in config — skipping")
            return []

        ports = DEFAULT_PORTS
        if ps_cfg:
            ports = getattr(ps_cfg, "ports", DEFAULT_PORTS) or DEFAULT_PORTS

        arguments = "-sT -T4 -sV --version-intensity 2 --open"
        if ps_cfg:
            arguments = getattr(ps_cfg, "scan_arguments", arguments) or arguments

        scan_timeout = 120
        if ps_cfg:
            scan_timeout = getattr(ps_cfg, "timeout_seconds", scan_timeout) or 120

        max_concurrent = 5
        if ps_cfg:
            max_concurrent = getattr(ps_cfg, "max_concurrent", max_concurrent) or 5

        # Collect targets: all live subdomains
        targets: list[tuple[str, int]] = []  # (fqdn, subdomain_id)
        all_domains = self._db.get_all_domains()
        seen_hosts: set[str] = set()

        for dom in all_domains:
            live = self._db.get_live_subdomains(dom.id)
            for sub in live:
                if sub.fqdn not in seen_hosts:
                    seen_hosts.add(sub.fqdn)
                    targets.append((sub.fqdn, sub.id))

        if not targets:
            logger.info("PortScanManager: no live subdomains to scan")
            return []

        logger.info("PortScanManager: scanning %d host(s)", len(targets))

        # Semaphore to cap concurrency
        sem = asyncio.Semaphore(max_concurrent)
        all_events: list = []

        async def _scan_one(fqdn: str, subdomain_id: int) -> None:
            async with sem:
                try:
                    raw = await scan_host(
                        host=fqdn,
                        ports=ports,
                        arguments=arguments,
                        timeout=scan_timeout,
                    )
                    events = self._persist_and_diff(fqdn, subdomain_id, raw)
                    all_events.extend(events)
                except Exception as exc:
                    logger.error("Port scan error for %s: %s", fqdn, exc)

        await asyncio.gather(*[_scan_one(f, sid) for f, sid in targets])
        logger.info("PortScanManager: scan complete — %d event(s)", len(all_events))
        return all_events

    def _persist_and_diff(
        self,
        host: str,
        subdomain_id: int,
        raw: dict,
    ) -> list:
        """Save the scan result and emit change events for port deltas."""
        current_ports: set[tuple[int, str]] = {
            (p["port"], p["protocol"]) for p in raw.get("open_ports", [])
        }

        # Retrieve previous scan to diff against
        prev_scan = self._db.get_latest_port_scan(host)
        prev_ports: set[tuple[int, str]] = set()
        if prev_scan is not None:
            prev_port_rows = self._db.get_open_ports_for_scan(prev_scan.id)
            prev_ports = {(r.port, r.protocol) for r in prev_port_rows}

        # Persist the new scan
        self._db.add_port_scan(
            host=host,
            subdomain_id=subdomain_id,
            status=raw.get("status", "unknown"),
            scan_duration=raw.get("scan_duration", 0.0),
            error=raw.get("error"),
            ports=raw.get("open_ports", []),
        )

        events: list = []

        # Only diff when we have a previous scan
        if prev_scan is None:
            return events

        port_info = {
            (p["port"], p["protocol"]): p
            for p in raw.get("open_ports", [])
        }

        for (port, proto) in current_ports - prev_ports:
            info = port_info.get((port, proto), {})
            svc = info.get("service", "")
            prod = info.get("product", "")
            label = f"{prod} {svc}".strip() or "unknown"
            sev = _port_severity(port)
            ev = self._db.add_change_event(
                event_type="PORT_OPENED",
                severity=sev,
                target=host,
                description=f"Port opened: {port}/{proto} ({label}) on {host}",
                diff_data={"port": port, "protocol": proto, "service": svc, "product": prod},
            )
            events.append(ev)
            logger.info("PORT_OPENED %s %d/%s [%s]", host, port, proto, sev)

        for (port, proto) in prev_ports - current_ports:
            ev = self._db.add_change_event(
                event_type="PORT_CLOSED",
                severity="INFO",
                target=host,
                description=f"Port closed: {port}/{proto} on {host}",
                diff_data={"port": port, "protocol": proto},
            )
            events.append(ev)
            logger.info("PORT_CLOSED %s %d/%s", host, port, proto)

        return events
