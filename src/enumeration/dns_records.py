"""DNS record enumeration (MX, NS, TXT, SOA, SRV, CAA, etc.) for target domain."""

from __future__ import annotations

import logging
import re
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype

logger = logging.getLogger(__name__)


async def enumerate_dns_records(
    domain: str,
    resolvers: list[str],
    timeout: int = 5,
) -> set[str]:
    """Enumerate MX, NS, TXT, and SOA records and extract FQDNs belonging to *domain*.

    Args:
        domain: Target domain.
        resolvers: List of DNS resolver IP addresses.
        timeout: Per-query lifetime in seconds.

    Returns:
        Deduplicated set of FQDNs ending in ``.{domain}`` extracted from DNS records.
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.lifetime = float(timeout)

    found: set[str] = set()

    def _normalise(name: str) -> str:
        return name.strip().lower().rstrip(".")

    def _keep(name: str) -> bool:
        return name == domain or name.endswith(f".{domain}")

    # ── MX records ─────────────────────────────────────────────────────────────
    try:
        answer = await resolver.resolve(domain, "MX")
        for rdata in answer:
            mx_host = _normalise(str(rdata.exchange))
            if mx_host and _keep(mx_host):
                found.add(mx_host)
        logger.debug(f"DNS records: MX resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no MX records for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: MX query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: MX error for {domain}: {exc}")

    # ── NS records ─────────────────────────────────────────────────────────────
    try:
        answer = await resolver.resolve(domain, "NS")
        for rdata in answer:
            ns_host = _normalise(str(rdata.target))
            if ns_host and _keep(ns_host):
                found.add(ns_host)
        logger.debug(f"DNS records: NS resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no NS records for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: NS query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: NS error for {domain}: {exc}")

    # ── TXT records ────────────────────────────────────────────────────────────
    # Pattern matches any token that looks like *.domain or domain itself
    _fqdn_pattern = re.compile(
        r"(?:^|[\s:=])([a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+)*\."
        + re.escape(domain)
        + r")\b",
        re.IGNORECASE,
    )
    try:
        answer = await resolver.resolve(domain, "TXT")
        for rdata in answer:
            txt_value = " ".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            for match in _fqdn_pattern.finditer(txt_value):
                candidate = _normalise(match.group(1))
                if candidate and _keep(candidate):
                    found.add(candidate)
        logger.debug(f"DNS records: TXT resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no TXT records for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: TXT query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: TXT error for {domain}: {exc}")

    # ── SOA record ─────────────────────────────────────────────────────────────
    try:
        answer = await resolver.resolve(domain, "SOA")
        for rdata in answer:
            primary_ns = _normalise(str(rdata.mname))
            if primary_ns and _keep(primary_ns):
                found.add(primary_ns)
        logger.debug(f"DNS records: SOA resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no SOA record for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: SOA query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: SOA error for {domain}: {exc}")

    logger.info(f"DNS records: found {len(found)} FQDNs in DNS records for {domain}")
    return found


# ── Comprehensive DNS Record Collection ───────────────────────────────────────

async def get_all_dns_records(
    domain: str,
    resolvers: list[str],
    timeout: int = 5,
) -> dict[str, Any]:
    """
    Collect all DNS record types for a domain in structured format.

    Args:
        domain: Target domain
        resolvers: List of DNS resolver IP addresses
        timeout: Per-query lifetime in seconds

    Returns:
        {
            "mx": [...],
            "ns": [...],
            "txt": [...],
            "soa": {...},
            "srv": [...],
            "caa": [...],
            "a": [...],
            "aaaa": [...]
        }
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.lifetime = float(timeout)

    result: dict[str, Any] = {
        "mx": [],
        "ns": [],
        "txt": [],
        "soa": None,
        "srv": [],
        "caa": [],
        "a": [],
        "aaaa": [],
    }

    # MX records
    try:
        answer = await resolver.resolve(domain, "MX")
        for rdata in answer:
            result["mx"].append({
                "exchange": str(rdata.exchange).rstrip("."),
                "priority": rdata.preference,
            })
    except Exception as e:
        logger.debug(f"MX query error for {domain}: {e}")

    # NS records
    try:
        answer = await resolver.resolve(domain, "NS")
        for rdata in answer:
            result["ns"].append(str(rdata.target).rstrip("."))
    except Exception as e:
        logger.debug(f"NS query error for {domain}: {e}")

    # TXT records
    try:
        answer = await resolver.resolve(domain, "TXT")
        for rdata in answer:
            txt_value = " ".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            result["txt"].append(txt_value)
    except Exception as e:
        logger.debug(f"TXT query error for {domain}: {e}")

    # SOA record
    try:
        answer = await resolver.resolve(domain, "SOA")
        if answer:
            rdata = answer[0]
            result["soa"] = {
                "mname": str(rdata.mname).rstrip("."),
                "rname": str(rdata.rname).rstrip("."),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum": rdata.minimum,
            }
    except Exception as e:
        logger.debug(f"SOA query error for {domain}: {e}")

    # A records
    try:
        answer = await resolver.resolve(domain, "A")
        for rdata in answer:
            result["a"].append(str(rdata))
    except Exception as e:
        logger.debug(f"A query error for {domain}: {e}")

    # AAAA records
    try:
        answer = await resolver.resolve(domain, "AAAA")
        for rdata in answer:
            result["aaaa"].append(str(rdata))
    except Exception as e:
        logger.debug(f"AAAA query error for {domain}: {e}")

    # SRV records (common services)
    common_services = [
        "_sip._tcp",
        "_sips._tcp",
        "_xmpp-server._tcp",
        "_xmpp-client._tcp",
        "_ldap._tcp",
        "_ldaps._tcp",
    ]

    for service in common_services:
        try:
            fqdn = f"{service}.{domain}"
            answer = await resolver.resolve(fqdn, "SRV")
            for rdata in answer:
                result["srv"].append({
                    "service": service,
                    "target": str(rdata.target).rstrip("."),
                    "port": rdata.port,
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                })
        except Exception:
            pass  # SRV records are optional

    # CAA records
    try:
        answer = await resolver.resolve(domain, "CAA")
        for rdata in answer:
            result["caa"].append({
                "flag": rdata.flag,
                "tag": rdata.tag,
                "value": rdata.value,
            })
    except Exception as e:
        logger.debug(f"CAA query error for {domain}: {e}")

    return result


async def get_nameservers_for_domain(
    domain: str,
    resolvers: list[str],
    timeout: int = 5,
) -> list[str]:
    """
    Get list of nameservers for a domain.

    Args:
        domain: Target domain
        resolvers: List of DNS resolver IP addresses
        timeout: Per-query lifetime in seconds

    Returns:
        List of nameserver hostnames
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.lifetime = float(timeout)

    nameservers = []

    try:
        answer = await resolver.resolve(domain, "NS")
        for rdata in answer:
            ns = str(rdata.target).rstrip(".")
            if ns:
                nameservers.append(ns)
    except Exception as e:
        logger.debug(f"NS query error for {domain}: {e}")

    return nameservers


async def check_dnssec_existence(
    domain: str,
    resolvers: list[str],
    timeout: int = 5,
) -> bool:
    """
    Quick check if DNSSEC is enabled for a domain.

    Args:
        domain: Target domain
        resolvers: List of DNS resolver IP addresses
        timeout: Per-query lifetime in seconds

    Returns:
        True if DNSKEY records found
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.lifetime = float(timeout)

    try:
        await resolver.resolve(domain, "DNSKEY")
        return True
    except Exception:
        return False
