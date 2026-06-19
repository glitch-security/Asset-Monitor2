"""
Nameserver security analysis.

Checks for AXFR exposure, open resolvers, version disclosure, and other vulnerabilities.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.query
import dns.flags
import dns.rdatatype
import logging
import socket
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def analyze_nameservers(
    domain: str, nameservers: list[str], resolvers: list[str]
) -> dict[str, Any]:
    """
    Analyze nameserver security posture.

    Args:
        domain: The domain being analyzed
        nameservers: List of nameserver hostnames
        resolvers: List of DNS resolver IPs for lookups

    Returns:
        {
            "axfr_exposed": [...],
            "open_resolver": [...],
            "version_info": {...},
            "amplification_attack_capable": [...],
            "edns_support": bool,
            "dnssec_support": bool,
            "any_query_allowed": bool,
            "inconsistent_responses": [...],
            "issues": [...]
        }
    """
    result: dict[str, Any] = {
        "axfr_exposed": [],
        "open_resolver": [],
        "version_info": {},
        "amplification_attack_capable": [],
        "edns_support": False,
        "dnssec_support": False,
        "any_query_allowed": False,
        "inconsistent_responses": [],
        "issues": [],
    }

    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    # Resolver for NS IP lookups
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    # Test each nameserver
    for ns in nameservers:
        try:
            # Resolve NS IP addresses
            ip_answers = await resolver.resolve(ns, "A")
            ips = [str(r) for r in ip_answers]

            for ip in ips:
                # Check AXFR
                if await _check_axfer(domain, ip):
                    result["axfr_exposed"].append(f"{ns} ({ip})")
                    result["issues"].append(f"AXFR exposed on {ns} ({ip}) - CRITICAL")

                # Check version.bind
                version = await _check_dns_version(ip)
                if version:
                    result["version_info"][f"{ns} ({ip})"] = version
                    result["issues"].append(f"DNS version disclosed on {ns} ({ip}): {version}")

                # Check EDNS support
                if await _check_edns(ip):
                    result["edns_support"] = True

                # Check DNSSEC support
                if await _check_dnssec_support(ip):
                    result["dnssec_support"] = True

                # Check ANY query response (amplification risk)
                if await _check_any_query(ip, domain):
                    result["any_query_allowed"] = True
                    result["amplification_attack_capable"].append(f"{ns} ({ip})")
                    result["issues"].append(
                        f"DNS amplification possible on {ns} ({ip}) - ANY queries return large responses"
                    )

                # Check open resolver
                if await _check_open_resolver(ip):
                    result["open_resolver"].append(f"{ns} ({ip})")
                    result["issues"].append(f"Open resolver on {ns} ({ip}) - CRITICAL")

        except dns.asyncresolver.NoAnswer:
            result["inconsistent_responses"].append(f"{ns}: No A record found")
        except dns.asyncresolver.NXDOMAIN:
            result["inconsistent_responses"].append(f"{ns}: NS does not exist")
        except Exception as e:
            result["inconsistent_responses"].append(f"{ns}: {str(e)}")
            logger.debug(f"Nameserver analysis error for {ns}: {e}")

    return result


async def _check_axfer(domain: str, nameserver_ip: str) -> bool:
    """Check if zone transfer is allowed."""
    try:
        # Create AXFR query
        query = dns.message.make_query(domain, "AXFR")
        query.set_rcode(dns.rcode.NOERROR)

        # Try TCP zone transfer
        try:
            response = dns.query.tcp(query, nameserver_ip, timeout=5)
            if response.answer:
                return True
        except:
            pass

        # Try UDP AXFR (some servers respond)
        try:
            response = dns.query.udp(query, nameserver_ip, timeout=3)
            if response.answer and response.rcode() == dns.rcode.NOERROR:
                return True
        except:
            pass

    except Exception as e:
        logger.debug(f"AXFR check error for {nameserver_ip}: {e}")

    return False


async def _check_dns_version(nameserver_ip: str) -> Optional[str]:
    """Check for DNS server version disclosure via VERSION.BIND."""
    try:
        query = dns.message.make_query("VERSION.BIND", "TXT", "CH")
        response = dns.query.udp(query, nameserver_ip, timeout=3)
        if response.answer:
            for r in response.answer:
                if r.rdtype == dns.rdatatype.TXT:
                    txt = b"".join(r.chunks).decode("utf-8", errors="replace")
                    # Remove quotes if present
                    return txt.strip('"')
    except Exception as e:
        logger.debug(f"Version check error for {nameserver_ip}: {e}")

    return None


async def _check_edns(nameserver_ip: str) -> bool:
    """Check EDNS support by sending EDNS-enabled query."""
    try:
        query = dns.message.make_query("test.com", "A")
        query.use_edns(edns=0)
        response = dns.query.udp(query, nameserver_ip, timeout=3)
        # Check if EDNS was supported (response has OPT record)
        return response.flags & dns.flags.DO != 0 or any(
            rr.rdtype == dns.rdatatype.OPT for rr in response.additional
        )
    except Exception:
        return False


async def _check_dnssec_support(nameserver_ip: str) -> bool:
    """Check if nameserver supports DNSSEC."""
    try:
        # Query for a domain with DNSSEC (e.g., root)
        query = dns.message.make_query(".", "NS")  # Root zone
        query.set_dnssec_ok(True)  # Set DO bit
        response = dns.query.udp(query, nameserver_ip, timeout=3)
        # Check if response has DNSSEC records (RRSIG)
        return any(rr.rdtype == dns.rdatatype.RRSIG for rr in response.answer + response.authority + response.additional)
    except Exception:
        return False


async def _check_any_query(nameserver_ip: str, domain: str) -> bool:
    """
    Check if ANY queries return all records (amplification risk).

    Returns True if response is large (potential amplification).
    """
    try:
        query = dns.message.make_query(domain, "ANY")
        response = dns.query.udp(query, nameserver_ip, timeout=3)

        # Count total records in response
        total_records = (
            len(response.answer)
            + len(response.authority)
            + len(response.additional)
        )

        # If response has more than 10 records, it's a potential amplification vector
        return total_records > 10
    except Exception:
        return False


async def _check_open_resolver(nameserver_ip: str) -> bool:
    """
    Check if the nameserver is an open DNS resolver.

    We test by querying an external domain that shouldn't normally be cached.
    """
    try:
        # Use a random domain that's unlikely to be cached
        import hashlib
        random_subdomain = f"test-{hashlib.md5(nameserver_ip.encode()).hexdigest()[:8]}.com"
        query = dns.message.make_query(random_subdomain, "A")
        response = dns.query.udp(query, nameserver_ip, timeout=3)

        # If we get a valid response (even NXDOMAIN), it's resolving external queries
        return response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
    except Exception:
        return False


async def check_dns_health(nameserver_ip: str) -> dict[str, Any]:
    """
    Basic health check for a DNS server.

    Returns:
        {
            "responding": bool,
            "latency_ms": float,
            "recursive": bool,
            "issues": [...]
        }
    """
    result = {
        "responding": False,
        "latency_ms": 0,
        "recursive": False,
        "issues": [],
    }

    try:
        import time

        start = time.time()
        query = dns.message.make_query("example.com", "A")
        response = dns.query.udp(query, nameserver_ip, timeout=5)
        latency = (time.time() - start) * 1000

        result["responding"] = True
        result["latency_ms"] = round(latency, 2)

        if response.rcode() == dns.rcode.NOERROR:
            result["recursive"] = True

        if latency > 500:
            result["issues"].append(f"High latency: {latency:.2f}ms")

    except dns.query.Timeout:
        result["issues"].append("DNS server timeout")
    except Exception as e:
        result["issues"].append(f"Health check failed: {str(e)}")

    return result


def get_nameserver_issues(result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract and categorize nameserver security issues.

    Returns:
        [
            {
                "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
                "type": str,
                "description": str,
                "affected": str
            },
            ...
        ]
    """
    issues = []

    # AXFR exposure - CRITICAL
    for ns in result.get("axfr_exposed", []):
        issues.append({
            "severity": "CRITICAL",
            "type": "AXFR Exposure",
            "description": "Zone transfer allowed - complete DNS zone can be downloaded",
            "affected": ns,
        })

    # Open resolver - CRITICAL
    for ns in result.get("open_resolver", []):
        issues.append({
            "severity": "CRITICAL",
            "type": "Open Resolver",
            "description": "Open DNS resolver - can be used for DNS amplification attacks",
            "affected": ns,
        })

    # Amplification capability - HIGH
    for ns in result.get("amplification_attack_capable", []):
        issues.append({
            "severity": "HIGH",
            "type": "DNS Amplification",
            "description": "Nameserver can be used for amplification attacks (ANY queries)",
            "affected": ns,
        })

    # Version disclosure - MEDIUM
    for ns, version in result.get("version_info", {}).items():
        issues.append({
            "severity": "MEDIUM",
            "type": "Information Disclosure",
            "description": f"DNS server version disclosed: {version}",
            "affected": ns,
        })

    # Inconsistent responses - LOW
    for error in result.get("inconsistent_responses", []):
        issues.append({
            "severity": "LOW",
            "type": "Nameserver Issue",
            "description": error,
            "affected": "Multiple",
        })

    return issues
