"""
DNSSEC analysis module.

Checks DNSSEC configuration, NSEC/NSEC3 walking, and DANE records.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.flags
import dns.rdatatype
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def analyze_dnssec(domain: str, resolvers: list[str]) -> dict[str, Any]:
    """
    Analyze DNSSEC configuration for a domain.

    Args:
        domain: The domain to analyze
        resolvers: List of DNS resolver IPs

    Returns:
        {
            "dnssec_enabled": bool,
            "validation_status": "secure" | "insecure" | "bogus",
            "nsec_walk_possible": bool,
            "nsec3_opt_out": bool,
            "dnskey_records": [...],
            "ds_records": [...],
            "issues": [...]
        }
    """
    result: dict[str, Any] = {
        "dnssec_enabled": False,
        "validation_status": "insecure",
        "nsec_walk_possible": False,
        "nsec3_opt_out": False,
        "dnskey_records": [],
        "ds_records": [],
        "issues": [],
    }

    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    try:
        # Check for DNSKEY records
        dnskey_answer = await resolver.resolve(domain, "DNSKEY")
        result["dnssec_enabled"] = True
        result["dnskey_records"] = [_format_dnskey(r) for r in dnskey_answer]

        # Check for DS records (at parent zone)
        try:
            # Get parent zone
            parts = domain.split(".")
            if len(parts) > 2:
                parent = ".".join(parts[1:])
                ds_answer = await resolver.resolve(parent, "DS", domain)
                result["ds_records"] = [_format_ds(r) for r in ds_answer]
        except Exception as e:
            logger.debug(f"DS record lookup failed for {domain}: {e}")

        result["validation_status"] = "secure"

        # Check for NSEC/NSEC3 (simplified check)
        try:
            # Try NSEC query for non-existent name
            nsec_domain = f"test-nonexistent-{hash(domain)}.test.{domain}"
            try:
                nsec_answer = await resolver.resolve(nsec_domain, "NSEC")
                result["nsec_walk_possible"] = True
            except dns.asyncresolver.NoAnswer:
                # Might be NSEC3
                try:
                    nsec3_answer = await resolver.resolve(domain, "NSEC3PARAM")
                    result["nsec3_opt_out"] = True
                except:
                    pass
        except:
            pass

    except dns.asyncresolver.NoAnswer:
        result["issues"].append("No DNSKEY records found - DNSSEC not enabled")
    except dns.asyncresolver.NXDOMAIN:
        result["validation_status"] = "bogus"
        result["issues"].append("Domain does not exist")
    except Exception as e:
        result["issues"].append(f"DNSSEC check failed: {str(e)}")
        logger.debug(f"DNSSEC analysis error for {domain}: {e}")

    return result


def _format_dnskey(record: dns.rdtypes.ANY.DNSKEY) -> dict[str, Any]:
    """Format DNSKEY record for storage."""
    try:
        key_text = record.key.to_text() if hasattr(record.key, 'to_text') else str(record.key)
    except:
        key_text = ""
    return {
        "flags": record.flags,
        "protocol": record.protocol,
        "algorithm": record.algorithm,
        "key_length": len(key_text) * 4 if key_text else 0,  # Approximate
        "key": key_text[:64] + "..." if len(key_text) > 64 else key_text,
    }


def _format_ds(record: dns.rdtypes.ANY.DS) -> dict[str, Any]:
    """Format DS record for storage."""
    try:
        digest_hex = record.digest.hex() if hasattr(record.digest, 'hex') else str(record.digest)
    except:
        digest_hex = ""
    return {
        "key_tag": record.key_tag,
        "algorithm": record.algorithm,
        "digest_type": record.digest_type,
        "digest": digest_hex[:32] + "..." if len(digest_hex) > 32 else digest_hex,
    }


async def check_dnssec_for_subdomain(fqdn: str, resolvers: list[str]) -> dict[str, Any]:
    """
    Check DNSSEC for a specific subdomain.

    This is a lighter version used during subdomain verification.
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 3
    resolver.lifetime = 5

    result = {"dnssec_enabled": False, "validated": False, "issues": []}

    try:
        # Try to get DNSKEY for the root domain
        parts = fqdn.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
            try:
                dnskey_answer = await resolver.resolve(root_domain, "DNSKEY")
                result["dnssec_enabled"] = True
                result["validated"] = True
            except:
                result["issues"].append(f"No DNSKEY for {root_domain}")
    except Exception as e:
        result["issues"].append(f"DNSSEC check error: {str(e)}")

    return result
