"""
Email security configuration analysis.

Checks SPF, DKIM, and DMARC configurations for domains.
"""

from __future__ import annotations

import dns.asyncresolver
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


async def analyze_email_security(domain: str, resolvers: list[str]) -> dict[str, Any]:
    """
    Analyze email security posture for a domain.

    Args:
        domain: The domain to analyze
        resolvers: List of DNS resolver IPs

    Returns:
        {
            "spf": {...},
            "dkim": {...},
            "dmarc": {...},
            "overall_score": int (0-100),
            "critical_issues": [...]
        }
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    spf = await _analyze_spf(domain, resolver)
    dmarc = await _analyze_dmarc(domain, resolver)
    dkim = await _analyze_dkim_common(domain, resolver)

    overall_score = _calculate_email_score(spf, dmarc, dkim)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "overall_score": overall_score,
        "critical_issues": spf.get("issues", []) + dmarc.get("issues", []),
    }


async def _analyze_spf(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, Any]:
    """Analyze SPF record."""
    result: dict[str, Any] = {"record": None, "valid": False, "issues": [], "score": 0, "parsed": None}

    try:
        answers = await resolver.resolve(domain, "TXT")
        for r in answers:
            txt = b"".join(r.chunks).decode("utf-8", errors="replace") if hasattr(r, 'chunks') else str(r)
            if txt.startswith("v=spf1"):
                result["record"] = txt
                result["valid"] = True

                # Parse SPF record
                parsed = _parse_spf(txt)
                result["parsed"] = parsed

                # Validate
                issues = _validate_spf(txt, parsed)
                result["issues"] = issues

                # Score calculation
                score = 10  # Base score for having SPF
                if issues:
                    score -= len(issues) * 5

                # Policy bonus/penalty
                if parsed.get("all_qualifier") == "-":
                    score += 5
                elif parsed.get("all_qualifier") == "~":
                    score += 2
                elif parsed.get("all_qualifier") == "+":
                    score -= 10
                elif parsed.get("all_qualifier") == "?":
                    score -= 3

                result["score"] = max(0, min(20, score))

                break
    except dns.asyncresolver.NoAnswer:
        result["issues"].append("No SPF record found")
    except dns.asyncresolver.NXDOMAIN:
        result["issues"].append("Domain does not exist")
    except Exception as e:
        result["issues"].append(f"SPF lookup failed: {str(e)}")
        logger.debug(f"SPF analysis error for {domain}: {e}")

    return result


def _parse_spf(record: str) -> dict[str, Any]:
    """Parse SPF record into components."""
    parsed = {
        "version": None,
        "mechanisms": [],
        "modifiers": [],
        "all_qualifier": None,
        "includes": [],
        "ip4_ranges": [],
        "ip6_ranges": [],
    }

    parts = record.split()
    for part in parts:
        if part.startswith("v="):
            parsed["version"] = part[2:]
        elif part.startswith("include:"):
            parsed["includes"].append(part[8:])
            parsed["mechanisms"].append(part)
        elif part.startswith("ip4:"):
            parsed["ip4_ranges"].append(part[4:])
            parsed["mechanisms"].append(part)
        elif part.startswith("ip6:"):
            parsed["ip6_ranges"].append(part[4:])
            parsed["mechanisms"].append(part)
        elif part.startswith("a"):
            parsed["mechanisms"].append(part)
        elif part.startswith("mx"):
            parsed["mechanisms"].append(part)
        elif part.startswith("exists:"):
            parsed["mechanisms"].append(part)
        elif part == "all" or part in ("-all", "~all", "+all", "?all"):
            parsed["all_qualifier"] = part[0] if len(part) > 1 else "+"
            parsed["mechanisms"].append(part)
        elif part.startswith("redirect="):
            parsed["modifiers"].append(part)
        elif part.startswith("exp="):
            parsed["modifiers"].append(part)

    return parsed


def _validate_spf(record: str, parsed: dict[str, Any]) -> list[str]:
    """Validate SPF record syntax and best practices."""
    issues = []

    # Check for +all (too permissive)
    if parsed.get("all_qualifier") == "+" or record.endswith("all") and not any(
        x in record for x in ["-all", "~all", "?all", "+all"]
    ):
        issues.append(
            "SPF record ends with '+all' or 'all' - accepts mail from any source"
        )

    # Check lookups (RFC limit is 10)
    lookup_count = (
        len(parsed.get("includes", []))
        + len(parsed.get("ip4_ranges", []))
        + len(parsed.get("ip6_ranges", []))
    )
    if lookup_count > 10:
        issues.append(f"Too many DNS lookups ({lookup_count} > 10 RFC limit)")

    # Check for valid mechanisms
    if not any(
        x in record
        for x in ["a:", "mx:", "ip4:", "ip6:", "include:", "a ", "mx ", "-all", "~all"]
    ):
        issues.append("SPF record has no valid mechanisms")

    # Check for redirect loops (simplified)
    redirects = [m for m in parsed.get("modifiers", []) if m.startswith("redirect=")]
    if len(redirects) > 1:
        issues.append("Multiple redirect modifiers (only one allowed)")

    return issues


async def _analyze_dmarc(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, Any]:
    """Analyze DMARC record."""
    result: dict[str, Any] = {
        "record": None,
        "policy": None,
        "subdomain_policy": None,
        "pct": 100,
        "rua": None,
        "ruf": None,
        "sp": None,
        "score": 0,
        "issues": [],
        "parsed": None,
    }

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = await resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            txt = b"".join(r.chunks).decode("utf-8", errors="replace") if hasattr(r, 'chunks') else str(r)
            if txt.startswith("v=DMARC1"):
                result["record"] = txt

                # Parse DMARC record
                parsed = _parse_dmarc(txt)
                result["parsed"] = parsed
                result["policy"] = parsed.get("p")
                result["subdomain_policy"] = parsed.get("sp")
                result["pct"] = parsed.get("pct", 100)
                result["rua"] = parsed.get("rua")
                result["ruf"] = parsed.get("ruf")
                result["sp"] = parsed.get("sp")

                # Score calculation
                score = 0
                policy = parsed.get("p")
                if policy == "reject":
                    score = 20
                elif policy == "quarantine":
                    score = 10
                elif policy == "none":
                    score = 0
                    result["issues"].append("DMARC policy is 'none' - not enforcing")

                # Percentage check
                pct = parsed.get("pct", 100)
                if pct < 100:
                    result["issues"].append(f"DMARC pct is {pct}% - not monitoring all mail")
                    score -= 5

                # RUA bonus
                if parsed.get("rua"):
                    score += 5

                # Subdomain policy
                if parsed.get("sp"):
                    score += 3

                result["score"] = max(0, min(25, score))

                break
    except dns.asyncresolver.NoAnswer:
        result["issues"].append("No DMARC record found")
    except dns.asyncresolver.NXDOMAIN:
        result["issues"].append("Domain does not exist")
    except Exception as e:
        result["issues"].append(f"DMARC lookup failed: {str(e)}")
        logger.debug(f"DMARC analysis error for {domain}: {e}")

    return result


def _parse_dmarc(record: str) -> dict[str, Any]:
    """Parse DMARC record into components."""
    parsed = {}

    parts = record.split()
    for part in parts:
        if not part.startswith("v="):
            if "=" in part:
                key, value = part.split("=", 1)
                # Remove trailing semicolon if present
                value = value.rstrip(";")
                parsed[key] = value

    return parsed


async def _analyze_dkim_common(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, Any]:
    """Check for common DKIM selectors."""
    result: dict[str, Any] = {
        "enabled": False,
        "selectors": [],
        "records": [],
        "issues": [],
        "score": 0,
    }

    # Common selectors to try
    common_selectors = [
        "default",
        "google",
        "selector1",
        "k1",
        "smtp",
        "mail",
        "dkim",
        "s1",
        "s1024",
    ]

    for selector in common_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = await resolver.resolve(dkim_domain, "TXT")
            for r in answers:
                txt = b"".join(r.chunks).decode("utf-8", errors="replace") if hasattr(r, 'chunks') else str(r)
                if txt.startswith("v=DKIM1"):
                    result["enabled"] = True
                    result["selectors"].append(selector)
                    result["records"].append(
                        {"selector": selector, "record": txt[:100] + "..."}
                    )
                    break
        except dns.asyncresolver.NoAnswer:
            continue
        except Exception as e:
            logger.debug(f"DKIM check error for {selector}: {e}")

    if not result["enabled"]:
        result["issues"].append("No DKIM records found for common selectors")
    else:
        result["score"] = 10  # Base score for having DKIM
        # Bonus for multiple selectors (redundancy)
        if len(result["selectors"]) > 1:
            result["score"] += 2

    return result


def _calculate_email_score(
    spf: dict[str, Any], dmarc: dict[str, Any], dkim: dict[str, Any]
) -> int:
    """Calculate overall email security score (0-100)."""
    score = 0

    # SPF: 0-30 points
    score += min(spf.get("score", 0) * 3, 30)

    # DMARC: 0-40 points
    score += min(dmarc.get("score", 0) * 1.6, 40)

    # DKIM: 0-30 points
    if dkim.get("enabled"):
        score += dkim.get("score", 10) * 3

    return min(max(int(score), 0), 100)


def get_email_security_grade(score: int) -> tuple[str, str]:
    """Get grade and color for email security score."""
    if score >= 90:
        return "A", "success"
    elif score >= 75:
        return "B", "info"
    elif score >= 60:
        return "C", "warning"
    elif score >= 40:
        return "D", "warning"
    else:
        return "F", "danger"
