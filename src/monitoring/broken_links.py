"""
Broken link hijacking detector.

Extracts all external links from crawled pages and checks whether:
  1. The linked domain is unregistered / expired (DNS fails to resolve)
  2. The linked URL returns a dead/hostile response
  3. Social media / SaaS links point to available or claimable accounts

This is a high-value bug bounty finding: if a target links to an expired
external domain, an attacker can register it and serve malicious content.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

# Social / SaaS platforms where username/account availability matters
_ACCOUNT_PLATFORMS = {
    "twitter.com": "Twitter/X",
    "x.com": "Twitter/X",
    "github.com": "GitHub",
    "linkedin.com": "LinkedIn",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "youtube.com": "YouTube",
    "medium.com": "Medium",
    "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress",
    "slack.com": "Slack",
    "discord.gg": "Discord",
    "discord.com": "Discord",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "tiktok.com": "TikTok",
    "pinterest.com": "Pinterest",
    "reddit.com": "Reddit",
    "soundcloud.com": "SoundCloud",
    "spotify.com": "Spotify",
    "behance.net": "Behance",
    "dribbble.com": "Dribbble",
    "dev.to": "DEV",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "npmjs.com": "npm",
    "pypi.org": "PyPI",
    "hub.docker.com": "Docker Hub",
    "heroku.com": "Heroku",
    "firebaseapp.com": "Firebase",
    "firebase.google.com": "Firebase",
    "azurewebsites.net": "Azure",
    "cloudapp.net": "Azure",
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "CloudFront",
}

# Response patterns that indicate an account/resource doesn't exist
_NOT_FOUND_PATTERNS = [
    "not found", "doesn't exist", "does not exist", "no longer available",
    "has been deleted", "was deleted", "account suspended",
    "page not found", "404", "sorry, this", "unavailable",
    "this content is no longer available", "nothing to see here",
    "the page you requested", "could not be found",
]


async def check_broken_links(
    base_url: str,
    crawl_data: Dict[str, Any],
    db: "DatabaseManager",
    subdomain_id: int,
    config: "AppConfig",
    timeout: int = 10,
) -> List[Dict[str, Any]]:
    """Analyze external links for broken link hijacking opportunities.

    Args:
        base_url: The target URL being analyzed.
        crawl_data: Output from BFSCrawler.crawl() containing external_links.
        db: DatabaseManager for persisting findings.
        subdomain_id: FK to the Subdomain being scanned.
        config: Application config.
        timeout: HTTP timeout per request.

    Returns:
        List of broken link findings with hijack risk assessment.
    """
    external_links: List[str] = crawl_data.get("external_links", [])
    if not external_links:
        logger.debug("No external links to analyze for %s", base_url)
        return []

    # Deduplicate by domain
    seen_domains: Set[str] = set()
    unique_links: Dict[str, str] = {}  # domain -> first URL

    for link in external_links:
        try:
            parsed = urlparse(link)
            domain = parsed.hostname or ""
            if domain and domain not in seen_domains:
                seen_domains.add(domain)
                unique_links[domain] = link
        except Exception:
            continue

    # Don't check links back to our own target
    target_host = urlparse(base_url).hostname or ""
    if target_host in seen_domains:
        seen_domains.discard(target_host)

    findings: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(10)

    async def _check_link(domain: str, url: str) -> Optional[Dict]:
        async with sem:
            result = await _analyze_external_link(domain, url, config, timeout)
            return result

    results = await asyncio.gather(
        *[_check_link(d, u) for d, u in unique_links.items()],
        return_exceptions=True,
    )

    for r in results:
        if isinstance(r, dict) and r.get("hijackable"):
            findings.append(r)

    # Persist high-value findings as events
    hostname = urlparse(base_url).hostname or ""
    for f in findings:
        severity = "HIGH" if f.get("dns_dead") else "MEDIUM"
        try:
            db.add_change_event(
                event_type="BROKEN_LINK_HIJACK",
                severity=severity,
                target=hostname,
                description=(
                    f"Broken link to {f['domain']} (found at {f['source_url']}) — "
                    f"{'DNS unresolvable (domain may be unregistered/expired)' if f.get('dns_dead') else 'Resource returns error/dead response'}"
                ),
                diff_data=f,
            )
        except Exception:
            pass

    if findings:
        logger.info(
            "Broken link hijacking: %d vulnerable link(s) on %s",
            len(findings), base_url,
        )
    return findings


async def _analyze_external_link(
    domain: str,
    url: str,
    config: "AppConfig",
    timeout: int,
) -> Optional[Dict[str, Any]]:
    """Check a single external link for broken link hijacking.

    Tests:
      1. DNS resolution — if domain doesn't resolve, it's hijackable
      2. HTTP response — dead servers / error pages
      3. Social media account availability patterns
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "url": url,
        "source_url": "",
        "hijackable": False,
        "dns_dead": False,
        "http_dead": False,
        "platform": _ACCOUNT_PLATFORMS.get(domain, ""),
        "risk": "LOW",
    }

    # ── Test 1: DNS resolution ──
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(domain, None, socket.AF_UNSPEC),
        )
    except socket.gaierror:
        result["dns_dead"] = True
        result["hijackable"] = True
        result["risk"] = "HIGH"
        return result
    except Exception:
        pass

    # ── Test 2: HTTP probe ──
    try:
        async with httpx.AsyncClient(
            verify=config.scan.verify_ssl,
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": config.scan.user_agent},
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            try:
                resp = await client.get(url)
            except (httpx.ConnectError, httpx.TimeoutException):
                result["http_dead"] = True
                result["hijackable"] = True
                result["risk"] = "MEDIUM"
                return result
            except Exception:
                return result

            # Check for dead/error responses
            if resp.status_code in (404, 410, 500, 502, 503):
                result["http_status"] = resp.status_code
                body = resp.text.lower()

                # Verify it's genuinely dead, not just a generic 404
                if any(pat in body for pat in _NOT_FOUND_PATTERNS):
                    result["http_dead"] = True
                    result["hijackable"] = True
                    result["risk"] = "MEDIUM"
                    return result

            # ── Test 3: Social media / SaaS account patterns ──
            if domain in _ACCOUNT_PLATFORMS:
                body = resp.text.lower()
                if resp.status_code == 404:
                    result["hijackable"] = True
                    result["risk"] = "HIGH"
                    result["account_available"] = True
                    return result

                # Check for account-not-found patterns in the body
                platform_patterns = {
                    "github.com": ["no results matched your query", "is not available", "there isn't a github page"],
                    "twitter.com": ["this account doesn't exist", "account suspended", "that page doesn't exist"],
                    "x.com": ["this account doesn't exist", "account suspended", "that page doesn't exist"],
                    "linkedin.com": ["page not found", "this page doesn't exist"],
                    "instagram.com": ["sorry, this page isn't available", "the link you followed may be broken"],
                    "medium.com": ["not found", "this page is unavailable"],
                    "tumblr.com": ["there's nothing here", "whatever you were looking for doesn't exist"],
                }

                patterns = platform_patterns.get(domain, [])
                if patterns and any(p in body for p in patterns):
                    result["hijackable"] = True
                    result["risk"] = "HIGH"
                    result["account_available"] = True

    except Exception:
        pass

    return result
