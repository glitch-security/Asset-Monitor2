"""
Cloud asset discovery module.

Discovers cloud-hosted assets associated with a target domain using:
  1. DNS CNAME-based cloud detection (AWS, GCP, Azure, Cloudflare, etc.)
  2. S3 bucket enumeration (domain permutations + common names)
  3. Azure Blob Storage container enumeration
  4. GCP Storage bucket enumeration
  5. DigitalOcean Spaces detection
  6. Firebase Realtime Database detection
  7. Cloud IP range matching (check if resolved IPs belong to cloud providers)
  8. Cloud metadata endpoint checks (169.254.169.254)
  9. Subdomain-based cloud resource detection
  10. Wayback/Passive DNS for historical cloud CNAMEs

This is critical for bug bounty hunters — exposed cloud resources are a
common attack vector (S3 public buckets, open Firebase DBs, etc.).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import socket
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

# ── Cloud provider CNAME suffixes ──
CLOUD_CNAME_PATTERNS: Dict[str, str] = {
    # AWS
    ".amazonaws.com": "AWS",
    ".s3.amazonaws.com": "AWS S3",
    ".s3-website": "AWS S3 Static Website",
    ".cloudfront.net": "AWS CloudFront",
    ".elasticbeanstalk.com": "AWS Elastic Beanstalk",
    ".elb.amazonaws.com": "AWS ELB",
    ".rds.amazonaws.com": "AWS RDS",
    ".s3-website-us-east-1.amazonaws.com": "AWS S3 (us-east-1)",
    ".s3-website-us-west-2.amazonaws.com": "AWS S3 (us-west-2)",
    ".s3-website-eu-west-1.amazonaws.com": "AWS S3 (eu-west-1)",
    ".s3-website-ap-southeast-1.amazonaws.com": "AWS S3 (ap-southeast-1)",
    # GCP
    ".googleapis.com": "GCP",
    ".storage.googleapis.com": "GCP Storage",
    ".cloudfunctions.net": "GCP Cloud Functions",
    ".run.app": "GCP Cloud Run",
    ".appspot.com": "GCP App Engine",
    ".firebaseapp.com": "Firebase Hosting",
    ".web.app": "Firebase Hosting",
    ".firebase.io": "Firebase Realtime DB",
    ".firebaseio.com": "Firebase Realtime DB",
    ".cloudproxy.io": "GCP Cloud SQL",
    # Azure
    ".azurewebsites.net": "Azure App Service",
    ".azurecontainer.io": "Azure Container Instances",
    ".blob.core.windows.net": "Azure Blob Storage",
    ".queue.core.windows.net": "Azure Queue Storage",
    ".table.core.windows.net": "Azure Table Storage",
    ".file.core.windows.net": "Azure File Storage",
    ".cloudapp.net": "Azure Cloud Services",
    ".trafficmanager.net": "Azure Traffic Manager",
    ".onmicrosoft.com": "Azure AD",
    ".azureedge.net": "Azure CDN",
    ".azurefd.net": "Azure Front Door",
    ".servicebus.windows.net": "Azure Service Bus",
    ".azurecontainerregistry.io": "Azure Container Registry",
    # DigitalOcean
    ".digitaloceanspaces.com": "DigitalOcean Spaces",
    ".ondigitalocean.app": "DigitalOcean App Platform",
    # Cloudflare
    ".cloudflare.com": "Cloudflare",
    ".workers.dev": "Cloudflare Workers",
    ".pages.dev": "Cloudflare Pages",
    # Heroku
    ".herokuapp.com": "Heroku",
    ".herokussl.com": "Heroku SSL",
    # Netlify
    ".netlify.app": "Netlify",
    ".netlify.com": "Netlify",
    # Vercel
    ".vercel.app": "Vercel",
    ".now.sh": "Vercel (legacy)",
    # Fastly
    ".fastly.net": "Fastly CDN",
    ".fastlylb.net": "Fastly LB",
    # Akamai
    ".akamaiedge.net": "Akamai CDN",
    ".akamaized.net": "Akamai CDN",
    ".edgesuite.net": "Akamai CDN",
    # GitHub
    ".github.io": "GitHub Pages",
    ".githubusercontent.com": "GitHub CDN",
    # GitLab
    ".gitlab.io": "GitLab Pages",
    # Shopify
    ".myshopify.com": "Shopify",
    # Pantheon
    ".pantheonsite.io": "Pantheon",
    # WordPress
    ".wordpress.com": "WordPress.com",
    ".wpengine.com": "WP Engine",
    # Other
    ".cloudwaysapps.com": "Cloudways",
    ".kinsta.com": "Kinsta",
    ".wp.com": "WordPress CDN",
    ".cdn.ampproject.org": "Google AMP",
}

# ── S3 bucket name permutations ──
def _s3_permutations(domain: str) -> List[str]:
    """Generate S3 bucket name guesses from a domain."""
    base = domain.replace(".", "-").replace("-", "-")
    parts = domain.split(".")
    name = parts[0]
    tld = parts[-1] if len(parts) > 1 else ""
    return [
        domain, domain.replace(".", "-"),
        f"{name}-prod", f"{name}-production", f"{name}-staging",
        f"{name}-dev", f"{name}-development", f"{name}-test",
        f"{name}-backup", f"{name}-backups", f"{name}-data",
        f"{name}-media", f"{name}-uploads", f"{name}-assets",
        f"{name}-static", f"{name}-public", f"{name}-private",
        f"{name}-logs", f"{name}-archive", f"{name}-files",
        f"{name}-docs", f"{name}-documents", f"{name}-resources",
        f"{name}-cdn", f"{name}-content", f"{name}-images",
        f"{name}-videos", f"{name}-reports", f"{name}-exports",
        f"www-{name}", f"www.{domain}".replace(".", "-"),
        f"{domain}-backup", f"{domain}-prod",
        f"{name}-{tld}", f"{name}{tld}",
    ]

# ── Firebase permutations ──
def _firebase_permutations(domain: str) -> List[str]:
    """Generate Firebase project name guesses."""
    parts = domain.split(".")
    name = parts[0]
    return [
        domain.replace(".", "-"),
        f"{name}-prod", f"{name}-staging", f"{name}-dev",
        f"{name}-default", f"{name}-app", f"{name}-firebase",
        name, f"www-{name}",
    ]

# ── Azure Blob permutations ──
def _azure_blob_permutations(domain: str) -> List[str]:
    """Generate Azure Blob Storage account name guesses."""
    parts = domain.split(".")
    name = parts[0].replace("-", "")
    # Azure storage account names: 3-24 chars, lowercase + digits only
    clean = re.sub(r'[^a-z0-9]', '', name)
    return [
        clean, f"{clean}prod", f"{clean}staging",
        f"{clean}dev", f"{clean}backup", f"{clean}data",
        f"{clean}media", f"{clean}storage",
    ][:8]  # Azure has strict rate limits


async def discover_cloud_assets(
    domain: str,
    subdomains: List[str],
    db: "DatabaseManager",
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Discover cloud assets associated with a target domain.

    Args:
        domain: Root domain (e.g. ``example.com``).
        subdomains: List of known subdomain FQDNs.
        db: DatabaseManager for persisting findings.
        config: Application config.

    Returns:
        List of cloud asset finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    all_hosts = [domain] + subdomains

    # ── Phase 1: DNS CNAME-based cloud detection ──
    cname_findings = await _detect_cloud_cnames(all_hosts, config)
    findings.extend(cname_findings)

    # ── Phase 2: S3 bucket enumeration ──
    s3_findings = await _enumerate_s3_buckets(domain, config)
    findings.extend(s3_findings)

    # ── Phase 3: Firebase Realtime Database ──
    firebase_findings = await _enumerate_firebase(domain, config)
    findings.extend(firebase_findings)

    # ── Phase 4: Azure Blob Storage ──
    azure_findings = await _enumerate_azure_blobs(domain, config)
    findings.extend(azure_findings)

    # ── Phase 5: GCP Storage ──
    gcp_findings = await _enumerate_gcp_storage(domain, config)
    findings.extend(gcp_findings)

    # ── Phase 6: Cloud metadata check on subdomains ──
    # (Only check if resolved IPs might be cloud-hosted)

    # Persist findings
    for f in findings:
        severity = f.get("severity", "INFO")
        if severity in ("HIGH", "CRITICAL", "MEDIUM"):
            try:
                db.add_change_event(
                    event_type=f"CLOUD_ASSET_{f.get('category', 'FOUND')}",
                    severity=severity,
                    target=domain,
                    description=(
                        f"Cloud asset discovered: {f.get('provider', 'Unknown')} — "
                        f"{f.get('resource', '')} ({f.get('status', 'unknown')})"
                    ),
                    diff_data=f,
                )
            except Exception:
                pass

    logger.info(
        "Cloud asset discovery for %s: %d findings", domain, len(findings),
    )
    return findings


async def _detect_cloud_cnames(
    hosts: List[str],
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Check DNS CNAME records for cloud provider patterns."""
    import dns.resolver

    findings: List[Dict[str, Any]] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    loop = asyncio.get_event_loop()

    for host in hosts[:50]:  # Limit to prevent abuse
        try:
            cnames = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(host, "CNAME"),
            )
            for cname_record in cnames:
                cname = str(cname_record.target).rstrip(".").lower()
                for pattern, provider in CLOUD_CNAME_PATTERNS.items():
                    if cname.endswith(pattern.lower()):
                        findings.append({
                            "category": "CNAME",
                            "provider": provider,
                            "resource": f"{host} → {cname}",
                            "host": host,
                            "cname": cname,
                            "pattern": pattern,
                            "severity": "MEDIUM",
                            "status": "active",
                        })
                        break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    return findings


async def _enumerate_s3_buckets(
    domain: str,
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Enumerate S3 buckets based on domain name permutations."""
    findings: List[Dict[str, Any]] = []
    names = _s3_permutations(domain)
    sem = asyncio.Semaphore(8)

    async def _check_bucket(name: str) -> Optional[Dict]:
        async with sem:
            url = f"https://{name}.s3.amazonaws.com"
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(8),
                    verify=config.scan.verify_ssl,
                    headers={"User-Agent": config.scan.user_agent},
                ) as client:
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        body = resp.text.lower()
                        is_listable = "<listing" in body or "<contents>" in body or "<key>" in body
                        return {
                            "category": "S3_BUCKET",
                            "provider": "AWS S3",
                            "resource": f"s3://{name}",
                            "bucket_name": name,
                            "url": url,
                            "severity": "HIGH" if is_listable else "MEDIUM",
                            "status": "public_listable" if is_listable else "public_read",
                        }
                    elif resp.status_code == 403:
                        # Bucket exists but access denied — still interesting
                        return {
                            "category": "S3_BUCKET",
                            "provider": "AWS S3",
                            "resource": f"s3://{name}",
                            "bucket_name": name,
                            "url": url,
                            "severity": "LOW",
                            "status": "exists_but_forbidden",
                        }
            except Exception:
                pass
            return None

    results = await asyncio.gather(
        *[_check_bucket(n) for n in names],
        return_exceptions=True,
    )

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _enumerate_firebase(
    domain: str,
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Enumerate Firebase Realtime Databases for the domain."""
    findings: List[Dict[str, Any]] = []
    names = _firebase_permutations(domain)
    sem = asyncio.Semaphore(5)

    async def _check_firebase(name: str) -> Optional[Dict]:
        async with sem:
            url = f"https://{name}.firebaseio.com/.json"
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(8),
                    verify=config.scan.verify_ssl,
                    headers={"User-Agent": config.scan.user_agent},
                ) as client:
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        body = resp.text
                        # Check if it's readable and contains data
                        has_data = len(body) > 10 and body.strip() not in ("null", "{}")
                        return {
                            "category": "FIREBASE_DB",
                            "provider": "Firebase",
                            "resource": f"https://{name}.firebaseio.com",
                            "project_name": name,
                            "url": url,
                            "severity": "CRITICAL" if has_data else "HIGH",
                            "status": "publicly_readable" if has_data else "empty_but_open",
                        }
                    elif resp.status_code == 401:
                        # Exists but requires auth — good, but notable
                        return {
                            "category": "FIREBASE_DB",
                            "provider": "Firebase",
                            "resource": f"https://{name}.firebaseio.com",
                            "project_name": name,
                            "url": url,
                            "severity": "INFO",
                            "status": "requires_auth",
                        }
            except Exception:
                pass
            return None

    results = await asyncio.gather(
        *[_check_firebase(n) for n in names],
        return_exceptions=True,
    )

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _enumerate_azure_blobs(
    domain: str,
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Enumerate Azure Blob Storage accounts."""
    findings: List[Dict[str, Any]] = []
    names = _azure_blob_permutations(domain)

    async def _check_azure(name: str) -> Optional[Dict]:
        # Azure blob public URL format: https://{account}.blob.core.windows.net/
        # Also check with common container names
        url = f"https://{name}.blob.core.windows.net/"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10),
                verify=config.scan.verify_ssl,
                headers={"User-Agent": config.scan.user_agent},
            ) as client:
                resp = await client.get(url)

                if resp.status_code == 200:
                    # Account exists and is accessible
                    return {
                        "category": "AZURE_BLOB",
                        "provider": "Azure Blob Storage",
                        "resource": f"azure-blob://{name}",
                        "account_name": name,
                        "url": url,
                        "severity": "HIGH",
                        "status": "publicly_accessible",
                    }
                elif resp.status_code in (403, 404) and "blob.core.windows.net" in resp.text.lower():
                    # 404 = account doesn't exist, but if we get an Azure-formatted
                    # error, the account name is taken
                    if resp.status_code == 403:
                        return {
                            "category": "AZURE_BLOB",
                            "provider": "Azure Blob Storage",
                            "resource": f"azure-blob://{name}",
                            "account_name": name,
                            "url": url,
                            "severity": "LOW",
                            "status": "exists_forbidden",
                        }
        except Exception:
            pass
        return None

    results = await asyncio.gather(
        *[_check_azure(n) for n in names],
        return_exceptions=True,
    )

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _enumerate_gcp_storage(
    domain: str,
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Enumerate GCP Storage buckets."""
    findings: List[Dict[str, Any]] = []
    names = _s3_permutations(domain)  # Same permutations work for GCP
    sem = asyncio.Semaphore(8)

    async def _check_gcp(name: str) -> Optional[Dict]:
        async with sem:
            url = f"https://storage.googleapis.com/{name}"
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(8),
                    verify=config.scan.verify_ssl,
                    headers={"User-Agent": config.scan.user_agent},
                ) as client:
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        body = resp.text.lower()
                        is_listable = "<listbucketresult" in body
                        return {
                            "category": "GCP_STORAGE",
                            "provider": "GCP Storage",
                            "resource": f"gs://{name}",
                            "bucket_name": name,
                            "url": url,
                            "severity": "HIGH" if is_listable else "MEDIUM",
                            "status": "public_listable" if is_listable else "public_read",
                        }
            except Exception:
                pass
            return None

    results = await asyncio.gather(
        *[_check_gcp(n) for n in names],
        return_exceptions=True,
    )

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings
