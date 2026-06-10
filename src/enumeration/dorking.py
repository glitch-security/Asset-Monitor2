"""
Google dorking / search engine dorking module.

Generates and executes search queries to discover:
  - Exposed sensitive files (.env, .git, config files, backups)
  - Leaked credentials on GitHub, Pastebin, etc.
  - Exposed admin panels, login pages, dashboards
  - Error messages revealing tech stack details
  - Open directories and directory listings
  - Exposed database dumps and log files
  - GitHub secrets / API key leaks

Uses multiple search engines and APIs:
  1. Direct web search via httpx (Google, Bing, DuckDuckGo)
  2. GitHub code search API (if token provided)
  3. Built-in dork lists from exploit-db, SecLists patterns
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

import httpx

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

# ── Dork categories with specific queries ──
# {dork_string: severity}

DORKS_SENSITIVE_FILES: Dict[str, str] = {
    # Exposed env/config files
    'site:{domain} ext:env "DB_PASSWORD" OR "SECRET" OR "API_KEY"': "CRITICAL",
    'site:{domain} ext:env "APP_KEY" OR "APP_SECRET"': "CRITICAL",
    'site:{domain} filetype:env "PASSWORD"': "CRITICAL",
    'site:{domain} filetype:conf "password"': "HIGH",
    'site:{domain} filetype:ini "password"': "HIGH",
    'site:{domain} filetype:yml "password" OR "secret"': "HIGH",
    'site:{domain} filetype:yaml "database" "password"': "HIGH",
    'site:{domain} filetype:xml "password"': "HIGH",
    'site:{domain} filetype:json "api_key" OR "secret_key"': "HIGH",
    'site:{domain} filetype:sql "INSERT INTO" "VALUES"': "HIGH",
    'site:{domain} filetype:log "password" OR "error" OR "exception"': "MEDIUM",
    # Exposed source code / repos
    'site:{domain} inurl:".git"': "HIGH",
    'site:{domain} filetype:git': "HIGH",
    'site:{domain} inurl:".svn" OR inurl:".hg"': "HIGH",
    # Backup files
    'site:{domain} ext:sql OR ext:db OR ext:datab OR ext:mdb': "CRITICAL",
    'site:{domain} ext:bak OR ext:old OR ext:backup OR ext:save': "HIGH",
    'site:{domain} ext:zip OR ext:tar OR ext:gz OR ext:rar': "MEDIUM",
    'site:{domain} inurl:"backup" OR inurl:"dump" OR inurl:"db"': "HIGH",
    # WordPress specific
    'site:{domain} inurl:wp-config.php.bak OR inurl:wp-config.php~': "CRITICAL",
    'site:{domain} inurl:"wp-content" "debug.log"': "HIGH",
    'site:{domain} inurl:"wp-content/uploads" ext:sql': "HIGH",
}

DORKS_EXPOSED_PANELS: Dict[str, str] = {
    'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard': "MEDIUM",
    'site:{domain} inurl:phpmyadmin OR inurl:pma OR inurl:myadmin': "HIGH",
    'site:{domain} inurl:cpanel OR inurl:webmin OR inurl:manager': "MEDIUM",
    'site:{domain} inurl:"/console" OR inurl:"/actuator"': "MEDIUM",
    'site:{domain} inurl:"/grafana" OR inurl:"/kibana" OR inurl:"/jenkins"': "HIGH",
    'site:{domain} intitle:"index of" OR intitle:"directory listing"': "MEDIUM",
    'site:{domain} intitle:"login" "password" "username"': "MEDIUM",
    'site:{domain} intitle:"admin" "panel" OR "control"': "MEDIUM",
}

DORKS_ERROR_MESSAGES: Dict[str, str] = {
    'site:{domain} "Warning" "mysql" OR "mysqli"': "MEDIUM",
    'site:{domain} "Fatal error" "Uncaught" OR "Stack trace"': "MEDIUM",
    'site:{domain} "SQL syntax" "MySQL" OR "MariaDB"': "HIGH",
    'site:{domain} "StackOverflowException" OR "NullReferenceException"': "MEDIUM",
    'site:{domain} "ORA-" "error"': "MEDIUM",
    'site:{domain} "PDOException" OR "SQLSTATE"': "MEDIUM",
    'site:{domain} inurl:"debug" "trace" OR "stack"': "MEDIUM",
}

DORKS_OPEN_REDIRECTS: Dict[str, str] = {
    'site:{domain} inurl:"redirect" OR inurl:"url=" OR inurl:"next="': "MEDIUM",
    'site:{domain} inurl:"?return=" OR inurl:"?goto=" OR inurl:"?target="': "MEDIUM",
    'site:{domain} inurl:"?page=" filetype:php': "LOW",
}

# ── GitHub-specific dorks for leaked secrets ──
GITHUB_DORKS: Dict[str, str] = {
    '"{domain}" password': "HIGH",
    '"{domain}" api_key OR apikey OR "api-key"': "HIGH",
    '"{domain}" secret OR token OR "access_token"': "HIGH",
    '"{domain}" "BEGIN RSA PRIVATE KEY"': "CRITICAL",
    '"{domain}" "-----BEGIN CERTIFICATE-----"': "HIGH",
    '"{domain}" "DB_PASSWORD" OR "DATABASE_URL"': "CRITICAL",
    '"{domain}" "AWS_SECRET_ACCESS_KEY"': "CRITICAL",
    '"{domain}" filename:.env "password"': "CRITICAL",
    '"{domain}" filename:.env "secret"': "CRITICAL",
    '"{domain}" filename:config.json "password"': "HIGH",
    '"{domain}" filename:settings.py SECRET_KEY': "HIGH",
    '"{domain}" filename:.npmrc "_auth"': "HIGH",
    '"{domain}" filename:.dockercfg "auth"': "HIGH",
    '"{domain}" filename:credentials aws_access_key_id': "CRITICAL",
    '"{domain}" "heroku" API_KEY OR SECRET': "HIGH",
    '"{domain}" "slack_token" OR "slack_webhook"': "MEDIUM",
    '"{domain}" "stripe" "sk_live" OR "sk_test"': "CRITICAL",
}

# ── Pastebin dorks ──
PASTEBIN_DORKS: Dict[str, str] = {
    'site:pastebin.com "{domain}" "password"': "HIGH",
    'site:pastebin.com "{domain}" "api_key"': "HIGH",
    'site:pastebin.com "{domain}" "secret"': "HIGH",
    'site:pastebin.com "{domain}" "BEGIN RSA"': "CRITICAL",
    'site:paste.ee "{domain}" "password"': "HIGH",
    'site:justpaste.it "{domain}" "password"': "MEDIUM",
    'site:ghostbin.com "{domain}"': "MEDIUM",
    'site:dpaste.org "{domain}" "secret"': "MEDIUM",
}

# ── ExploitDB / vulnerability dorks ──
EXPLOIT_DORKS: Dict[str, str] = {
    'site:exploit-db.com "{domain}"': "INFO",
    '"{domain}" "powered by" inurl:exploit': "INFO",
    'site:cvedetails.com "{domain}"': "INFO",
}


def get_all_dorks(domain: str) -> List[Dict[str, str]]:
    """Generate all dork queries for a given domain.

    Returns a list of dicts with 'query' and 'severity' keys.
    """
    all_dorks: Dict[str, str] = {}
    for category in (
        DORKS_SENSITIVE_FILES, DORKS_EXPOSED_PANELS,
        DORKS_ERROR_MESSAGES, DORKS_OPEN_REDIRECTS,
    ):
        for template, severity in category.items():
            query = template.format(domain=domain)
            all_dorks[query] = severity

    return [{"query": q, "severity": s} for q, s in all_dorks.items()]


def get_github_dorks(domain: str) -> List[Dict[str, str]]:
    """Generate GitHub-specific dorks for a domain."""
    return [
        {"query": template.format(domain=domain), "severity": s}
        for template, s in GITHUB_DORKS.items()
    ]


def get_pastebin_dorks(domain: str) -> List[Dict[str, str]]:
    """Generate Pastebin dorks for a domain."""
    return [
        {"query": template.format(domain=domain), "severity": s}
        for template, s in PASTEBIN_DORKS.items()
    ]


async def run_dorking(
    domain: str,
    db: "DatabaseManager",
    config: "AppConfig",
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Execute dorking queries for a domain.

    This generates dork queries and optionally executes them via:
      1. GitHub code search API (if token provided)
      2. Web search engine scraping (limited, may hit captchas)

    Results are stored as change events with the dork findings.

    Args:
        domain: Target domain to dork.
        db: DatabaseManager for persisting findings.
        config: Application config.
        github_token: Optional GitHub API token for code search.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    # ── Phase 1: GitHub code search (if token available) ──
    gh_token = github_token or ""
    if gh_token:
        gh_findings = await _github_search(domain, gh_token, config)
        findings.extend(gh_findings)

    # ── Phase 2: Generate dork reports (for manual use) ──
    all_dorks = get_all_dorks(domain)
    gh_dorks = get_github_dorks(domain)
    pb_dorks = get_pastebin_dorks(domain)

    # Store a dork summary event
    if all_dorks:
        dork_summary = {
            "domain": domain,
            "total_dorks": len(all_dorks) + len(gh_dorks) + len(pb_dorks),
            "search_engine_dorks": len(all_dorks),
            "github_dorks": len(gh_dorks),
            "pastebin_dorks": len(pb_dorks),
            "github_results": len([f for f in findings if f.get("source") == "github"]),
            "top_queries": [
                d["query"] for d in (all_dorks + gh_dorks + pb_dorks)[:20]
            ],
        }
        try:
            db.add_change_event(
                event_type="DORK_SCAN_COMPLETE",
                severity="INFO",
                target=domain,
                description=(
                    f"Dorking scan complete for {domain}: "
                    f"{dork_summary['total_dorks']} queries generated, "
                    f"{dork_summary['github_results']} GitHub results found"
                ),
                diff_data=dork_summary,
            )
        except Exception:
            pass

    # Persist GitHub findings as HIGH/CRITICAL events
    for f in findings:
        if f.get("severity") in ("HIGH", "CRITICAL"):
            try:
                db.add_change_event(
                    event_type="DORK_LEAK_FOUND",
                    severity=f["severity"],
                    target=domain,
                    description=(
                        f"Potential leak found via {f.get('source', 'dorking')}: "
                        f"{f.get('title', f.get('query', ''))}"
                    ),
                    diff_data=f,
                )
            except Exception:
                pass

    logger.info(
        "Dorking complete for %s: %d findings", domain, len(findings),
    )
    return findings


async def _github_search(
    domain: str,
    token: str,
    config: "AppConfig",
) -> List[Dict[str, Any]]:
    """Search GitHub code for leaked secrets related to a domain."""
    findings: List[Dict[str, Any]] = []
    gh_dorks = get_github_dorks(domain)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15),
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": config.scan.user_agent,
        },
    ) as client:
        for dork in gh_dorks[:10]:  # Rate limit: 10 requests per scan
            try:
                resp = await client.get(
                    "https://api.github.com/search/code",
                    params={
                        "q": dork["query"],
                        "per_page": 5,
                        "sort": "indexed",
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    if total > 0:
                        items = data.get("items", [])
                        for item in items[:3]:
                            findings.append({
                                "source": "github",
                                "severity": dork["severity"],
                                "query": dork["query"],
                                "title": item.get("name", ""),
                                "url": item.get("html_url", ""),
                                "repository": item.get("repository", {}).get("full_name", ""),
                                "total_matches": total,
                            })
                elif resp.status_code == 403:
                    logger.warning("GitHub API rate limit hit — stopping search")
                    break
                elif resp.status_code == 422:
                    continue  # Invalid query, skip
                else:
                    logger.debug("GitHub search returned %d for query: %s", resp.status_code, dork["query"])
            except Exception as exc:
                logger.debug("GitHub search error: %s", exc)

            # Small delay to avoid rate limiting
            await asyncio.sleep(1.5)

    return findings
