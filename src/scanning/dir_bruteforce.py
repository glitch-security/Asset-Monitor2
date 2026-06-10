"""
Async directory & file brute-forcer using httpx.

Fuzzes common web paths against live hosts to discover hidden directories,
backup files, config files, admin panels, and other interesting resources.
Uses pure Python (no external binary like ffuf/gobuster required) and
leverages httpx async for high-concurrency scanning.

Results are stored as discovered endpoints and change events.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Dict, List, Optional, Set

import httpx

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

# ── Wordlist: high-value paths for bug bounty / attack surface discovery ──

DIRECTORY_WORDLIST: List[str] = [
    # ── Admin / Control Panels ──
    "/admin", "/admin/", "/administrator/", "/admin/login", "/admin/login.php",
    "/admin/index.php", "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/manager", "/manager/", "/manager/html", "/cpanel", "/panel",
    "/control", "/console", "/dashboard", "/backend", "/phpmyadmin",
    "/phpmyadmin/", "/pma", "/pma/", "/myadmin", "/mysql", "/mysql/",
    "/db", "/dbadmin", "/server-status", "/server-info",
    # ── API / Docs ──
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger-ui/", "/swagger.json",
    "/api-docs", "/openapi", "/openapi.json", "/docs", "/redoc",
    "/spec", "/swagger-resources", "/swagger-ui.html",
    # ── Config / Info files ──
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.backup", "/.env.bak", "/.env.old", "/.env.save",
    "/config", "/config.json", "/config.yml", "/config.yaml",
    "/config.php", "/config.inc.php", "/configuration.php",
    "/app.config", "/appsettings.json", "/web.config",
    "/settings.json", "/settings.py", "/local.settings.json",
    "/info.php", "/phpinfo.php", "/test.php", "/info",
    "/server-status", "/server-info", "/status", "/health",
    "/heartbeat", "/version", "/ping", "/alive",
    # ── Source / Version Control ──
    "/.git", "/.git/", "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.svn", "/.svn/", "/.svn/entries", "/.hg", "/.hg/",
    "/.bzr", "/.bzr/",
    # ── Backup files ──
    "/backup", "/backup/", "/backup.zip", "/backup.tar.gz",
    "/backup.sql", "/backup.tar", "/backup.rar",
    "/db.sql", "/db.sql.gz", "/database.sql", "/database.sql.gz",
    "/dump.sql", "/dump.sql.gz", "/mysql.sql",
    "/site.zip", "/site.tar.gz", "/www.zip", "/www.tar.gz",
    "/web.zip", "/web.tar.gz", "/archive.zip",
    "/.backup", "/.bak", "/old/", "/temp/", "/tmp/",
    # ── WordPress / CMS ──
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/wp-content/", "/wp-content/debug.log", "/wp-content/uploads/",
    "/wp-includes/", "/xmlrpc.php", "/wp-cron.php",
    "/wp-json/wp/v2/users", "/wp-json/", "/?rest_route=/wp/v2/users",
    "/readme.html", "/license.txt",
    # ── CI/CD / DevOps ──
    "/.well-known/", "/.well-known/security.txt",
    "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
    "/docker-compose.yaml", "/.travis.yml", "/.gitlab-ci.yml",
    "/Jenkinsfile", "/.circleci/config.yml",
    "/jenkins", "/jenkins/", "/bamboo", "/teamcity",
    # ── Misc sensitive ──
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.htaccess", "/.htpasswd", "/webalizer",
    "/phpmy", "/typo3", "/typo3/", "/drupal",
    "/joomla", "/joomla/", "/magento", "/magento/",
    "/laravel", "/laravel/", "/symfony", "/symfony/",
    "/cakephp", "/yii", "/zend",
    "/wp-content/backups/", "/wp-content/backup-db/",
    "/cgi-bin/", "/cgi-bin/test", "/cgi-mod/",
    "/actuator", "/actuator/", "/actuator/health",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/actuator/configprops", "/actuator/info", "/actuator/metrics",
    "/actuator/trace", "/actuator/dump", "/actuator/heapdump",
    # ── OAuth / Auth endpoints ──
    "/oauth", "/oauth/", "/oauth/authorize", "/oauth/token",
    "/auth", "/auth/", "/auth/login", "/auth/callback",
    "/login", "/login/", "/signin", "/signup", "/register",
    "/forgot-password", "/reset-password",
    # ── Common file extensions to probe on known names ──
    "/index.php~", "/index.php.bak", "/index.php.old",
    "/index.html~", "/index.html.bak", "/index.old",
    "/.DS_Store", "/.DS_Store?", "/Thumbs.db",
]

# Status codes considered interesting
_INTERESTING_STATUSES = {200, 201, 204, 301, 302, 401, 403}

# File extensions that indicate high-value content
_HIGH_VALUE_EXTENSIONS = {
    ".sql", ".zip", ".tar", ".gz", ".bak", ".old", ".env",
    ".config", ".conf", ".cfg", ".ini", ".yml", ".yaml",
}


def _classify_finding(path: str, status_code: int, content_length: int) -> str:
    """Return severity for a discovered path."""
    if status_code in (200, 201, 204):
        # Check for high-value extensions
        lower = path.lower()
        if any(lower.endswith(ext) for ext in _HIGH_VALUE_EXTENSIONS):
            return "HIGH"
        if any(kw in lower for kw in (
            ".env", ".git/", "backup", "dump", "heapdump", "phpmyadmin",
            "wp-config", ".sql", "debug.log", "swagger",
        )):
            return "HIGH"
        if any(kw in lower for kw in ("admin", "config", "api-docs", "actuator")):
            return "MEDIUM"
        return "LOW"
    if status_code == 403:
        return "INFO"  # Confirms path exists but access denied
    if status_code in (301, 302):
        return "INFO"
    if status_code == 401:
        return "MEDIUM"
    return "INFO"


async def bruteforce_directories(
    base_url: str,
    db: "DatabaseManager",
    subdomain_id: int,
    config: "AppConfig",
    wordlist: Optional[List[str]] = None,
    max_concurrent: int = 20,
    timeout: int = 8,
) -> List[Dict]:
    """Fuzz a web server with a directory/file wordlist.

    Args:
        base_url: Target URL (e.g. ``https://example.com``).
        db: DatabaseManager for persisting endpoints and events.
        subdomain_id: FK to the Subdomain being scanned.
        config: Application config for user-agent and SSL settings.
        wordlist: Custom path list. Defaults to the built-in wordlist.
        max_concurrent: Max concurrent HTTP requests.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with path, status, severity, etc.
    """
    paths = wordlist or DIRECTORY_WORDLIST
    base = base_url.rstrip("/")
    findings: List[Dict] = []
    seen_paths: Set[str] = set()

    # Baseline: detect default responses (some servers return 200 for everything)
    baseline_length: Optional[int] = None
    baseline_status: Optional[int] = None
    try:
        async with httpx.AsyncClient(
            verify=config.scan.verify_ssl,
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": config.scan.user_agent},
            follow_redirects=False,
        ) as client:
            # Probe a random nonexistent path for baseline
            try:
                resp = await client.get(f"{base}/thispagedoesnotexist12345")
                baseline_status = resp.status_code
                baseline_length = len(resp.content)
            except Exception:
                pass
    except Exception:
        pass

    sem = asyncio.Semaphore(max_concurrent)

    async def _probe(client: httpx.AsyncClient, path: str) -> Optional[Dict]:
        async with sem:
            url = base + path
            try:
                resp = await client.get(url)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout):
                return None
            except Exception:
                return None

        status = resp.status_code
        if status not in _INTERESTING_STATUSES:
            return None

        length = len(resp.content)

        # Filter out responses that match the baseline (catch-all pages)
        if baseline_status == 200 and status == 200:
            if baseline_length and abs(length - baseline_length) < 50:
                return None  # Same length as 404-equivalent → skip

        severity = _classify_finding(path, status, length)

        return {
            "path": path,
            "status_code": status,
            "content_length": length,
            "severity": severity,
            "url": url,
        }

    async with httpx.AsyncClient(
        verify=config.scan.verify_ssl,
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": config.scan.user_agent},
        follow_redirects=False,
    ) as client:
        tasks = [_probe(client, p) for p in paths if p not in seen_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict) and r.get("path"):
            findings.append(r)
            seen_paths.add(r["path"])

    # Persist discovered endpoints and generate events
    for f in findings:
        try:
            db.upsert_endpoint(
                subdomain_id=subdomain_id,
                path=f["path"],
                method="GET",
                status_code=f["status_code"],
                source="dir_bruteforce",
            )
        except Exception:
            pass  # Endpoint already exists

        if f["severity"] in ("HIGH", "CRITICAL"):
            try:
                db.add_change_event(
                    event_type="SENSITIVE_PATH_FOUND",
                    severity=f["severity"],
                    target=base_url.replace("https://", "").replace("http://", "").split("/")[0],
                    description=f"Sensitive path discovered: {f['path']} (HTTP {f['status_code']}, {f['content_length']} bytes)",
                    diff_data=f,
                )
            except Exception:
                pass

    logger.info(
        "Directory brute-force on %s: %d findings from %d paths",
        base_url, len(findings), len(paths),
    )
    return findings
