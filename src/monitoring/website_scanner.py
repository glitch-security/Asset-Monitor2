"""
Comprehensive website scanner.

Runs a multi-technique scan against a single website URL:
  1. HTTP probe + technology fingerprinting (via VerificationManager)
  2. BFS crawl  — pages, endpoints, forms, external links
  3. JS analysis — API endpoints, routes extracted from JS files
  4. Security files — robots.txt, .git, .env, swagger, etc.
  5. Screenshot (Playwright headless Chromium)

The screenshot is always attempted if `techniques.get("screenshot")` is True
and stored at data/screenshots/<sha256[:16]>.png.  The file path is included
in the return dict so callers can derive the serve URL.
"""

from __future__ import annotations

import hashlib
import logging
import os
import urllib.parse
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

_SCREENSHOT_DIR = "data/screenshots"
# Playwright timeout for page load (ms)
_SCREENSHOT_TIMEOUT_MS = 30_000


def screenshot_path_for_url(url: str) -> str:
    """Return the expected screenshot file path for *url* (may not exist yet)."""
    filename = hashlib.sha256(url.encode()).hexdigest()[:16] + ".png"
    return os.path.join(_SCREENSHOT_DIR, filename)


async def scan_website(
    url: str,
    techniques: dict,
    config: "AppConfig",
    db: "DatabaseManager",
) -> dict:
    """
    Run all enabled techniques against *url*.

    Returns a dict with:
        url, hostname, domain_id, live, status, http_status, page_title,
        technologies, pages, endpoints, api_endpoints, js_routes,
        security_files, disallow_paths, screenshot_path, ssl_valid, error
    """
    result: dict = {
        "url": url,
        "hostname": "",
        "domain_id": None,
        "live": False,
        "status": "unknown",
        "http_status": 0,
        "page_title": "",
        "technologies": [],
        "pages": [],
        "endpoints": [],
        "api_endpoints": [],
        "js_routes": [],
        "security_files": [],
        "disallow_paths": [],
        "screenshot_path": None,
        "ssl_valid": True,
        "error": None,
    }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result["url"] = url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        result["error"] = f"Cannot parse hostname from URL: {url}"
        return result
    result["hostname"] = hostname

    parts = hostname.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    domain = db.get_domain(root) or db.add_domain(root)
    result["domain_id"] = domain.id

    cfg_scan = config.scan
    timeout = cfg_scan.request_timeout_seconds
    verify_ssl = cfg_scan.verify_ssl

    # ------------------------------------------------------------------
    # Step 1 — HTTP probe + fingerprint
    # ------------------------------------------------------------------
    try:
        from ..verification.manager import VerificationManager
        vm = VerificationManager(config, db)
        probe = await vm.verify_subdomain(hostname, domain.id, "website")
        result["live"] = probe.get("live", False)
        result["http_status"] = probe.get("status_code", 0)
        result["page_title"] = probe.get("page_title", "")
        result["technologies"] = probe.get("technologies", [])
        result["ssl_valid"] = probe.get("ssl_valid", True)

        if result["live"]:
            result["status"] = "alive"
        elif probe.get("dns_resolved"):
            result["status"] = "dead"
        else:
            result["status"] = "unknown"

        logger.info(
            "Website probe %s → live=%s status=%s ssl_valid=%s",
            hostname, result["live"], result["http_status"], result["ssl_valid"],
        )
    except Exception as exc:
        logger.warning("Probe failed for %s: %s", url, exc)
        result["error"] = str(exc)
        return result

    if not result["live"]:
        # Still try screenshot even for dead hosts so the user can see what's there
        if techniques.get("screenshot", False):
            result["screenshot_path"] = await _take_screenshot(url, timeout)
        return result

    # Use canonical URL after redirects if available
    base_url = url

    # ------------------------------------------------------------------
    # Step 2 — BFS crawl
    # ------------------------------------------------------------------
    js_urls: list[str] = []
    if techniques.get("crawl", True):
        try:
            from .crawler import BFSCrawler
            crawler = BFSCrawler(
                base_url=base_url,
                max_depth=cfg_scan.max_crawl_depth,
                max_pages=cfg_scan.max_pages_per_domain,
                timeout=timeout,
                verify_ssl=verify_ssl,
                user_agent=cfg_scan.user_agent,
            )
            crawl_data = await crawler.crawl()
            result["pages"] = crawl_data.get("pages", [])
            result["endpoints"] = crawl_data.get("endpoints", [])

            sub = db.get_subdomain(hostname)
            if sub:
                for path in result["endpoints"]:
                    try:
                        db.upsert_endpoint(sub.id, path, "GET")
                    except Exception:
                        pass

            for asset in crawl_data.get("assets", []):
                if asset.get("asset_type") == "js":
                    js_urls.append(asset["url"])
        except Exception as exc:
            logger.warning("Crawl failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Step 3 — JS analysis
    # ------------------------------------------------------------------
    if techniques.get("js_analysis", True) and js_urls:
        try:
            from .js_analyzer import analyze_js_file
            all_api_endpoints: set[str] = set()
            all_routes: set[str] = set()
            for js_url in js_urls[:20]:
                try:
                    js_result = await analyze_js_file(
                        url=js_url, domain=root, timeout=timeout, verify_ssl=verify_ssl,
                    )
                    all_api_endpoints.update(js_result.get("endpoints", []))
                    all_routes.update(js_result.get("routes", []))
                except Exception as js_exc:
                    logger.debug("JS analysis failed for %s: %s", js_url, js_exc)

            result["api_endpoints"] = sorted(all_api_endpoints)
            result["js_routes"] = sorted(all_routes)

            sub = db.get_subdomain(hostname)
            if sub:
                for path in result["api_endpoints"]:
                    try:
                        db.upsert_endpoint(sub.id, path, "GET")
                    except Exception:
                        pass
        except Exception as exc:
            logger.warning("JS analysis step failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Step 4 — Security files
    # ------------------------------------------------------------------
    if techniques.get("security_files", True):
        try:
            from .security_files import check_security_files
            sec_result = await check_security_files(
                base_url=base_url, timeout=timeout, verify_ssl=verify_ssl,
            )
            result["security_files"] = sec_result.get("found", [])
            result["disallow_paths"] = sec_result.get("disallow_paths", [])
        except Exception as exc:
            logger.warning("Security files check failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Step 5 — Screenshot
    # ------------------------------------------------------------------
    if techniques.get("screenshot", False):
        result["screenshot_path"] = await _take_screenshot(url, timeout)

    return result


async def _take_screenshot(url: str, timeout: int = 15) -> Optional[str]:
    """Take a headless Chromium screenshot. Returns the file path or None."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.debug("playwright not installed — screenshot skipped")
        return None

    os.makedirs(_SCREENSHOT_DIR, exist_ok=True)
    path = screenshot_path_for_url(url)

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                ],
            )
            ctx = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = await ctx.new_page()
            try:
                await page.goto(
                    url,
                    timeout=max(_SCREENSHOT_TIMEOUT_MS, timeout * 1000),
                    wait_until="domcontentloaded",
                )
                # Brief settle to let critical CSS render
                await page.wait_for_timeout(800)
                await page.screenshot(path=path, full_page=False)
                logger.info("Screenshot saved: %s → %s", url, path)
                return path
            except Exception as exc:
                logger.warning("Page load/screenshot failed for %s: %s", url, exc)
                return None
            finally:
                await browser.close()
    except Exception as exc:
        logger.warning("Playwright launch failed for %s: %s", url, exc)
        return None
