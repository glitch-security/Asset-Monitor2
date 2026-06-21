"""
APScheduler-based periodic scan scheduler.

Uses AsyncIOScheduler so jobs run as native coroutines in the same event loop
as uvicorn — no sync/async bridge, no extra threads, no asyncio.run() per tick.

Domain and website targets are read exclusively from the database. There is no
flat-file fallback (domains.txt, subdomains.txt, websites.txt are examples only
and are NOT read at runtime).
"""

from __future__ import annotations

import copy
import logging
from datetime import datetime, timezone
from typing import List, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config import AppConfig
from src.database import ChangeEvent, DatabaseManager, Domain
from src.notifications.manager import NotificationManager

logger = logging.getLogger(__name__)


def _apply_profile_to_config(config: AppConfig, settings: dict) -> None:
    """Mutate *config* in-place to apply the given scan profile settings."""
    enum_settings = settings.get("enumeration") or {}
    for k, v in enum_settings.items():
        if hasattr(config.enumeration.techniques, k):
            setattr(config.enumeration.techniques, k, bool(v))

    port_settings = settings.get("port_scanning") or {}
    if "enabled" in port_settings:
        config.port_scanning.enabled = bool(port_settings["enabled"])
    if port_settings.get("arguments"):
        config.port_scanning.scan_arguments = port_settings["arguments"]

    crawl_settings = settings.get("crawl") or {}
    if "max_depth" in crawl_settings:
        config.scan.max_crawl_depth = int(crawl_settings["max_depth"])
    if "max_pages" in crawl_settings:
        config.scan.max_pages_per_domain = int(crawl_settings["max_pages"])
    if "enabled" in crawl_settings:
        config.scan.crawl_enabled = bool(crawl_settings["enabled"])


class SchedManager:
    """Wraps AsyncIOScheduler to run periodic full-scan coroutines.

    All jobs execute as coroutines in the uvicorn event loop — no threads,
    no asyncio.run() calls.
    """

    def __init__(
        self,
        config: AppConfig,
        db: DatabaseManager,
        notification_manager: NotificationManager,
    ) -> None:
        self._config = config
        self._db = db
        self._notification_manager = notification_manager
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._running = False

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Add the periodic job and start the scheduler."""
        interval_minutes = self._config.scan.interval_minutes
        self._scheduler.add_job(
            func=self.run_full_scan,
            trigger=IntervalTrigger(minutes=interval_minutes),
            id="full_scan",
            name="AssetMonitor full scan",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        self._scheduler.start()
        self._running = True
        logger.info("AsyncIOScheduler started (interval=%d min)", interval_minutes)

    def stop(self) -> None:
        """Shut down the scheduler without blocking the event loop."""
        if self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scheduler stopped")

    def reschedule(self, interval_minutes: int) -> None:
        """Update the scan interval without restarting the scheduler."""
        if not self._running:
            return
        self._scheduler.reschedule_job(
            "full_scan",
            trigger=IntervalTrigger(minutes=interval_minutes),
        )
        logger.info("Scan interval updated to %d minute(s)", interval_minutes)

    # ── Core async scan ──────────────────────────────────────────────────────

    async def run_full_scan(self) -> None:
        """Execute one full scan cycle across all configured targets.

        1. Enumerate + verify all root domains from the database.
        2. Scan all monitored websites from the website store.
        3. Run port scanning.
        4. Dispatch notifications.
        5. Update domain.last_scan timestamps.
        """
        scan_start = datetime.now(tz=timezone.utc)
        logger.info("=== Full scan started at %s ===", scan_start.isoformat())

        all_domains: List[Domain] = self._db.get_all_domains()

        # ── 1. Enumerate + verify each root domain ───────────────────────────
        total_subdomains_found = 0
        all_new_events: List[ChangeEvent] = []

        for dom in all_domains:
            logger.info("Scanning domain: %s", dom.domain)
            orig_config = self._config
            try:
                if dom.profile_id:
                    profile = self._db.get_profile(dom.profile_id)
                    if profile and profile.settings:
                        self._config = copy.deepcopy(orig_config)
                        _apply_profile_to_config(self._config, profile.settings)
                        logger.info("Domain %s using profile %r", dom.domain, profile.name)
                new_events, sub_count = await self._scan_domain(dom)
                total_subdomains_found += sub_count
                all_new_events.extend(new_events)
            except Exception as exc:
                logger.error("Error scanning domain %s: %s", dom.domain, exc, exc_info=True)
            finally:
                self._config = orig_config

        # ── 2. Websites from the website store ───────────────────────────────
        try:
            from src.monitoring.website_store import read_websites
            websites = read_websites()
        except Exception as exc:
            logger.error("Failed to read website store: %s", exc)
            websites = []

        if websites and self._config.scan.crawl_enabled:
            logger.info("Processing %d website(s)", len(websites))
            try:
                ws_events = await self._scan_websites(websites)
                all_new_events.extend(ws_events)
            except Exception as exc:
                logger.error("Error scanning websites: %s", exc, exc_info=True)

        # ── 3. Port scanning ─────────────────────────────────────────────────
        try:
            from src.scanning.manager import PortScanManager
            psm = PortScanManager(self._config, self._db)
            port_events = await psm.scan_all()
            all_new_events.extend(port_events)
        except ImportError:
            logger.debug("scanning module not available — skipping port scan")
        except Exception as exc:
            logger.error("Port scanning failed: %s", exc, exc_info=True)

        # ── 3.5. GitHub monitoring ────────────────────────────────────────────
        try:
            gh_result = await self._run_github_monitoring()
            if gh_result and gh_result.get('total_findings', 0) > 0:
                logger.info(
                    "GitHub monitoring found %d finding(s)",
                    gh_result.get('total_findings', 0)
                )
        except Exception as exc:
            logger.error("GitHub monitoring failed: %s", exc, exc_info=True)

        # ── 4. Dispatch notifications ────────────────────────────────────────
        events_by_domain = self._group_events_by_domain(all_new_events, all_domains)
        for dom_name, dom_events in events_by_domain.items():
            if dom_events:
                try:
                    await self._notification_manager.dispatch(dom_events, dom_name)
                except Exception as exc:
                    logger.error("Notification dispatch error for %s: %s", dom_name, exc)

        # ── 5. Update domain.last_scan timestamps ────────────────────────────
        now = datetime.now(tz=timezone.utc)
        from sqlalchemy import update as _update
        from src.database import Domain as _Domain
        with self._db.get_session() as session:
            for dom in all_domains:
                session.execute(
                    _update(_Domain).where(_Domain.id == dom.id).values(last_scan=now)
                )

        elapsed = (datetime.now(tz=timezone.utc) - scan_start).total_seconds()
        logger.info(
            "=== Full scan complete in %.1fs — domains=%d subs_found=%d events=%d ===",
            elapsed, len(all_domains), total_subdomains_found, len(all_new_events),
        )

    # ── Single-domain scan (used by on-demand trigger) ───────────────────────

    async def run_domain_scan(
        self,
        domain_name: str,
        technique_overrides: Optional[dict] = None,
    ) -> tuple[int, int]:
        """Enumerate + verify a single domain and dispatch notifications.

        Returns ``(subdomains_found, events_generated)``.
        """
        domain = self._db.add_domain(domain_name)

        orig_config = self._config
        if domain.profile_id or technique_overrides:
            self._config = copy.deepcopy(orig_config)
            if domain.profile_id:
                profile = self._db.get_profile(domain.profile_id)
                if profile and profile.settings:
                    _apply_profile_to_config(self._config, profile.settings)
                    logger.info("Using profile %r for domain %s", profile.name, domain_name)
            if technique_overrides:
                techniques = self._config.enumeration.techniques
                for k, v in technique_overrides.items():
                    if hasattr(techniques, k):
                        setattr(techniques, k, bool(v))

        try:
            events, sub_count = await self._scan_domain(domain)
        finally:
            self._config = orig_config

        if events:
            try:
                await self._notification_manager.dispatch(events, domain_name)
            except Exception as exc:
                logger.error("Notification dispatch error for %s: %s", domain_name, exc)

        from sqlalchemy import update as _update
        from src.database import Domain as _Domain
        with self._db.get_session() as session:
            session.execute(
                _update(_Domain)
                .where(_Domain.id == domain.id)
                .values(last_scan=datetime.now(tz=timezone.utc))
            )

        logger.info(
            "Domain scan complete for %s: %d subdomains, %d events",
            domain_name, sub_count, len(events),
        )
        return sub_count, len(events)

    # ── Internal helpers ─────────────────────────────────────────────────────

    async def _scan_domain(self, dom: Domain) -> tuple[List[ChangeEvent], int]:
        """Run enumeration and verification for a single root domain."""
        # ── Scope enforcement ──
        if self._config.scope.enforce_scope and dom.scope_type == "out_of_scope":
            logger.info("Skipping out-of-scope domain: %s", dom.domain)
            return [], 0

        new_events: List[ChangeEvent] = []
        subdomain_count = 0
        cfg = self._config
        techniques = cfg.enumeration.techniques
        discovered_fqdns: set[str] = set()

        if techniques.certificate_transparency:
            try:
                from src.enumeration.ct_logs import enumerate_ct_logs
                ct_fqdns = await enumerate_ct_logs(dom.domain)
                discovered_fqdns.update(ct_fqdns)
                logger.debug("CT logs found %d FQDNs for %s", len(ct_fqdns), dom.domain)
            except ImportError:
                logger.debug("ct_logs module not available — skipping")
            except Exception as exc:
                logger.warning("CT log enumeration failed for %s: %s", dom.domain, exc)

        if techniques.passive_dns:
            try:
                from src.enumeration.passive_dns import aggregate_passive_dns
                pdns_fqdns = await aggregate_passive_dns(dom.domain, cfg.api_keys.model_dump())
                discovered_fqdns.update(pdns_fqdns)
                logger.debug("Passive DNS found %d FQDNs for %s", len(pdns_fqdns), dom.domain)
            except ImportError:
                logger.debug("passive_dns module not available — skipping")
            except Exception as exc:
                logger.warning("Passive DNS enumeration failed for %s: %s", dom.domain, exc)

        if techniques.wayback_machine:
            try:
                from src.enumeration.wayback import enumerate_wayback
                wb_fqdns = await enumerate_wayback(dom.domain)
                discovered_fqdns.update(wb_fqdns)
                logger.debug("Wayback found %d FQDNs for %s", len(wb_fqdns), dom.domain)
            except ImportError:
                logger.debug("wayback module not available — skipping")
            except Exception as exc:
                logger.warning("Wayback enumeration failed for %s: %s", dom.domain, exc)

        if techniques.dns_records:
            try:
                from src.enumeration.dns_records import enumerate_dns_records
                dr_fqdns = await enumerate_dns_records(dom.domain, resolvers=cfg.enumeration.dns_resolvers)
                discovered_fqdns.update(dr_fqdns)
                logger.debug("DNS records found %d FQDNs for %s", len(dr_fqdns), dom.domain)
            except ImportError:
                logger.debug("dns_records module not available — skipping")
            except Exception as exc:
                logger.warning("DNS records enumeration failed for %s: %s", dom.domain, exc)

        if techniques.dns_bruteforce:
            try:
                from src.enumeration.dns_bruteforce import bruteforce_dns
                bf_fqdns = await bruteforce_dns(
                    dom.domain,
                    wordlist_path=cfg.enumeration.wordlist_path,
                    resolvers=cfg.enumeration.dns_resolvers,
                    max_concurrent=cfg.enumeration.max_dns_concurrent,
                )
                discovered_fqdns.update(bf_fqdns)
                logger.debug("DNS bruteforce found %d FQDNs for %s", len(bf_fqdns), dom.domain)
            except ImportError:
                logger.debug("dns_bruteforce module not available — skipping")
            except Exception as exc:
                logger.warning("DNS bruteforce failed for %s: %s", dom.domain, exc)

        if discovered_fqdns:
            try:
                from src.verification.manager import VerificationManager
                vm = VerificationManager(cfg, self._db)

                old_states: dict[str, dict] = {}
                for fqdn in discovered_fqdns:
                    ex = self._db.get_subdomain(fqdn)
                    if ex:
                        # Get latest scan for DNS security data
                        latest_scan = self._db.get_latest_subdomain_scan(ex.id)
                        dnssec_info = None
                        email_security = None
                        nameserver_security = None
                        if latest_scan:
                            dnssec_info = latest_scan.dnssec_info
                            email_security = latest_scan.email_security
                            nameserver_security = latest_scan.nameserver_security

                        old_states[fqdn] = {
                            "live": ex.status == "alive",
                            "a_records": list(ex.ip_addresses or []),
                            "aaaa_records": [],
                            "status_code": ex.http_status or 0,
                            "technologies": ex.technologies or [],
                            "cert_fingerprint": ex.cert_fingerprint,
                            "takeover": (
                                {"service": "unknown", "confidence": "unknown"}
                                if ex.takeover_vulnerable else None
                            ),
                            "dnssec_info": dnssec_info,
                            "email_security": email_security,
                            "nameserver_security": nameserver_security,
                        }

                results = await vm.verify_batch(discovered_fqdns, dom.id, "enumeration")
                subdomain_count = len([r for r in results if "error" not in r])

                for res in results:
                    fqdn = res.get("fqdn", "")
                    if not fqdn or "error" in res:
                        continue
                    old = old_states.get(fqdn, {})
                    ev_data_list = await vm.generate_change_events(fqdn, old, res)
                    for ev_data in ev_data_list:
                        ev = self._db.add_change_event(**ev_data)
                        new_events.append(ev)

            except Exception as exc:
                logger.error("Verification failed for %s: %s", dom.domain, exc, exc_info=True)

        # ── Phase: Cloud asset discovery ──
        if techniques.cloud_asset_discovery:
            try:
                from src.enumeration.cloud_assets import discover_cloud_assets
                sub_fqdns = [s.fqdn for s in self._db.get_live_subdomains(dom.id)]
                cloud_findings = await discover_cloud_assets(dom.domain, sub_fqdns, self._db, cfg)
                logger.info("Cloud asset discovery for %s: %d findings", dom.domain, len(cloud_findings))
            except ImportError:
                logger.debug("cloud_assets module not available — skipping")
            except Exception as exc:
                logger.warning("Cloud asset discovery failed for %s: %s", dom.domain, exc)

        # ── Phase: Dorking ──
        if techniques.dorking:
            try:
                from src.enumeration.dorking import run_dorking
                gh_token = cfg.api_keys.github_token if hasattr(cfg.api_keys, 'github_token') else ""
                dork_findings = await run_dorking(dom.domain, self._db, cfg, github_token=gh_token or None)
                logger.info("Dorking for %s: %d findings", dom.domain, len(dork_findings))
            except ImportError:
                logger.debug("dorking module not available — skipping")
            except Exception as exc:
                logger.warning("Dorking failed for %s: %s", dom.domain, exc)

        # ── Phase: Attack surface scanning (dir bruteforce + API discovery) on live subs ──
        atk_cfg = getattr(cfg, 'attack_surface', None)
        if atk_cfg:
            live_subs = self._db.get_live_subdomains(dom.id)
            for sub in live_subs[:20]:  # Cap to avoid runaway scans
                base_url = f"https://{sub.fqdn}"

                # Directory brute-force
                if getattr(atk_cfg, 'dir_bruteforce', False):
                    try:
                        from src.scanning.dir_bruteforce import bruteforce_directories
                        await bruteforce_directories(
                            base_url=base_url,
                            db=self._db,
                            subdomain_id=sub.id,
                            config=cfg,
                            max_concurrent=getattr(atk_cfg, 'dir_bruteforce_concurrency', 20),
                        )
                    except ImportError:
                        pass
                    except Exception as exc:
                        logger.debug("Dir brute-force failed for %s: %s", sub.fqdn, exc)

                # API endpoint discovery
                if getattr(atk_cfg, 'api_discovery', False):
                    try:
                        from src.scanning.api_discovery import discover_api_endpoints
                        await discover_api_endpoints(
                            base_url=base_url,
                            db=self._db,
                            subdomain_id=sub.id,
                            config=cfg,
                            max_concurrent=getattr(atk_cfg, 'api_discovery_concurrency', 15),
                        )
                    except ImportError:
                        pass
                    except Exception as exc:
                        logger.debug("API discovery failed for %s: %s", sub.fqdn, exc)

        return new_events, subdomain_count

    async def _scan_websites(self, websites: List[dict]) -> List[ChangeEvent]:
        """Run comprehensive scanning for all monitored website entries."""
        import urllib.parse

        from src.monitoring.website_scanner import scan_website
        from src.verification.manager import VerificationManager

        new_events: List[ChangeEvent] = []
        vm = VerificationManager(self._config, self._db)

        for entry in websites:
            raw_url: str = entry if isinstance(entry, str) else entry.get("url", "")
            techniques: dict = (
                entry.get("techniques", {}) if isinstance(entry, dict) else {}
            )
            try:
                url = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
                hostname = urllib.parse.urlparse(url).hostname or ""
                if not hostname:
                    logger.warning("Cannot parse hostname from website URL: %s", raw_url)
                    continue

                ex = self._db.get_subdomain(hostname)
                old_state: dict = {}
                if ex:
                    old_state = {
                        "live": ex.status == "alive",
                        "a_records": list(ex.ip_addresses or []),
                        "aaaa_records": [],
                        "status_code": ex.http_status or 0,
                        "technologies": ex.technologies or [],
                        "cert_fingerprint": ex.cert_fingerprint,
                        "takeover": (
                            {"service": "unknown", "confidence": "unknown"}
                            if ex.takeover_vulnerable else None
                        ),
                    }

                scan_result = await scan_website(
                    url=url, techniques=techniques, config=self._config, db=self._db,
                )

                verify_compat = {
                    "fqdn": hostname,
                    "live": scan_result.get("live", False),
                    "status_code": scan_result.get("http_status", 0),
                    "technologies": scan_result.get("technologies", []),
                    "a_records": [],
                    "aaaa_records": [],
                    "cert_fingerprint": None,
                    "takeover": None,
                    "discovery_technique": "website",
                }

                ev_data_list = await vm.generate_change_events(hostname, old_state, verify_compat)
                for ev_data in ev_data_list:
                    ev = self._db.add_change_event(**ev_data)
                    new_events.append(ev)

                for finding in scan_result.get("security_files", []):
                    severity = finding.get("severity", "INFO")
                    if severity in ("CRITICAL", "HIGH"):
                        path = finding.get("path", "")
                        note = finding.get("note", "")
                        desc = f"Sensitive file accessible on {hostname}: {path}"
                        if note:
                            desc += f" — {note}"
                        ev = self._db.add_change_event(
                            event_type="SECURITY_FILE_FOUND",
                            severity=severity,
                            target=hostname,
                            description=desc,
                            diff_data=finding,
                        )
                        new_events.append(ev)

                # ── Broken link hijacking ──
                atk_cfg = getattr(self._config, 'attack_surface', None)
                if atk_cfg and getattr(atk_cfg, 'broken_link_hijacking', False):
                    try:
                        from src.monitoring.broken_links import check_broken_links
                        crawl_data = scan_result.get("crawl_data", {})
                        if crawl_data:
                            sub = self._db.get_subdomain(hostname)
                            if sub:
                                await check_broken_links(
                                    base_url=url,
                                    crawl_data=crawl_data,
                                    db=self._db,
                                    subdomain_id=sub.id,
                                    config=self._config,
                                )
                    except ImportError:
                        pass
                    except Exception as exc:
                        logger.debug("Broken link check failed for %s: %s", hostname, exc)

            except Exception as exc:
                logger.warning("Website scan failed for %s: %s", raw_url, exc)

        return new_events

    def _group_events_by_domain(
        self,
        events: List[ChangeEvent],
        domains: List[Domain],
    ) -> dict[str, List[ChangeEvent]]:
        grouped: dict[str, List[ChangeEvent]] = {d.domain: [] for d in domains}
        grouped["unknown"] = []

        for ev in events:
            matched = False
            for dom in domains:
                if ev.target == dom.domain or ev.target.endswith(f".{dom.domain}"):
                    grouped[dom.domain].append(ev)
                    matched = True
                    break
            if not matched:
                grouped["unknown"].append(ev)

        return {k: v for k, v in grouped.items() if v}

    # ── GitHub monitoring ─────────────────────────────────────────────────────

    async def _run_github_monitoring(self) -> Optional[dict]:
        """Run GitHub monitoring if enabled."""
        if not self._config.github.enabled:
            return None

        logger.info("Starting GitHub monitoring...")

        try:
            from src.github.monitor import GitHubMonitor
        except ImportError:
            logger.debug("github.monitor module not available — skipping GitHub monitoring")
            return None

        monitor = GitHubMonitor(
            db=self._db,
            github_token=self._config.github.token or self._config.api_keys.github_token or None
        )

        result = await monitor.scan_all_repos()

        logger.info(
            "GitHub monitoring complete: %d finding(s) from %d repo(s)",
            result.get('total_findings', 0),
            result.get('total_repos', 0)
        )

        return result
