"""
Verification manager.

Orchestrates the full verification pipeline for each discovered subdomain:
DNS resolution → HTTP probing → technology fingerprinting → takeover check →
classification, then persists the result to the database.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from ..config import AppConfig
from ..database import DatabaseManager
from .classifier import classify_subdomain
from .dns_resolver import resolve_subdomain
from .dnssec import analyze_dnssec
from .email_security import analyze_email_security
from .fingerprinter import fingerprint, get_cert_fingerprint, get_favicon_hash
from .http_prober import probe_subdomain
from .nameserver_security import analyze_nameservers
from .takeover import check_takeover

logger = logging.getLogger(__name__)

# Default concurrency cap for batch verification
_DEFAULT_SEMAPHORE = 20


class VerificationManager:
    """
    High-level coordinator for subdomain verification.

    Parameters
    ----------
    config:
        Application configuration object.
    db:
        Initialised :class:`~database.DatabaseManager` instance.
    """

    def __init__(self, config: AppConfig, db: DatabaseManager) -> None:
        self._config = config
        self._db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def verify_subdomain(
        self,
        fqdn: str,
        domain_id: int,
        discovery_technique: str,
    ) -> dict:
        """
        Run the full verification pipeline for a single subdomain.

        Steps
        -----
        1. DNS resolution (A / AAAA / CNAME)
        2. HTTP / HTTPS probing across configured ports
        3. Technology fingerprinting (headers + body)
        4. Favicon hash & TLS certificate fingerprint
        5. Subdomain takeover check
        6. Functional classification
        7. Upsert result into the database

        Parameters
        ----------
        fqdn:
            Fully-qualified domain name to verify.
        domain_id:
            Primary key of the parent domain in the database.
        discovery_technique:
            Short string describing how this subdomain was found
            (e.g. ``"ct_logs"``, ``"dns_bruteforce"``).

        Returns
        -------
        Complete verification result dict containing all collected fields.
        """
        logger.info("Verifying %s", fqdn)

        cfg_verification = self._config.verification
        cfg_scan = self._config.scan
        resolvers = self._config.enumeration.dns_resolvers

        result: dict = {
            "fqdn": fqdn,
            "domain_id": domain_id,
            "discovery_technique": discovery_technique,
            # DNS
            "a_records": [],
            "aaaa_records": [],
            "cname": None,
            "is_internal": False,
            "dns_resolved": False,
            # HTTP
            "live": False,
            "url": "",
            "status_code": 0,
            "response_size": 0,
            "page_title": "",
            "response_headers": {},
            "redirect_chain": [],
            "port": 0,
            "scheme": "",
            # Fingerprinting
            "technologies": [],
            "favicon_hash": None,
            "cert_fingerprint": None,
            # Takeover
            "takeover": None,
            # Classification
            "classification": "DEFAULT",
        }

        # ------------------------------------------------------------------
        # Step 1 – DNS resolution
        # ------------------------------------------------------------------
        try:
            dns_result = await resolve_subdomain(
                fqdn,
                resolvers=resolvers,
                timeout=cfg_scan.request_timeout_seconds,
            )
            result.update({
                "a_records": dns_result["a_records"],
                "aaaa_records": dns_result["aaaa_records"],
                "cname": dns_result["cname"],
                "is_internal": dns_result["is_internal"],
                "dns_resolved": dns_result["resolved"],
            })
        except Exception as exc:
            logger.warning("DNS resolution failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 2 – HTTP probing
        # ------------------------------------------------------------------
        http_result: dict = {}
        try:
            http_result = await probe_subdomain(
                fqdn,
                ports=cfg_verification.ports,
                timeout=cfg_scan.request_timeout_seconds,
                verify_ssl=cfg_scan.verify_ssl,
            )
            result.update({
                "live": http_result.get("live", False),
                "url": http_result.get("url", ""),
                "status_code": http_result.get("status_code", 0),
                "response_size": http_result.get("response_size", 0),
                "page_title": http_result.get("page_title", ""),
                "response_headers": http_result.get("response_headers", {}),
                "redirect_chain": http_result.get("redirect_chain", []),
                "port": http_result.get("port", 0),
                "scheme": http_result.get("scheme", ""),
            })
        except Exception as exc:
            logger.warning("HTTP probing failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 3 – Technology fingerprinting (only if live)
        # ------------------------------------------------------------------
        body_text: str = http_result.get("body", "")
        if cfg_verification.technology_detection and result["live"]:
            try:
                techs = await fingerprint(
                    url=result["url"],
                    headers=result["response_headers"],
                    body=body_text,
                )
                result["technologies"] = techs
            except Exception as exc:
                logger.warning("Fingerprinting failed for %s: %s", fqdn, exc)

            # Favicon hash
            base_url = f"{result['scheme']}://{fqdn}:{result['port']}" if result["scheme"] else ""
            if base_url:
                try:
                    result["favicon_hash"] = await get_favicon_hash(
                        base_url,
                        timeout=cfg_scan.request_timeout_seconds,
                        verify_ssl=cfg_scan.verify_ssl,
                    )
                except Exception as exc:
                    logger.debug("Favicon hash failed for %s: %s", fqdn, exc)

            # TLS certificate fingerprint
            if result["scheme"] == "https":
                try:
                    result["cert_fingerprint"] = await get_cert_fingerprint(
                        fqdn,
                        port=result["port"],
                        timeout=cfg_scan.request_timeout_seconds,
                    )
                except Exception as exc:
                    logger.debug("Cert fingerprint failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 4 – Takeover check
        # ------------------------------------------------------------------
        if cfg_verification.takeover_check:
            try:
                takeover = await check_takeover(
                    fqdn=fqdn,
                    cname=result["cname"],
                    http_result=http_result,
                )
                result["takeover"] = takeover
            except Exception as exc:
                logger.warning("Takeover check failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 5 – Classification
        # ------------------------------------------------------------------
        try:
            result["classification"] = classify_subdomain(
                fqdn=fqdn,
                page_title=result["page_title"],
                technologies=result["technologies"],
            )
        except Exception as exc:
            logger.warning("Classification failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 6 – DNS Security Analysis
        # ------------------------------------------------------------------
        try:
            # Get root domain for DNS security checks
            parts = fqdn.split(".")
            if len(parts) >= 2:
                root_domain = ".".join(parts[-2:])

                # DNSSEC analysis (if enabled)
                if cfg_verification.dnssec_check:
                    try:
                        dnssec_result = await analyze_dnssec(root_domain, resolvers)
                        result["dnssec_info"] = dnssec_result
                    except Exception as exc:
                        logger.debug("DNSSEC analysis failed for %s: %s", fqdn, exc)
                        result["dnssec_info"] = None
                else:
                    result["dnssec_info"] = None

                # Email security analysis (if enabled)
                if cfg_verification.email_security_check:
                    try:
                        email_security_result = await analyze_email_security(root_domain, resolvers)
                        result["email_security"] = email_security_result
                    except Exception as exc:
                        logger.debug("Email security analysis failed for %s: %s", fqdn, exc)
                        result["email_security"] = None
                else:
                    result["email_security"] = None

                # Nameserver security analysis (if enabled)
                if cfg_verification.nameserver_security_check:
                    try:
                        # First get the nameservers for the domain
                        from ..enumeration.dns_records import get_nameservers_for_domain
                        nameservers = await get_nameservers_for_domain(root_domain, resolvers)
                        if nameservers:
                            ns_security_result = await analyze_nameservers(root_domain, nameservers, resolvers)
                            result["nameserver_security"] = ns_security_result
                        else:
                            result["nameserver_security"] = None
                    except Exception as exc:
                        logger.debug("Nameserver security analysis failed for %s: %s", fqdn, exc)
                        result["nameserver_security"] = None
                else:
                    result["nameserver_security"] = None
        except Exception as exc:
            logger.warning("DNS security analysis failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 7 – Upsert into database
        # ------------------------------------------------------------------
        await self._persist(result)

        return result

    async def _persist(self, result: dict) -> None:
        """Upsert the verification result into the database."""
        fqdn = result["fqdn"]
        domain_id = result["domain_id"]

        # Determine status string
        if result.get("live"):
            status = "alive"
        elif result.get("dns_resolved"):
            status = "dead"
        else:
            status = "unknown"

        # Compute a simple body hash if body data was included
        body_hash: Optional[str] = result.get("body_hash")

        takeover_vulnerable = bool(result.get("takeover"))

        try:
            self._db.upsert_subdomain(
                fqdn=fqdn,
                domain_id=domain_id,
                discovery_technique=result.get("discovery_technique"),
                status=status,
                ip_addresses=(
                    result.get("a_records", []) + result.get("aaaa_records", [])
                ) or None,
                technologies=result.get("technologies") or None,
                http_status=result.get("status_code") or None,
                page_title=result.get("page_title") or None,
                classification=result.get("classification"),
                favicon_hash=result.get("favicon_hash"),
                body_hash=body_hash,
                cert_fingerprint=result.get("cert_fingerprint"),
                takeover_vulnerable=takeover_vulnerable,
            )

            # Add a snapshot scan record with DNS security data
            self._db.add_scan_record(
                subdomain_id=self._db.get_subdomain(fqdn).id,
                status=status,
                http_status=result.get("status_code") or None,
                response_size=result.get("response_size") or None,
                body_hash=body_hash,
                technologies=result.get("technologies") or None,
                raw_headers=result.get("response_headers") or None,
                dnssec_info=result.get("dnssec_info"),
                email_security=result.get("email_security"),
                nameserver_security=result.get("nameserver_security"),
            )
        except Exception as exc:
            logger.error("Database upsert failed for %s: %s", fqdn, exc)

    async def verify_batch(
        self,
        fqdns: set[str],
        domain_id: int,
        technique: str,
    ) -> list[dict]:
        """
        Verify a batch of subdomains concurrently.

        A semaphore caps the maximum number of in-flight verifications to
        avoid overwhelming the network or the target hosts.

        Parameters
        ----------
        fqdns:
            Set of fully-qualified domain names to verify.
        domain_id:
            Parent domain primary key.
        technique:
            Discovery technique label applied to all subdomains in this batch.

        Returns
        -------
        List of verification result dicts (one per FQDN).
        """
        semaphore = asyncio.Semaphore(
            getattr(self._config.scan, "concurrent_threads", _DEFAULT_SEMAPHORE)
        )

        async def _guarded(fqdn: str) -> dict:
            async with semaphore:
                try:
                    return await self.verify_subdomain(fqdn, domain_id, technique)
                except Exception as exc:
                    logger.error("Unhandled error verifying %s: %s", fqdn, exc)
                    return {"fqdn": fqdn, "error": str(exc)}

        tasks = [_guarded(fqdn) for fqdn in fqdns]
        results = await asyncio.gather(*tasks)
        return list(results)

    async def generate_change_events(
        self,
        fqdn: str,
        old_data: dict,
        new_data: dict,
    ) -> list[dict]:
        """
        Compare old and new subdomain state and produce change event dicts.

        Detected change types
        ---------------------
        - ``SUBDOMAIN_NEW``         – subdomain seen for the first time
        - ``SUBDOMAIN_CAME_ALIVE``  – was dead, now live
        - ``SUBDOMAIN_WENT_DEAD``   – was live, now dead
        - ``TAKEOVER_DETECTED``     – new takeover vulnerability found
        - ``TECH_ADDED``            – new technology detected
        - ``TECH_REMOVED``          – technology no longer detected
        - ``STATUS_CHANGE``         – HTTP status code changed
        - ``IP_CHANGE``             – resolved IP addresses changed
        - ``CERT_CHANGE``           – TLS certificate fingerprint changed

        Parameters
        ----------
        fqdn:
            The subdomain FQDN.
        old_data:
            Previous verification result dict (empty dict if first scan).
        new_data:
            Current verification result dict.

        Returns
        -------
        List of change event dicts ready for
        :meth:`~database.DatabaseManager.add_change_event`.
        """
        events: list[dict] = []

        def _event(event_type: str, severity: str, description: str, diff: dict | None = None) -> dict:
            return {
                "event_type": event_type,
                "severity": severity,
                "target": fqdn,
                "description": description,
                "diff_data": diff,
            }

        # New subdomain (no previous record)
        if not old_data:
            events.append(_event(
                "SUBDOMAIN_NEW",
                "INFO",
                f"New subdomain discovered: {fqdn}",
                {"discovery_technique": new_data.get("discovery_technique")},
            ))
            if new_data.get("takeover"):
                events.append(_event(
                    "TAKEOVER_DETECTED",
                    "HIGH",
                    f"Subdomain takeover vulnerability: {new_data['takeover']['service']} "
                    f"({new_data['takeover']['confidence']})",
                    new_data["takeover"],
                ))
            return events

        # Liveness changes
        old_live = old_data.get("live", False)
        new_live = new_data.get("live", False)
        if not old_live and new_live:
            events.append(_event(
                "SUBDOMAIN_CAME_ALIVE",
                "MEDIUM",
                f"{fqdn} is now responding to HTTP requests (HTTP {new_data.get('status_code')})",
            ))
        elif old_live and not new_live:
            events.append(_event(
                "SUBDOMAIN_WENT_DEAD",
                "LOW",
                f"{fqdn} is no longer responding to HTTP requests",
            ))

        # HTTP status code change
        old_status = old_data.get("status_code", 0)
        new_status = new_data.get("status_code", 0)
        if old_status and new_status and old_status != new_status:
            events.append(_event(
                "STATUS_CHANGE",
                "LOW",
                f"HTTP status changed from {old_status} to {new_status} on {fqdn}",
                {"old_status": old_status, "new_status": new_status},
            ))

        # IP address changes
        old_ips = set(old_data.get("a_records", []) + old_data.get("aaaa_records", []))
        new_ips = set(new_data.get("a_records", []) + new_data.get("aaaa_records", []))
        if old_ips and new_ips and old_ips != new_ips:
            added_ips = new_ips - old_ips
            removed_ips = old_ips - new_ips
            events.append(_event(
                "IP_CHANGE",
                "MEDIUM",
                f"IP addresses changed for {fqdn}: +{sorted(added_ips)} -{sorted(removed_ips)}",
                {"added": sorted(added_ips), "removed": sorted(removed_ips)},
            ))

        # Technology stack changes — technologies are list[dict] ({name, version}),
        # not hashable, so diff via name/version maps rather than set() arithmetic.
        from ..detection.tech_stack import diff_technologies
        tech_diff = diff_technologies(
            old_data.get("technologies", []) or [],
            new_data.get("technologies", []) or [],
        )
        if tech_diff["added"]:
            added_names = sorted(t["name"] for t in tech_diff["added"])
            events.append(_event(
                "TECH_ADDED",
                "LOW",
                f"New technologies detected on {fqdn}: {added_names}",
                {"technologies": tech_diff["added"]},
            ))
        if tech_diff["removed"]:
            removed_names = sorted(t["name"] for t in tech_diff["removed"])
            events.append(_event(
                "TECH_REMOVED",
                "INFO",
                f"Technologies no longer detected on {fqdn}: {removed_names}",
                {"technologies": tech_diff["removed"]},
            ))

        # TLS certificate fingerprint change
        old_cert = old_data.get("cert_fingerprint")
        new_cert = new_data.get("cert_fingerprint")
        if old_cert and new_cert and old_cert != new_cert:
            events.append(_event(
                "CERT_CHANGE",
                "MEDIUM",
                f"TLS certificate changed on {fqdn}",
                {"old_fingerprint": old_cert, "new_fingerprint": new_cert},
            ))

        # Takeover vulnerability appearing
        old_takeover = old_data.get("takeover")
        new_takeover = new_data.get("takeover")
        if new_takeover and not old_takeover:
            events.append(_event(
                "TAKEOVER_DETECTED",
                "HIGH",
                f"Subdomain takeover vulnerability: {new_takeover['service']} "
                f"({new_takeover['confidence']})",
                new_takeover,
            ))

        # DNS security changes
        _check_dnssec_changes(fqdn, old_data, new_data, _event, events)
        _check_email_security_changes(fqdn, old_data, new_data, _event, events)
        _check_nameserver_security_changes(fqdn, old_data, new_data, _event, events)

        return events


def _check_dnssec_changes(
    fqdn: str, old_data: dict, new_data: dict, _event: callable, events: list[dict]
) -> None:
    """Check for DNSSEC configuration changes."""
    old_dnssec = old_data.get("dnssec_info") or {}
    new_dnssec = new_data.get("dnssec_info") or {}

    old_enabled = old_dnssec.get("dnssec_enabled", False)
    new_enabled = new_dnssec.get("dnssec_enabled", False)

    if old_enabled != new_enabled:
        if new_enabled:
            events.append(_event(
                "DNSSEC_ENABLED",
                "INFO",
                f"DNSSEC is now enabled for {fqdn}",
                {"dnssec_enabled": True},
            ))
        else:
            events.append(_event(
                "DNSSEC_DISABLED",
                "WARNING",
                f"DNSSEC is now disabled for {fqdn}",
                {"dnssec_enabled": False},
            ))


def _check_email_security_changes(
    fqdn: str, old_data: dict, new_data: dict, _event: callable, events: list[dict]
) -> None:
    """Check for email security (SPF/DKIM/DMARC) changes."""
    old_email = old_data.get("email_security") or {}
    new_email = new_data.get("email_security") or {}

    # Check for SPF changes
    old_spf = (old_email.get("spf") or {}).get("record")
    new_spf = (new_email.get("spf") or {}).get("record")
    if old_spf != new_spf:
        if new_spf and not old_spf:
            events.append(_event(
                "SPF_CONFIGURED",
                "INFO",
                f"SPF record now present for {fqdn}",
                {"spf_record": new_spf[:100] + "..." if len(new_spf or "") > 100 else new_spf},
            ))
        elif old_spf and not new_spf:
            events.append(_event(
                "SPF_REMOVED",
                "WARNING",
                f"SPF record removed for {fqdn}",
                {"old_spf_record": old_spf[:100] + "..." if len(old_spf) > 100 else old_spf},
            ))
        else:
            events.append(_event(
                "SPF_CHANGED",
                "INFO",
                f"SPF record changed for {fqdn}",
                {"old": old_spf[:50] + "..." if len(old_spf or "") > 50 else old_spf,
                 "new": new_spf[:50] + "..." if len(new_spf or "") > 50 else new_spf},
            ))

    # Check for DMARC changes
    old_dmarc = (old_email.get("dmarc") or {}).get("record")
    new_dmarc = (new_email.get("dmarc") or {}).get("record")
    if old_dmarc != new_dmarc:
        if new_dmarc and not old_dmarc:
            events.append(_event(
                "DMARC_CONFIGURED",
                "INFO",
                f"DMARC record now present for {fqdn}",
                {"dmarc_record": new_dmarc[:100] + "..." if len(new_dmarc or "") > 100 else new_dmarc},
            ))
        elif old_dmarc and not new_dmarc:
            events.append(_event(
                "DMARC_REMOVED",
                "WARNING",
                f"DMARC record removed for {fqdn}",
                {"old_dmarc_record": old_dmarc[:100] + "..." if len(old_dmarc) > 100 else old_dmarc},
            ))
        else:
            events.append(_event(
                "DMARC_CHANGED",
                "INFO",
                f"DMARC record changed for {fqdn}",
                {"old": old_dmarc[:50] + "..." if len(old_dmarc or "") > 50 else old_dmarc,
                 "new": new_dmarc[:50] + "..." if len(new_dmarc or "") > 50 else new_dmarc},
            ))

    # Check overall score changes (significant drops only)
    old_score = (old_email.get("spf") or {}).get("score", 0) + (old_email.get("dmarc") or {}).get("score", 0)
    new_score = (new_email.get("spf") or {}).get("score", 0) + (new_email.get("dmarc") or {}).get("score", 0)
    if old_score > 0 and new_score > 0 and abs(new_score - old_score) >= 10:
        events.append(_event(
            "EMAIL_SECURITY_SCORE_CHANGED",
            "LOW",
            f"Email security score changed for {fqdn}: {old_score} → {new_score}",
            {"old_score": old_score, "new_score": new_score},
        ))


def _check_nameserver_security_changes(
    fqdn: str, old_data: dict, new_data: dict, _event: callable, events: list[dict]
) -> None:
    """Check for nameserver security changes."""
    old_ns = old_data.get("nameserver_security") or {}
    new_ns = new_data.get("nameserver_security") or {}

    # Check for new security issues
    old_issues = set(old_ns.get("issues", []) or [])
    new_issues = set(new_ns.get("issues", []) or [])
    added_issues = new_issues - old_issues
    removed_issues = old_issues - new_issues

    if added_issues:
        events.append(_event(
            "NS_SECURITY_ISSUE_DETECTED",
            "MEDIUM",
            f"Nameserver security issue detected for {fqdn}: {list(added_issues)[0] if added_issues else 'unknown'}",
            {"issues": list(added_issues)},
        ))

    if removed_issues and not added_issues:
        events.append(_event(
            "NS_SECURITY_ISSUE_RESOLVED",
            "INFO",
            f"Nameserver security issue resolved for {fqdn}",
            {"resolved_issues": list(removed_issues)},
        ))

    # Check for DNSSEC validation changes
    old_validated = old_ns.get("dnssec_validated", False)
    new_validated = new_ns.get("dnssec_validated", False)
    if old_validated != new_validated:
        if new_validated:
            events.append(_event(
                "NS_DNSSEC_VALIDATION_OK",
                "INFO",
                f"Nameserver DNSSEC validation now passing for {fqdn}",
                {"dnssec_validated": True},
            ))
        else:
            events.append(_event(
                "NS_DNSSEC_VALIDATION_FAILED",
                "WARNING",
                f"Nameserver DNSSEC validation now failing for {fqdn}",
                {"dnssec_validated": False},
            ))
