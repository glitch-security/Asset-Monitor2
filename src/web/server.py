"""
Flask web dashboard server.

Provides:
  GET /                     — full dashboard HTML
  GET /api/summary          — aggregated stat cards
  GET /api/subdomains       — all subdomains with status + latest port data
  GET /api/ports            — latest port scan per host
  GET /api/changes          — recent change events (default: last 48h)
  GET /api/headers          — latest HTTP header snapshots per subdomain

Runs in a daemon thread alongside APScheduler so it never blocks the scan
loop, and exits automatically when the main process exits.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from flask import Flask, jsonify, render_template, request

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _serial(obj: Any) -> Any:
    """JSON serialiser for datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")


def _ev_to_dict(ev: Any) -> dict:
    return {
        "id": ev.id,
        "event_type": ev.event_type,
        "severity": ev.severity,
        "target": ev.target,
        "description": ev.description,
        "detected_at": ev.detected_at.isoformat() if ev.detected_at else None,
        "alerted": ev.alerted,
        "diff_data": ev.diff_data,
    }


def create_app(db: "DatabaseManager", config: "AppConfig") -> Flask:
    app = Flask(__name__, template_folder=_TEMPLATE_DIR)

    # ------------------------------------------------------------------ #
    # Dashboard HTML
    # ------------------------------------------------------------------ #

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    # ------------------------------------------------------------------ #
    # API — summary cards
    # ------------------------------------------------------------------ #

    @app.route("/api/summary")
    def api_summary():
        try:
            data = db.get_dashboard_summary()
            return jsonify(data)
        except Exception as exc:
            logger.error("api_summary error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — all subdomains with latest open-port list
    # ------------------------------------------------------------------ #

    @app.route("/api/subdomains")
    def api_subdomains():
        try:
            from sqlalchemy import select
            from ..database import Subdomain, PortScan, OpenPort

            with db.get_session() as session:
                subs = list(session.scalars(
                    select(Subdomain).order_by(Subdomain.fqdn)
                ).all())

            # Build a host→ports map from the latest scan per host
            latest_scans = db.get_all_latest_port_scans()
            host_ports: dict[str, list[dict]] = {}
            for scan in latest_scans:
                host_ports[scan.host] = [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                    }
                    for p in scan.open_ports
                ]

            rows = []
            for s in subs:
                rows.append({
                    "id": s.id,
                    "fqdn": s.fqdn,
                    "status": s.status,
                    "http_status": s.http_status,
                    "ip_addresses": s.ip_addresses or [],
                    "technologies": s.technologies or [],
                    "classification": s.classification,
                    "page_title": s.page_title,
                    "takeover_vulnerable": s.takeover_vulnerable,
                    "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                    "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                    "open_ports": host_ports.get(s.fqdn, []),
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_subdomains error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — latest port scan per host
    # ------------------------------------------------------------------ #

    @app.route("/api/ports")
    def api_ports():
        try:
            scans = db.get_all_latest_port_scans()
            rows = []
            for scan in scans:
                rows.append({
                    "host": scan.host,
                    "status": scan.status,
                    "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
                    "scan_duration": scan.scan_duration,
                    "error": scan.error,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                            "extra_info": p.extra_info,
                        }
                        for p in sorted(scan.open_ports, key=lambda x: x.port)
                    ],
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_ports error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — recent change events
    # ------------------------------------------------------------------ #

    @app.route("/api/changes")
    def api_changes():
        try:
            hours = int(request.args.get("hours", 48))
            hours = min(max(hours, 1), 8760)  # clamp to 1h–1yr
            events = db.get_recent_events(hours=hours)
            return jsonify([_ev_to_dict(e) for e in events])
        except Exception as exc:
            logger.error("api_changes error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — HTTP header snapshots (latest SubdomainScan per subdomain)
    # ------------------------------------------------------------------ #

    @app.route("/api/headers")
    def api_headers():
        SECURITY_HEADERS = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection",
        ]
        INFO_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

        try:
            from sqlalchemy import select, func as sqlfunc
            from ..database import Subdomain, SubdomainScan

            with db.get_session() as session:
                # Latest scan per subdomain
                subq = (
                    select(
                        SubdomainScan.subdomain_id,
                        sqlfunc.max(SubdomainScan.scanned_at).label("max_at"),
                    )
                    .group_by(SubdomainScan.subdomain_id)
                    .subquery()
                )
                pairs = session.execute(
                    select(Subdomain, SubdomainScan)
                    .join(SubdomainScan, Subdomain.id == SubdomainScan.subdomain_id)
                    .join(
                        subq,
                        (SubdomainScan.subdomain_id == subq.c.subdomain_id)
                        & (SubdomainScan.scanned_at == subq.c.max_at),
                    )
                    .where(SubdomainScan.raw_headers.isnot(None))
                    .order_by(Subdomain.fqdn)
                ).all()

            rows = []
            for sub, scan in pairs:
                raw = scan.raw_headers or {}
                # Normalise keys to lowercase
                headers = {k.lower(): v for k, v in raw.items()}

                sec_status = {
                    h: ("present" if h in headers else "missing")
                    for h in SECURITY_HEADERS
                }
                info_leaked = {
                    h: headers[h] for h in INFO_HEADERS if h in headers
                }

                rows.append({
                    "fqdn": sub.fqdn,
                    "status_code": scan.http_status,
                    "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
                    "security_headers": sec_status,
                    "info_leaked": info_leaked,
                    "all_headers": headers,
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_headers error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    return app


def start_web_server(
    db: "DatabaseManager",
    config: "AppConfig",
    host: str = "0.0.0.0",
    port: int = 5000,
) -> threading.Thread:
    """Start the Flask server in a daemon thread.

    Returns the thread so the caller can join if needed.
    """
    app = create_app(db, config)

    thread = threading.Thread(
        target=lambda: app.run(
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
            threaded=True,
        ),
        daemon=True,
        name="web-dashboard",
    )
    thread.start()
    logger.info("Web dashboard started on http://%s:%d", host, port)
    return thread
