"""
FastAPI web dashboard server.

Routes:
  GET  /                            — full dashboard HTML
  GET  /login                       — login page
  POST /login                       — authenticate (JSON: {username, password})
  GET  /logout                      — clear session and redirect to /login
  GET  /health                      — Docker healthcheck (no auth)
  GET  /screenshots/{filename}      — serve screenshot files
  GET  /api/session                 — current session info
  GET  /api/summary                 — aggregated stat cards
  GET  /api/domains                 — all root domains with subdomain stats
  GET  /api/subdomains              — all subdomains with status + port data
  GET  /api/ports                   — latest port scan per host
  GET  /api/changes                 — recent change events
  GET  /api/headers                 — HTTP security header snapshots
  GET  /api/websites                — monitored websites with live-status enrichment
  DELETE /api/websites              — remove a website from monitoring
  PATCH /api/websites               — update per-website techniques
  POST /api/targets                 — add domain / subdomain / website
  DELETE /api/targets/domain/{id}   — delete a root domain (cascade)
  PATCH /api/targets/domain/{id}    — assign a scan profile to a domain
  GET  /api/domains/{id}/details    — per-domain full detail payload
  GET  /api/profiles                — list scan profiles
  POST /api/profiles                — create a scan profile
  PUT  /api/profiles/{id}           — update a scan profile
  DELETE /api/profiles/{id}         — delete a scan profile
  POST /api/scan/trigger            — trigger an on-demand scan
  GET  /api/scan/status             — current scan state
  GET  /api/settings                — config overrides from DB
  POST /api/settings                — save config overrides
  GET  /api/users                   — list users (admin)
  POST /api/users                   — create a user (admin)
  DELETE /api/users/{username}      — delete a user (admin)
  POST /api/users/{username}/password — change a user's password
  GET  /api/github/repos            — list monitored GitHub repositories
  POST /api/github/repos            — add GitHub repository to monitoring (admin)
  DELETE /api/github/repos/{id}     — delete GitHub repository (admin)
  GET  /api/github/findings         — get GitHub findings with filters
  PUT  /api/github/findings/{id}/review — mark finding as reviewed (admin)
  POST /api/github/scan/{id}        — trigger immediate GitHub repo scan (admin)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.sessions import SessionMiddleware

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager
    from ..scheduler import SchedManager

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)$"
)

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_SCREENSHOT_DIR = "data/screenshots"

_CSRF_EXEMPT_METHODS = frozenset(["GET", "HEAD", "OPTIONS"])
_AUTH_EXEMPT_PREFIXES = ("/login", "/logout", "/health", "/screenshots/", "/static/")

_scan_lock = asyncio.Lock()
_scan_state: dict = {
    "running": False,
    "started_at": None,
    "domain": None,
    "error": None,
    "last_completed": None,
    "last_subs_found": 0,
    "last_events": 0,
}


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


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse({"error": "Too many requests — try again later"}, status_code=429)


def build_app(
    db: "DatabaseManager",
    config: "AppConfig",
    sched_manager: Optional["SchedManager"] = None,
) -> FastAPI:
    """
    Build and return the FastAPI application.

    The lifespan function starts the scheduler (initial scan + periodic) and
    stops it on shutdown. All session state uses starlette SessionMiddleware
    with a DB-persisted secret key so sessions survive container restarts.
    """

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        if sched_manager:
            # Run initial scan concurrently so the server accepts traffic immediately
            asyncio.create_task(sched_manager.run_full_scan())
            sched_manager.start()
            logger.info("Scheduler started (interval=%dm)", config.scan.interval_minutes)
        yield
        if sched_manager:
            sched_manager.stop()

    app = FastAPI(title="AssetMonitor Dashboard", docs_url=None, redoc_url=None, lifespan=_lifespan)

    # ── Rate limiter ────────────────────────────────────────────────────────
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)

    # ── Templates ───────────────────────────────────────────────────────────
    templates = Jinja2Templates(directory=_TEMPLATE_DIR)

    # ── Static files — screenshots ──────────────────────────────────────────
    os.makedirs(_SCREENSHOT_DIR, exist_ok=True)
    app.mount("/screenshots", StaticFiles(directory=_SCREENSHOT_DIR), name="screenshots")

    # ── Security headers + auth gate ─────────────────────────────────────────
    # IMPORTANT: SessionMiddleware is added AFTER this decorator (see below).
    # In Starlette, later add_middleware() calls are OUTER — they run first.
    # So SessionMiddleware runs before _gate, making request.session available.
    @app.middleware("http")
    async def _gate(request: Request, call_next):
        path = request.url.path

        # Inject security headers on every response
        response = await _maybe_auth_check(request, path, call_next)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    async def _maybe_auth_check(request, path, call_next):
        exempt = path == "/login" or path == "/logout" or path == "/health" or \
                 path.startswith("/screenshots/") or path.startswith("/static/")
        if not exempt:
            if not request.session.get("authenticated"):
                if path.startswith("/api/"):
                    return JSONResponse({"error": "Unauthorized"}, status_code=401)
                return RedirectResponse(url="/login", status_code=302)
            # CSRF validation for mutating requests
            if request.method not in _CSRF_EXEMPT_METHODS:
                expected = request.session.get("csrf_token")
                provided = request.headers.get("X-CSRF-Token")
                if not expected or not secrets.compare_digest(expected, provided or ""):
                    if path.startswith("/api/"):
                        return JSONResponse({"error": "CSRF token invalid"}, status_code=403)
                    return RedirectResponse(url="/login", status_code=302)
        return await call_next(request)

    # ── Admin dependency ─────────────────────────────────────────────────────
    def _require_admin(request: Request) -> None:
        if request.session.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Forbidden — admin role required")

    # ── Session middleware ──────────────────────────────────────────────────
    # Added AFTER the @app.middleware("http") decorator so Starlette makes it
    # the OUTER layer — it runs first and populates request.session before
    # _gate is reached.
    secret_key = db.get_or_create_flask_secret()
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        max_age=30 * 24 * 3600,
        https_only=False,
        same_site="lax",
    )

    # ────────────────────────────────────────────────────────────────────────
    # Auth routes
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/login")
    async def login_page(request: Request):
        if request.session.get("authenticated"):
            return RedirectResponse(url="/", status_code=302)
        return templates.TemplateResponse(request, "login.html")

    @app.post("/login")
    @limiter.limit("5/minute")
    async def login_submit(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return JSONResponse({"error": "Username and password required"}, status_code=400)
        role = db.verify_password(username, password)
        if role is None:
            return JSONResponse({"error": "Invalid credentials"}, status_code=401)
        request.session.clear()
        request.session["authenticated"] = True
        request.session["username"] = username
        request.session["role"] = role
        request.session["csrf_token"] = secrets.token_hex(32)
        return {"ok": True, "username": username, "role": role}

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)

    # ────────────────────────────────────────────────────────────────────────
    # Health + dashboard
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/")
    async def dashboard(request: Request):
        return templates.TemplateResponse(request, "dashboard.html")

    # ────────────────────────────────────────────────────────────────────────
    # API — session
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/session")
    async def api_session(request: Request):
        return {
            "authenticated": request.session.get("authenticated", False),
            "username": request.session.get("username"),
            "role": request.session.get("role"),
            "csrf_token": request.session.get("csrf_token"),
        }

    # ────────────────────────────────────────────────────────────────────────
    # API — summary + domains + subdomains
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/summary")
    async def api_summary():
        try:
            return db.get_dashboard_summary()
        except Exception as exc:
            logger.error("api_summary error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/domains")
    async def api_domains():
        try:
            return db.get_all_domains_with_stats()
        except Exception as exc:
            logger.error("api_domains error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/subdomains")
    async def api_subdomains():
        try:
            from sqlalchemy import select
            from ..database import Subdomain

            with db.get_session() as session_:
                subs = list(session_.scalars(
                    select(Subdomain).order_by(Subdomain.fqdn)
                ).all())

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

            return [
                {
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
                }
                for s in subs
            ]
        except Exception as exc:
            logger.error("api_subdomains error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — ports
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/ports")
    async def api_ports():
        try:
            scans = db.get_all_latest_port_scans()
            return [
                {
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
                }
                for scan in scans
            ]
        except Exception as exc:
            logger.error("api_ports error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — change events
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/changes")
    async def api_changes(request: Request):
        try:
            hours = int(request.query_params.get("hours", 48))
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="hours must be a positive integer")
        hours = min(max(hours, 1), 8760)
        try:
            events = db.get_recent_events(hours=hours)
            return [_ev_to_dict(e) for e in events]
        except Exception as exc:
            logger.error("api_changes error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — HTTP headers
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/headers")
    async def api_headers():
        _SECURITY_HEADERS = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "x-xss-protection",
        ]
        _INFO_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

        try:
            from sqlalchemy import select, func as sqlfunc
            from ..database import Subdomain, SubdomainScan

            with db.get_session() as session_:
                subq = (
                    select(
                        SubdomainScan.subdomain_id,
                        sqlfunc.max(SubdomainScan.scanned_at).label("max_at"),
                    )
                    .group_by(SubdomainScan.subdomain_id)
                    .subquery()
                )
                pairs = session_.execute(
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
                headers = {k.lower(): v for k, v in raw.items()}
                rows.append({
                    "fqdn": sub.fqdn,
                    "status_code": scan.http_status,
                    "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
                    "security_headers": {
                        h: ("present" if h in headers else "missing")
                        for h in _SECURITY_HEADERS
                    },
                    "info_leaked": {h: headers[h] for h in _INFO_HEADERS if h in headers},
                    "all_headers": headers,
                })
            return rows
        except Exception as exc:
            logger.error("api_headers error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — websites
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/websites")
    async def api_websites():
        import urllib.parse
        try:
            from ..monitoring.website_store import read_websites
            from ..monitoring.website_scanner import screenshot_path_for_url
            entries = read_websites()

            rows = []
            for entry in entries:
                url = entry.get("url", "")
                techniques = entry.get("techniques", {})
                norm = url if url.startswith(("http://", "https://")) else "https://" + url
                hostname = urllib.parse.urlparse(norm).hostname or ""

                status = "unknown"
                http_status = None
                page_title = ""
                last_seen = None
                technologies_list: list = []

                if hostname:
                    sub = db.get_subdomain(hostname)
                    if sub:
                        status = sub.status
                        http_status = sub.http_status
                        page_title = sub.page_title or ""
                        last_seen = sub.last_seen.isoformat() if sub.last_seen else None
                        technologies_list = sub.technologies or []

                # Check if a screenshot exists for this URL
                screenshot_url: Optional[str] = None
                try:
                    ss_path = screenshot_path_for_url(norm)
                    if os.path.isfile(ss_path):
                        screenshot_url = "/screenshots/" + os.path.basename(ss_path)
                except Exception:
                    pass

                rows.append({
                    "url": url,
                    "hostname": hostname,
                    "status": status,
                    "http_status": http_status,
                    "page_title": page_title,
                    "last_seen": last_seen,
                    "technologies": technologies_list,
                    "techniques": techniques,
                    "screenshot_url": screenshot_url,
                })
            return rows
        except Exception as exc:
            logger.error("api_websites error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/websites", dependencies=[Depends(_require_admin)])
    async def api_delete_website(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        url = (data.get("url") or "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="url is required")
        try:
            from ..monitoring.website_store import remove_website
            removed = remove_website(url)
            if not removed:
                raise HTTPException(status_code=404, detail="URL not found")
            return {"deleted": url}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_website error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.patch("/api/websites", dependencies=[Depends(_require_admin)])
    async def api_update_website_techniques(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        url = (data.get("url") or "").strip()
        techniques = data.get("techniques") or {}
        if not url:
            raise HTTPException(status_code=400, detail="url is required")
        try:
            from ..monitoring.website_store import update_techniques
            updated = update_techniques(url, techniques)
            if not updated:
                raise HTTPException(status_code=404, detail="URL not found")
            return {"updated": True, "url": url, "techniques": techniques}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_update_website_techniques error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — add target
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/targets", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_add_target(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        target_type = (data.get("type") or "").lower()
        value = (data.get("value") or "").strip()
        scan_now = bool(data.get("scan_now", False))
        techniques = data.get("techniques") or {}

        if not value:
            raise HTTPException(status_code=400, detail="value is required")
        if target_type not in ("domain", "subdomain", "website"):
            raise HTTPException(status_code=400, detail="type must be domain, subdomain, or website")
        if target_type in ("domain", "subdomain"):
            if len(value) > 253 or not _DOMAIN_RE.match(value):
                raise HTTPException(status_code=400, detail="Invalid domain name")

        try:
            if target_type == "domain":
                dom = db.add_domain(value)
                result: dict = {"type": "domain", "id": dom.id, "value": dom.domain}
                if scan_now and sched_manager:
                    asyncio.create_task(_run_domain_scan(sched_manager, dom.domain, techniques))
                    result["scan_triggered"] = True

            elif target_type == "subdomain":
                parts = value.split(".")
                root = ".".join(parts[-2:]) if len(parts) >= 2 else value
                parent = db.get_domain(root) or db.add_domain(root)
                sub, is_new = db.upsert_subdomain(
                    fqdn=value, domain_id=parent.id, discovery_technique="manual",
                )
                result = {"type": "subdomain", "id": sub.id, "value": sub.fqdn, "is_new": is_new}
                if scan_now and sched_manager:
                    asyncio.create_task(_run_domain_scan(sched_manager, parent.domain, techniques))
                    result["scan_triggered"] = True

            else:  # website
                from ..monitoring.website_store import add_website
                website_techniques = data.get("website_techniques") or {}
                add_website(value, website_techniques if website_techniques else None)
                result = {"type": "website", "value": value}
                if scan_now and sched_manager:
                    asyncio.create_task(_run_full_scan(sched_manager))
                    result["scan_triggered"] = True

            return result

        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_add_target error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — domain management
    # ────────────────────────────────────────────────────────────────────────

    @app.patch("/api/targets/domain/{domain_id}", dependencies=[Depends(_require_admin)])
    async def api_patch_domain(domain_id: int, request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        updated_fields = []
        if "profile_id" in data:
            ok = db.set_domain_profile(domain_id, data["profile_id"])
            if not ok:
                raise HTTPException(status_code=404, detail="Domain not found")
            updated_fields.append("profile_id")
        if "scope_type" in data:
            scope = data["scope_type"]
            if scope not in ("in_scope", "out_of_scope", "unknown"):
                raise HTTPException(status_code=400, detail="scope_type must be in_scope, out_of_scope, or unknown")
            ok = db.set_domain_scope(domain_id, scope)
            if not ok:
                raise HTTPException(status_code=404, detail="Domain not found")
            updated_fields.append("scope_type")
        if not updated_fields:
            raise HTTPException(status_code=400, detail="profile_id or scope_type is required")
        return {"updated": True, "domain_id": domain_id, "fields": updated_fields}

    @app.delete("/api/targets/domain/{domain_id}", dependencies=[Depends(_require_admin)])
    async def api_delete_domain(domain_id: int):
        try:
            deleted = db.delete_domain(domain_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Domain not found")
            return {"deleted": True, "id": domain_id}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_domain error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/domains/{domain_id}/details")
    async def api_domain_details(domain_id: int):
        try:
            details = db.get_domain_details(domain_id)
            if details is None:
                raise HTTPException(status_code=404, detail="Domain not found")
            return details
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_domain_details error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/domains/{domain_id}/dns-security")
    async def api_domain_dns_security(domain_id: int):
        """Get DNS security analysis data for all subdomains of a domain."""
        try:
            from sqlalchemy import select, desc
            from src.database import SubdomainScan, Subdomain

            with db.get_session() as session:
                # Get all subdomains for this domain
                subs = list(session.scalars(
                    select(Subdomain)
                    .where(Subdomain.domain_id == domain_id)
                    .order_by(Subdomain.fqdn)
                ).all())

                dns_security_data = []
                for sub in subs:
                    # Get the latest scan with DNS security data
                    latest_scan = session.scalars(
                        select(SubdomainScan)
                        .where(SubdomainScan.subdomain_id == sub.id)
                        .order_by(desc(SubdomainScan.scanned_at))
                        .limit(1)
                    ).first()

                    if latest_scan:
                        dns_security_data.append({
                            "fqdn": sub.fqdn,
                            "status": sub.status,
                            "scanned_at": latest_scan.scanned_at.isoformat() if latest_scan.scanned_at else None,
                            "dnssec_info": latest_scan.dnssec_info,
                            "email_security": latest_scan.email_security,
                            "nameserver_security": latest_scan.nameserver_security,
                        })
                    else:
                        dns_security_data.append({
                            "fqdn": sub.fqdn,
                            "status": sub.status,
                            "scanned_at": None,
                            "dnssec_info": None,
                            "email_security": None,
                            "nameserver_security": None,
                        })

                return dns_security_data
        except Exception as exc:
            logger.error("api_domain_dns_security error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — scan profiles
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/profiles")
    async def api_profiles():
        try:
            profiles = db.get_all_profiles()
            return [
                {
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "is_builtin": p.is_builtin,
                    "settings": p.settings,
                    "created_at": p.created_at.isoformat() if p.created_at else None,
                }
                for p in profiles
            ]
        except Exception as exc:
            logger.error("api_profiles error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/profiles", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_create_profile(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        name = (data.get("name") or "").strip()
        description = (data.get("description") or "").strip()
        settings = data.get("settings") or {}
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        try:
            p = db.create_profile(name, description, settings)
            return {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "is_builtin": p.is_builtin,
                "settings": p.settings,
            }
        except Exception as exc:
            logger.error("api_create_profile error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.put("/api/profiles/{profile_id}", dependencies=[Depends(_require_admin)])
    async def api_update_profile(profile_id: int, request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        try:
            p = db.update_profile(
                profile_id,
                name=data.get("name"),
                description=data.get("description"),
                settings=data.get("settings"),
            )
            if p is None:
                raise HTTPException(status_code=404, detail="Profile not found or is built-in")
            return {"id": p.id, "name": p.name, "description": p.description, "settings": p.settings}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_update_profile error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/profiles/{profile_id}", dependencies=[Depends(_require_admin)])
    async def api_delete_profile(profile_id: int):
        try:
            deleted = db.delete_profile(profile_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Profile not found or is built-in")
            return {"deleted": True, "id": profile_id}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_profile error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — scan trigger + status
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/scan/trigger", dependencies=[Depends(_require_admin)])
    async def api_scan_trigger(request: Request):
        if not sched_manager:
            raise HTTPException(status_code=503, detail="Scheduler not available in this mode")
        if _scan_state["running"]:
            raise HTTPException(status_code=409, detail="A scan is already in progress")

        try:
            data = await request.json()
        except Exception:
            data = {}
        domain = (data.get("domain") or "").strip() or None
        techniques = data.get("techniques") or {}

        if domain:
            asyncio.create_task(_run_domain_scan(sched_manager, domain, techniques))
        else:
            asyncio.create_task(_run_full_scan(sched_manager))

        return {"started": True, "domain": domain}

    @app.get("/api/scan/status")
    async def api_scan_status():
        return dict(_scan_state)

    # ────────────────────────────────────────────────────────────────────────
    # API — dorking / attack surface scan
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/dorking/{domain}", dependencies=[Depends(_require_admin)])
    async def api_run_dorking(domain: str, request: Request):
        """Run dorking scan for a specific domain."""
        if not _DOMAIN_RE.match(domain):
            raise HTTPException(status_code=400, detail="Invalid domain name")
        try:
            from ..enumeration.dorking import run_dorking
            gh_token = config.api_keys.github_token if hasattr(config.api_keys, 'github_token') else ""
            findings = await run_dorking(domain, db, config, github_token=gh_token or None)
            return {"domain": domain, "findings": len(findings), "results": findings}
        except Exception as exc:
            logger.error("api_run_dorking error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/cloud-assets/{domain}", dependencies=[Depends(_require_admin)])
    async def api_run_cloud_discovery(domain: str, request: Request):
        """Run cloud asset discovery for a specific domain."""
        if not _DOMAIN_RE.match(domain):
            raise HTTPException(status_code=400, detail="Invalid domain name")
        try:
            from ..enumeration.cloud_assets import discover_cloud_assets
            dom = db.get_domain(domain)
            sub_fqdns = []
            if dom:
                sub_fqdns = [s.fqdn for s in db.get_live_subdomains(dom.id)]
            findings = await discover_cloud_assets(domain, sub_fqdns, db, config)
            return {"domain": domain, "findings": len(findings), "results": findings}
        except Exception as exc:
            logger.error("api_run_cloud_discovery error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/dir-scan/{subdomain_id}", dependencies=[Depends(_require_admin)])
    async def api_run_dir_scan(subdomain_id: int, request: Request):
        """Run directory brute-force on a specific subdomain."""
        try:
            from sqlalchemy import select
            from ..database import Subdomain
            with db.get_session() as session_:
                sub = session_.scalar(select(Subdomain).where(Subdomain.id == subdomain_id))
                if not sub:
                    raise HTTPException(status_code=404, detail="Subdomain not found")
                fqdn = sub.fqdn
                sid = sub.id
            from ..scanning.dir_bruteforce import bruteforce_directories
            base_url = f"https://{fqdn}"
            findings = await bruteforce_directories(base_url, db, sid, config)
            return {"subdomain": fqdn, "findings": len(findings), "results": findings}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_run_dir_scan error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/api-discovery/{subdomain_id}", dependencies=[Depends(_require_admin)])
    async def api_run_api_discovery(subdomain_id: int, request: Request):
        """Run API endpoint discovery on a specific subdomain."""
        try:
            from sqlalchemy import select
            from ..database import Subdomain
            with db.get_session() as session_:
                sub = session_.scalar(select(Subdomain).where(Subdomain.id == subdomain_id))
                if not sub:
                    raise HTTPException(status_code=404, detail="Subdomain not found")
                fqdn = sub.fqdn
                sid = sub.id
            from ..scanning.api_discovery import discover_api_endpoints
            base_url = f"https://{fqdn}"
            findings = await discover_api_endpoints(base_url, db, sid, config)
            return {"subdomain": fqdn, "findings": len(findings), "results": findings}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_run_api_discovery error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — settings
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/settings")
    async def api_get_settings():
        try:
            return db.get_config_overrides()
        except Exception as exc:
            logger.error("api_get_settings error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/settings", dependencies=[Depends(_require_admin)])
    async def api_post_settings(request: Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        try:
            db.set_config_overrides(data)
            db.apply_settings_to_config(config)
            new_interval = (data.get("scan") or {}).get("interval_minutes")
            if new_interval and sched_manager:
                try:
                    sched_manager.reschedule(int(new_interval))
                except Exception as exc:
                    logger.warning("reschedule failed: %s", exc)
            return {"saved": True}
        except Exception as exc:
            logger.error("api_post_settings error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — user management
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/users", dependencies=[Depends(_require_admin)])
    async def api_list_users():
        try:
            return db.list_users()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/users", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_create_user(request: Request):
        import bcrypt as _bcrypt
        try:
            data = await request.json()
        except Exception:
            data = {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = (data.get("role") or "viewer").strip()
        if not username or not password:
            raise HTTPException(status_code=400, detail="username and password required")
        if role not in ("admin", "viewer"):
            raise HTTPException(status_code=400, detail="role must be admin or viewer")
        try:
            password_hash = "bcrypt:" + _bcrypt.hashpw(
                password.encode(), _bcrypt.gensalt()
            ).decode()
            db.set_user(username, password_hash, role)
            return {"created": True, "username": username, "role": role}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/users/{username}", dependencies=[Depends(_require_admin)])
    async def api_delete_user(username: str, request: Request):
        if username == request.session.get("username"):
            raise HTTPException(status_code=400, detail="Cannot delete currently logged-in user")
        try:
            ok = db.delete_user(username)
            if not ok:
                raise HTTPException(status_code=404, detail="User not found")
            return {"deleted": True, "username": username}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/users/{username}/password")
    async def api_change_password(username: str, request: Request):
        import bcrypt as _bcrypt
        session_role = request.session.get("role")
        session_user = request.session.get("username")
        if session_role != "admin" and username != session_user:
            raise HTTPException(status_code=403, detail="Forbidden")
        try:
            data = await request.json()
        except Exception:
            data = {}
        new_password = data.get("password") or ""
        if not new_password:
            raise HTTPException(status_code=400, detail="password required")
        try:
            user = db.get_user(username)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")
            password_hash = "bcrypt:" + _bcrypt.hashpw(
                new_password.encode(), _bcrypt.gensalt()
            ).decode()
            db.set_user(username, password_hash, user.get("role", "viewer"))
            return {"updated": True}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — Projects (Companies) management
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/projects")
    async def api_list_projects(user: str = Depends(_require_admin)) -> JSONResponse:
        """List all projects/companies with summary stats."""
        try:
            companies = db.get_all_companies()
            result = []
            for company in companies:
                # Get counts for each asset type
                domain_count = len([d for d in company.domains if d.domain])
                mobile_count = len(company.mobile_apps)
                api_count = len(company.api_assets)
                result.append({
                    "id": company.id,
                    "name": company.name,
                    "description": company.description,
                    "is_active": company.is_active,
                    "program_type": company.program_type,
                    "program_url": company.program_url,
                    "notes": company.notes,
                    "created_at": company.created_at.isoformat() if company.created_at else None,
                    "stats": {
                        "domains": domain_count,
                        "mobile_apps": mobile_count,
                        "api_assets": api_count,
                    }
                })
            return JSONResponse(result)
        except Exception as exc:
            logger.error("api_list_projects error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/projects/{project_id}")
    async def api_get_project(project_id: int):
        """Get full details for a specific project."""
        try:
            details = db.get_company_details(project_id)
            if details is None:
                raise HTTPException(status_code=404, detail="Project not found")
            return details
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_get_project error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/projects", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_create_project(request: Request):
        """Create a new project/company."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        name = (data.get("name") or "").strip()
        description = data.get("description")
        program_type = data.get("program_type")
        program_url = data.get("program_url")
        notes = data.get("notes")

        if not name:
            raise HTTPException(status_code=400, detail="name is required")

        try:
            company = db.create_company(
                name=name,
                description=description,
                program_type=program_type,
                program_url=program_url,
                notes=notes,
            )
            return {
                "id": company.id,
                "name": company.name,
                "description": company.description,
                "is_active": company.is_active,
                "program_type": company.program_type,
                "program_url": company.program_url,
                "notes": company.notes,
                "created_at": company.created_at.isoformat() if company.created_at else None,
            }
        except Exception as exc:
            logger.error("api_create_project error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.patch("/api/projects/{project_id}", dependencies=[Depends(_require_admin)])
    async def api_update_project(project_id: int, request: Request):
        """Update a project's attributes."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        try:
            company = db.update_company(project_id, **data)
            if company is None:
                raise HTTPException(status_code=404, detail="Project not found")
            return {
                "id": company.id,
                "name": company.name,
                "description": company.description,
                "is_active": company.is_active,
                "program_type": company.program_type,
                "program_url": company.program_url,
                "notes": company.notes,
            }
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_update_project error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/projects/{project_id}", dependencies=[Depends(_require_admin)])
    async def api_delete_project(project_id: int):
        """Delete a project and all its assets."""
        try:
            deleted = db.delete_company(project_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Project not found")
            return {"deleted": True, "id": project_id}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_project error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — Mobile Apps management
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/projects/{project_id}/mobile-apps")
    async def api_list_mobile_apps(project_id: int):
        """List all mobile apps for a project."""
        try:
            apps = db.get_all_mobile_apps(company_id=project_id)
            return [
                {
                    "id": app.id,
                    "name": app.name,
                    "platform": app.platform,
                    "package_name": app.package_name,
                    "app_store_url": app.app_store_url,
                    "store_id": app.store_id,
                    "is_active": app.is_active,
                    "notes": app.notes,
                    "last_scan": app.last_scan.isoformat() if app.last_scan else None,
                    "created_at": app.created_at.isoformat() if app.created_at else None,
                }
                for app in apps
            ]
        except Exception as exc:
            logger.error("api_list_mobile_apps error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/projects/{project_id}/mobile-apps", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_create_mobile_app(project_id: int, request: Request):
        """Create a new mobile app asset for a project."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        name = (data.get("name") or "").strip()
        platform = (data.get("platform") or "").strip().lower()
        package_name = data.get("package_name")
        app_store_url = data.get("app_store_url")
        store_id = data.get("store_id")
        notes = data.get("notes")

        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        if platform not in ("android", "ios"):
            raise HTTPException(status_code=400, detail="platform must be 'android' or 'ios'")

        try:
            app = db.create_mobile_app(
                company_id=project_id,
                name=name,
                platform=platform,
                package_name=package_name,
                app_store_url=app_store_url,
                store_id=store_id,
                notes=notes,
            )
            return {
                "id": app.id,
                "name": app.name,
                "platform": app.platform,
                "package_name": app.package_name,
                "app_store_url": app.app_store_url,
                "store_id": app.store_id,
                "is_active": app.is_active,
                "notes": app.notes,
                "created_at": app.created_at.isoformat() if app.created_at else None,
            }
        except Exception as exc:
            logger.error("api_create_mobile_app error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.patch("/api/mobile-apps/{app_id}", dependencies=[Depends(_require_admin)])
    async def api_update_mobile_app(app_id: int, request: Request):
        """Update a mobile app's attributes."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        try:
            app = db.update_mobile_app(app_id, **data)
            if app is None:
                raise HTTPException(status_code=404, detail="Mobile app not found")
            return {
                "id": app.id,
                "name": app.name,
                "platform": app.platform,
                "package_name": app.package_name,
                "app_store_url": app.app_store_url,
                "store_id": app.store_id,
                "is_active": app.is_active,
                "notes": app.notes,
            }
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_update_mobile_app error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/mobile-apps/{app_id}", dependencies=[Depends(_require_admin)])
    async def api_delete_mobile_app(app_id: int):
        """Delete a mobile app."""
        try:
            deleted = db.delete_mobile_app(app_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Mobile app not found")
            return {"deleted": True, "id": app_id}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_mobile_app error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — API Assets management
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/projects/{project_id}/api-assets")
    async def api_list_api_assets(project_id: int):
        """List all API assets for a project."""
        try:
            assets = db.get_all_api_assets(company_id=project_id)
            return [
                {
                    "id": asset.id,
                    "name": asset.name,
                    "base_url": asset.base_url,
                    "api_type": asset.api_type,
                    "specification_url": asset.specification_url,
                    "authentication": asset.authentication,
                    "is_public": asset.is_public,
                    "is_active": asset.is_active,
                    "notes": asset.notes,
                    "last_scan": asset.last_scan.isoformat() if asset.last_scan else None,
                    "created_at": asset.created_at.isoformat() if asset.created_at else None,
                }
                for asset in assets
            ]
        except Exception as exc:
            logger.error("api_list_api_assets error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/projects/{project_id}/api-assets", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_create_api_asset(project_id: int, request: Request):
        """Create a new API asset for a project."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        name = (data.get("name") or "").strip()
        base_url = (data.get("base_url") or "").strip()
        api_type = (data.get("api_type") or "").strip().lower()
        specification_url = data.get("specification_url")
        authentication = data.get("authentication")
        is_public = bool(data.get("is_public", False))
        notes = data.get("notes")

        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        if not base_url:
            raise HTTPException(status_code=400, detail="base_url is required")
        if api_type not in ("rest", "graphql", "grpc", "soap"):
            raise HTTPException(status_code=400, detail="api_type must be one of: rest, graphql, grpc, soap")

        try:
            asset = db.create_api_asset(
                company_id=project_id,
                name=name,
                base_url=base_url,
                api_type=api_type,
                specification_url=specification_url,
                authentication=authentication,
                is_public=is_public,
                notes=notes,
            )
            return {
                "id": asset.id,
                "name": asset.name,
                "base_url": asset.base_url,
                "api_type": asset.api_type,
                "specification_url": asset.specification_url,
                "authentication": asset.authentication,
                "is_public": asset.is_public,
                "is_active": asset.is_active,
                "notes": asset.notes,
                "created_at": asset.created_at.isoformat() if asset.created_at else None,
            }
        except Exception as exc:
            logger.error("api_create_api_asset error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.patch("/api/api-assets/{asset_id}", dependencies=[Depends(_require_admin)])
    async def api_update_api_asset(asset_id: int, request: Request):
        """Update an API asset's attributes."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        try:
            asset = db.update_api_asset(asset_id, **data)
            if asset is None:
                raise HTTPException(status_code=404, detail="API asset not found")
            return {
                "id": asset.id,
                "name": asset.name,
                "base_url": asset.base_url,
                "api_type": asset.api_type,
                "specification_url": asset.specification_url,
                "authentication": asset.authentication,
                "is_public": asset.is_public,
                "is_active": asset.is_active,
                "notes": asset.notes,
            }
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_update_api_asset error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/api-assets/{asset_id}", dependencies=[Depends(_require_admin)])
    async def api_delete_api_asset(asset_id: int):
        """Delete an API asset."""
        try:
            deleted = db.delete_api_asset(asset_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="API asset not found")
            return {"deleted": True, "id": asset_id}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_api_asset error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ────────────────────────────────────────────────────────────────────────
    # API — GitHub Monitoring
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/github/repos")
    async def api_list_github_repos():
        """List all monitored GitHub repositories."""
        try:
            repos = db.list_github_repos()
            return {
                "repos": [
                    {
                        "id": r.id,
                        "organization": r.organization,
                        "repository": r.repository,
                        "full_name": r.full_name,
                        "monitor_secrets": r.monitor_secrets,
                        "monitor_dangerous_functions": r.monitor_dangerous_functions,
                        "monitor_issues": r.monitor_issues,
                        "monitor_wiki": r.monitor_wiki,
                        "monitor_gists": r.monitor_gists,
                        "alert_on_new_repos": r.alert_on_new_repos,
                        "last_scan": r.last_scan_timestamp.isoformat() if r.last_scan_timestamp else None,
                        "last_commit": r.last_commit_hash,
                        "created_at": r.created_at.isoformat() if r.created_at else None,
                    }
                    for r in repos
                ]
            }
        except Exception as exc:
            logger.error("api_list_github_repos error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/github/repos", status_code=201, dependencies=[Depends(_require_admin)])
    async def api_add_github_repo(request: Request):
        """Add a GitHub repository to monitoring."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        org = (data.get("organization") or "").strip()
        repo = (data.get("repository") or "").strip()

        if not org or not repo:
            raise HTTPException(status_code=400, detail="organization and repository are required")

        try:
            repo_id = db.add_github_repo(
                organization=org,
                repository=repo,
                monitor_secrets=data.get("monitor_secrets", True),
                monitor_dangerous_functions=data.get("monitor_dangerous_functions", True),
                monitor_issues=data.get("monitor_issues", True),
                monitor_wiki=data.get("monitor_wiki", True),
                monitor_gists=data.get("monitor_gists", False),
                alert_on_new_repos=data.get("alert_on_new_repos", False),
            )
            return {"repo_id": repo_id, "status": "added"}
        except Exception as exc:
            logger.error("api_add_github_repo error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.delete("/api/github/repos/{repo_id}", dependencies=[Depends(_require_admin)])
    async def api_delete_github_repo(repo_id: int):
        """Delete a GitHub repository from monitoring."""
        try:
            deleted = db.delete_github_repo(repo_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Repository not found")
            return {"deleted": True, "id": repo_id}
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_delete_github_repo error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/github/findings")
    async def api_get_github_findings(request: Request):
        """Get GitHub findings with optional filters."""
        try:
            # Parse query parameters
            repo_id_str = request.query_params.get("repo_id")
            repo_id = int(repo_id_str) if repo_id_str else None

            finding_type = request.query_params.get("finding_type")
            if finding_type and finding_type not in ("secret", "dangerous_function", "sensitive_data"):
                raise HTTPException(
                    status_code=400,
                    detail="finding_type must be one of: secret, dangerous_function, sensitive_data"
                )

            severity = request.query_params.get("severity")
            if severity and severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                raise HTTPException(
                    status_code=400,
                    detail="severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO"
                )

            unreviewed_only_str = request.query_params.get("unreviewed_only", "false").lower()
            unreviewed_only = unreviewed_only_str in ("true", "1", "yes")

            try:
                limit = int(request.query_params.get("limit", 100))
            except ValueError:
                limit = 100
            limit = min(max(limit, 1), 1000)  # Clamp between 1 and 1000

            findings = db.get_github_findings(
                repo_id=repo_id,
                finding_type=finding_type,
                severity=severity,
                unreviewed_only=unreviewed_only,
                limit=limit,
            )

            return {
                "findings": [
                    {
                        "id": f.id,
                        "repo_id": f.repo_id,
                        "finding_type": f.finding_type,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "pattern_name": f.pattern_name,
                        "matched_text": (
                            f.matched_text[:100] + "..."
                            if f.matched_text and len(f.matched_text) > 100
                            else f.matched_text
                        ),
                        "context_before": f.context_before,
                        "context_after": f.context_after,
                        "commit_hash": f.commit_hash,
                        "commit_url": f.commit_url,
                        "author": f.author,
                        "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                        "false_positive": f.false_positive,
                        "reviewed": f.reviewed,
                        "notes": f.notes,
                    }
                    for f in findings
                ],
                "count": len(findings),
            }
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("api_get_github_findings error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.put("/api/github/findings/{finding_id}/review", dependencies=[Depends(_require_admin)])
    async def api_review_finding(finding_id: int, request: Request):
        """Mark a finding as reviewed (and optionally as false positive)."""
        try:
            data = await request.json()
        except Exception:
            data = {}
        is_fp = data.get("false_positive", False)

        try:
            if is_fp:
                db.mark_finding_false_positive(finding_id, is_fp)
            else:
                db.mark_finding_reviewed(finding_id)

            return {"status": "reviewed"}
        except Exception as exc:
            logger.error("api_review_finding error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/github/scan/{repo_id}", status_code=202, dependencies=[Depends(_require_admin)])
    async def api_trigger_github_scan(repo_id: int, background_tasks: BackgroundTasks):
        """Trigger an immediate scan of a GitHub repository."""
        # Verify repo exists
        repo = db.get_github_repo(repo_id)
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")

        # Run scan in background
        async def run_scan():
            from src.github.monitor import GitHubMonitor
            try:
                gh_token = config.github.token if hasattr(config, 'github') else None
                monitor = GitHubMonitor(db=db, github_token=gh_token)
                await monitor.scan_repository(repo_id)
                logger.info(f"Background scan completed for repo {repo_id}")
            except Exception as exc:
                logger.error(f"Background scan failed for repo {repo_id}: %s", exc)

        background_tasks.add_task(run_scan)

        return {"status": "scan_started", "repo_id": repo_id}

    # ────────────────────────────────────────────────────────────────────────
    # API — GitHub Configuration
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/config/github")
    async def api_get_github_config(user: str = Depends(_require_admin)) -> JSONResponse:
        """Get current GitHub configuration (without exposing the full token)."""
        if not hasattr(config, 'github'):
            return JSONResponse({"enabled": False, "token_configured": False})

        return JSONResponse({
            "enabled": config.github.enabled,
            "token_configured": bool(config.github.token),
            "scan_interval_hours": config.github.scan_interval_hours,
            "monitor_secrets": config.github.monitor_secrets,
            "monitor_dangerous_functions": config.github.monitor_dangerous_functions,
            "monitor_issues": config.github.monitor_issues,
            "monitor_wiki": config.github.monitor_wiki,
            "monitor_gists": config.github.monitor_gists,
            "alert_on_severity": config.github.alert_on_severity,
            "auto_discover_organizations": config.github.auto_discover_organizations,
        })

    @app.put("/api/config/github")
    async def api_update_github_config(payload: dict, user: str = Depends(_require_admin)) -> JSONResponse:
        """Update GitHub configuration."""
        try:
            # Store token in database if provided
            if "token" in payload and payload["token"]:
                token = payload["token"]
                # Store as app setting
                existing = db.get_setting("config.github.token")
                if existing:
                    db.update_setting("config.github.token", token)
                else:
                    db.add_setting("config.github.token", token)

            # Store other config values
            updates = {
                "enabled": payload.get("enabled", False),
                "scan_interval_hours": payload.get("scan_interval_hours", 24),
                "monitor_secrets": payload.get("monitor_secrets", True),
                "monitor_dangerous_functions": payload.get("monitor_dangerous_functions", True),
                "monitor_issues": payload.get("monitor_issues", True),
                "monitor_wiki": payload.get("monitor_wiki", True),
                "monitor_gists": payload.get("monitor_gists", False),
                "alert_on_severity": payload.get("alert_on_severity", "MEDIUM"),
                "auto_discover_organizations": payload.get("auto_discover_organizations", []),
            }

            for key, value in updates.items():
                setting_key = f"config.github.{key}"
                existing = db.get_setting(setting_key)
                if existing:
                    db.update_setting(setting_key, value)
                else:
                    db.add_setting(setting_key, value)

            # Reload config from database
            db.apply_settings_to_config(config)

            return JSONResponse({"status": "updated"})
        except Exception as exc:
            logger.error("api_update_github_config error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    return app


# ────────────────────────────────────────────────────────────────────────────
# Background scan coroutines (run via asyncio.create_task)
# ────────────────────────────────────────────────────────────────────────────

async def _run_domain_scan(
    sched_manager: "SchedManager",
    domain: str,
    techniques: dict,
) -> None:
    async with _scan_lock:
        if _scan_state["running"]:
            return
        _scan_state.update({
            "running": True,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "error": None,
        })
    try:
        sub_count, event_count = await sched_manager.run_domain_scan(
            domain, technique_overrides=techniques or None
        )
        _scan_state.update({
            "running": False,
            "last_completed": datetime.now(timezone.utc).isoformat(),
            "last_subs_found": sub_count,
            "last_events": event_count,
        })
    except Exception as exc:
        logger.error("Background domain scan failed: %s", exc, exc_info=True)
        _scan_state.update({"running": False, "error": str(exc)})


async def _run_full_scan(sched_manager: "SchedManager") -> None:
    async with _scan_lock:
        if _scan_state["running"]:
            return
        _scan_state.update({
            "running": True,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "domain": None,
            "error": None,
        })
    try:
        await sched_manager.run_full_scan()
        _scan_state.update({
            "running": False,
            "last_completed": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.error("Background full scan failed: %s", exc, exc_info=True)
        _scan_state.update({"running": False, "error": str(exc)})
