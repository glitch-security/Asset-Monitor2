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

from fastapi import Depends, FastAPI, HTTPException, Request
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
        return templates.TemplateResponse("login.html", {"request": request})

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
        return templates.TemplateResponse("dashboard.html", {"request": request})

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
        if "profile_id" not in data:
            raise HTTPException(status_code=400, detail="profile_id is required")
        profile_id = data["profile_id"]
        ok = db.set_domain_profile(domain_id, profile_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Domain not found")
        return {"updated": True, "domain_id": domain_id, "profile_id": profile_id}

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

    @app.get("/api/users")
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
