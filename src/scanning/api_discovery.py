"""
API endpoint discovery module.

Discovers hidden API endpoints through multiple techniques:
  1. Common API path fuzzing (REST, GraphQL, SOAP)
  2. OpenAPI / Swagger spec parsing
  3. HTTP method fuzzing on discovered endpoints
  4. API parameter discovery from JS analysis results
  5. WSDL / SOAP endpoint detection

Results are persisted as endpoints and change events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

import httpx

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)

# ── Common API base paths to probe ──
_API_BASE_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1", "/v2", "/v3", "/v1/", "/v2/",
    "/rest", "/rest/", "/rest/api", "/rest/api/",
    "/graphql", "/graphiql", "/playground",
    "/api/graphql", "/gql",
    "/api/jsonws", "/api/json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/assetlinks.json",
    "/oauth/jwks", "/oauth/jwks.json",
    "/.well-known/swagger.json", "/.well-known/api-docs",
]

# ── API spec endpoints ──
_SPEC_ENDPOINTS = [
    "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/swagger/v3/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api-docs", "/api-docs/", "/api/docs", "/api/spec",
    "/docs/json", "/docs/swagger.json", "/docs/openapi.json",
    "/redoc", "/api/swagger.json", "/api/openapi.json",
    "/swagger-resources", "/swagger-resources/",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.yml", "/openapi.yaml", "/swagger.yaml",
    "/wsdl", "/wsdl/", "/?wsdl", "/?singleWsdl",
    "/asmx", "/api.asmx", "/service.asmx",
    "/api/health", "/api/status", "/api/ping",
    "/api/version", "/api/info", "/api/me", "/api/user",
    "/api/users", "/api/config", "/api/settings",
    "/api/auth/login", "/api/auth/register",
    "/api/auth/me", "/api/auth/token",
    "/api/auth/refresh", "/api/auth/logout",
    "/admin/api", "/admin/api/", "/admin/api/v1",
    "/internal/api", "/internal/", "/debug/", "/debug/vars",
    "/debug/pprof", "/debug/pprof/", "/expvar",
    "/trace", "/metrics", "/prometheus",
]

# ── HTTP methods to fuzz ──
_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# ── Common API parameters to fuzz ──
_FUZZ_PARAMS = [
    "id", "user_id", "page", "limit", "offset", "count",
    "q", "query", "search", "filter", "sort", "order",
    "format", "callback", "debug", "test", "admin",
    "role", "type", "action", "cmd", "exec", "file",
    "path", "url", "redirect", "next", "return",
    "token", "key", "api_key", "access_token",
    "username", "email", "password", "secret",
]


async def discover_api_endpoints(
    base_url: str,
    db: "DatabaseManager",
    subdomain_id: int,
    config: "AppConfig",
    max_concurrent: int = 15,
    timeout: int = 8,
) -> List[Dict[str, Any]]:
    """Discover API endpoints on a target using multiple techniques.

    Args:
        base_url: Target URL (e.g. ``https://example.com``).
        db: DatabaseManager for persisting findings.
        subdomain_id: FK to the Subdomain being scanned.
        config: Application config.
        max_concurrent: Max concurrent requests.
        timeout: Per-request timeout.

    Returns:
        List of discovered API endpoint dicts.
    """
    base = base_url.rstrip("/")
    all_paths = set(_API_BASE_PATHS + _SPEC_ENDPOINTS)
    findings: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(max_concurrent)

    headers = {
        "User-Agent": config.scan.user_agent,
        "Accept": "application/json, application/xml, text/html, */*",
    }

    async with httpx.AsyncClient(
        verify=config.scan.verify_ssl,
        timeout=httpx.Timeout(timeout),
        headers=headers,
        follow_redirects=True,
        max_redirects=3,
    ) as client:

        # ── Phase 1: Probe all API paths ──
        async def _probe_path(path: str) -> Optional[Dict]:
            async with sem:
                url = base + path
                try:
                    resp = await client.get(url)
                except (httpx.ConnectError, httpx.TimeoutException):
                    return None
                except Exception:
                    return None

            if resp.status_code in (200, 201, 401, 403, 405):
                content_type = resp.headers.get("content-type", "")
                body = resp.text[:2000] if resp.status_code == 200 else ""

                return {
                    "path": path,
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "content_length": len(resp.content),
                    "body_preview": body,
                    "url": url,
                }
            return None

        results = await asyncio.gather(
            *[_probe_path(p) for p in all_paths],
            return_exceptions=True,
        )

        phase1_findings = [r for r in results if isinstance(r, dict) and r]

        # ── Phase 2: Parse OpenAPI/Swagger specs ──
        spec_endpoints = await _parse_api_specs(client, base, phase1_findings)

        # ── Phase 3: HTTP method fuzzing on discovered endpoints ──
        method_findings = await _fuzz_methods(
            client, base, phase1_findings, sem,
        )

    # Combine all findings
    all_findings = phase1_findings + spec_endpoints + method_findings
    seen: Set[str] = set()
    unique_findings: List[Dict[str, Any]] = []

    for f in all_findings:
        path = f.get("path", "")
        if path and path not in seen:
            seen.add(path)
            unique_findings.append(f)

    # Persist to database
    hostname = base_url.replace("https://", "").replace("http://", "").split("/")[0]
    for f in unique_findings:
        try:
            db.upsert_endpoint(
                subdomain_id=subdomain_id,
                path=f["path"],
                method=f.get("method", "GET"),
                status_code=f.get("status_code"),
                source="api_discovery",
                parameters=f.get("parameters"),
            )
        except Exception:
            pass

        severity = _classify_api_finding(f)
        if severity in ("HIGH", "CRITICAL"):
            try:
                db.add_change_event(
                    event_type="API_ENDPOINT_FOUND",
                    severity=severity,
                    target=hostname,
                    description=(
                        f"API endpoint discovered: {f.get('method', 'GET')} "
                        f"{f['path']} (HTTP {f.get('status_code', '?')})"
                    ),
                    diff_data=f,
                )
            except Exception:
                pass

    logger.info(
        "API discovery on %s: %d unique endpoints found", base_url, len(unique_findings),
    )
    return unique_findings


async def _parse_api_specs(
    client: httpx.AsyncClient,
    base: str,
    probe_results: List[Dict],
) -> List[Dict[str, Any]]:
    """Parse discovered OpenAPI/Swagger specs to extract endpoint definitions."""
    endpoints: List[Dict[str, Any]] = []

    spec_bodies: List[str] = []
    for r in probe_results:
        body = r.get("body_preview", "")
        if not body:
            continue
        lower = body.lower()
        if '"openapi"' in lower or '"swagger"' in lower or '"paths"' in lower:
            spec_bodies.append(body)

    for body in spec_bodies:
        try:
            spec = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            continue

        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            continue

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in methods:
                if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "status_code": None,
                        "source": "openapi_spec",
                        "spec_url": r.get("path", ""),
                    })

    # Deduplicate
    seen: Set[str] = set()
    unique: List[Dict[str, Any]] = []
    for ep in endpoints:
        key = f"{ep.get('method', 'GET')}:{ep['path']}"
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    return unique


async def _fuzz_methods(
    client: httpx.AsyncClient,
    base: str,
    probe_results: List[Dict],
    sem: asyncio.Semaphore,
) -> List[Dict[str, Any]]:
    """Fuzz HTTP methods on discovered API paths."""
    findings: List[Dict[str, Any]] = []

    # Only fuzz paths that returned 200, 401, 403, or 405
    fuzzable = [
        r for r in probe_results
        if r.get("status_code") in (200, 401, 403, 405) and r.get("path")
    ][:20]  # Limit to top 20 to avoid excessive requests

    async def _fuzz_one(path: str, method: str) -> Optional[Dict]:
        async with sem:
            url = base + path
            try:
                resp = await client.request(method, url)
            except Exception:
                return None

        if resp.status_code in (200, 201, 204, 401, 403):
            ct = resp.headers.get("content-type", "")
            if "json" in ct or "xml" in ct or resp.status_code in (201, 204):
                return {
                    "path": path,
                    "method": method,
                    "status_code": resp.status_code,
                    "content_type": ct,
                    "content_length": len(resp.content),
                }
        return None

    tasks = []
    for r in fuzzable:
        path = r["path"]
        for method in _METHODS:
            if method != "GET":  # GET was already probed
                tasks.append(_fuzz_one(path, method))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict) and r:
            findings.append(r)

    return findings


def _classify_api_finding(finding: Dict) -> str:
    """Classify the severity of an API endpoint discovery."""
    path = finding.get("path", "").lower()
    status = finding.get("status_code", 0)

    # Public API specs are HIGH — they reveal the full attack surface
    if any(kw in path for kw in ("swagger", "openapi", "api-docs", "wsdl")):
        if status == 200:
            return "HIGH"

    # Debug/internal endpoints
    if any(kw in path for kw in ("debug", "pprof", "expvar", "trace", "metrics", "internal")):
        if status in (200, 201, 204):
            return "HIGH"

    # Auth endpoints accessible without auth
    if any(kw in path for kw in ("auth/me", "auth/token", "users", "admin")):
        if status == 200:
            return "MEDIUM"

    # GraphQL with introspection
    if "graphql" in path and status == 200:
        return "MEDIUM"

    return "LOW"
