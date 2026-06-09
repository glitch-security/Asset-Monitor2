"""
HTTP prober for subdomain and website liveness detection.

Key design decisions:
- Standard ports (80, 443) are NOT included in the URL string — some CDNs and
  load balancers reject `https://host:443` (explicit standard port) even though
  it is technically equivalent.  Omitting them matches normal browser behaviour.
- HTTPS probing always precedes HTTP for the same port family.
- If SSL verification fails and verify_ssl=True, we retry without verification
  so the host is still flagged as alive (with ssl_valid=False in the result).
- Body reads are capped at 512 KB — enough for title/fingerprint extraction
  without timing out on very large responses.
- Connect and read timeouts are set independently for tighter control.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

PORTS: list[int] = [80, 443, 8080, 8443, 8888]

# Any valid HTTP response means the server is reachable, including 4xx / 5xx.
_LIVE_STATUS_CODES: set[int] = set(range(200, 600))

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_BODY_LIMIT = 512 * 1024  # 512 KB


def _extract_title(html: str) -> str:
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()


def _build_url(scheme: str, fqdn: str, port: int) -> str:
    """Build a URL, omitting the port when it is the scheme default."""
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{fqdn}"
    return f"{scheme}://{fqdn}:{port}"


def _build_attempts(ports: list[int]) -> list[tuple[str, int]]:
    """Return (scheme, port) pairs to try, HTTPS before HTTP on ambiguous ports."""
    attempts: list[tuple[str, int]] = []
    for port in ports:
        if port in (443, 8443):
            attempts.append(("https", port))
        elif port == 80:
            # Try plain HTTP first (very common redirect entry point), then HTTPS
            # fallback in case the server does HTTPS-on-80 (unusual but possible).
            attempts.append(("http", port))
            attempts.append(("https", port))
        else:
            attempts.append(("https", port))
            attempts.append(("http", port))
    return attempts


async def _single_probe(
    url: str,
    verify: bool,
    timeout_connect: float,
    timeout_read: float,
) -> Optional[dict]:
    """
    Make one HTTP GET to *url*.  Return a result dict on any HTTP response,
    or None on connection/protocol errors.
    """
    timeout = httpx.Timeout(
        connect=timeout_connect,
        read=timeout_read,
        write=timeout_connect,
        pool=timeout_connect,
    )
    try:
        async with httpx.AsyncClient(
            verify=verify,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=10,
        ) as client:
            response = await client.get(url)

            # Build redirect chain from response history
            chain = [str(r.url) for r in response.history] + [str(response.url)]

            # Read body, capped to avoid timeouts on enormous pages
            body_bytes = response.content[:_BODY_LIMIT]
            body_text = body_bytes.decode("utf-8", errors="replace")

            return {
                "status_code": response.status_code,
                "url": str(response.url),
                "redirect_chain": chain,
                "response_headers": dict(response.headers),
                "response_size": int(response.headers.get("content-length", len(body_bytes))),
                "page_title": _extract_title(body_text),
                "body": body_text,
                "ssl_valid": verify,
            }

    except httpx.SSLError:
        return None  # caller retries without verify
    except httpx.TimeoutException:
        logger.debug("Timeout probing %s", url)
        return None
    except httpx.ConnectError:
        logger.debug("Connect error probing %s", url)
        return None
    except httpx.RemoteProtocolError:
        logger.debug("Protocol error probing %s", url)
        return None
    except Exception as exc:
        logger.debug("Unexpected error probing %s: %s", url, exc)
        return None


async def probe_subdomain(
    fqdn: str,
    ports: list[int] | None = None,
    timeout: int = 15,
    verify_ssl: bool = True,
) -> dict:
    """
    Probe *fqdn* for HTTP/HTTPS liveness across the given *ports*.

    For each (scheme, port) pair it attempts a GET with SSL verification.
    On SSL error, retries once without verification (flagging ssl_valid=False).
    Returns on the first successful HTTP response.

    Parameters
    ----------
    fqdn:
        Hostname to probe (no scheme or path).
    ports:
        TCP ports to try. Defaults to [80, 443, 8080, 8443, 8888].
    timeout:
        Base timeout in seconds (connect uses half, read uses the full value).
    verify_ssl:
        When True, SSL certificates are validated.  On failure a second attempt
        is made without verification so the host is still detected as alive.

    Returns
    -------
    dict with keys: fqdn, live, url, status_code, response_size, page_title,
    body, response_headers, redirect_chain, port, scheme, ssl_valid.
    """
    if ports is None:
        ports = PORTS

    result: dict = {
        "fqdn": fqdn,
        "live": False,
        "url": "",
        "status_code": 0,
        "response_size": 0,
        "page_title": "",
        "body": "",
        "response_headers": {},
        "redirect_chain": [],
        "port": 0,
        "scheme": "",
        "ssl_valid": True,
    }

    timeout_connect = max(5.0, timeout / 2)
    timeout_read = float(timeout)

    for scheme, port in _build_attempts(ports):
        url = _build_url(scheme, port=port, fqdn=fqdn)

        hit = await _single_probe(url, verify=verify_ssl, timeout_connect=timeout_connect, timeout_read=timeout_read)

        # On SSL error, retry without verification
        if hit is None and verify_ssl and scheme == "https":
            hit = await _single_probe(url, verify=False, timeout_connect=timeout_connect, timeout_read=timeout_read)
            if hit is not None:
                hit["ssl_valid"] = False
                logger.info("SSL verification failed for %s — host is alive with unverified cert", fqdn)

        if hit is None:
            continue

        # Record the first response regardless of status, keep trying if not live
        result.update(hit)
        result["port"] = port
        result["scheme"] = scheme

        if hit["status_code"] in _LIVE_STATUS_CODES:
            result["live"] = True
            return result

    return result
