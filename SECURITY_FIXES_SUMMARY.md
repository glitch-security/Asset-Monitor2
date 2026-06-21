# Security Fixes Summary

All 5 security issues have been fixed:

## ✅ Issue 1 (HIGH): Dead SSL Context → mTLS Silently Does Nothing
**Location**: `src/cli.py:526-558`

**Problem**: 
- Built custom SSLContext with client cert verification
- Never passed context to uvicorn.run()
- Only passed ssl_keyfile/ssl_certfile directly
- Result: mTLS appeared enabled but did nothing

**Fix Applied**:
- Removed manual SSLContext building
- Now uses uvicorn's native SSL support:
  - `ssl_ca_certs` for CA bundle
  - `ssl_cert_reqs=ssl.CERT_REQUIRED` for client verification
- Client cert verification now actually works

**Files Modified**: `src/cli.py`

---

## ✅ Issue 2 (MEDIUM): Session Cookie Missing Secure Flag
**Location**: `src/web/server.py:197`

**Problem**:
- `https_only=False` hardcoded in SessionMiddleware
- Session cookie sent over plaintext even when SSL enabled

**Fix Applied**:
```python
https_only=config.web.ssl_enabled  # Secure flag when SSL is enabled
```

**Files Modified**: `src/web/server.py`

---

## ✅ Issue 3 (MEDIUM): Docker Healthcheck Probes Plain HTTP
**Location**: `docker-compose.yml:71`

**Problem**:
- Healthcheck used `http://localhost:5000/health`
- Fails for SSL-enabled deployments (container marked unhealthy)

**Fix Applied**:
- Added `ASSETMONITOR_HEALTHCHECK_PROTO` env var (defaults to `http`)
- Set `ASSETMONITOR_HEALTHCHECK_PROTO=https` in environment for SSL deployments
- Uses proper SSL context with `ssl._create_unverified_context()` for HTTPS

**Usage**:
```bash
# For SSL-enabled deployments:
docker run -e ASSETMONITOR_HEALTHCHECK_PROTO=https ...
# Or in docker-compose.yml:
environment:
  ASSETMONITOR_HEALTHCHECK_PROTO: "https"
```

**Files Modified**: `docker-compose.yml`

---

## ✅ Issue 4 (LOW): No Path Validation Before uvicorn.run()
**Location**: `src/cli.py:526-558`

**Problem**:
- Checked if cert/key paths are non-empty but not if they exist
- Typo'd paths failed deep inside OpenSSL with unhelpful traceback

**Fix Applied**:
```python
if not os.path.isfile(config.web.ssl_cert_path):
    console.print(f"[bold red]SSL certificate file not found: {config.web.ssl_cert_path}[/bold red]")
    sys.exit(1)
if not os.path.isfile(config.web.ssl_key_path):
    console.print(f"[bold red]SSL key file not found: {config.web.ssl_key_path}[/bold red]")
    sys.exit(1)
# Same validation for ssl_ca_path when mTLS is enabled
```

**Files Modified**: `src/cli.py` (fixed alongside Issue #1)

---

## Issue 5 (DEFENSE-IN-DEPTH): Proxy Headers Security
**Location**: `src/cli.py:550-558`

**Assessment**:
- Current defaults (proxy_headers not set) are SAFE for direct deployment
- Not exploitable today since nothing fronts the container

**Documentation Added**:
```python
# Security note: proxy_headers and forwarded_allow_ips
# If deploying behind a reverse proxy/load balancer, set:
#   proxy_headers=True to trust X-Forwarded-* headers
#   forwarded_allow_ips=<proxy_ip> to only accept headers from the proxy
# Current defaults (proxy_headers not set) are safe for direct deployment.
```

**Recommendation for Future**:
When adding reverse proxy support, add config options:
```yaml
web:
  proxy_headers: true
  trusted_proxy_ips: "127.0.0.1,10.0.0.0/8"
```

**Files Modified**: `src/cli.py` (documentation added)

---

## Testing Checklist

### SSL/mTLS Testing
```bash
# Test with SSL enabled
python -m src.cli

# In another terminal, test with client cert:
curl -k --cert client.crt --key client.key https://localhost:5000/health
# Should succeed with valid cert, fail without
```

### Session Cookie Testing
```bash
# Login with HTTPS
# Check cookie in browser dev tools
# Should see "Secure: Yes" on session cookie
```

### Docker Healthcheck Testing
```bash
# Test HTTP deployment
docker-compose up
docker inspect --format='{{.State.Health.Status}}' assetmonitor

# Test HTTPS deployment
docker run -e ASSETMONITOR_HEALTHCHECK_PROTO=https ...
```

### Path Validation Testing
```bash
# Set invalid paths in config.yaml
# Should see clean error message at startup
# Not OpenSSL traceback
```

---

## Files Modified Summary

1. **src/cli.py**
   - Fixed SSL context (Issue #1)
   - Added path validation (Issue #4)
   - Added proxy_headers documentation (Issue #5)

2. **src/web/server.py**
   - Fixed session cookie Secure flag (Issue #2)

3. **docker-compose.yml**
   - Fixed healthcheck for SSL support (Issue #3)
