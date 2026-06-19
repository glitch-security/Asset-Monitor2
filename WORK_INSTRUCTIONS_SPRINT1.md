# Sprint 1: Advanced DNS Enumeration - Implementation Instructions

> Advanced DNS enumeration including DNS record types, DNSSEC analysis, email security, and nameserver security

---

## Overview

Implement advanced DNS enumeration features including:
1. Complete DNS record type enumeration (MX, NS, TXT, SRV, PTR, CAA, SOA)
2. DNSSEC analysis and validation
3. Email security (SPF/DKIM/DMARC) analysis
4. Nameserver security checks (AXFR, open resolver, etc.)

---

## Task 1.1: Extended DNS Records Module

**File:** `src/enumeration/dns_records.py` (extends existing)

**New Functions:**

```python
async def enumerate_mx_records(domain: str, resolvers: list[str]) -> list[dict]:
    """Query MX records for the domain."""
    answers = await resolver.resolve(domain, 'MX')
    return [{
        'exchange': str(r.exchange).rstrip('.'),
        'priority': r.preference,
    } for r in answers]

async def enumerate_ns_records(domain: str, resolvers: list[str]) -> list[str]:
    """Query NS records for the domain."""
    answers = await resolver.resolve(domain, 'NS')
    return [str(r.target).rstrip('.') for r in answers]

async def enumerate_txt_records(domain: str, resolvers: list[str]) -> list[str]:
    """Query TXT records for the domain."""
    answers = await resolver.resolve(domain, 'TXT')
    return [b''.join(r.chunks).decode('utf-8', errors='replace') for r in answers]

async def enumerate_srv_records(domain: str, resolvers: list[str]) -> list[dict]:
    """Query SRV records for common services."""
    services = ['_sip._tcp', '_sips._tcp', '_xmpp-server._tcp', '_ldap._tcp']
    results = []
    for service in services:
        try:
            fqdn = f"{service}.{domain}"
            answers = await resolver.resolve(fqdn, 'SRV')
            for r in answers:
                results.append({
                    'service': service,
                    'target': str(r.target).rstrip('.'),
                    'port': r.port,
                    'priority': r.priority,
                    'weight': r.weight,
                })
        except: pass
    return results

async def enumerate_caa_records(domain: str, resolvers: list[str]) -> list[dict]:
    """Query CAA records for the domain."""
    try:
        answers = await resolver.resolve(domain, 'CAA')
        return [{
            'flag': r.flag,
            'tag': r.tag,
            'value': r.value,
        } for r in answers]
    except: return []

async def enumerate_soa_record(domain: str, resolvers: list[str]) -> dict | None:
    """Query SOA record for the domain."""
    try:
        answers = await resolver.resolve(domain, 'SOA')
        r = answers[0]
        return {
            'mname': str(r.mname).rstrip('.'),
            'rname': str(r.rname).rstrip('.'),
            'serial': r.serial,
            'refresh': r.refresh,
            'retry': r.retry,
            'expire': r.expire,
            'minimum': r.minimum,
        }
    except: return None
```

---

## Task 1.2: DNSSEC Analysis Module

**New File:** `src/verification/dnssec.py`

```python
"""
DNSSEC analysis module.
Checks DNSSEC configuration, NSEC/NSEC3 walking, and DANE records.
"""

import dns.resolver
import dns.flags
import dns.rdatatype
from typing import Any

async def analyze_dnssec(domain: str, resolvers: list[str]) -> dict:
    """
    Analyze DNSSEC configuration for a domain.

    Returns:
        {
            "dnssec_enabled": bool,
            "validation_status": "secure" | "insecure" | "bogus",
            "nsec_walk_possible": bool,
            "nsec3_opt_out": bool,
            "dnskey_records": [...],
            "ds_records": [...],
            "issues": [...]
        }
    """
    result = {
        "dnssec_enabled": False,
        "validation_status": "insecure",
        "nsec_walk_possible": False,
        "nsec3_opt_out": False,
        "dnskey_records": [],
        "ds_records": [],
        "issues": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    try:
        # Check for DNSKEY records
        dnskey_answer = resolver.resolve(domain, 'DNSKEY')
        result["dnssec_enabled"] = True
        result["dnskey_records"] = [_format_dnskey(r) for r in dnskey_answer]

        # Check for DS records (at parent)
        try:
            # Get parent zone
            parts = domain.split('.')
            if len(parts) > 2:
                parent = '.'.join(parts[1:])
                ds_answer = resolver.resolve(parent, 'DS', domain)
                result["ds_records"] = [_format_ds(r) for r in ds_answer]
        except: pass

        result["validation_status"] = "secure"

    except dns.resolver.NoAnswer:
        result["issues"].append("No DNSKEY records found - DNSSEC not enabled")
    except dns.resolver.NXDOMAIN:
        result["validation_status"] = "bogus"
        result["issues"].append("Domain does not exist")
    except Exception as e:
        result["issues"].append(f"DNSSEC check failed: {str(e)}")

    return result

def _format_dnskey(record) -> dict:
    return {
        "flags": record.flags,
        "protocol": record.protocol,
        "algorithm": record.algorithm,
        "key": record.key.to_text(),
    }

def _format_ds(record) -> dict:
    return {
        "key_tag": record.key_tag,
        "algorithm": record.algorithm,
        "digest_type": record.digest_type,
        "digest": record.digest.hex(),
    }
```

---

## Task 1.3: Email Security Module

**New File:** `src/verification/email_security.py`

```python
"""
Email security configuration analysis.
Checks SPF, DKIM, and DMARC configurations.
"""

import dns.resolver
import re
from typing import Any

async def analyze_email_security(domain: str, resolvers: list[str]) -> dict:
    """
    Analyze email security posture for a domain.

    Returns:
        {
            "spf": {...},
            "dkim": {...},
            "dmarc": {...},
            "overall_score": int,
            "critical_issues": [...]
        }
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = resolvers

    spf = await _analyze_spf(domain, resolver)
    dmarc = await _analyze_dmarc(domain, resolver)

    # DKIM requires selectors - we can only check for common ones
    dkim = await _analyze_dkim_common(domain, resolver)

    overall_score = _calculate_email_score(spf, dmarc, dkim)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "overall_score": overall_score,
        "critical_issues": spf["issues"] + dmarc["issues"],
    }

async def _analyze_spf(domain: str, resolver) -> dict:
    """Analyze SPF record."""
    result = {"record": None, "valid": False, "issues": [], "score": 0}

    try:
        answers = resolver.resolve(domain, 'TXT')
        for r in answers:
            txt = b''.join(r.chunks).decode('utf-8')
            if txt.startswith('v=spf1'):
                result["record"] = txt
                result["valid"] = True

                # Parse and validate
                issues = _validate_spf(txt)
                result["issues"] = issues

                # Score: +10 for having SPF, -5 per issue
                result["score"] = 10 + (len(issues) * -5)

                # Bonus for strict policies
                if '-all' in txt or '~all' in txt:
                    result["score"] += 5
                if '?all' in txt:
                    result["score"] -= 5

                break
    except Exception as e:
        result["issues"].append(f"SPF lookup failed: {str(e)}")

    return result

def _validate_spf(record: str) -> list[str]:
    """Validate SPF record syntax and best practices."""
    issues = []

    # Check for +all (too permissive)
    if '+all' in record or 'all' in record and not any(x in record for x in ['-all', '~all', '?all']):
        issues.append("SPF record ends with '+all' or 'all' - accepts all mail sources")

    # Check lookups
    lookup_count = record.count('include:') + record.count('exists')
    if lookup_count > 10:
        issues.append(f"Too many DNS lookups ({lookup_count} > 10)")

    # Check for IP4/IP6 with CIDR
    if 'ip4:' not in record and 'ip6:' not in record and 'include:' not in record:
        issues.append("SPF record has no valid mechanisms")

    # Check for a or mx mechanisms
    if 'a:' not in record and 'mx:' not in record and 'include:' not in record:
        issues.append("SPF record may be missing authorized mail servers")

    return issues

async def _analyze_dmarc(domain: str, resolver) -> dict:
    """Analyze DMARC record."""
    result = {"record": None, "policy": None, "pct": 100, "rua": None, "ruf": None, "score": 0, "issues": []}

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for r in answers:
            txt = b''.join(r.chunks).decode('utf-8')
            if txt.startswith('v=DMARC1'):
                result["record"] = txt

                # Parse policy
                policy_match = re.search(r'p=(none|quarantine|reject)', txt)
                if policy_match:
                    result["policy"] = policy_match.group(1)

                # Parse percentage
                pct_match = re.search(r'pct=(\d+)', txt)
                if pct_match:
                    result["pct"] = int(pct_match.group(1))

                # Parse RUA
                rua_match = re.search(r'rua=([^;]+)', txt)
                if rua_match:
                    result["rua"] = rua_match.group(1).strip()

                # Parse RUF
                ruf_match = re.search(r'ruf=([^;]+)', txt)
                if ruf_match:
                    result["ruf"] = ruf_match.group(1).strip()

                # Score
                if result["policy"] == "reject":
                    result["score"] = 10
                elif result["policy"] == "quarantine":
                    result["score"] = 5
                else:
                    result["score"] = 0
                    result["issues"].append("DMARC policy is 'none' - not enforcing")

                if result["pct"] < 100:
                    result["issues"].append(f"DMARC pct is {result['pct']}% - not monitoring all mail")

                break
    except dns.resolver.NoAnswer:
        result["issues"].append("No DMARC record found")
    except Exception as e:
        result["issues"].append(f"DMARC lookup failed: {str(e)}")

    return result

async def _analyze_dkim_common(domain: str, resolver) -> dict:
    """Check for common DKIM selectors."""
    result = {"enabled": False, "selectors": [], "issues": []}

    common_selectors = ['default', 'google', 'selector1', 'k1', 'smtp']

    for selector in common_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, 'TXT')
            for r in answers:
                txt = b''.join(r.chunks).decode('utf-8')
                if txt.startswith('v=DKIM1'):
                    result["enabled"] = True
                    result["selectors"].append(selector)
                    break
        except: pass

    if not result["enabled"]:
        result["issues"].append("No DKIM records found for common selectors")

    return result

def _calculate_email_score(spf: dict, dmarc: dict, dkim: dict) -> int:
    """Calculate overall email security score (0-100)."""
    score = 0

    # SPF: 0-30 points
    score += min(spf.get("score", 0) * 3, 30)

    # DMARC: 0-40 points
    score += min(dmarc.get("score", 0) * 8, 40)

    # DKIM: 0-30 points
    if dkim.get("enabled"):
        score += 30

    return min(max(score, 0), 100)
```

---

## Task 1.4: Nameserver Security Module

**New File:** `src/verification/nameserver_security.py`

```python
"""
Nameserver security analysis.
Checks for AXFR exposure, open resolvers, version disclosure, etc.
"""

import dns.resolver
import dns.query
import dns.flags
import socket
from typing import Any

async def analyze_nameservers(domain: str, nameservers: list[str], resolvers: list[str]) -> dict:
    """
    Analyze nameserver security posture.

    Returns:
        {
            "axfr_exposed": [...],
            "open_resolver": [...],
            "version_info": {...},
            "amplification_attack_capable": [...],
            "edns_support": bool,
            "dnssec_support": bool,
            "any_query_allowed": bool,
            "inconsistent_responses": [...]
        }
    """
    result = {
        "axfr_exposed": [],
        "open_resolver": [],
        "version_info": {},
        "amplification_attack_capable": [],
        "edns_support": False,
        "dnssec_support": False,
        "any_query_allowed": False,
        "inconsistent_responses": [],
    }

    # Test each nameserver
    for ns in nameservers:
        # Resolve NS IP
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = resolvers
            ip_answers = resolver.resolve(ns, 'A')
            ips = [str(r) for r in ip_answers]

            for ip in ips:
                # Check AXFR
                if await _check_axfer(domain, ip):
                    result["axfr_exposed"].append(f"{ns} ({ip})")

                # Check version.bind
                version = await _check_dns_version(ip)
                if version:
                    result["version_info"][f"{ns} ({ip})"] = version

                # Check EDNS support
                if await _check_edns(ip):
                    result["edns_support"] = True

                # Check ANY query response
                if await _check_any_query(ip, domain):
                    result["any_query_allowed"] = True

        except Exception as e:
            result["inconsistent_responses"].append(f"{ns}: {str(e)}")

    return result

async def _check_axfer(domain: str, nameserver_ip: str) -> bool:
    """Check if zone transfer is allowed."""
    try:
        query = dns.query.xfr(nameserver_ip, domain, timeout=5)
        for _ in query:
            return True  # Got at least one record
    except:
        return False
    return False

async def _check_dns_version(nameserver_ip: str) -> str | None:
    """Check for DNS server version disclosure via VERSION.BIND."""
    try:
        query = dns.message.make_query('VERSION.BIND', 'TXT', 'CH')
        response = dns.query.udp(query, nameserver_ip, timeout=3)
        if response.answer:
            for r in response.answer:
                if r.rdtype == dns.rdatatype.TXT:
                    return b''.join(r.chunks).decode('utf-8')
    except:
        pass
    return None

async def _check_edns(nameserver_ip: str) -> bool:
    """Check EDNS support by sending EDNS-enabled query."""
    try:
        query = dns.message.make_query('test.com', 'A')
        query.use_edns(edns=0)
        response = dns.query.udp(query, nameserver_ip, timeout=3)
        return response.flags & dns.flags.DO != 0
    except:
        return False

async def _check_any_query(nameserver_ip: str, domain: str) -> bool:
    """Check if ANY queries return all records (amplification risk)."""
    try:
        query = dns.message.make_query(domain, 'ANY')
        response = dns.query.udp(query, nameserver_ip, timeout=3)
        return len(response.answer) > 10  # Arbitrary threshold
    except:
        return False
```

---

## Database Updates

**Update `subdomain_scans` table schema to include additional DNS data:**

Add JSON columns for:
- `dns_records: dict` - All DNS record types
- `dnssec_info: dict` - DNSSEC analysis results
- `email_security: dict` - SPF/DKIM/DMARC analysis
- `nameserver_security: dict` - Nameserver security findings

---

## Integration with Scheduler

**File:** `src/scheduler.py`

In the scan cycle, after DNS records enumeration:
```python
# Run advanced DNS analysis
dns_records = await enumerate_all_record_types(domain, resolvers)
dnssec = await analyze_dnssec(domain, resolvers)
email_sec = await analyze_email_security(domain, resolvers)
ns_sec = await analyze_nameservers(domain, nameservers, resolvers)

# Store results
db.update_subdomain_scan(dns_records=dns_records, dnssec_info=dnssec, ...)
```

---

## Testing Checklist

- [ ] MX records are enumerated correctly
- [ ] NS records are enumerated
- [ ] TXT records include SPF/DMARC
- [ ] DNSSEC analysis works
- [ ] Email security scoring is accurate
- [ ] AXFR detection works
- [ ] Version disclosure is detected
- [ ] Results are stored in database

---

**Status:** Ready to implement
**Estimated Time:** 4-6 hours
