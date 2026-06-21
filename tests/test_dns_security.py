"""
Comprehensive test suite for DNS Security features (Sprint 1).

Tests:
  1. DNS security config options
  2. Database methods for DNS security data
  3. DNS security API endpoint
  4. DNS security change event generation
  5. End-to-end integration

Run: python tests/test_dns_security.py
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDNSSecurityConfig(unittest.TestCase):
    """Test DNS security configuration options."""

    def test_dnssec_check_exists(self):
        """DNSSEC check config option exists."""
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertTrue(hasattr(cfg.verification, 'dnssec_check'))
        self.assertTrue(cfg.verification.dnssec_check)

    def test_email_security_check_exists(self):
        """Email security check config option exists."""
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertTrue(hasattr(cfg.verification, 'email_security_check'))
        self.assertTrue(cfg.verification.email_security_check)

    def test_nameserver_security_check_exists(self):
        """Nameserver security check config option exists."""
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertTrue(hasattr(cfg.verification, 'nameserver_security_check'))
        self.assertTrue(cfg.verification.nameserver_security_check)

    def test_config_can_disable_dnssec(self):
        """Can disable DNSSEC via config."""
        from src.config import AppConfig
        cfg = AppConfig(**{'verification': {'dnssec_check': False}})
        self.assertFalse(cfg.verification.dnssec_check)


class TestDNSSecurityDatabase(unittest.TestCase):
    """Test database methods for DNS security data."""

    @classmethod
    def setUpClass(cls):
        cls.db_path = os.path.join(tempfile.gettempdir(), 'test_dns_security.db')
        # Remove stale DB
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                os.unlink(p)

    def setUp(self):
        from src.database import DatabaseManager
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        self.db._engine.dispose()

    @classmethod
    def tearDownClass(cls):
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def test_get_latest_subdomain_scan_exists(self):
        """Method exists and returns None for new subdomain."""
        dom = self.db.add_domain('test.example.com')
        sub, _ = self.db.upsert_subdomain('www.test.example.com', dom.id, discovery_technique='test')

        latest = self.db.get_latest_subdomain_scan(sub.id)
        self.assertIsNone(latest)

    def test_add_scan_record_with_dnssec(self):
        """Can add scan record with DNSSEC data."""
        dom = self.db.add_domain('dnssec.example.com')
        sub, _ = self.db.upsert_subdomain('www.dnssec.example.com', dom.id, discovery_technique='test')

        scan = self.db.add_scan_record(
            sub.id,
            http_status=200,
            dnssec_info={'dnssec_enabled': True, 'validation_status': 'secure'},
            email_security={'spf': {'record': 'v=spf1 -all'}},
            nameserver_security={'dnssec_validated': True}
        )

        self.assertIsNotNone(scan)
        self.assertEqual(scan.http_status, 200)

    def test_get_latest_scan_returns_dnssec_data(self):
        """Latest scan retrieval includes DNS security data."""
        dom = self.db.add_domain('latest.example.com')
        sub, _ = self.db.upsert_subdomain('www.latest.example.com', dom.id, discovery_technique='test')

        # Add first scan
        self.db.add_scan_record(
            sub.id,
            http_status=200,
            dnssec_info={'dnssec_enabled': False},
        )

        # Add second scan with different data
        self.db.add_scan_record(
            sub.id,
            http_status=200,
            dnssec_info={'dnssec_enabled': True, 'validation_status': 'secure'},
            email_security={'spf': {'record': 'v=spf1 -all'}, 'dmarc': {'record': 'v=DMARC1;p=reject'}},
            nameserver_security={'dnssec_validated': True, 'issues': []}
        )

        latest = self.db.get_latest_subdomain_scan(sub.id)
        self.assertIsNotNone(latest)
        self.assertTrue(latest.dnssec_info.get('dnssec_enabled'))
        self.assertIsNotNone(latest.email_security)
        self.assertIsNotNone(latest.nameserver_security)


class TestDNSSecurityAPI(unittest.TestCase):
    """Test DNS security API endpoints."""

    @classmethod
    def setUpClass(cls):
        from src.config import AppConfig
        from src.database import DatabaseManager
        from src.web.server import build_app

        cls.db_path = os.path.join(tempfile.gettempdir(), 'test_dns_api.db')
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

        cls.cfg = AppConfig()
        cls.db = DatabaseManager(cls.db_path)

        # Create admin user
        import bcrypt
        pw_hash = "bcrypt:" + bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode()
        cls.db.set_user("testadmin", pw_hash, "admin")

        cls.app = build_app(cls.db, cls.cfg, sched_manager=None)

        # Setup test data
        dom = cls.db.add_domain('apitest.example.com')
        cls.domain_id = dom.id
        sub, _ = cls.db.upsert_subdomain('www.apitest.example.com', dom.id, discovery_technique='test')
        sub2, _ = cls.db.upsert_subdomain('mail.apitest.example.com', dom.id, discovery_technique='test')

        # Add scan with DNS security data
        cls.db.add_scan_record(
            sub.id,
            http_status=200,
            dnssec_info={'dnssec_enabled': True, 'validation_status': 'secure'},
            email_security={'spf': {'record': 'v=spf1 -all'}, 'dmarc': {'record': 'v=DMARC1;p=reject'}},
            nameserver_security={'dnssec_validated': True, 'issues': []}
        )

        # Add scan for second subdomain without DNSSEC
        cls.db.add_scan_record(
            sub2.id,
            http_status=200,
            dnssec_info={'dnssec_enabled': False},
            email_security={'spf': None, 'dmarc': None},
            nameserver_security={'dnssec_validated': False, 'issues': ['No DNSSEC']}
        )

    @classmethod
    def tearDownClass(cls):
        cls.db._engine.dispose()
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def test_dns_security_endpoint_requires_auth(self):
        """DNS security endpoint requires authentication."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                r = await client.get(f"/api/domains/{self.domain_id}/dns-security")
                self.assertIn(r.status_code, [401, 302])

        asyncio.run(_test())

    def test_dns_security_endpoint_returns_data(self):
        """DNS security endpoint returns structured data."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Login
                await client.post("/login", json={"username": "testadmin", "password": "testpass"})

                r = await client.get(f"/api/domains/{self.domain_id}/dns-security")
                self.assertEqual(r.status_code, 200)
                data = r.json()
                self.assertIsInstance(data, list)
                self.assertEqual(len(data), 2)  # Two subdomains

                # Check first subdomain has DNSSEC enabled
                www = [d for d in data if d['fqdn'] == 'www.apitest.example.com'][0]
                self.assertTrue(www['dnssec_info']['dnssec_enabled'])
                self.assertIsNotNone(www['email_security']['spf'])
                self.assertTrue(www['nameserver_security']['dnssec_validated'])

                # Check second subdomain has DNSSEC disabled
                mail = [d for d in data if d['fqdn'] == 'mail.apitest.example.com'][0]
                self.assertFalse(mail['dnssec_info']['dnssec_enabled'])

        asyncio.run(_test())

    def test_dns_security_endpoint_invalid_domain(self):
        """Returns empty list for domain with no subdomains."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Login
                await client.post("/login", json={"username": "testadmin", "password": "testpass"})

                r = await client.get("/api/domains/99999/dns-security")
                self.assertEqual(r.status_code, 200)
                data = r.json()
                self.assertEqual(data, [])  # Empty list for non-existent domain

        asyncio.run(_test())


class TestSubdomainScanColumnMigration(unittest.TestCase):
    """Regression test: databases created before the DNS-security columns
    (dns_records, dnssec_info, email_security, nameserver_security) existed
    on subdomain_scans had no migration adding them, so every verify_batch()
    call against such a DB raised 'no such column: subdomain_scans.dns_records'
    and silently aborted — meaning NO subdomains were ever persisted for that
    domain again, even though enumeration kept finding them."""

    def test_migration_adds_missing_columns_to_old_db(self):
        import sqlite3
        from src.database import DatabaseManager

        db_path = os.path.join(tempfile.gettempdir(), 'test_old_schema_migration.db')
        for ext in ('', '-shm', '-wal'):
            p = db_path + ext
            if os.path.exists(p):
                os.remove(p)

        # Build a minimal pre-Sprint-1 schema: subdomain_scans WITHOUT the
        # four DNS-security columns, simulating a database created before
        # they were added to the SubdomainScan model.
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fqdn TEXT NOT NULL UNIQUE,
                domain_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown'
            )
        """)
        conn.execute("""
            CREATE TABLE subdomain_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown',
                http_status INTEGER,
                response_size INTEGER,
                body_hash TEXT,
                technologies TEXT,
                raw_headers TEXT
            )
        """)
        conn.commit()
        conn.close()

        db = None
        try:
            # Opening the DB must run the migration and add the missing columns
            # rather than crash or silently skip them.
            db = DatabaseManager(db_path)

            conn2 = sqlite3.connect(db_path)
            cols = {row[1] for row in conn2.execute("PRAGMA table_info(subdomain_scans)")}
            conn2.close()
            for expected in ("dns_records", "dnssec_info", "email_security", "nameserver_security"):
                self.assertIn(expected, cols)

            # The exact query shape that previously raised OperationalError.
            from sqlalchemy import select
            from src.database import SubdomainScan
            with db.get_session() as session:
                list(session.scalars(select(SubdomainScan)).all())
        finally:
            if db is not None:
                db._engine.dispose()
            for ext in ('', '-shm', '-wal'):
                p = db_path + ext
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass


class TestDNSSecurityChangeEvents(unittest.TestCase):
    """Test DNS security change event generation."""

    def test_dnssec_enabled_event(self):
        """DNSSEC_ENABLED event generated when DNSSEC turns on."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'dnssec_info': {'dnssec_enabled': False}}
            new_data = {'dnssec_info': {'dnssec_enabled': True}}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            dnssec_events = [e for e in events if e['event_type'] == 'DNSSEC_ENABLED']
            self.assertEqual(len(dnssec_events), 1)
            self.assertEqual(dnssec_events[0]['severity'], 'INFO')

        asyncio.run(_test())

    def test_dnssec_disabled_event(self):
        """DNSSEC_DISABLED event generated when DNSSEC turns off."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'dnssec_info': {'dnssec_enabled': True}}
            new_data = {'dnssec_info': {'dnssec_enabled': False}}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            dnssec_events = [e for e in events if e['event_type'] == 'DNSSEC_DISABLED']
            self.assertEqual(len(dnssec_events), 1)
            self.assertEqual(dnssec_events[0]['severity'], 'WARNING')

        asyncio.run(_test())

    def test_spf_configured_event(self):
        """SPF_CONFIGURED event generated when SPF record appears."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'email_security': {'spf': {'record': None}}}
            new_data = {'email_security': {'spf': {'record': 'v=spf1 -all'}}}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            spf_events = [e for e in events if e['event_type'] == 'SPF_CONFIGURED']
            self.assertEqual(len(spf_events), 1)

        asyncio.run(_test())

    def test_dmarc_configured_event(self):
        """DMARC_CONFIGURED event generated when DMARC record appears."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'email_security': {'dmarc': {'record': None}}}
            new_data = {'email_security': {'dmarc': {'record': 'v=DMARC1;p=reject'}}}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            dmarc_events = [e for e in events if e['event_type'] == 'DMARC_CONFIGURED']
            self.assertEqual(len(dmarc_events), 1)

        asyncio.run(_test())

    def test_ns_security_issue_event(self):
        """NS_SECURITY_ISSUE_DETECTED event generated for new NS issues."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'nameserver_security': {'issues': []}}
            new_data = {'nameserver_security': {'issues': ['Open resolver detected']}}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            ns_events = [e for e in events if e['event_type'] == 'NS_SECURITY_ISSUE_DETECTED']
            self.assertEqual(len(ns_events), 1)
            self.assertEqual(ns_events[0]['severity'], 'MEDIUM')

        asyncio.run(_test())

    def test_no_event_when_no_change(self):
        """No DNS security events when data unchanged."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            dnssec = {'dnssec_enabled': True}
            email = {'spf': {'record': 'v=spf1 -all'}, 'dmarc': {'record': 'v=DMARC1;p=reject'}}
            ns = {'dnssec_validated': True, 'issues': []}

            old_data = {'dnssec_info': dnssec, 'email_security': email, 'nameserver_security': ns}
            new_data = {'dnssec_info': dnssec, 'email_security': email, 'nameserver_security': ns}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            dns_events = [e for e in events if 'DNSSEC' in e['event_type'] or 'SPF' in e['event_type'] or 'DMARC' in e['event_type'] or 'NS_SECURITY' in e['event_type']]
            self.assertEqual(len(dns_events), 0)

        asyncio.run(_test())

    def test_tech_diff_with_dict_shaped_technologies(self):
        """Regression: technologies are stored as list[dict] ({name, version}), which are
        unhashable — generate_change_events must not raise TypeError('unhashable type: dict')
        when diffing them (previously used a raw set() diff that crashed in production)."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'live': True, 'technologies': [{'name': 'nginx', 'version': '1.18'}]}
            new_data = {
                'live': True,
                'technologies': [
                    {'name': 'nginx', 'version': '1.18'},
                    {'name': 'WordPress', 'version': '6.4'},
                ],
            }

            events = await vm.generate_change_events('test.com', old_data, new_data)
            added = [e for e in events if e['event_type'] == 'TECH_ADDED']
            self.assertEqual(len(added), 1)
            self.assertEqual(added[0]['diff_data']['technologies'], [{'name': 'WordPress', 'version': '6.4'}])

        asyncio.run(_test())

    def test_tech_diff_with_legacy_string_technologies(self):
        """diff_technologies also accepts the legacy list[str] format without crashing."""
        import asyncio
        from src.verification.manager import VerificationManager
        from src.config import AppConfig

        cfg = AppConfig()
        vm = VerificationManager(cfg, None)

        async def _test():
            old_data = {'live': True, 'technologies': ['nginx']}
            new_data = {'live': True, 'technologies': []}

            events = await vm.generate_change_events('test.com', old_data, new_data)
            removed = [e for e in events if e['event_type'] == 'TECH_REMOVED']
            self.assertEqual(len(removed), 1)

        asyncio.run(_test())


class TestVerificationPersist(unittest.TestCase):
    """Regression test for the _persist method being misplaced outside the
    VerificationManager class (it ended up nested inside a module-level helper
    function, so self._persist(result) raised AttributeError on every single
    verification — silently preventing ALL subdomains from ever being saved)."""

    def test_persist_is_a_bound_method(self):
        from src.verification.manager import VerificationManager

        self.assertTrue(hasattr(VerificationManager, '_persist'))
        self.assertTrue(callable(getattr(VerificationManager, '_persist')))

    def test_persist_writes_to_database(self):
        """_persist must actually be callable as self._persist(...) and upsert the subdomain."""
        import asyncio
        import os
        import tempfile
        from src.config import AppConfig
        from src.database import DatabaseManager
        from src.verification.manager import VerificationManager

        db_path = os.path.join(tempfile.gettempdir(), 'test_persist_regression.db')
        for ext in ('', '-shm', '-wal'):
            p = db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

        db = DatabaseManager(db_path)
        try:
            domain = db.add_domain('persist-test.example.com')
            cfg = AppConfig()
            vm = VerificationManager(cfg, db)

            async def _test():
                result = {
                    "fqdn": "sub.persist-test.example.com",
                    "domain_id": domain.id,
                    "live": True,
                    "dns_resolved": True,
                    "discovery_technique": "manual",
                    "a_records": ["1.2.3.4"],
                    "aaaa_records": [],
                    "technologies": [{"name": "nginx", "version": "1.18"}],
                    "status_code": 200,
                    "page_title": "Test",
                    "classification": None,
                    "favicon_hash": None,
                    "body_hash": "abc123",
                    "cert_fingerprint": None,
                    "takeover": None,
                }
                await vm._persist(result)

            asyncio.run(_test())

            sub = db.get_subdomain("sub.persist-test.example.com")
            self.assertIsNotNone(sub)
            self.assertEqual(sub.status, "alive")
        finally:
            db._engine.dispose()
            for ext in ('', '-shm', '-wal'):
                p = db_path + ext
                if os.path.exists(p):
                    try:
                        os.unlink(p)
                    except Exception:
                        pass


class TestDNSSecurityDashboard(unittest.TestCase):
    """Test DNS security dashboard visibility."""

    @classmethod
    def setUpClass(cls):
        from src.config import AppConfig
        from src.database import DatabaseManager
        from src.web.server import build_app

        cls.db_path = os.path.join(tempfile.gettempdir(), 'test_dns_dashboard.db')
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

        cls.cfg = AppConfig()
        cls.db = DatabaseManager(cls.db_path)

        import bcrypt
        pw_hash = "bcrypt:" + bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode()
        cls.db.set_user("testadmin", pw_hash, "admin")

        cls.app = build_app(cls.db, cls.cfg, sched_manager=None)

    @classmethod
    def tearDownClass(cls):
        cls.db._engine.dispose()
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def test_dashboard_html_has_dns_security_tab(self):
        """Dashboard HTML includes DNS Security tab."""
        with open('src/web/templates/dashboard.html', 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('dd-dnssec', content)
            self.assertIn('DNS Security', content)

    def test_dashboard_html_has_load_dnssec_function(self):
        """Dashboard has DNS security data loading function."""
        with open('src/web/templates/dashboard.html', 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('loadDnsSecurityData', content)
            self.assertIn('/api/domains/', content)
            self.assertIn('/dns-security', content)

    def test_dashboard_renders_with_dnssec_columns(self):
        """DNS security table has expected columns."""
        with open('src/web/templates/dashboard.html', 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('DNSSEC', content)
            self.assertIn('Email Security', content)
            self.assertIn('Nameserver Security', content)


if __name__ == '__main__':
    unittest.main(verbosity=2)
