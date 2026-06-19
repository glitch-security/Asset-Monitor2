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
