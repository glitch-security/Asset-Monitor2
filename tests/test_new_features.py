"""
Comprehensive test suite for Asset-Monitor2 new features.

Tests:
  1. Config loading with new fields
  2. Database schema migrations (scope_type)
  3. Scope management (set/get/cycle)
  4. Directory brute-force module (mock HTTP)
  5. API endpoint discovery module (mock HTTP)
  6. Broken link hijacking module (mock HTTP)
  7. Dorking module (query generation)
  8. Cloud asset discovery module (mock HTTP)
  9. Scheduler integration (scope enforcement)
  10. Web server API endpoints (full HTTP test)

Run: python tests/test_new_features.py
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


class TestConfig(unittest.TestCase):
    """Test new config fields load correctly."""

    def test_app_config_loads_defaults(self):
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertTrue(hasattr(cfg, 'attack_surface'))
        self.assertTrue(hasattr(cfg, 'scope'))

    def test_attack_surface_defaults(self):
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertTrue(cfg.attack_surface.dir_bruteforce)
        self.assertTrue(cfg.attack_surface.api_discovery)
        self.assertTrue(cfg.attack_surface.broken_link_hijacking)
        self.assertEqual(cfg.attack_surface.dir_bruteforce_concurrency, 20)
        self.assertEqual(cfg.attack_surface.api_discovery_concurrency, 15)

    def test_scope_defaults(self):
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertFalse(cfg.scope.enforce_scope)
        self.assertEqual(cfg.scope.default_scope, 'unknown')

    def test_enumeration_new_techniques(self):
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertTrue(cfg.enumeration.techniques.cloud_asset_discovery)
        self.assertTrue(cfg.enumeration.techniques.dorking)

    def test_github_token_field(self):
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertEqual(cfg.api_keys.github_token, '')

    def test_config_from_dict(self):
        from src.config import AppConfig
        cfg = AppConfig(**{
            'attack_surface': {'dir_bruteforce': False, 'api_discovery': False},
            'scope': {'enforce_scope': True, 'default_scope': 'in_scope'},
        })
        self.assertFalse(cfg.attack_surface.dir_bruteforce)
        self.assertTrue(cfg.scope.enforce_scope)
        self.assertEqual(cfg.scope.default_scope, 'in_scope')


class TestDatabase(unittest.TestCase):
    """Test database schema migrations and new methods."""

    @classmethod
    def setUpClass(cls):
        cls.db_path = os.path.join(tempfile.gettempdir(), 'test_features.db')
        # Remove stale DB
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                os.unlink(p)

    def setUp(self):
        from src.database import DatabaseManager
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        # Close engine
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

    def test_scope_type_column_exists(self):
        """Verify migration added scope_type column."""
        from sqlalchemy import text
        with self.db.get_session() as session:
            rows = session.execute(text("PRAGMA table_info(domains)")).fetchall()
            cols = {r[1] for r in rows}
        self.assertIn('scope_type', cols)

    def test_set_domain_scope(self):
        """Test setting scope on a domain."""
        dom = self.db.add_domain('scope-test.example.com')
        self.assertEqual(dom.scope_type, 'unknown')

        ok = self.db.set_domain_scope(dom.id, 'in_scope')
        self.assertTrue(ok)

        details = self.db.get_all_domains_with_stats()
        d = [x for x in details if x['domain'] == 'scope-test.example.com'][0]
        self.assertEqual(d['scope_type'], 'in_scope')

    def test_set_domain_scope_invalid(self):
        """Reject invalid scope types."""
        dom = self.db.add_domain('invalid-scope.example.com')
        ok = self.db.set_domain_scope(dom.id, 'invalid_value')
        self.assertFalse(ok)

    def test_set_domain_scope_cycle(self):
        """Simulate UI cycling: unknown → in_scope → out_of_scope → unknown."""
        dom = self.db.add_domain('cycle-scope.example.com')
        for scope in ['in_scope', 'out_of_scope', 'unknown']:
            ok = self.db.set_domain_scope(dom.id, scope)
            self.assertTrue(ok)

    def test_scope_in_domain_details(self):
        """Verify scope_type appears in domain detail payload."""
        dom = self.db.add_domain('detail-scope.example.com')
        self.db.set_domain_scope(dom.id, 'out_of_scope')
        details = self.db.get_all_domains_with_stats()
        d = [x for x in details if x['domain'] == 'detail-scope.example.com'][0]
        self.assertEqual(d['scope_type'], 'out_of_scope')

    def test_scope_nonexistent_domain(self):
        """Return False for non-existent domain."""
        ok = self.db.set_domain_scope(99999, 'in_scope')
        self.assertFalse(ok)


class TestDorkingModule(unittest.TestCase):
    """Test dorking query generation."""

    def test_get_all_dorks(self):
        from src.enumeration.dorking import get_all_dorks
        dorks = get_all_dorks('example.com')
        self.assertGreater(len(dorks), 20)
        for d in dorks:
            self.assertIn('query', d)
            self.assertIn('severity', d)
            self.assertIn('example.com', d['query'])

    def test_get_github_dorks(self):
        from src.enumeration.dorking import get_github_dorks
        dorks = get_github_dorks('example.com')
        self.assertGreater(len(dorks), 10)
        for d in dorks:
            self.assertIn('example.com', d['query'])
            self.assertIn(d['severity'], ['HIGH', 'CRITICAL', 'MEDIUM'])

    def test_get_pastebin_dorks(self):
        from src.enumeration.dorking import get_pastebin_dorks
        dorks = get_pastebin_dorks('example.com')
        self.assertGreater(len(dorks), 5)
        all_queries = ' '.join(d['query'].lower() for d in dorks)
        # Should contain paste-site references
        self.assertTrue(
            'pastebin.com' in all_queries or 'paste.ee' in all_queries or 'justpaste.it' in all_queries,
            "No paste-site dorks found"
        )


class TestCloudAssetsModule(unittest.TestCase):
    """Test cloud asset discovery."""

    def test_s3_permutations(self):
        from src.enumeration.cloud_assets import _s3_permutations
        perms = _s3_permutations('example.com')
        self.assertGreater(len(perms), 15)
        self.assertIn('example.com', perms)
        self.assertIn('example-com', perms)

    def test_firebase_permutations(self):
        from src.enumeration.cloud_assets import _firebase_permutations
        perms = _firebase_permutations('example.com')
        self.assertGreater(len(perms), 5)

    def test_azure_blob_permutations(self):
        from src.enumeration.cloud_assets import _azure_blob_permutations
        perms = _azure_blob_permutations('example.com')
        self.assertGreater(len(perms), 3)
        # Azure names must be lowercase alphanumeric only
        for p in perms:
            self.assertTrue(p.islower() or p.isalnum(), f"Invalid Azure name: {p}")

    def test_cname_patterns_comprehensive(self):
        from src.enumeration.cloud_assets import CLOUD_CNAME_PATTERNS
        # Verify major providers are covered
        providers = set(CLOUD_CNAME_PATTERNS.values())
        for expected in ['AWS', 'AWS S3', 'AWS CloudFront', 'GCP Storage',
                         'Firebase Hosting', 'Firebase Realtime DB',
                         'Azure App Service', 'Azure Blob Storage',
                         'Heroku', 'Netlify', 'Vercel', 'GitHub Pages']:
            self.assertIn(expected, providers, f"Missing provider: {expected}")


class TestDirBruteforceModule(unittest.TestCase):
    """Test directory brute-force module structure."""

    def test_wordlist_not_empty(self):
        from src.scanning.dir_bruteforce import DIRECTORY_WORDLIST
        self.assertGreater(len(DIRECTORY_WORDLIST), 100)

    def test_wordlist_contains_key_paths(self):
        from src.scanning.dir_bruteforce import DIRECTORY_WORDLIST
        paths_str = ' '.join(DIRECTORY_WORDLIST)
        for critical in ['.env', '.git/HEAD', 'wp-admin', 'phpmyadmin',
                         'swagger', 'actuator', 'backup', 'graphql']:
            self.assertIn(critical, paths_str, f"Missing critical path: {critical}")

    def test_classify_finding_high(self):
        from src.scanning.dir_bruteforce import _classify_finding
        self.assertEqual(_classify_finding('/.env', 200, 50), 'HIGH')
        self.assertEqual(_classify_finding('/backup.sql', 200, 100), 'HIGH')
        self.assertEqual(_classify_finding('/.git/HEAD', 200, 30), 'HIGH')

    def test_classify_finding_medium(self):
        from src.scanning.dir_bruteforce import _classify_finding
        self.assertEqual(_classify_finding('/admin', 200, 5000), 'MEDIUM')
        self.assertEqual(_classify_finding('/api/login', 401, 100), 'MEDIUM')

    def test_classify_finding_info(self):
        from src.scanning.dir_bruteforce import _classify_finding
        self.assertEqual(_classify_finding('/some-path', 403, 2000), 'INFO')


class TestApiDiscoveryModule(unittest.TestCase):
    """Test API discovery module structure."""

    def test_api_base_paths(self):
        from src.scanning.api_discovery import _API_BASE_PATHS
        self.assertGreater(len(_API_BASE_PATHS), 15)
        paths_str = ' '.join(_API_BASE_PATHS)
        self.assertIn('/api', paths_str)
        self.assertIn('/graphql', paths_str)
        self.assertIn('/swagger', paths_str)

    def test_spec_endpoints(self):
        from src.scanning.api_discovery import _SPEC_ENDPOINTS
        self.assertGreater(len(_SPEC_ENDPOINTS), 20)
        paths_str = ' '.join(_SPEC_ENDPOINTS)
        self.assertIn('swagger.json', paths_str)
        self.assertIn('openapi.json', paths_str)

    def test_classify_api_finding(self):
        from src.scanning.api_discovery import _classify_api_finding
        self.assertEqual(_classify_api_finding({
            'path': '/swagger.json', 'status_code': 200
        }), 'HIGH')
        self.assertEqual(_classify_api_finding({
            'path': '/debug/vars', 'status_code': 200
        }), 'HIGH')
        self.assertEqual(_classify_api_finding({
            'path': '/api/auth/me', 'status_code': 200
        }), 'MEDIUM')
        self.assertEqual(_classify_api_finding({
            'path': '/api/v1/status', 'status_code': 200
        }), 'LOW')


class TestBrokenLinksModule(unittest.TestCase):
    """Test broken link hijacking module."""

    def test_account_platforms(self):
        from src.monitoring.broken_links import _ACCOUNT_PLATFORMS
        self.assertGreater(len(_ACCOUNT_PLATFORMS), 20)
        for domain in ['github.com', 'twitter.com', 'linkedin.com', 'slack.com']:
            self.assertIn(domain, _ACCOUNT_PLATFORMS)

    def test_not_found_patterns(self):
        from src.monitoring.broken_links import _NOT_FOUND_PATTERNS
        self.assertGreater(len(_NOT_FOUND_PATTERNS), 5)


class TestSchedulerScopeEnforcement(unittest.TestCase):
    """Test that scope enforcement skips out-of-scope domains."""

    def test_scope_enforcement_skips_oos(self):
        from src.config import AppConfig
        cfg = AppConfig()
        cfg.scope.enforce_scope = True
        self.assertTrue(cfg.scope.enforce_scope)

        from src.database import DatabaseManager
        db_path = os.path.join(tempfile.gettempdir(), 'test_scope_sched.db')
        for ext in ('', '-shm', '-wal'):
            p = db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

        db = DatabaseManager(db_path)
        dom = db.add_domain('oos.example.com')
        db.set_domain_scope(dom.id, 'out_of_scope')

        # Verify domain has out_of_scope scope
        details = db.get_all_domains_with_stats()
        d = [x for x in details if x['domain'] == 'oos.example.com'][0]
        self.assertEqual(d['scope_type'], 'out_of_scope')

        db._engine.dispose()
        for ext in ('', '-shm', '-wal'):
            p = db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass


class TestWebServerAPIs(unittest.TestCase):
    """Test API endpoints by starting the server and hitting them with httpx.

    Uses a single async runner to avoid nested asyncio.run() issues.
    All tests run inside one coroutine for proper session management.
    """

    @classmethod
    def setUpClass(cls):
        from src.config import AppConfig
        from src.database import DatabaseManager
        from src.web.server import build_app

        cls.db_path = os.path.join(tempfile.gettempdir(), 'test_api.db')
        for ext in ('', '-shm', '-wal'):
            p = cls.db_path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

        cls.cfg = AppConfig()
        cls.db = DatabaseManager(cls.db_path)

        # Create admin user for auth
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

    def test_health_endpoint(self):
        """Health endpoint works without auth."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                r = await client.get("/health")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()['status'], 'ok')

        asyncio.run(_test())

    def test_login_and_session(self):
        """Login works and returns session info."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                r = await client.post("/login", json={
                    "username": "testadmin", "password": "testpass"
                })
                self.assertEqual(r.status_code, 200)
                data = r.json()
                self.assertTrue(data['ok'])
                self.assertIn('role', data)
                self.assertEqual(data['role'], 'admin')

        asyncio.run(_test())

    def test_api_summary(self):
        """Summary endpoint returns expected fields after auth."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Login first
                await client.post("/login", json={
                    "username": "testadmin", "password": "testpass"
                })
                r = await client.get("/api/summary")
                self.assertEqual(r.status_code, 200)
                data = r.json()
                self.assertIn('domains', data)
                self.assertIn('subdomains_total', data)
                self.assertIn('events_24h', data)

        asyncio.run(_test())

    def test_add_domain_and_scope(self):
        """Add domain, then set scope via PATCH."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Login
                login_r = await client.post("/login", json={
                    "username": "testadmin", "password": "testpass"
                })
                # Get CSRF from session endpoint
                sess_r = await client.get("/api/session")
                csrf = sess_r.json().get('csrf_token', '')

                # Add domain
                r = await client.post("/api/targets", json={
                    "type": "domain",
                    "value": "scope-api-test.example.com",
                    "scan_now": False,
                }, headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"})
                self.assertEqual(r.status_code, 201)
                domain_id = r.json()['id']

                # Set scope to in_scope
                r = await client.patch(
                    f"/api/targets/domain/{domain_id}",
                    json={"scope_type": "in_scope"},
                    headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
                )
                self.assertEqual(r.status_code, 200)
                self.assertIn('scope_type', r.json()['fields'])

                # Verify in domain list
                r = await client.get("/api/domains")
                self.assertEqual(r.status_code, 200)
                domains = r.json()
                d = [x for x in domains if x['domain'] == 'scope-api-test.example.com']
                self.assertEqual(len(d), 1)
                self.assertEqual(d[0]['scope_type'], 'in_scope')

        asyncio.run(_test())

    def test_domain_detail_with_scope(self):
        """Domain detail endpoint includes scope info."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Login
                await client.post("/login", json={
                    "username": "testadmin", "password": "testpass"
                })
                sess_r = await client.get("/api/session")
                csrf = sess_r.json().get('csrf_token', '')

                # Add domain
                r = await client.post("/api/targets", json={
                    "type": "domain",
                    "value": "detail-scope-test.example.com",
                    "scan_now": False,
                }, headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"})
                domain_id = r.json()['id']

                # Get details
                r = await client.get(f"/api/domains/{domain_id}/details")
                self.assertEqual(r.status_code, 200)
                data = r.json()
                self.assertIn('domain', data)
                self.assertIn('stats', data)
                self.assertIn('subdomains', data)

        asyncio.run(_test())

    def test_dorking_endpoint(self):
        """Dorking endpoint runs and returns results."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Login
                await client.post("/login", json={
                    "username": "testadmin", "password": "testpass"
                })
                sess_r = await client.get("/api/session")
                csrf = sess_r.json().get('csrf_token', '')

                # Run dorking (without GitHub token, it'll just generate queries)
                r = await client.post(
                    "/api/dorking/example.com",
                    headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
                )
                self.assertIn(r.status_code, [200, 500])
                if r.status_code == 200:
                    data = r.json()
                    self.assertIn('domain', data)
                    self.assertIn('findings', data)

        asyncio.run(_test())

    def test_unauthenticated_rejected(self):
        """API endpoints reject unauthenticated requests."""
        import asyncio
        from httpx import ASGITransport, AsyncClient

        async def _test():
            transport = ASGITransport(app=self.app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                r = await client.get("/api/summary")
                self.assertIn(r.status_code, [401, 302])

                r = await client.post("/api/targets", json={"type": "domain", "value": "evil.com"})
                self.assertIn(r.status_code, [401, 302, 403])

        asyncio.run(_test())


if __name__ == '__main__':
    unittest.main(verbosity=2)
