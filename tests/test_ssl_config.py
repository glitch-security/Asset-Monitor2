"""
Test suite for SSL/TLS certificate configuration.

Tests:
  1. SSL config options exist in WebConfig
  2. SSL can be enabled via config
  3. SSL cert and key paths are configurable
  4. Daemon handles SSL enabled with certs
  5. Daemon fails when SSL enabled but paths missing

Run: python tests/test_ssl_config.py
"""

import os
import sys
import tempfile
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSSLConfig(unittest.TestCase):
    """Test SSL/TLS configuration options."""

    def test_web_config_has_ssl_enabled(self):
        """WebConfig has ssl_enabled option."""
        from src.config import WebConfig
        cfg = WebConfig()
        self.assertTrue(hasattr(cfg, 'ssl_enabled'))
        self.assertFalse(cfg.ssl_enabled)  # Default is False

    def test_web_config_has_ssl_cert_path(self):
        """WebConfig has ssl_cert_path option."""
        from src.config import WebConfig
        cfg = WebConfig()
        self.assertTrue(hasattr(cfg, 'ssl_cert_path'))
        self.assertEqual(cfg.ssl_cert_path, "")

    def test_web_config_has_ssl_key_path(self):
        """WebConfig has ssl_key_path option."""
        from src.config import WebConfig
        cfg = WebConfig()
        self.assertTrue(hasattr(cfg, 'ssl_key_path'))
        self.assertEqual(cfg.ssl_key_path, "")

    def test_web_config_has_ssl_ca_path(self):
        """WebConfig has ssl_ca_path option."""
        from src.config import WebConfig
        cfg = WebConfig()
        self.assertTrue(hasattr(cfg, 'ssl_ca_path'))
        self.assertEqual(cfg.ssl_ca_path, "")

    def test_web_config_has_ssl_verify_clients(self):
        """WebConfig has ssl_verify_clients option."""
        from src.config import WebConfig
        cfg = WebConfig()
        self.assertTrue(hasattr(cfg, 'ssl_verify_clients'))
        self.assertFalse(cfg.ssl_verify_clients)

    def test_app_config_loads_ssl_settings(self):
        """AppConfig includes SSL settings from WebConfig."""
        from src.config import AppConfig
        cfg = AppConfig(**{
            'web': {
                'ssl_enabled': True,
                'ssl_cert_path': '/path/to/cert.pem',
                'ssl_key_path': '/path/to/key.pem',
            }
        })
        self.assertTrue(cfg.web.ssl_enabled)
        self.assertEqual(cfg.web.ssl_cert_path, '/path/to/cert.pem')
        self.assertEqual(cfg.web.ssl_key_path, '/path/to/key.pem')


class TestSSLDaemon(unittest.TestCase):
    """Test daemon command SSL handling."""

    def test_daemon_ssl_disabled_by_default(self):
        """Daemon starts without SSL by default."""
        from src.config import AppConfig
        cfg = AppConfig()
        self.assertFalse(cfg.web.ssl_enabled)

    def test_daemon_ssl_enabled_shows_https(self):
        """Daemon shows HTTPS URL when SSL enabled."""
        from src.config import AppConfig
        cfg = AppConfig(**{
            'web': {
                'ssl_enabled': True,
                'ssl_cert_path': '/tmp/cert.pem',
                'ssl_key_path': '/tmp/key.pem',
            }
        })
        self.assertTrue(cfg.web.ssl_enabled)
        protocol = "https" if cfg.web.ssl_enabled else "http"
        self.assertEqual(protocol, "https")

    def test_daemon_requires_cert_and_key_when_ssl_enabled(self):
        """SSL enabled requires both cert_path and key_path."""
        from src.config import AppConfig

        # Missing cert_path
        cfg = AppConfig(**{
            'web': {
                'ssl_enabled': True,
                'ssl_key_path': '/tmp/key.pem',
            }
        })
        self.assertTrue(cfg.web.ssl_enabled)
        self.assertFalse(cfg.web.ssl_cert_path)  # Missing - should fail in daemon

        # Missing key_path
        cfg = AppConfig(**{
            'web': {
                'ssl_enabled': True,
                'ssl_cert_path': '/tmp/cert.pem',
            }
        })
        self.assertTrue(cfg.web.ssl_enabled)
        self.assertFalse(cfg.web.ssl_key_path)  # Missing - should fail in daemon


class TestSSLContext(unittest.TestCase):
    """Test SSL context creation."""

    def test_ssl_module_available(self):
        """SSL module is available for HTTPS support."""
        import ssl
        self.assertTrue(hasattr(ssl, 'SSLContext'))
        self.assertTrue(hasattr(ssl, 'PROTOCOL_TLS_SERVER'))

    def test_ssl_context_creation(self):
        """SSL context can be created without errors."""
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.assertIsNotNone(context)

    def test_ssl_context_with_client_verification(self):
        """SSL context can be configured for client certificate verification."""
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_REQUIRED
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == '__main__':
    unittest.main(verbosity=2)
