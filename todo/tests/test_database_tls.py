import os
import ssl
from unittest import TestCase

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost/test",
)
os.environ.setdefault("JWKS_URL", "http://auth-user.test/.well-known/jwks.json")
os.environ.setdefault("JWT_ISSUER", "auth-user.test")
os.environ.setdefault("JWT_AUDIENCE", "todo.test")

from database.connection import create_db_ssl_context, ssl_context


class DatabaseTlsTests(TestCase):
    def test_database_context_uses_verify_full_security(self) -> None:
        self.assertEqual(ssl_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ssl_context.check_hostname)
        self.assertGreater(len(ssl_context.get_ca_certs()), 0)

    def test_context_rejects_invalid_trust_material(self) -> None:
        context = create_db_ssl_context()

        with self.assertRaises(ssl.SSLError):
            context.load_verify_locations(cadata="not a CA certificate")

    def test_context_cannot_disable_certificate_validation(self) -> None:
        context = create_db_ssl_context()

        with self.assertRaises(ValueError):
            context.verify_mode = ssl.CERT_NONE
