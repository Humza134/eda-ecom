import os
import ssl
from unittest import TestCase

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost/test",
)
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")
os.environ.setdefault("PRIVATE_KEY_PATH", "unused-private.pem")
os.environ.setdefault("PUBLIC_KEY_PATH", "unused-public.pem")
os.environ.setdefault("JWT_KEY_ID", "test-key")
os.environ.setdefault("JWT_ISSUER", "auth-user.test")
os.environ.setdefault("JWT_ACCESS_AUDIENCE", "auth-user-access.test")
os.environ.setdefault("JWT_REFRESH_AUDIENCE", "auth-user-refresh.test")
os.environ.setdefault("EMAIL_USER", "test@example.com")
os.environ.setdefault("EMAIL_PASS", "unused")
os.environ.setdefault("SMTP_HOST", "smtp.test")
os.environ.setdefault("SMTP_PORT", "587")
os.environ.setdefault("RATE_LIMIT_KEY_SECRET", "test-rate-limit-secret-at-least-32-bytes")
os.environ.setdefault("OTP_HMAC_SECRET", "test-otp-hmac-secret-at-least-32-bytes")

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
