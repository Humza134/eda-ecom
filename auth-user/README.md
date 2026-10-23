# Auth User Service

## Authentication rate limiting

Authentication endpoints use Redis-backed fixed-window counters so limits are shared by all
workers and containers. Counter increments, limit decisions, and expiry are performed atomically
by a short Redis Lua script. Before starting the service, set `RATE_LIMIT_KEY_SECRET` to a random
value of at least 32 characters. Keep it stable and secret; it is used to HMAC client and account
keys.

The default client/account-or-credential limits are:

- login: 20/5 requests per 300 seconds
- signup: 10/3 requests per 3600 seconds
- email verification: 30/5 requests per 900 seconds
- verification resend: 10 requests per client and 1 per email per 60 seconds
- token refresh: 120/30 requests per 60 seconds

Each value and window is configurable through the corresponding `*_RATE_LIMIT` and
`*_RATE_LIMIT_WINDOW_SECONDS` environment variables shown in `compose.yaml`.

By default, forwarded IP headers are ignored. Set `TRUSTED_PROXY_CIDRS` to a comma-separated list
of the reverse proxies that overwrite or append `X-Forwarded-For`; do not add untrusted networks.

Compose maps `AUTH_REDIS_URL` to the application's `REDIS_URL`; it defaults to
`redis://redis:6379/0`. Connection and socket timeouts default to two seconds and can be changed
with `REDIS_CONNECT_TIMEOUT_SECONDS` and
`REDIS_SOCKET_TIMEOUT_SECONDS`. `REDIS_RATE_LIMIT_KEY_PREFIX` isolates these keys from other Redis
uses. Redis is intentionally not exposed on a host port and rate-limit data is ephemeral.

Redis rate limiting does not require a PostgreSQL schema change. The abandoned PostgreSQL counter
migration was removed after a read-only check confirmed that the development database remained at
the preceding revision and did not contain the counter table.

## Email verification OTPs

Set `OTP_HMAC_SECRET` to an independent random secret of at least 32 characters. OTPs expire after
`OTP_EXPIRY_SECONDS` (600 by default), and each code permits at most `OTP_MAX_ATTEMPTS` (5 by
default). Only an HMAC digest is stored. Issuing a replacement code invalidates the prior code.
The resend cooldown and client abuse limit are configured with `RESEND_OTP_*` settings.

The secure OTP migration deliberately discards any legacy plaintext codes. After deploying the
migration, users with an unverified account must use the resend endpoint to obtain a new code.
