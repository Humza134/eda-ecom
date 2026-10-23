# AGENTS.md

## Project

- This repository contains two FastAPI microservices: `auth-user/` and `todo/`.
- Both target Python 3.13+ and use FastAPI, Pydantic v2, SQLModel, asyncpg,
  PostgreSQL/Neon, Alembic, `uv`, and Docker Compose.
- `auth-user` owns registration, login, refresh, email verification, RS256 signing, JWKS, and
  Redis-backed authentication rate limiting.
- `todo` owns user-scoped todo resources and validates access tokens issued by `auth-user`.
- Kafka and additional commerce services are not implemented; do not describe them as available.

## Repository boundaries

- Treat each service as independent, with its own dependencies, models, migrations, configuration,
  and database connection.
- Do not import ORM models, sessions, or service internals across service directories.
- Pass cross-service data through APIs or, when explicitly introduced, versioned events.
- Only `auth-user` may load private signing keys or issue tokens. Downstream services consume
  public JWKS and a small typed identity such as a user UUID.
- Redis only stores ephemeral authentication rate-limit counters; it is not a source of truth.
- Use `compose.yaml` for topology and `auth-user/README.md` for rate-limit and verification settings.

## Python and FastAPI conventions

- Keep HTTP validation, dependencies, authorization, response schemas, and safe error mapping in routes.
- Put business rules and transaction boundaries in service modules. New or refactored service
  code should raise typed domain exceptions rather than `HTTPException`.
- Use explicit Pydantic v2/SQLModel schemas and `model_dump()`; do not expose sensitive entities.
- Inject `AsyncSession` and authenticated identity with `Depends`; request dependencies manage
  lifetime, while services own commit and rollback decisions.
- Await all I/O; move unavoidable blocking calls to `asyncio.to_thread`.
- Keep complete type annotations and the services' existing absolute-import execution layout.
- Preserve public API contracts unless the task explicitly authorizes a breaking change.
- Update a service's `pyproject.toml` and `uv.lock` together when a dependency change is authorized.

## Data and events

- Each stateful service owns its database or schema. Never query, join, or share tables across
  service boundaries.
- Use the existing async engine, `async_sessionmaker`, `AsyncSession`, and async `get_session`
  pattern.
- Use timezone-aware UTC values and `Decimal` with fixed-precision columns for money.
- Kafka is not configured. If event-driven integration is requested, use versioned Pydantic event
  contracts, stable event IDs, and an atomic transactional outbox.
- Consumers must be idempotent, deduplicate event IDs, and acknowledge only after database commit.

## Security and migration safety

- Never commit or log passwords, OTPs, JWTs, authorization headers, signing keys, database URLs,
  or other credentials. Return stable, sanitized errors without provider or database details.
- Never copy secrets or private keys into Docker images.
- Validate JWT signature, allow-listed RS256 algorithm, `kid`, expiration, issuer, audience, token
  type, and UUID subject. Accept refresh tokens only in the refresh flow.
- Enforce resource ownership server-side; use `401` for invalid auth and `403` for insufficient access.
- Production PostgreSQL connections must verify TLS certificates and hostnames.
- Alembic owns schemas. Change SQLModel entities and add a reviewed migration together; do not add
  startup-time schema creation.
- Never edit an applied migration. Review upgrade and downgrade behavior, constraints, backfills,
  and data-loss risk.
- Obtain explicit approval before any database-changing command, including Alembic upgrades and
  Compose migration services. Before a read-only migration check, confirm the configured target is
  an intended non-production database and that the command cannot write.

## Verification

- Run only relevant tests; avoid unnecessary full-suite runs and repeated testing loops.
- Run focused tests for the affected service. From `auth-user/`:

```powershell
uv run python -m unittest discover -s tests -v
```

- From `todo/`:

```powershell
uv run python -m unittest discover -s tests -v
```

- Test changed auth claims, ownership, transaction outcomes, and security-sensitive failure paths.
- No Ruff, Pytest, or static type-check command is configured; do not invent or claim those checks.
- Report only checks actually run and call out skipped checks or remaining risks.
