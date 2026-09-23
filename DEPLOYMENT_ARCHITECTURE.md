# DEPLOYMENT ARCHITECTURE — Security Dashboard

**Stato:** TARGET ARCHITECTURE 2.1  
**Branch:** `architecture/initial-design`

## 1. Target topology

```text
Internet
   |
   v
Vercel
   | HTTPS
   v
Render Web Service (FastAPI API/HTMX, no scheduler)
   | TLS
   v
Neon PostgreSQL Production

Render Cron Job / dedicated single worker
   | HTTPS / application invocation
   v
NVD/Feed sync -> Neon PostgreSQL
```

The Render Web Service must not run a periodic scheduler inside the FastAPI lifespan. NVD and Feed synchronization is executed by a dedicated single-schedule component, preferably Render Cron Job. This avoids duplicate periodic jobs when the web service scales horizontally.

## 2. Environments

| Environment | Frontend | Backend | Database | Secrets |
|---|---|---|---|---|
| Development | local | local FastAPI | local SQLite WAL or dedicated Neon development DB | local .env, never committed |
| Preview/Staging | Vercel Preview | isolated Render Preview/Staging | separate Neon preview/development DB | Preview-only secrets |
| Production | Vercel Production | Render Production Web Service | Neon Production | Production-only secrets |

Preview must never point to the production Neon database.

## 3. Required environment variables

Names must match application configuration before implementation. At minimum:
- `DATABASE_URL`
- `SECRET_KEY`
- `ALLOWED_ORIGINS`
- `NVD_API_KEY`
- `APP_ENV`
- sync configuration values where required

No secret, database URL or API key may be committed to Git. Vercel and Render environment variables must be separated by environment scope.

## 4. Network and browser security

- Vercel -> Render only over HTTPS.
- Render -> Neon using the Neon TLS connection string.
- CORS allows only explicitly configured Vercel origins for the corresponding environment.
- Security headers, CSRF and secure session cookies are mandatory for the browser application.

## 5. Authentication

The browser application uses authenticated server-compatible sessions rather than exposing bearer JWTs to browser JavaScript. Session cookies require `Secure`, `HttpOnly`, appropriate `SameSite`, bounded lifetime and server-side invalidation on logout. State-changing HTMX/API requests require CSRF protection. Direct API clients use the documented server authentication mechanism or a separately controlled service credential.

## 6. Database migrations

Schema evolution is performed with Alembic against PostgreSQL. A migration must be tested against a disposable/preview database before production. SQLite is retained only for local development compatibility and is not the production target.

Migration flow: create revision -> test upgrade -> test downgrade where safe -> PostgreSQL integration tests -> production backup/recovery check -> apply -> verify health and critical queries.

## 7. Deployment flow

1. Pull request to `main` from feature/security/refactor branch.
2. Automated tests, dependency/security checks and review.
3. Merge only after Quality/Security/Release gates.
4. Vercel builds frontend from approved commit.
5. Render deploys backend from approved commit.
6. Database migrations run as an explicit controlled release step, not automatically on every web-worker startup.
7. Health/readiness checks validate application and database connectivity.
8. Cron synchronization is deployed independently and uses the approved application version.

## 8. Rollback and recovery

Application rollback uses the previous known-good Vercel/Render deployment. Database rollback is not assumed automatic. Prefer backward-compatible migrations; destructive changes require an explicit recovery plan and verified backup.

Neon production backup/branching/recovery capabilities must be configured and periodically tested according to the selected plan. Recovery objectives must be documented before production release.

## 9. Observability

Production must provide structured application logs, request/error correlation identifiers, health/readiness checks, sync execution status/duration/result/failure reason, audit logs for security-sensitive actions and alerts for repeated sync failures or authentication/application anomalies. Secrets must never appear in logs.

## 10. Scheduler execution contract

NVD/Feed synchronization is idempotent. Each execution records a `sync_run`/job record with start/end time, status, source, counters and error details. External records are upserted using stable source identifiers. Retries use bounded exponential backoff. A job must not overlap another execution for the same source. Manual admin-triggered runs use the same service path and idempotency rules.

## 11. Production gate

Production deployment is blocked until authentication/RBAC, CSRF/CORS, upload limits, PostgreSQL integration tests, migration validation, dependency scanning, backup/recovery validation and independent security review are complete.
