# Implementation Snapshot

Current branch: `main`.

See [roadmap.md](roadmap.md) for the project check-up, readiness matrix and
delivery roadmap.

## Реализовано

| Area | Status |
| --- | --- |
| Go backend | HTTP server, graceful shutdown, structured JSON logging |
| Auth | local username/password login, Argon2id password hashes |
| Sessions | server-side sessions, hashed session tokens, CSRF token for mutating API |
| User portal API | `/api/v1/me`, `/api/v1/resources`, public portal settings and downloads |
| Frontend shell | embedded static login, searchable/grouped portal catalog, public downloads and admin UI shell with resources/downloads/settings/groups/users/sessions/audit tabs |
| Nginx integration | `/auth/request` endpoint for `auth_request` |
| Admin API | users, groups, resources, sessions, audit, dashboard |
| RBAC | permission-based admin middleware with group permissions and `is_admin` superuser compatibility |
| Nginx recommendations | generated per-resource server block snippets, no auto-apply |
| Resource diagnostics | admin-triggered DNS, TCP and HTTP upstream checks |
| Public downloads | unauthenticated enabled file list/downloads, admin upload/hide/delete |
| Portal customization | DB-backed brand name, logo text, page titles, support link and footer |
| Access denied UX | generic `/access-denied` page for missing or unauthorized proxied resources |
| Observability | `/healthz`, `/readyz`, Prometheus-style `/metrics`, structured logs |
| PostgreSQL | production storage backend with embedded migrations |
| SQLite | development/small-install fallback with same storage contract |
| Audit | login/logout, proxy auth decisions and admin actions persisted |
| Bootstrap | `agpctl hash-password`, `agpctl create-admin` |
| Documentation | architecture, security, operations, PostgreSQL, Admin API, Nginx recommendations |

## Security Model

- protected resources fail closed on missing session, missing resource, storage
  error, invalid CIDR, disabled resource or missing group mapping;
- missing and unauthorized resources share the same denial surface to reduce
  entry-point enumeration signals;
- backend trusts proxy headers only when configured to do so;
- state-changing admin endpoints require CSRF;
- session cookies are `HttpOnly`, `Secure` by default and `SameSite=Lax`;
- AGP generates Nginx snippets but does not modify system Nginx configs.

## Verification

Current automated checks:

```bash
go test ./...
go vet ./...
go build -trimpath -o bin/agp ./cmd/agp
go build -trimpath -o bin/agpctl ./cmd/agpctl
node --check internal/frontend/static/app.js
git diff --check
```

Covered by tests:

- Nginx recommendation generation;
- unsafe host rejection;
- invalid CIDR rejection;
- admin login/session/CSRF/resource creation/Nginx recommendation flow via
  `httptest` and SQLite.
- public downloads and portal settings flow via `httptest` and SQLite.
- embedded SPA fallback route.
- PostgreSQL integration profile when `AGP_TEST_POSTGRES_DSN` is set.

## Not Implemented Yet

| Area | Gap |
| --- | --- |
| Frontend completeness | shell exists, resource edit UX exists, other edit/update UX is not feature-complete |
| PostgreSQL integration test | opt-in harness exists and is wired into release-check when `AGP_TEST_POSTGRES_DSN` is set |
| RBAC management UX | permission data model exists, UI is still basic |
| Rate limiting | in-memory only, not Redis-backed |
| MFA/SSO | MFA/invite links planned for v1.1; LDAP/AD/OIDC/SAML later |
| Resource health checks | diagnostics exist, no scheduled checks/history yet |
| SIEM/export | audit is stored in DB, no external export yet |
| Config apply | Nginx recommendations are manual-review only |

## Next Recommended Increment

1. Execute [production-v1.0.md](production-v1.0.md) on the target host.
2. Tag v1.0 after release-check and manual production checks pass.
3. Start v1.1 MFA/invite/notification work from [v1.1-plan.md](v1.1-plan.md).
