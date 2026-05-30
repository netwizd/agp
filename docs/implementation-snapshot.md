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
| User portal API | `/api/v1/me`, `/api/v1/resources` |
| Frontend shell | embedded static login, portal and admin UI shell with resources/groups/users/sessions/audit tabs |
| Nginx integration | `/auth/request` endpoint for `auth_request` |
| Admin API | users, groups, resources, sessions, audit, dashboard |
| RBAC | permission-based admin middleware with group permissions and `is_admin` superuser compatibility |
| Nginx recommendations | generated per-resource server block snippets, no auto-apply |
| Resource diagnostics | admin-triggered DNS, TCP and HTTP upstream checks |
| PostgreSQL | production storage backend with embedded migrations |
| SQLite | development/small-install fallback with same storage contract |
| Audit | login/logout, proxy auth decisions and admin actions persisted |
| Bootstrap | `agpctl hash-password`, `agpctl create-admin` |
| Documentation | architecture, security, operations, PostgreSQL, Admin API, Nginx recommendations |

## Security Model

- protected resources fail closed on missing session, missing resource, storage
  error, invalid CIDR, disabled resource or missing group mapping;
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
git diff --check
```

Covered by tests:

- Nginx recommendation generation;
- unsafe host rejection;
- invalid CIDR rejection;
- admin login/session/CSRF/resource creation/Nginx recommendation flow via
  `httptest` and SQLite.
- embedded SPA fallback route.
- PostgreSQL integration profile when `AGP_TEST_POSTGRES_DSN` is set.

## Not Implemented Yet

| Area | Gap |
| --- | --- |
| Frontend completeness | shell exists, but UX is not feature-complete |
| PostgreSQL integration test | opt-in harness exists, not yet part of CI |
| RBAC management UX | permission data model exists, UI is still basic |
| Rate limiting | in-memory only, not Redis-backed |
| MFA/SSO | LDAP/AD/TOTP/SSO not implemented |
| Resource health checks | diagnostics exist, no scheduled checks/history yet |
| SIEM/export | audit is stored in DB, no external export yet |
| Config apply | Nginx recommendations are manual-review only |

## Next Recommended Increment

1. Wire PostgreSQL integration tests into CI/local release checklist.
2. Expand portal/admin UI edit forms and polish error states.
3. Improve RBAC management UX and add role templates.
4. Add scheduled resource health checks and history.
