# AGP Check-up and Roadmap

Date: 2026-05-30

## Executive Summary

AGP сейчас находится на стадии backend foundation с первым встроенным UI shell.
Уже есть рабочее ядро авторизации, PostgreSQL/SQLite storage, Admin API, audit
model, Nginx `auth_request` контракт, генератор Nginx-рекомендаций и
on-demand диагностика ресурсов.

Проект еще не является готовым продуктом для пользователей, потому что frontend
пока является shell-реализацией, нет PostgreSQL integration test profile,
granular RBAC и полноценного operational hardening. Однако архитектурный
фундамент выбран правильно: AGP выступает control plane, Nginx остается data
plane.

## Readiness Matrix

| Layer | Status | Readiness | Notes |
| --- | --- | --- | --- |
| Backend runtime | Implemented | MVP-ready | HTTP server, graceful shutdown, structured logs |
| Local auth | Implemented | MVP-ready | Argon2id, local users |
| Sessions | Implemented | MVP-ready | server-side sessions, hashed tokens, CSRF |
| PostgreSQL | Implemented | Needs integration test | production default, embedded migrations |
| SQLite fallback | Implemented | Dev-ready | useful for tests and local bootstrap |
| User portal API | Implemented | MVP-ready | `/me`, user resource list |
| Admin API | Implemented | Needs UI and RBAC refinement | CRUD users/groups/resources, sessions, audit |
| Nginx auth_request | Implemented | MVP-ready | fail-closed authorization endpoint |
| Nginx recommendations | Implemented | MVP-ready | generated snippets, no auto-apply |
| Audit | Implemented | Needs retention/export strategy | DB-backed events |
| Frontend | Partial | Needs feature completion | embedded shell for login, portal and admin basics |
| PostgreSQL runtime validation | Not implemented | Blocker for production confidence | needs live DB integration tests |
| Permission model | Partial | Needs hardening | boolean admin only |
| Rate limiting | Partial | Single-node only | in-memory limiter |
| MFA/SSO | Not implemented | Enterprise phase | LDAP/AD/TOTP/SSO later |
| Observability | Partial | Needs metrics/health expansion | logs exist, metrics absent |
| Deployment automation | Partial | Needs packaging | systemd/nginx/logrotate docs exist |

## What Is Ready

### Core Security Path

- Login with local users.
- Password hashing with Argon2id.
- Server-side session creation and revocation.
- Secure session cookies by default.
- CSRF protection for mutating authenticated API.
- Nginx `auth_request` endpoint.
- Resource authorization by session, enabled flag, group mapping and IP allowlist.
- Fail-closed behavior on storage errors and invalid CIDR data.

### Admin Backend

- Dashboard counters.
- Users CRUD.
- Groups CRUD.
- Resources CRUD.
- Active session listing and revocation.
- Audit event listing.
- Nginx recommendation generation per resource.
- On-demand resource diagnostics.

### Frontend Shell

- Login screen.
- User portal resource list.
- Admin dashboard counters.
- Admin resource creation.
- Nginx recommendation view.
- Resource diagnostics action.

### Storage

- PostgreSQL production storage backend.
- SQLite fallback backend with the same storage contract.
- Embedded migrations for both backends.
- Bootstrap CLI for first administrator.

### Documentation

- Architecture notes.
- Security model.
- Operations notes.
- PostgreSQL setup.
- Admin API.
- Nginx recommendations.
- Bootstrap flow.
- Implementation snapshot.

## What Is Not Ready

### Product UX

The embedded frontend shell exists, but it is not yet a complete product UI.
User/resource workflows are present at a basic level, while full CRUD editing,
audit browsing, session management and polished error handling still need work.

### Production Validation

PostgreSQL code compiles and is structurally implemented, but there is no
repeatable live PostgreSQL integration test. This is a production confidence
gap.

### Authorization Granularity

Administration is controlled by `is_admin=true`. For enterprise use this should
be replaced or extended with permission-based RBAC:

- `users.read`
- `users.manage`
- `groups.manage`
- `resources.manage`
- `sessions.revoke`
- `audit.read`
- `nginx.recommendations.read`

### Operational Hardening

Missing or incomplete:

- metrics endpoint;
- DB health details;
- scheduled resource upstream health checks and history;
- audit retention policy enforcement;
- SIEM/export path;
- Redis-backed distributed rate limits;
- backup/restore runbooks with tested commands.

### Enterprise Identity

Not implemented yet:

- LDAP;
- Active Directory;
- TOTP;
- SSO/OIDC/SAML;
- password reset flow.

## MVP Definition

AGP MVP should be considered ready when the following are complete:

1. User portal UI:
   - login;
   - available resources;
   - logout;
   - 401/403 pages.
2. Admin UI:
   - dashboard;
   - users/groups/resources management;
   - session revocation;
   - audit view;
   - Nginx recommendation view.
3. PostgreSQL integration test profile.
4. First production install guide:
   - PostgreSQL;
   - AGP binary;
   - systemd;
   - Nginx;
   - logrotate;
   - first admin bootstrap;
   - backup.
5. Basic metrics and health diagnostics.

## Roadmap

### Phase 1: Usable MVP

Goal: AGP can be used by administrators and users without raw API calls.

Tasks:

- expand static frontend shell;
- implement login/logout flow;
- implement user resource portal;
- implement admin dashboard;
- implement users/groups/resources UI;
- implement Nginx recommendation view with copy/download;
- add 401/403 pages;
- add PostgreSQL integration test profile;
- document first VM deployment.

Exit criteria:

- admin can create a resource from UI;
- user can log in and see only allowed resources;
- Nginx snippet can be generated from UI;
- PostgreSQL-backed test run passes;
- basic VM install can be reproduced from documentation.

### Phase 2: Production Hardening

Goal: AGP is safe to run as a single-node production gateway.

Tasks:

- add permission-based RBAC;
- add metrics endpoint;
- add scheduled resource diagnostics and history;
- add audit retention settings;
- add backup/restore runbook;
- add brute-force lockout policy;
- add password policy config;
- add admin action metadata in audit events;
- add PostgreSQL TLS configuration examples.

Exit criteria:

- each admin action is auditable;
- blocked users and revoked sessions are enforced;
- resource health can be diagnosed from admin UI/API;
- backups and restores are documented and testable;
- access decisions remain fail-closed.

### Phase 3: Enterprise Integrations

Goal: AGP integrates with corporate identity and monitoring.

Tasks:

- LDAP/AD authentication;
- group sync from LDAP/AD;
- TOTP MFA;
- OIDC/SAML evaluation;
- SIEM/audit export;
- notification integrations;
- Redis-backed distributed rate limiting;
- PostgreSQL HA deployment notes.

Exit criteria:

- local users remain available as break-glass accounts;
- external identity provider can be used for normal users;
- audit data can leave AGP into security monitoring;
- multiple AGP instances can run safely.

### Phase 4: Controlled Nginx Apply

Goal: optional controlled application of generated Nginx configs.

Tasks:

- design privileged local agent;
- define signed/verified config bundle format;
- require `nginx -t` before reload;
- add config versioning;
- add rollback support;
- audit every generated, applied and rolled-back config.

Exit criteria:

- config apply is explicit, RBAC-protected and auditable;
- failed `nginx -t` never reloads Nginx;
- previous working config can be restored.

This phase is intentionally later. Manual-review recommendations are safer for
the current maturity level.

## Current Technical Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Frontend is still basic | High | complete portal/admin CRUD workflows |
| No live PostgreSQL integration test | High | add test profile with disposable DB |
| Boolean admin only | Medium | introduce permission-based RBAC |
| In-memory rate limiting | Medium | acceptable for single-node MVP, move to Redis later |
| No metrics | Medium | add `/metrics` or structured health endpoint |
| Manual Nginx apply | Low | acceptable and safer for MVP |

## Recommended Next Sprint

1. Add PostgreSQL integration tests.
2. Expand frontend CRUD workflows.
3. Add scheduled resource diagnostics and history.
4. Start RBAC data model migration.

The most valuable immediate move is PostgreSQL integration tests plus frontend
CRUD completion. This turns AGP from a backend foundation into a demonstrable
MVP while raising confidence in the preferred production database.
