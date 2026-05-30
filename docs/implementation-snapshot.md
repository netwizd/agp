# Срез Реализации

Текущая ветка: `main`.

Подробный roadmap: [roadmap.md](roadmap.md).

## Реализовано

| Область | Статус |
| --- | --- |
| Go backend | HTTP server, graceful shutdown, structured JSON logging |
| Auth | local username/password login, Argon2id password hashes |
| Sessions | server-side sessions, hashed tokens, CSRF для изменяющих API |
| User portal | `/me`, `/resources`, search, category filter, access denied UX |
| Admin UI | ресурсы, файлы, портал, группы, пользователи, сессии, аудит |
| RBAC | group permissions, permission middleware, `is_admin` compatibility |
| PostgreSQL | production backend, embedded migrations, integration tests |
| SQLite | fallback backend для dev/test |
| Nginx | `auth_request`, full bundle, per-resource snippets |
| Path resources | `public_path`, redirect rewrite, cookie rewrite |
| Public downloads | upload, progress indicator, SHA-256, extension policy, publish/hide/delete |
| Portal customization | brand, logo text, titles, support/help, footer |
| Diagnostics | DNS/TCP/HTTP checks, CIDR policy, rate limit, history |
| Audit | login/logout, auth decisions, admin actions, diagnostics, export |
| Observability | `/healthz`, `/readyz`, `/metrics`, JSON logs |
| Bootstrap | `agpctl hash-password`, `agpctl create-admin` |
| Install/update | `install.sh`, `update.sh`, systemd, backup timer |

## Модель Безопасности

- backend не должен быть публичным;
- trusted proxy headers принимаются только от trusted CIDR;
- защищенные ресурсы fail closed;
- неизвестные и запрещенные ресурсы ведут на одинаковый `/access-denied`;
- state-changing endpoints требуют CSRF;
- session cookies `HttpOnly`, `Secure`, `SameSite=Lax`;
- audit export требует отдельный `audit.export`;
- CSV export защищен от formula injection;
- diagnostics ограничены allow/deny CIDR policy.

## Проверки

Базовые команды:

```bash
go test ./...
go vet ./...
node --check internal/frontend/static/app.js
git diff --check
```

Release check:

```bash
AGP_TEST_POSTGRES_DSN='postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=disable' \
  ./scripts/release-check.sh
```

Покрыто тестами:

- Nginx generator;
- unsafe host rejection;
- invalid CIDR rejection;
- login/session/CSRF/resource flow через `httptest`;
- public downloads и portal settings;
- audit export;
- diagnostics history;
- PostgreSQL storage integration при `AGP_TEST_POSTGRES_DSN`.

## Не Реализовано В v1.0

| Область | Gap |
| --- | --- |
| MFA | запланировано на v1.1 |
| Invite/password setup links | запланировано на v1.1 |
| Email/notification channels | запланировано на v1.1 |
| LDAP/AD/OIDC/SAML | следующий enterprise этап |
| Redis-backed distributed rate limit | нужно для multi-instance |
| Автоприменение Nginx | намеренно отложено до privileged agent design |
| SIEM pipeline | аудит хранится в БД, внешний pipeline позже |

## Следующий Инкремент

1. Пройти production runbook на целевом host.
2. Закрепить `v1.0.0` tag после release-check и ручных проверок.
3. Начать v1.1: MFA, invite links, notification settings, user activity.
