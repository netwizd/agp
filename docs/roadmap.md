# Check-Up И Roadmap AGP

Дата актуализации: 2026-05-31.

## Краткое Резюме

AGP доведен до single-node v1.0 baseline: есть backend, PostgreSQL storage,
встроенный portal/admin UI, RBAC, public downloads, audit, diagnostics,
Nginx bundle generator, install/update scripts, backup/restore scripts и
production runbook.

Проект готовится к первому production rollout без Docker. v1.1 сфокусирована на
MFA, invite/password setup links, уведомлениях и activity visibility.

## Readiness Matrix

| Слой | Статус | Готовность | Комментарий |
| --- | --- | --- | --- |
| Backend runtime | реализовано | v1.0 | Go HTTP server, graceful shutdown, JSON logs |
| Local auth | реализовано | v1.0 | Argon2id, local users |
| Sessions | реализовано | v1.0 | server-side sessions, hashed tokens, CSRF |
| PostgreSQL | реализовано | v1.0 | production default, migrations, integration test |
| SQLite fallback | реализовано | dev/test | fallback, не основной production backend |
| User portal | реализовано | v1.0 | resources, search, downloads, help, logout |
| Admin UI | реализовано | v1.0 baseline | CRUD resources/users/groups/downloads, audit, sessions |
| RBAC | реализовано | v1.0 baseline | permission model, group permissions, superadmin guard |
| Nginx integration | реализовано | v1.0 | `auth_request`, bundle/snippets |
| Path proxying | реализовано | v1.0 | public path, redirect/cookie rewrite |
| Public downloads | реализовано | v1.0 | upload progress, SHA-256, policy, publish/hide/delete |
| Audit | реализовано | v1.0 | filters, CSV/JSON export, admin metadata |
| Diagnostics | реализовано | v1.0 | on-demand checks, history, CIDR policy |
| Observability | реализовано | v1.0 | `/healthz`, `/readyz`, `/metrics`, logs |
| Deployment | реализовано | v1.0 | install/update scripts, systemd, Nginx docs |
| Backup/restore | реализовано | v1.0 baseline | PostgreSQL dump, downloads archive, checksum validation |
| MFA/SSO | не реализовано | v1.1+ | MFA first, external IdP later |
| Notifications | не реализовано | v1.1 | login/resource/admin activity notifications |

## Что Готово

### Security Path

- local login;
- Argon2id password hashing;
- secure session cookies;
- CSRF для mutating API;
- trusted proxy boundary для proxy headers;
- Nginx `auth_request`;
- authorization по session, resource enabled flag, groups и CIDR;
- fail closed на storage errors, invalid CIDR и unknown resources.

### Admin/Product UX

- login/logout;
- portal с ресурсами, поиском и группировкой;
- public downloads на login/portal;
- help page;
- admin tabs: resources, downloads, portal, groups, users, sessions, audit;
- group picker для resources/users;
- permission reference в UI;
- Nginx bundle/snippet copy;
- diagnostics history;
- audit filters/export.

### Operations

- PostgreSQL migrations;
- `agpctl create-admin`;
- `install.sh`;
- `update.sh`;
- systemd unit;
- Nginx baseline config;
- backup/restore scripts;
- release-check script.

## Ограничения v1.0

| Ограничение | Почему Оставлено | Следующий Шаг |
| --- | --- | --- |
| Single-node rate limit | достаточно для первой production VM | Redis-backed limiter |
| Manual Nginx apply | безопаснее на текущей зрелости | privileged local agent |
| Local users only | быстрее и контролируемее для v1.0 | MFA/invite, затем LDAP/SSO |
| Audit в PostgreSQL | нормально для v1.0 | SIEM/export pipeline |
| No scheduled health checks | есть on-demand diagnostics/history | scheduler и alerts |

## v1.0 Exit Criteria

AGP можно считать v1.0-ready, когда на целевом host:

1. `./scripts/release-check.sh` проходит с `AGP_TEST_POSTGRES_DSN`.
2. `install.sh` или manual runbook успешно завершен.
3. `/readyz` возвращает ready.
4. Nginx config проходит `nginx -t`.
5. Администратор может создать пользователя, группу и ресурс.
6. Пользователь видит только разрешенные ресурсы.
7. Запрещенный пользователь получает `/access-denied`.
8. Public download загружается и скачивается.
9. Backup создан и restore drill выполнен на тестовой БД.

## Roadmap

### Phase 1: v1.0 Stabilization

Цель: стабильно развернуть AGP на первом production host.

Задачи:

- пройти production runbook;
- проверить Nginx bundle на реальных ресурсах;
- задокументировать реальные TLS paths и backup directory;
- зафиксировать `v1.0.0` tag;
- собрать список production feedback.

Exit criteria:

- портал доступен по HTTPS;
- ресурсы открываются через portal path;
- аудит фиксирует login/resource/admin actions;
- backup/restore проверен.

### Phase 2: v1.1 Identity Lifecycle

Цель: добавить зрелый lifecycle пользователей.

Задачи:

- TOTP MFA;
- recovery codes;
- invite/password setup links;
- SMTP settings;
- encrypted sensitive fields;
- admin activity timeline;
- notification settings.

Exit criteria:

- новый пользователь получает ссылку и сам задает пароль;
- MFA можно включить policy по группе;
- администратор видит действия пользователя;
- login/resource notifications работают по настройке.

### Phase 3: Enterprise Identity

Цель: интеграция с корпоративной identity-инфраструктурой.

Задачи:

- LDAP/AD authentication;
- group sync;
- OIDC/SAML evaluation;
- break-glass local admin policy;
- Redis-backed distributed rate limits;
- PostgreSQL HA notes.

### Phase 4: Controlled Nginx Apply

Цель: безопасное опциональное применение Nginx config из AGP.

Требования:

- отдельный privileged local agent;
- signed/verified config bundle;
- обязательный `nginx -t`;
- rollback последнего working config;
- RBAC и audit для generate/apply/rollback.

До этой фазы manual apply остается правильной production-моделью.

## Текущие Риски

| Риск | Severity | Mitigation |
| --- | --- | --- |
| Ошибка ручного Nginx apply | Medium | copy button, docs, обязательный `nginx -t` |
| Потеря backup discipline | High | systemd timer, alert, monthly restore drill |
| Local-only identity | Medium | v1.1 MFA/invite, затем LDAP/SSO |
| Single-node rate limit | Medium | допустимо для v1.0, Redis позже |
| Неполный SIEM pipeline | Medium | audit export сейчас, streaming позже |

## Ближайшие Действия

1. Выполнить установку на production host по [production-v1.0.md](production-v1.0.md).
2. Проверить реальные ресурсы, redirects и cookies.
3. Настроить backup timer и сделать restore drill.
4. Создать tag `v1.0.0`.
5. Начать v1.1 по [v1.1-plan.md](v1.1-plan.md).
