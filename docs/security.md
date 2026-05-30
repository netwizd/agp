# Модель Безопасности AGP

## Trust Boundaries

AGP backend нельзя открывать напрямую в недоверенную сеть. Production-модель:
backend слушает localhost/private interface, а публичный доступ идет только через
Nginx.

AGP доверяет `X-Real-IP`, `X-Forwarded-*` и related proxy headers только если:

- `AGP_TRUST_PROXY_HEADERS=true`;
- remote address попадает в `AGP_TRUSTED_PROXY_CIDRS`.

`/auth/request` также использует trusted proxy boundary для host/original URI
логики. Direct access к backend не должен давать возможность spoofing.

## Authentication

- пароли хранятся как Argon2id hashes;
- session cookies: `HttpOnly`, `Secure`, `SameSite=Lax`;
- session tokens хранятся в БД как SHA-256 hashes;
- state-changing API требует CSRF token;
- logout и session revoke инвалидируют server-side session.

## Authorization

Доступ к ресурсу разрешается только если выполнены все условия:

1. сессия существует и не истекла;
2. пользователь не заблокирован;
3. ресурс найден по public host/path и включен;
4. если задан CIDR allowlist, IP клиента входит в allowlist;
5. группы пользователя пересекаются с группами ресурса.

Storage errors, invalid CIDR, disabled resource и unknown resource должны
заканчиваться fail closed.

## Anti-Enumeration

Неизвестные и запрещенные ресурсы показываются пользователю через одинаковую
страницу `/access-denied`. Nginx error pages не должны раскрывать, существует ли
угаданный entry point.

## Auditability

AGP пишет audit events для:

- успешных и неуспешных login attempts;
- logout;
- `auth_request` decisions;
- access denied по ресурсу, группе или IP;
- CRUD-действий администратора;
- diagnostics runs;
- audit exports.

CSV export защищен от spreadsheet formula injection: ячейки, начинающиеся с
`=`, `+`, `-`, `@` и control characters, экранируются.

## Public Downloads

Загрузка файлов ограничивается:

- `AGP_DOWNLOAD_MAX_BYTES`;
- `AGP_DOWNLOAD_ALLOWED_EXTENSIONS`;
- опциональным scanner hook `AGP_DOWNLOAD_SCAN_COMMAND`;
- Nginx `client_max_body_size`.

Скачивание отдается как attachment. Для недоверенных типов предпочтительно
оставлять `application/octet-stream`.

## Diagnostics

Resource diagnostics - привилегированная функция, потому что она может стать
поверхностью internal network probing. Защиты:

- отдельный permission `resources.diagnostics`;
- deny/allow CIDR policy;
- default deny для loopback, link-local и metadata ranges;
- rate limit по пользователю/ресурсу;
- audit каждого запуска.

## MVP Limits

- rate limiting пока in-memory и рассчитан на single-node;
- LDAP/AD/OIDC/SAML не реализованы;
- MFA, invite links и уведомления запланированы на v1.1;
- для enterprise audit scale нужен SIEM/export pipeline.
