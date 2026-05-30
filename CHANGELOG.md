# Журнал Изменений

## v1.0.0-dev

- Усилено управление глобальными администраторами через отдельную super-admin
  проверку.
- Trusted proxy headers переведены в secure-by-default модель с проверкой CIDR.
- `/readyz` и `/metrics` используют дешевые проверки liveness.
- Добавлена структурированная audit metadata для критичных админских действий.
- Добавлены SHA-256 checksums, extension policy и опциональный scanner hook для
  public downloads.
- Добавлены inline editing и group picker для пользователей, групп, ресурсов и
  metadata публичных файлов.
- Добавлен full Nginx bundle generator и действие в админке.
- Для path-based ресурсов добавлены `proxy_redirect` и cookie rewrite.
- CSP убран из Nginx bundle для проксируемых legacy-приложений; CSP остается на
  страницах самого AGP backend.
- В Nginx bundle добавлен `client_max_body_size 256m` для загрузки файлов.
- Добавлена индикация прогресса загрузки public downloads.
- Добавлены release build metadata, endpoint версии и CLI output версии.
- Добавлены PostgreSQL release gate, backup/restore scripts и systemd backup
  timer.
