# AGP - Auth Gateway Portal

AGP - корпоративный портал доступа к внутренним ресурсам. Система ставится перед
внутренними сервисами, проверяет пользователя через единый портал, применяет
права доступа и пишет аудит действий.

Целевая модель v1.0 - один production-сервер без Docker:

- backend на Go с локальной аутентификацией, сессиями и CSRF-защитой;
- PostgreSQL как основной production storage;
- SQLite только как fallback для разработки и небольших стендов;
- Nginx как внешний TLS reverse proxy и data plane через `auth_request`;
- web-интерфейс для пользователей и администраторов;
- RBAC по группам и permission, плюс совместимость с `is_admin`;
- публичные файлы для скачивания без авторизации;
- генератор Nginx bundle/snippet для портала и защищенных ресурсов;
- аудит логинов, доступов, отказов и критичных админских действий.

## Структура Репозитория

```text
cmd/agp/                  основной процесс AGP
cmd/agpctl/               служебная CLI-утилита
internal/auth/            пароли, Argon2id, session token primitives
internal/config/          конфигурация из environment
internal/domain/          доменные модели
internal/httpapi/         HTTP API, UI shell, auth_request contract
internal/reverseproxy/    генераторы безопасных Nginx-рекомендаций
internal/storage/         storage-интерфейсы
internal/storage/postgres/PostgreSQL backend и миграции
internal/storage/sqlite/  SQLite backend и миграции
configs/                  пример runtime-конфигурации
deploy/                   systemd, Nginx, logrotate, Docker templates
docs/                     архитектура, безопасность, эксплуатация
scripts/                  release-check, backup, restore
```

## Быстрый Локальный Запуск

Требуется Go 1.22+ и PostgreSQL.

```sql
CREATE USER agp WITH PASSWORD 'change-me';
CREATE DATABASE agp OWNER agp;
```

```bash
cp configs/agp.example.env .env
go mod download
set -a && . ./.env && set +a
go run ./cmd/agp
```

По умолчанию AGP слушает `127.0.0.1:8080` и подключается к PostgreSQL на
`127.0.0.1:5432`. Для локальной разработки можно указать
`AGP_DATABASE_DRIVER=sqlite`.

Первый администратор:

```bash
printf '%s\n' "$AGP_ADMIN_PASSWORD" | go run ./cmd/agpctl create-admin \
  -username admin \
  -display-name "Administrator"
```

## Установка На Ubuntu

Основной способ установки:

```bash
sudo ./install.sh
```

Скрипт спрашивает минимальные параметры:

- доменное имя портала;
- имя базы и пользователя PostgreSQL;
- логин первого администратора;
- использовать ли официальный репозиторий Nginx;
- ставить ли Certbot;
- трогать ли firewall;
- запускать ли установку автоматически или пошагово.

Скрипт генерирует пароль БД, настраивает PostgreSQL, пишет
`/etc/agp/agp.env`, собирает бинарники, ставит systemd unit, запускает AGP и
может включить backup timer. Firewall не изменяется без явного согласия.

```bash
sudo ./install.sh --auto
sudo ./install.sh --manual
```

Подробный runbook: [docs/production-v1.0.md](docs/production-v1.0.md).

## Обновление

На сервере:

```bash
cd /opt/agp-src
git pull --ff-only
sudo ./update.sh --auto --allow-dirty
```

`update.sh` сравнивает текущий upstream commit и commit, встроенный в
`/usr/local/bin/agp`. Если обновлять нечего, сборка и restart не выполняются.
Если исходники уже обновлены, но установленный бинарник старее, скрипт все равно
пересобирает и переустанавливает AGP.

При обновлении скрипт:

- запускает проверки Go по умолчанию;
- собирает `agp` и `agpctl`;
- сохраняет backup старых бинарников и systemd unit;
- перезапускает AGP;
- проверяет `/readyz`;
- при провале readiness пытается вернуть предыдущие бинарники.

Nginx-конфиг намеренно не затирается автоматически. Новый bundle нужно
скопировать из админки, проверить `nginx -t` и выполнить reload вручную.

## Основные Документы

| Документ | Назначение |
| --- | --- |
| [docs/production-v1.0.md](docs/production-v1.0.md) | установка, deployment, backup, restore, release checklist |
| [docs/architecture.md](docs/architecture.md) | архитектура и поток запросов |
| [docs/security.md](docs/security.md) | модель безопасности |
| [docs/rbac.md](docs/rbac.md) | роли и permissions |
| [docs/nginx-recommendations.md](docs/nginx-recommendations.md) | Nginx bundle/snippet и reverse proxy модель |
| [docs/admin-api.md](docs/admin-api.md) | административный и публичный API |
| [docs/postgresql.md](docs/postgresql.md) | PostgreSQL setup, миграции и тесты |
| [docs/operations.md](docs/operations.md) | эксплуатация, observability, backup |
| [docs/roadmap.md](docs/roadmap.md) | состояние проекта и roadmap |
| [docs/v1.1-plan.md](docs/v1.1-plan.md) | план MFA, invite links и уведомлений |

## Production Security Baseline

AGP является security boundary. В production backend должен слушать localhost
или приватный интерфейс и быть доступен только через Nginx с TLS.

Обязательные условия:

- `AGP_COOKIE_SECURE=true`;
- `AGP_TRUST_PROXY_HEADERS=true` только при корректном
  `AGP_TRUSTED_PROXY_CIDRS`;
- PostgreSQL закрыт от внешней сети;
- `/metrics` ограничен localhost или monitoring network;
- Nginx bundle проверяется через `nginx -t` перед reload;
- backup PostgreSQL и downloads регулярно проверяется restore drill.
