# AGP - Auth Gateway Portal

AGP - корпоративный портал доступа к внутренним ресурсам. Система ставится перед
внутренними сервисами, проверяет пользователя через единый портал, применяет
права доступа и пишет аудит действий.

К single-node baseline v1 добавлен явно включаемый secure S0 pilot. Полный проект следующей
распределённой платформы для команды разработки находится в
[docs/v2/README.md](docs/v2/README.md): ТЗ, UX, архитектура, БД, типы, API,
агентный протокол, безопасность, эксплуатация и план приёмки. Документы v2 содержат
принятое владельцем итоговое ТЗ; статусы отдельных ADR указаны в комплекте.
S0 покрывает только ограниченный identity/journal/EdgeAuth сценарий; остальные возможности v2 ещё предстоит реализовать.
Границы S0 pilot — в [статусе разработки](docs/v2/development.md#текущий-срез-s0--as-is-на-2026-11-18); [активация, restore и rollback](docs/operations.md#s0-pilot-активация-и-восстановление).
Opt-in S1 draft/revision/preview authoring — [AS-IS и ограничения](docs/v2/development.md#текущий-срез-s1--authoring-pilot), [активация/API](docs/operations.md#s1-authoring-pilot); apply остаётся вне этого среза.
Принятый [component repository и базовые WAF policies](docs/operations.md#component-repository-и-базовые-waf-policies): реальный `/config-ui/` workflow create → native validate → independent approve → publish.
Новый [read-only агент и trusted WAF zones](docs/operations.md#read-only-agent-inventory-и-trusted-waf-zones) связывает mTLS inventory с публикацией зон, frozen resolution и полной desired ConfigRevision под CAS. Доступны external registry и opt-in [управляемая agent identity](docs/operations.md#управляемая-agent-identity-и-локальная-проверка-синтаксиса): owner-approved CSR, отдельный issuer, renewal/revoke и узловая CLI проверки синтаксиса. Добавлены [основа допуска helper](docs/v2/development.md#основа-допуска-helper--as-is-на-2026-11-24), [предложения плана с независимым review](docs/operations.md#предложения-плана-и-независимый-review) и [локальная read-only проверка owned tree](docs/operations.md#локальная-проверка-owned-tree).
Новые [native sandbox/bootstrap candidate](docs/v2/development.md#native-sandbox-и-managed-bootstrap--as-is-на-2026-11-25)
и [direct AD/provider](docs/v2/development.md#direct-ad-и-управление-provider--as-is-на-2026-11-25)
прошли локальные проверки с указанными ограничениями. Добавлены opt-in
[контакты, email-коды и SMTP outbox](docs/v2/development.md#контакты-email-коды-и-smtp--as-is-на-2026-11-25);
[настройка доставки](docs/operations.md#контакты-и-smtp-opt-in). Интерфейс собственных
контактов доступен на `/auth-ui/contacts`. Реализован [AD-backed OIDC](docs/v2/development.md#ad-backed-oidc--as-is-на-2026-11-25)
с управлением на `/directory-ui/?view=oidc` и обязательным TOTP AGP;
[installation policy](docs/operations.md#ad-backed-oidc-opt-in) настраивается отдельно.
Добавлены [приглашения, initial activation и typed recovery](docs/v2/development.md#invitations-initial-activation-и-recovery--as-is-на-2026-11-25):
управление на `/directory-ui/?view=identity`, обязательные email-код и TOTP при активации,
отдельно согласованные действия восстановления без создания сессии.
Итоговая регрессия интегрированного кода и корпоративная приёмка ещё не завершены.
Кандидат не подтверждает active baseline и не разрешает apply.
Исполнитель, безопасное применение и rollout остаются TARGET; приложение ещё не готово
к публикации как полный продукт по ТЗ. [Внешний стенд](docs/v2/testing.md#ресурсы-для-обязательной-внешней-приёмки)
понадобится после готовности реализации.
[WAF Zones](docs/v2/waf-zones.md) задают групповое управление защитой, локальные исключения
и проверяемое массовое применение для 1000+ сервисов.
Обязательные требования к [AD, 2FA и одноразовым кодам](docs/v2/identity.md)
согласованы с ТЗ, API, reference БД и сценариями входа.
Пример нового Angular-интерфейса с контекстной справкой и внутренним manual —
[web/console-prototype](web/console-prototype/README.md).

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
cmd/agp-agent/            исходящий read-only Linux inventory agent
cmd/agp-agent-identity/   локальный ключ/CSR, approved enrollment и renewal
cmd/agp-agent-validate/   локальный native syntax probe без apply
cmd/agp-owned-tree/       read-only наблюдение protected tree по trusted manifest
cmd/agp-bootstrap-candidate/ root-only syntax candidate с nonroot sandbox, без apply
cmd/agp-issuer/           отдельная issuing CA и durable ledger
internal/auth/            пароли, Argon2id, session token primitives
internal/config/          конфигурация из environment
internal/domain/          доменные модели
internal/httpapi/         HTTP API, UI shell, auth_request contract
internal/helper/          локальный журнал допуска без исполнения задач
internal/ownedtree/       descriptor-bound проверка manifest, файлов и metadata
internal/nativesandbox/   фиксированный Linux namespace profile для nginx -t
internal/deploymentplan/  полный immutable Plan и purpose-separated подпись
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

Требуется Go 1.27.4+ и PostgreSQL.

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

`install.sh` устанавливает заранее собранный пакет из публичного
[netwizd/agp](https://github.com/netwizd/agp), `update.sh` обновляет такую установку.
Целевая платформа этих скриптов — **Ubuntu 24.04 amd64 с systemd**. Go и Git на
сервере не нужны. PostgreSQL, приватная конфигурация и внешний HTTPS должны быть
подготовлены заранее. Подробности — [актуальный runbook](docs/operations.md#установка-и-обновление-из-github).

Для выбранного опубликованного релиза задайте `AGP_RELEASE_VERSION`, доверенный
SHA256 пакета `AGP_RELEASE_SHA256` и SHA256 самого скрипта `AGP_INSTALL_SHA256`.
Контрольные суммы получите через независимый доверенный канал; скачанный рядом
`SHA256SUMS` сам по себе не подтверждает подлинность.

```bash
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "https://github.com/netwizd/agp/releases/download/${AGP_RELEASE_VERSION}/install.sh" \
  --output install.sh
printf '%s  install.sh\n' "$AGP_INSTALL_SHA256" | sha256sum --check - && \
sudo bash ./install.sh --version "$AGP_RELEASE_VERSION" \
  --sha256 "$AGP_RELEASE_SHA256" --config /etc/agp-install.env
```

Исходный env должен принадлежать root, быть закрыт от посторонних и содержать
одну запись `NAME=value` на строку, без shell-подстановок. Основа —
[`configs/agp.example.env`](configs/agp.example.env); замените примерные значения.
Пакет включает девять компонентов. Автоматически запускается только `agp.service`;
остальные роли требуют собственных защищённых профилей. Настройки Nginx/WAF,
сертификаты и независимый journal готовятся по соответствующим разделам runbook.

Это установка с явно закреплённым оператором SHA256. Она не заменяет TUF и
независимую подпись релиза из целевой модели. Публичный релиз с этим форматом
необходимо подготовить и опубликовать отдельно; скрипт не собирает код с `main`.

Для отдельно разрешённого тестового стенда с текущими secure/config профилями
есть [подготовка лабораторной установки](deploy/lab/README.md). Этот путь включает
отдельные PostgreSQL и journal, MFA и прямой HTTPS-вход; он не расширяет список
поддерживаемых ОС публичного установщика.

## Обновление

Скачайте `update.sh` из выбранного релиза и проверьте его доверенный SHA256
аналогично установщику. Затем:

```bash
sudo bash ./update.sh --version "$AGP_RELEASE_VERSION" --sha256 "$AGP_RELEASE_SHA256"
```

Обновление сохраняет конфигурацию и данные, останавливает CP и создаёт приватную
копию БД до миграций. Все компоненты переключаются общей ссылкой `current`;
проверяются `/healthz` и `/readyz`. При сбое после попытки запуска сервис остаётся
остановленным: база могла изменить структуру, поэтому её восстановление требует
отдельной процедуры. Journal, его counters и доверенные ключи в CP backup не входят.
Старые установки через `git pull` требуют отдельной миграции.

Для проверки пакета без установки используйте `--verify-only`; `--archive` позволяет
указать заранее скачанный файл. Повторное обновление на те же проверенные bytes
не перезапускает приложение. Понижение версии и перезапись релиза блокируются.

## Основные Документы

| Документ | Назначение |
| --- | --- |
| [docs/operations.md](docs/operations.md#установка-и-обновление-из-github) | установка и обновление текущей системы, эксплуатация и восстановление |
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
