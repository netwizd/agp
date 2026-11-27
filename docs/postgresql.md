# PostgreSQL

PostgreSQL - основной storage backend для production.

Secure S0 pilot требует прямого подключения CP к primary: identity writer lease и
`WriteIdentity` выполняются на одном PostgreSQL session. PgBouncer transaction/statement
pooling не квалифицированы; SQLite/legacy backend не получает journal/restore guarantees.
Journal — отдельная PostgreSQL БД/restore domain со своими credentials; совместный
CP+journal/VM snapshot rollback вне гарантий. [Активация и restore](operations.md#s0-pilot-активация-и-восстановление).

## Минимальная Настройка

```sql
CREATE USER agp WITH PASSWORD 'change-me';
CREATE DATABASE agp OWNER agp;
```

Runtime configuration:

```env
AGP_DATABASE_DRIVER=postgres
AGP_DATABASE_DSN=postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=disable
```

Для production рекомендуется:

- отдельная роль БД только для AGP;
- пароль, сгенерированный случайно;
- доступ к PostgreSQL только с AGP host/network;
- SCRAM authentication;
- TLS для сетевого PostgreSQL;
- регулярный backup и restore drill.

## Миграции

Миграции встроены в backend binary:

```text
internal/storage/postgres/migrations/
```

При старте backend применяет непримененные миграции и записывает результат в
`schema_migrations`. Отдельный ручной запуск миграций не требуется.

## Backup Baseline

Минимум для production:

- ежедневный dump/base backup;
- WAL archiving для point-in-time recovery, если требуется RPO меньше суток;
- encrypted off-host storage;
- проверка восстановления минимум раз в месяц;
- retention, согласованный с audit policy.

Скрипты проекта:

```text
scripts/agp-backup.sh
scripts/agp-restore.sh
deploy/systemd/agp-backup.service
deploy/systemd/agp-backup.timer
```

## Integration Tests

Для локальной разработки и будущего CI запускайте disposable native PostgreSQL
от непривилегированного пользователя:

```bash
AGP_TEST_PG_BINDIR=/path/to/postgresql/bin make test-postgres
```

В указанной директории должны находиться `initdb`, `pg_ctl`, `postgres`, `psql`
одной установки PostgreSQL. Если они уже находятся в `PATH`, достаточно
`make test-postgres`. Go берётся из `GO` (по умолчанию `go`). Скрипт не устанавливает
пакеты и не требует Docker. Версию PostgreSQL и Go закрепляет окружение runner.
Reference schema v2 рассчитана на PostgreSQL 17+ по [data-model](v2/data-model.md);
текущий harness проверяет существующие storage packages, без установки reference schema v2.

Harness `scripts/test-postgres.sh` создаёт новый кластер в `/tmp`, отключает TCP и
разрешает подключения через Unix socket внутри приватной директории с правами
`0700`. `trust` используется только в этом одноразовом кластере. Входные
`AGP_TEST_POSTGRES_DSN`/`AGP_DATABASE_DSN` и переменные подключения libpq очищаются;
production DSN и credentials не требуются и не используются.

После проверки реального SQL-подключения запускаются пакеты `internal/storage`
и `internal/storage/postgres` с `-count=1` и timeout 3 минуты. Integration tests
создают временные схемы, применяют embedded migrations и проверяют storage
операции. Отсутствие binaries, недоступность PostgreSQL, ошибка теста, любой
`SKIP`, отсутствие успешного `TestStoreIntegration`, `TestIdentityMutationStorage/postgres`
или `TestSessionProfileStorage/postgres` завершают job с ошибкой.
Обычный `make test` без DSN продолжает пропускать PG integration и сам по себе
не подтверждает PostgreSQL acceptance.

При завершении, ошибке или сигнале `HUP`/`INT`/`TERM` trap останавливает кластер
и удаляет временные данные. Если остановка не удалась, скрипт возвращает ошибку
и показывает путь оставшегося кластера; работающий каталог не удаляется.
`SIGKILL` и сбой runner невозможно обработать trap: runner также должен удалять
свои временные файлы и процессы. Скрипт пока не подключён к корпоративному CI;
платформа runner/service выбирается отдельно.

Для единого S0 acceptance используйте [scripts/test-s0-full.sh](../scripts/test-s0-full.sh)
по [инструкции](v2/testing.md#текущий-пакет-s0-команды-и-границы): обязательны два
изолированных CP/journal clusters, journal mTLS/idempotency, настоящий CP
`pg_dump`/`pg_restore`, replay и quarantine, затем реальные HTTPS/browser/EdgeAuth.
Один `make test-postgres` проверяет SQL/storage, но не этот сквозной сценарий.
CP restore не запускают через rollback независимого journal; внешний approved epoch
и fencing выполняют **до** возврата старой CP БД.

S1 authoring использует embedded `012_configuration_core.sql` в существующей secure
CP БД: immutable draft versions/revisions/catalog/reports и global-head CAS. Persisted
`configuration-profile` активируют отдельным offline CLI после первого immutable head;
оно закрывает legacy resource writer и не отключается одним env flag. [Процедура](operations.md#s1-authoring-pilot).
Reference `agp_v2.validation_reports` по TARGET имеет ровно одну FK-цель из config/WAF/
profile/zone revision; отдельный reference DB harness проверяет все четыре positive
варианта, отсутствие/двойную цель и недостающую zone FK. Это не утверждение, что весь
reference schema уже используется runtime S1 (у него таблицы `config_reports` и др.).
