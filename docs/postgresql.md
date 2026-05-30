# PostgreSQL

PostgreSQL - основной storage backend для production.

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

PostgreSQL integration tests требуют временную схему в живой БД:

```bash
AGP_TEST_POSTGRES_DSN='postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=disable' \
  go test ./internal/storage/postgres
```

Тест создает временную схему, применяет embedded migrations, проверяет базовые
CRUD/access/audit операции и удаляет схему после завершения.
