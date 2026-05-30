# PostgreSQL

PostgreSQL is the preferred production storage backend.

## Minimal Setup

```sql
CREATE USER agp WITH PASSWORD 'change-me';
CREATE DATABASE agp OWNER agp;
```

Runtime configuration:

```bash
AGP_DATABASE_DRIVER=postgres
AGP_DATABASE_DSN='postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=disable'
```

For production, prefer TLS-enabled PostgreSQL connections, restricted network
access and managed backups.

## Migrations

Migrations are embedded in the backend binary under:

```text
internal/storage/postgres/migrations/
```

The backend applies unapplied migrations on startup and records them in
`schema_migrations`.

## Backup Model

Minimum production baseline:

- daily base backups;
- WAL archiving for point-in-time recovery;
- encrypted off-host backup storage;
- monthly restore drill.
