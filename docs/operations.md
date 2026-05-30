# AGP Operations

## Observability

Backend logs are structured JSON on stdout. Systemd deployments should route
them to journald or a log collector. Nginx keeps separate portal and resource
access logs.

Minimum production alerts:

- AGP backend process down;
- HTTP 5xx spike on backend;
- repeated failed login attempts;
- repeated `ip_denied` / `access_denied` audit outcomes;
- SQLite file disk usage and backup failures.

## Backup Strategy

For SQLite MVP:

1. put DB under `/var/lib/agp/agp.db`;
2. enable WAL-aware backup using SQLite online backup or a brief maintenance
   window;
3. encrypt off-host backups;
4. test restore monthly.

For PostgreSQL stage:

- daily base backups;
- WAL archiving;
- restore drills;
- retention aligned with audit policy.

## Log Rotation

Use `deploy/logrotate/agp` as baseline:

- daily rotation;
- 30 days retention;
- gzip compression;
- Nginx reload after rotation.
