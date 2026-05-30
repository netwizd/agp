# AGP Operations

## Observability

Backend logs are structured JSON on stdout. Systemd deployments should route
them to journald or a log collector. Nginx keeps separate portal and resource
access logs.

HTTP probes:

- `/healthz` checks that the HTTP process is serving;
- `/readyz` checks that AGP can query its storage backend;
- `/metrics` exports Prometheus-style gauges and should be limited to localhost
  or monitoring networks at Nginx.

Minimum production alerts:

- AGP backend process down;
- HTTP 5xx spike on backend;
- repeated failed login attempts;
- repeated `ip_denied` / `access_denied` audit outcomes;
- `/readyz` failures;
- backup failures.

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

See [production-v1.0.md](production-v1.0.md) for install, backup and restore
commands.

## Log Rotation

Use `deploy/logrotate/agp` as baseline:

- daily rotation;
- 30 days retention;
- gzip compression;
- Nginx reload after rotation.
