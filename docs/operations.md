# AGP Operations

## Observability

Backend logs are structured JSON on stdout. Systemd deployments should route
them to journald or a log collector. Nginx keeps separate portal and resource
access logs.

HTTP probes:

- `/healthz` checks that the HTTP process is serving;
- `/readyz` checks that AGP can query its storage backend;
- `/metrics` exports cheap Prometheus-style liveness gauges and should be
  limited to localhost or monitoring networks at Nginx.

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

For PostgreSQL production:

- daily base backups;
- WAL archiving;
- restore drills;
- retention aligned with audit policy.

Use `scripts/agp-backup.sh`, `scripts/agp-restore.sh`,
`deploy/systemd/agp-backup.service` and `deploy/systemd/agp-backup.timer` as the
baseline. The default systemd timer runs daily and keeps backup retention in
`AGP_BACKUP_RETENTION_DAYS`.

Backup artifacts are created with `umask 077` and should remain mode `0600`.
Restore requires the matching SHA-256 manifest, validates the downloads archive
paths before extraction and extracts into a temporary directory before replacing
the target downloads directory.

## Retention

Runtime cleanup is controlled by:

- `AGP_AUDIT_RETENTION`, default `8760h`;
- `AGP_SESSION_RETENTION`, default `720h`.

AGP prunes old audit events and expired/revoked sessions on startup. Backup
retention is independent and must be long enough to satisfy the organization's
audit policy.

See [production-v1.0.md](production-v1.0.md) for install, backup, restore and
release commands.

## Log Rotation

Use `deploy/logrotate/agp` as baseline:

- daily rotation;
- 30 days retention;
- gzip compression;
- Nginx reload after rotation.
