# Эксплуатация AGP

## Observability

Backend пишет структурированные JSON-логи в stdout. В systemd deployment они
попадают в journald:

```bash
journalctl -u agp -f
journalctl -u agp -n 200 --no-pager
```

Nginx ведет отдельные access/error logs для портала и ресурсов.

HTTP probes:

| Endpoint | Назначение |
| --- | --- |
| `/healthz` | процесс AGP отвечает на HTTP |
| `/readyz` | storage backend доступен |
| `/metrics` | дешевые Prometheus-style liveness metrics |

`/metrics` должен быть доступен только localhost или monitoring network.

## Минимальные Alerts

- процесс `agp` остановлен;
- `/readyz` не отвечает;
- рост HTTP 5xx;
- серия failed logins;
- частые `access_denied` или `ip_denied`;
- ошибка backup timer;
- Nginx reload failed;
- истечение TLS certificate.

## Backup

Production backup включает PostgreSQL и downloads directory:

```bash
sudo install -o root -g root -m 0755 scripts/agp-backup.sh scripts/agp-restore.sh /usr/local/bin/
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.service /etc/systemd/system/agp-backup.service
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.timer /etc/systemd/system/agp-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now agp-backup.timer
```

Ручной запуск:

```bash
sudo -u agp AGP_BACKUP_DIR=/secure-backups AGP_DATABASE_NAME=agp /usr/local/bin/agp-backup.sh
```

Backup artifacts создаются с `umask 077`; файлы backup и checksum manifest
должны оставаться с правами `0600`.

## Restore

Restore script:

- требует matching SHA-256 manifest;
- проверяет tar archive на absolute paths и `..`;
- распаковывает downloads во временную директорию;
- затем заменяет целевой каталог.

Пример:

```bash
createdb agp_restore
AGP_DOWNLOADS_PARENT=/var/lib/agp /usr/local/bin/agp-restore.sh \
  /secure-backups/agp-db-YYYYMMDDTHHMMSSZ.dump \
  /secure-backups/agp-downloads-YYYYMMDDTHHMMSSZ.tar.gz \
  agp_restore \
  /secure-backups/agp-YYYYMMDDTHHMMSSZ.sha256
```

После restore нужно проверить:

- `/readyz`;
- login администратора;
- список ресурсов;
- скачивание public downloads;
- чтение audit.

## Retention

Runtime cleanup:

```env
AGP_AUDIT_RETENTION=8760h
AGP_SESSION_RETENTION=720h
```

AGP удаляет старые audit events и expired/revoked sessions при старте. Backup
retention независим и задается политикой организации.

## Logrotate

Базовый template:

```text
deploy/logrotate/agp
```

Рекомендуемая политика:

- daily rotation;
- хранить минимум 30 дней локально;
- gzip compression;
- reload Nginx после rotation.
