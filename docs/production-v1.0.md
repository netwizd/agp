# AGP v1.0: инструкция production-развертывания

## Scope

v1.0 - production-ready single-node deployment без Docker:

- AGP backend работает как systemd service;
- PostgreSQL используется как production database;
- Nginx является публичным TLS reverse proxy и data plane;
- Nginx bundle генерируется в AGP, но применяется администратором вручную;
- backup/restore покрывает PostgreSQL и public downloads.

v1.1 зарезервирована для MFA, invite/password setup links, encrypted sensitive
profile fields и notification workflows.

## Production Baseline

Требования:

- Ubuntu 22.04/24.04 или совместимый Linux host;
- локальный system user `agp`;
- PostgreSQL DB с отдельной ролью `agp`;
- публичный DNS host портала, например `enter.company.com`;
- TLS certificate для портала;
- Nginx, доступный из внешней сети;
- закрытый backend `127.0.0.1:8080`.

Рекомендуемая файловая структура:

```text
/usr/local/bin/agp
/usr/local/bin/agpctl
/etc/agp/agp.env
/var/lib/agp/downloads
/var/log/agp
/opt/agp-src
```

## Автоматическая Установка

На выделенном Ubuntu host:

```bash
sudo ./install.sh
```

Скрипт спрашивает:

- portal host;
- имя DB и DB user;
- логин первого администратора;
- ставить ли Nginx из официального репозитория `nginx.org`;
- нужен ли Certbot;
- нужно ли менять firewall;
- режим `auto` или `manual`.

Скрипт автоматически:

- генерирует PostgreSQL password;
- настраивает PostgreSQL role/database;
- пишет `/etc/agp/agp.env`;
- собирает и устанавливает `agp`/`agpctl`;
- ставит systemd unit;
- запускает AGP и проверяет readiness;
- опционально ставит Nginx config и backup timer.

Firewall не изменяется без явного согласия администратора.

## Ручная Установка

1. Собрать и проверить:

```bash
./scripts/release-check.sh
```

2. Создать пользователя и директории:

```bash
sudo useradd --system --home /var/lib/agp --shell /usr/sbin/nologin agp
sudo install -d -o root -g agp -m 0750 /etc/agp
sudo install -d -o agp -g agp -m 0750 /var/lib/agp /var/lib/agp/downloads /var/log/agp
sudo install -o root -g root -m 0755 bin/agp /usr/local/bin/agp
sudo install -o root -g root -m 0755 bin/agpctl /usr/local/bin/agpctl
```

3. Создать PostgreSQL:

```sql
CREATE USER agp WITH PASSWORD 'change-me';
CREATE DATABASE agp OWNER agp;
```

4. Записать `/etc/agp/agp.env`:

```env
AGP_HTTP_ADDR=127.0.0.1:8080
AGP_PORTAL_HOST=enter.company.com

AGP_DATABASE_DRIVER=postgres
AGP_DATABASE_DSN=postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=disable

AGP_DOWNLOADS_DIR=/var/lib/agp/downloads
AGP_DOWNLOAD_MAX_BYTES=268435456
AGP_DOWNLOAD_ALLOWED_EXTENSIONS=.zip,.rar,.7z,.msi,.exe,.pkg,.dmg,.pdf,.txt,.rdp,.ovpn,.conf
AGP_DOWNLOAD_SCAN_COMMAND=
AGP_DOWNLOAD_SCAN_TIMEOUT=30s

AGP_COOKIE_SECURE=true
AGP_TRUST_PROXY_HEADERS=true
AGP_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128

AGP_SESSION_TTL=8h
AGP_SESSION_RETENTION=720h
AGP_AUDIT_RETENTION=8760h
AGP_SHUTDOWN_TIMEOUT=10s

AGP_LOGIN_RATE_LIMIT_MAX=5
AGP_LOGIN_RATE_LIMIT_WINDOW=1m

AGP_DIAGNOSTICS_ALLOW_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
AGP_DIAGNOSTICS_DENY_CIDRS=127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10,0.0.0.0/8,::/128
AGP_DIAGNOSTICS_RATE_LIMIT_MAX=30
AGP_DIAGNOSTICS_RATE_LIMIT_WINDOW=1m
```

Права:

```bash
sudo chown root:agp /etc/agp/agp.env
sudo chmod 0640 /etc/agp/agp.env
```

5. Установить systemd unit:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/agp.service /etc/systemd/system/agp.service
sudo systemctl daemon-reload
sudo systemctl enable --now agp
```

6. Создать первого администратора:

```bash
set -a && . /etc/agp/agp.env && set +a
printf '%s\n' "$AGP_ADMIN_PASSWORD" | sudo -u agp /usr/local/bin/agpctl create-admin \
  -username admin \
  -display-name "Administrator"
```

7. Настроить Nginx.

Скопировать bundle из админки или использовать `deploy/nginx/agp.conf` как
baseline. Проверить реальные пути сертификатов:

```nginx
ssl_certificate     /etc/nginx/ssl/aym.ru/cert.pem;
ssl_certificate_key /etc/nginx/ssl/aym.ru/private.key;
```

Проверить и применить:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Обновление

```bash
cd /opt/agp-src
git pull --ff-only
sudo ./update.sh --auto --allow-dirty
```

После обновления backend Nginx config не затирается. Если менялся generator,
нужно заново скопировать bundle из админки, сохранить реальные TLS paths,
проверить `nginx -t` и выполнить reload.

## Readiness И Metrics

Локальные проверки:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

`/healthz` проверяет HTTP process. `/readyz` проверяет storage liveness.
`/metrics` содержит дешевые Prometheus-style metrics и должен быть закрыт от
публичной сети.

## Backup

Установка timer:

```bash
sudo install -o root -g root -m 0755 scripts/agp-backup.sh scripts/agp-restore.sh /usr/local/bin/
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.service /etc/systemd/system/agp-backup.service
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.timer /etc/systemd/system/agp-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now agp-backup.timer
```

Ручной backup:

```bash
sudo -u agp AGP_BACKUP_DIR=/secure-backups AGP_DATABASE_NAME=agp /usr/local/bin/agp-backup.sh
```

Production requirements:

- шифровать backups перед off-host transfer;
- сохранять backup и checksum files с mode `0600`;
- держать retention согласно audit policy;
- тестировать restore минимум ежемесячно;
- мониторить свежесть backups.

## Restore Drill

```bash
createdb agp_restore
AGP_DOWNLOADS_PARENT=/var/lib/agp /usr/local/bin/agp-restore.sh \
  /secure-backups/agp-db-YYYYMMDDTHHMMSSZ.dump \
  /secure-backups/agp-downloads-YYYYMMDDTHHMMSSZ.tar.gz \
  agp_restore \
  /secure-backups/agp-YYYYMMDDTHHMMSSZ.sha256
```

Проверить восстановленный стенд:

- `/readyz` возвращает `ready`;
- admin login работает;
- ресурсы видны;
- public downloads скачиваются;
- audit readable.

## Release Checklist

Перед tag v1.0:

```bash
./scripts/release-check.sh
```

Для полноценного release-check нужен live PostgreSQL DSN:

```bash
export AGP_TEST_POSTGRES_DSN='postgres://agp:change-me@127.0.0.1:5432/agp?sslmode=disable'
```

Ручные проверки:

- `systemctl status agp`;
- `journalctl -u agp -n 100`;
- `nginx -t`;
- login/logout;
- создание и изменение ресурса;
- генерация Nginx bundle;
- доступ к ресурсу разрешенному пользователю;
- отказ пользователю без прав;
- `/access-denied` не раскрывает существование guessed resource;
- загрузка и скачивание public download.
