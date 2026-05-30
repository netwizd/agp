#!/usr/bin/env sh
set -eu
umask 077

backup_dir="${AGP_BACKUP_DIR:-/var/backups/agp}"
downloads_dir="${AGP_DOWNLOADS_DIR:-/var/lib/agp/downloads}"
database_name="${AGP_DATABASE_NAME:-agp}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

install -d -m 0750 "$backup_dir"

db_backup="agp-db-$timestamp.dump"
downloads_backup="agp-downloads-$timestamp.tar.gz"
checksum_file="agp-$timestamp.sha256"

pg_dump --format=custom --file="$backup_dir/$db_backup" "$database_name"
tar -C "$(dirname "$downloads_dir")" -czf "$backup_dir/$downloads_backup" "$(basename "$downloads_dir")"
(
  cd "$backup_dir"
  sha256sum "$db_backup" "$downloads_backup" > "$checksum_file"
  chmod 0600 "$db_backup" "$downloads_backup" "$checksum_file"
)

find "$backup_dir" -type f -name 'agp-*' -mtime +"${AGP_BACKUP_RETENTION_DAYS:-30}" -delete
