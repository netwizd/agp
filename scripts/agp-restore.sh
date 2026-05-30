#!/usr/bin/env sh
set -eu
umask 077

if [ "$#" -ne 4 ]; then
  echo "usage: agp-restore.sh <db-dump> <downloads-tar.gz> <target-database> <sha256-file>" >&2
  exit 2
fi

db_dump="$1"
downloads_archive="$2"
target_db="$3"
checksum_file="$4"
downloads_parent="${AGP_DOWNLOADS_PARENT:-/var/lib/agp}"
downloads_name="${AGP_DOWNLOADS_NAME:-downloads}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

verify_checksum() {
  target="$1"
  base="$(basename "$target")"
  expected="$(awk -v base="$base" '{ name=$2; sub(/^.*\//, "", name); if (name == base) { print $1; exit } }' "$checksum_file")"
  if [ "$expected" = "" ]; then
    echo "checksum for $base not found in $checksum_file" >&2
    exit 1
  fi
  actual="$(sha256sum "$target" | awk '{ print $1 }')"
  if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $base" >&2
    exit 1
  fi
}

validate_tar_entries() {
  tar -tzf "$downloads_archive" | while IFS= read -r entry; do
    case "$entry" in
      ""|/*|..|../*|*/../*|*/..)
        echo "unsafe tar entry: $entry" >&2
        exit 1
        ;;
    esac
  done
}

verify_checksum "$db_dump"
verify_checksum "$downloads_archive"
validate_tar_entries

pg_restore --clean --if-exists --dbname="$target_db" "$db_dump"

install -d -m 0750 "$downloads_parent"
tmp_extract="$(mktemp -d "$downloads_parent/.agp-restore-$timestamp.XXXXXX")"
trap 'rm -rf "$tmp_extract"' EXIT INT TERM

tar -C "$tmp_extract" -xzf "$downloads_archive"
if [ ! -d "$tmp_extract/$downloads_name" ]; then
  echo "downloads directory $downloads_name not found in archive" >&2
  exit 1
fi

target_downloads="$downloads_parent/$downloads_name"
if [ -e "$target_downloads" ]; then
  mv "$target_downloads" "$downloads_parent/$downloads_name.pre-restore-$timestamp"
fi
mv "$tmp_extract/$downloads_name" "$target_downloads"
chmod -R go-rwx "$target_downloads"
