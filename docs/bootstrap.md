# AGP Bootstrap

## First Admin User

AGP does not ship with a default password. Generate an Argon2id hash locally:

```bash
printf '%s\n' "$AGP_ADMIN_PASSWORD" | go run ./cmd/agpctl hash-password
```

Preferred bootstrap path:

```bash
printf '%s\n' "$AGP_ADMIN_PASSWORD" | go run ./cmd/agpctl create-admin \
  -username admin \
  -display-name "Administrator" \
  -group-name "Administrators"
```

The command uses the same `AGP_DATABASE_DRIVER`, `AGP_DATABASE_DSN` and
`AGP_DATABASE_PATH` settings as the backend. It applies migrations before
creating the administrator.

Manual PostgreSQL equivalent:

```sql
INSERT INTO users(id, username, password_hash, display_name, is_admin)
VALUES (
    'usr_admin',
    'admin',
    '<argon2id-hash>',
    'Administrator',
    true
);
```

Create a group and resource mapping:

```sql
INSERT INTO groups(id, name, description)
VALUES ('grp_admins', 'Administrators', 'AGP administrators');

INSERT INTO user_groups(user_id, group_id)
VALUES ('usr_admin', 'grp_admins');

INSERT INTO resources(id, name, description, internal_url, public_host, enabled)
VALUES (
    'res_e1c',
    '1C Enterprise',
    'Internal 1C service',
    'http://e1c.osrp.local',
    'e1c.company.ru',
    true
);

INSERT INTO resource_groups(resource_id, group_id)
VALUES ('res_e1c', 'grp_admins');
```

For SQLite fallback, use the same statements with `1` and `0` for boolean
columns if your SQLite client does not accept `true` and `false`.

For production, run bootstrap from a maintenance workstation and avoid storing
plaintext passwords in shell history, tickets or deployment manifests.
