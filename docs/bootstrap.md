# Bootstrap AGP

## Первый Администратор

AGP не поставляется с дефолтным паролем. Первый администратор создается через
`agpctl`, используя ту же конфигурацию БД, что и backend.

```bash
set -a && . /etc/agp/agp.env && set +a
printf '%s\n' "$AGP_ADMIN_PASSWORD" | sudo -u agp /usr/local/bin/agpctl create-admin \
  -username admin \
  -display-name "Administrator" \
  -group-name "Administrators"
```

Команда:

- применяет миграции;
- создает пользователя;
- создает группу администраторов при необходимости;
- назначает пользователя в группу;
- сохраняет пароль как Argon2id hash.

## Hash Пароля

Для ручных операций можно получить hash:

```bash
printf '%s\n' "$AGP_ADMIN_PASSWORD" | /usr/local/bin/agpctl hash-password
```

Plaintext пароль нельзя сохранять в shell history, tickets, wiki или deployment
manifest. Для production лучше вводить пароль интерактивно или через временный
секрет.

## Ручной SQL Fallback

Использовать только в аварийном обслуживании:

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

Пример группы и ресурса:

```sql
INSERT INTO groups(id, name, description)
VALUES ('grp_admins', 'Administrators', 'AGP administrators');

INSERT INTO user_groups(user_id, group_id)
VALUES ('usr_admin', 'grp_admins');

INSERT INTO resources(id, name, description, category, internal_url, public_host, public_path, enabled)
VALUES (
    'res_example',
    'Example Service',
    'Internal example service',
    'Operations',
    'http://app.internal.local/anything-needed',
    'enter.company.ru',
    '/anything-needed',
    true
);

INSERT INTO resource_groups(resource_id, group_id)
VALUES ('res_example', 'grp_admins');
```

Для SQLite boolean можно записывать как `1` и `0`, если клиент не принимает
`true` и `false`.
