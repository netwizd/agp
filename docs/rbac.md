# RBAC

AGP использует permission-based RBAC для административного API и UI.

## Модель

```text
user -> user_groups -> groups -> group_permissions -> permissions
```

`is_admin=true` остается compatibility superuser flag. Такой пользователь
получает все известные permissions при lookup сессии. В production этот режим
нужно использовать как break-glass/superuser и не выдавать обычным операторам.

## Permissions

| Permission | Назначение |
| --- | --- |
| `dashboard.read` | просмотр dashboard |
| `users.read` | просмотр пользователей |
| `users.manage` | создание, изменение, блокировка и удаление пользователей |
| `users.superadmin.manage` | управление `is_admin` |
| `groups.read` | просмотр групп |
| `groups.manage` | создание, изменение и удаление групп |
| `resources.read` | просмотр ресурсов |
| `resources.manage` | создание, изменение и удаление ресурсов |
| `resources.diagnostics` | запуск диагностики ресурсов |
| `nginx.recommendations.read` | генерация Nginx snippets/bundle |
| `downloads.read` | просмотр public downloads в админке |
| `downloads.manage` | загрузка, публикация, скрытие и удаление public downloads |
| `portal.settings.read` | просмотр настроек оформления портала |
| `portal.settings.manage` | изменение оформления портала |
| `sessions.read` | просмотр активных сессий |
| `sessions.revoke` | отзыв сессий |
| `audit.read` | просмотр аудита |
| `audit.export` | экспорт аудита в CSV/JSON |

## Пример Группы

```json
{
  "name": "Resource Operators",
  "description": "Управление опубликованными ресурсами",
  "permission_ids": [
    "resources.read",
    "resources.manage",
    "nginx.recommendations.read",
    "resources.diagnostics"
  ]
}
```

В админке permissions выбираются из справочника. Это снижает риск ошибок по
сравнению с ручным вводом raw identifiers.

## Security Notes

- permissions проверяются при каждом lookup сессии;
- заблокированный пользователь отклоняется даже при активной сессии;
- отсутствие permission возвращает `403`;
- `audit.export` отделен от `audit.read`, потому что выгрузки содержат IP,
  User-Agent и административные metadata;
- изменение `is_admin` защищено отдельной super-admin проверкой.
