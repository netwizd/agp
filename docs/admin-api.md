# Административный API

Административные endpoints требуют:

1. действующую AGP-сессию;
2. permission, соответствующий операции;
3. заголовок `X-CSRF-Token` для изменяющих запросов.

`is_admin=true` остается режимом совместимости superuser и дает все известные
permissions. В production предпочтительно управлять доступом через группы.

## Административные Endpoints

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `/api/v1/admin/dashboard` | счетчики и последние события аудита |
| `GET` | `/api/v1/admin/users` | список пользователей |
| `POST` | `/api/v1/admin/users` | создание пользователя |
| `PATCH` | `/api/v1/admin/users/{id}` | изменение пользователя, пароля, блокировки и групп |
| `DELETE` | `/api/v1/admin/users/{id}` | удаление пользователя |
| `GET` | `/api/v1/admin/groups` | список групп |
| `POST` | `/api/v1/admin/groups` | создание группы |
| `PATCH` | `/api/v1/admin/groups/{id}` | изменение группы и permissions |
| `DELETE` | `/api/v1/admin/groups/{id}` | удаление группы |
| `GET` | `/api/v1/admin/resources` | список ресурсов |
| `POST` | `/api/v1/admin/resources` | создание ресурса |
| `GET` | `/api/v1/admin/resources/{id}` | карточка ресурса |
| `PATCH` | `/api/v1/admin/resources/{id}` | изменение ресурса, групп и CIDR allowlist |
| `DELETE` | `/api/v1/admin/resources/{id}` | удаление ресурса |
| `GET` | `/api/v1/admin/nginx/bundle` | полный Nginx bundle для портала |
| `GET` | `/api/v1/admin/resources/{id}/nginx` | Nginx snippet для ресурса |
| `POST` | `/api/v1/admin/resources/{id}/diagnostics` | запуск DNS/TCP/HTTP диагностики upstream |
| `GET` | `/api/v1/admin/resources/{id}/diagnostics` | история диагностики ресурса |
| `GET` | `/api/v1/admin/downloads` | список публичных файлов, включая скрытые |
| `POST` | `/api/v1/admin/downloads` | загрузка публичного файла через multipart |
| `PATCH` | `/api/v1/admin/downloads/{id}` | изменение названия, описания или публикации |
| `DELETE` | `/api/v1/admin/downloads/{id}` | удаление metadata и файла |
| `GET` | `/api/v1/admin/portal-settings` | чтение оформления портала |
| `PUT` | `/api/v1/admin/portal-settings` | изменение оформления портала |
| `GET` | `/api/v1/admin/sessions` | активные сессии |
| `DELETE` | `/api/v1/admin/sessions/{id}` | отзыв сессии |
| `GET` | `/api/v1/admin/audit` | журнал аудита с фильтрами |
| `GET` | `/api/v1/admin/audit/export` | экспорт аудита, требует `audit.export` |

## Публичные Endpoints

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `/api/v1/version` | версия backend |
| `GET` | `/api/v1/public/settings` | публичные настройки оформления |
| `GET` | `/api/v1/public/downloads` | опубликованные файлы без авторизации |
| `GET` | `/downloads/{id}` | скачивание опубликованного файла |

## Пример Создания Ресурса

```json
{
  "name": "Example Service",
  "description": "Внутренний сервис",
  "category": "Operations",
  "internal_url": "http://app.internal.local/anything-needed",
  "public_host": "enter.company.ru",
  "public_path": "/anything-needed",
  "enabled": true,
  "group_ids": ["grp_users"],
  "allow_cidrs": ["10.50.0.0/16"]
}
```

`public_host` - публичный host портала. `public_path` - защищенная точка входа
на этом host. В примере пользователь открывает
`https://enter.company.ru/anything-needed`, а Nginx после `auth_request`
проксирует запрос в `http://app.internal.local/anything-needed`.

API валидирует host, path, internal URL и CIDR до сохранения.

## Диагностика И Аудит

Диагностика ресурсов считается высокопривилегированной операцией. Перед TCP/HTTP
проверками AGP применяет `AGP_DIAGNOSTICS_ALLOW_CIDRS`,
`AGP_DIAGNOSTICS_DENY_CIDRS` и rate limit по пользователю/ресурсу.

Экспорт аудита отделен от чтения аудита. CSV export защищен от spreadsheet
formula injection: значения, похожие на формулы, экранируются перед отдачей.
