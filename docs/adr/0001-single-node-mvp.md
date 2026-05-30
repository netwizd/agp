# ADR 0001: Single-Node MVP C PostgreSQL/SQLite И Nginx auth_request

## Статус

Принято.

## Контекст

AGP должен стать централизованной точкой доступа к внутренним сервисам. Первый
релиз должен ставиться на одну VM, но не блокировать дальнейший переход к
multi-instance deployment.

## Решение

- backend пишется на Go;
- production storage - PostgreSQL;
- SQLite остается fallback для разработки и малых стендов;
- Nginx используется как TLS reverse proxy и `auth_request` data plane;
- AGP генерирует Nginx config recommendations, но не применяет их сам.

## Последствия

Плюсы:

- низкая операционная сложность v1.0;
- четкая security boundary через Nginx;
- audit point централизован в AGP;
- storage отделен интерфейсами, есть путь к HA.

Компромиссы:

- single-node rate limiting остается локальным;
- Nginx config применяется вручную;
- enterprise identity integrations вынесены в следующие версии;
- SQLite не подходит как основной production backend.
