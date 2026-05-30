# Nginx Рекомендации

AGP генерирует Nginx configuration bundle/snippet на основе ресурсов, но не
применяет его автоматически. Это сделано намеренно: Nginx является production
data plane, и изменение конфигурации должно проходить review, `nginx -t` и
контролируемый reload.

## Рабочий Процесс

1. Администратор создает или изменяет ресурс в AGP.
2. В админке нажимает `Nginx bundle` или запрашивает snippet ресурса.
3. Проверяет сгенерированный config.
4. Вставляет config в `/etc/nginx/conf.d/agp-portal.conf` или отдельный файл.
5. Проверяет:

```bash
sudo nginx -t
```

6. Применяет:

```bash
sudo systemctl reload nginx
```

## Path-Based Модель

Основная production-модель: один публичный portal host и много защищенных paths.

Пример metadata:

```text
public_host=enter.company.ru
public_path=/anything-needed
internal_url=http://app.internal.local/anything-needed
```

Пользователь открывает:

```text
https://enter.company.ru/anything-needed
```

Nginx выполняет `auth_request /_agp_auth`, AGP проверяет сессию, группы и CIDR,
после чего Nginx делает `proxy_pass` во внутренний сервис.

## Redirect И Cookies

Path-based snippets включают:

- `proxy_redirect` для переписывания upstream `Location`;
- `proxy_cookie_path`;
- `proxy_cookie_domain`.

Это нужно для legacy-приложений, которые после входа делают redirect вида:

```text
Location: http://app.internal.local/anything-needed/ru_RU
```

Через AGP такой redirect остается внутри публичного path:

```text
https://enter.company.ru/anything-needed/ru_RU
```

## Access Denied

Сгенерированный config отправляет `403` на:

```text
https://<portal-host>/access-denied
```

AGP намеренно показывает одинаковую поверхность отказа для неизвестных и
запрещенных ресурсов. Это снижает риск перебора entry points.

## CSP И Legacy Apps

AGP backend отправляет CSP для собственных страниц портала. Nginx bundle не
добавляет `Content-Security-Policy` на общем `server` level, потому что
проксируемые legacy-приложения часто используют inline scripts/styles.

Если добавить CSP в общий Nginx server, можно сломать ресурс, который напрямую
работает, но через портал начинает показывать ошибки CSP в браузере.

## Upload Limit

Bundle задает:

```nginx
client_max_body_size 256m;
```

Это соответствует дефолтному:

```env
AGP_DOWNLOAD_MAX_BYTES=268435456
```

Если лимит AGP увеличен, Nginx `client_max_body_size` должен быть не меньше
AGP-лимита плюс multipart overhead.

## TLS Пути

Генератор использует нейтральные placeholder paths:

```nginx
ssl_certificate /etc/nginx/ssl/portal/cert.pem;
ssl_certificate_key /etc/nginx/ssl/portal/private.key;
```

Перед применением их нужно заменить на реальные файлы сертификата.
