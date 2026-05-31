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

## Troubleshooting

### Новый Ресурс Возвращает В Портал

Если старые точки входа работают, а новая при клике открывает портал, чаще всего
в активном Nginx config нет `location` для нового `public_path`. Запрос
попадает в fallback:

```nginx
location / {
    proxy_pass http://agp_backend;
}
```

Проверка на сервере:

```bash
sudo nginx -T 2>/dev/null | grep -n "location \\^~ /anything-needed"
```

Замените `/anything-needed` на реальный `public_path`. Если строки нет:

1. откройте AGP admin;
2. нажмите `Nginx bundle`;
3. скопируйте новый bundle в `/etc/nginx/conf.d/agp-portal.conf`;
4. сохраните реальные `ssl_certificate` paths;
5. примените:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### Как Отличить Причины

| Симптом | Вероятная причина | Проверка |
| --- | --- | --- |
| Открывается портал вместо ресурса | нет `location` для `public_path` в Nginx | `sudo nginx -T \| grep "location \\^~ /path"` |
| Открывается `/access-denied` | AGP отказал по группе, CIDR, disabled resource или session | audit tab, `journalctl -u agp` |
| Ошибка DNS/upstream | Nginx не резолвит или не достигает `internal_url` | `curl -I http://internal.host/path` с Nginx/AGP host |
| CSP errors в консоли | CSP остался в Nginx server или его ставит upstream | `curl -k -I https://portal/path \| grep -i content-security-policy` |

### Минимальный Debug Набор

```bash
sudo nginx -t
sudo nginx -T 2>/dev/null | grep -n "location \\^~ /anything-needed"
curl -k -I https://portal.company.ru/anything-needed/
journalctl -u agp -n 100 --no-pager
sudo tail -n 100 /var/log/nginx/agp.portal.access.log
sudo tail -n 100 /var/log/nginx/agp.portal.error.log
```
