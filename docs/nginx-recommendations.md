# Nginx Рекомендации

AGP генерирует Nginx configuration bundle/snippet на основе ресурсов, но не
применяет его автоматически. Это сделано намеренно: Nginx является production
data plane, и изменение конфигурации должно проходить review, `nginx -t` и
контролируемый reload.

## Версия и native qualification

Текущий project pin — **Nginx stable 1.30.8**, закреплён в
[`scripts/nginx-toolchain.env`](../scripts/nginx-toolchain.env) и используется
`install.sh`. Обновление pin требует отдельного review и qualification. Обязательны статически
собранные `http_auth_request`, `http_ssl`, `http_v2` modules. Версию, configure
flags, пакет, architecture и используемые библиотеки нужно сохранять в CI evidence.

Текущий native WAF tuple использует собранный Ubuntu 24.04 amd64 bundle и его loader;
те же Nginx bytes запускаются в общем S0/S1/WAF harness. Единый
`scripts/test-waf-full.sh` завершился PASS 2026-11-18, включая три native Nginx группы.
Принятый AS-IS ограничен Ubuntu 24 userland на host kernel `7.0.0-38-generic`;
другой APT package с тем же version string требует собственной qualification.
Для текущего pin 1.30.8 подтверждены сборка, 25/25 native WAF cases и отдельное
HTTPS/browser продолжение и последующая штатная native syntax-проверка с production
лимитами. Общий lifecycle pipeline сохраняет exit 1 на проверке владельцев каталогов
в том запуске; полноценная Ubuntu 24 host/root bridge qualification остаётся OPEN.
[Команды и границы](v2/testing.md#component-repository-и-native-waf-принятый-as-is).

Из непривилегированной учётной записи укажите предварительно проверенный binary:

```bash
AGP_TEST_NGINX_BIN=/path/to/verified/nginx sh scripts/test-nginx.sh
```

Harness сравнивает `nginx -V` с pin, проверяет modules и запускает весь пакет
`internal/reverseproxy/nginx` с `-count=1` и timeout 3 минуты. Ошибка, любой `SKIP`
или отсутствие успешных `TestNativeIdentityHeaderSpoofing` и
`TestNativeManagementHostIsolation` останавливает проверку.
Suite поднимает Nginx и HTTP upstreams на loopback в временных директориях;
production config и service не используются. Для запуска нужны разрешённые
локальные sockets. `go test ./...` без `AGP_TEST_NGINX_BIN` этот native сценарий
пропускает и не закрывает qualification.

Проверяются подмена identity headers и очистка неподтверждённой identity для
server/path proxy locations, неизвестный Host на management listener и порты redirect.
TLS/HTTP2 handshake, cookies, browser SSO,
WAF/ModSecurity/CRS и production reload этой suite не квалифицируются.
Отдельный HTTPS browser harness описан в [проверках S0](v2/testing.md);
переход на management isolation — в [runbook](operations.md).

Историческое provenance S0/S1b сохранено для официального пакета `nginx_1.30.6-1~resolute_amd64.deb`
на Ubuntu 26.04 x86_64. Provenance: подпись `Release.gpg` проверяется ключом
`8540A6F18833A80E9C1653A42FD21310B49F6B46`, затем SHA256 `Packages` из `Release`
и SHA256 пакета из `Packages`. Этот fingerprint опубликован в
[официальной документации Nginx](https://github.com/nginx/documentation/blob/main/content/nginx/admin-guide/installing-nginx/installing-nginx-open-source.md).
SHA256 проверенного `.deb`:

```text
a0cdf00d73634b9223d7e83a08dd445260ae16059926ec89d05dd10556650dd5
```

Это evidence именно `.deb` 1.30.6; оно не переносится на package 1.30.7.
Другие `.deb`, OS/architecture/kernel требуют собственного native прогона:
одинаковый upstream version не подтверждает другую сборку и её библиотеки.

## Установка и обновление

`install.sh` ставит только закреплённую stable из подписанного `nginx.org` APT
repository на чистый host. `NGINX_VERSION` можно задать явно; несовпадение с
reviewed pin завершается ошибкой. Если Nginx, `/etc/nginx` или целевые repository
files уже существуют, installer прекращает Nginx setup до установки пакетов.
Для сохранения существующего Nginx выберите «no» на вопрос его установки и
настройте proxy самостоятельно. Повторный запуск installer не является upgrade.
APT preference разрешает только закреплённую ветку patch version; обновление pin
требует review и повторной qualification, включая исправления безопасности.

Отдельный upgrade выполняется в согласованное окно: сохранить `/etc/nginx`,
вывод `nginx -V` и точные версии всех модулей/пакетов; заранее получить проверенный
старый пакет для отката. Проверить новый tuple и bundle на стенде, затем отдельно
согласовать изменение production. После установки согласованного точного пакета
с сохранением конфигурации выполнить `nginx -t`, контролируемый reload и smoke
разрешённого/запрещённого доступа. При ошибке восстановить совместимые прежние
binary/modules и конфигурацию, снова проверить синтаксис и smoke. `update.sh`
обновляет AGP и не выбирает новую версию Nginx.

## Рабочий Процесс

Этот workflow относится к legacy v1/S0.2a. В secure profile legacy resource snippet
и bundle API возвращают `409 edge_auth_configuration_required`; используйте EdgeAuth
и генератор `nginx-edge` по следующему разделу.

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

## EdgeAuth для secure S0 pilot

Management и login vhosts обслуживают CP browser listener, private Central Auth
доступен только по отдельному mTLS listener. Для каждого app origin запускается
отдельный `agp-edge-auth -config FILE` с fixed gateway/node/generation/routes и private UDS.
[Config example](../configs/edge-auth.example.json) и [activation runbook](operations.md#s0-pilot-активация-и-восстановление).
URI SAN client certificate имеет namespace `spiffe://agp/edge/<nodeId>/<gatewayId>`;
agent-role certificate не заменяет EdgeAuth identity. Public HTTP headers не являются
доказательством mTLS client identity.

[CLI](../cmd/agpctl/edge_nginx.go) вызывает [генератор](../internal/reverseproxy/nginx/edge_generator.go):

```bash
agpctl nginx-edge --origin https://app.example.com \
  --socket /run/agp-edge-example/edge.sock \
  --certificate /etc/nginx/ssl/gateway/cert.pem \
  --key /etc/nginx/ssl/gateway/private.key > edge-example.conf
```

Команда выводит snippet в stdout; установка/reload не выполняются. Origin, UDS и
TLS file paths должны совпадать с подготовленным оператором profile.
Генератор создаёт per-origin names
и `/_agp/authorize` как internal auth subrequest, публичные `/_agp/start`,
`/_agp/callback`, `/_agp/logout`, закрывает остальные `/_agp` paths.
Проверенный allow adapter возвращает статус;
Central Auth JSON нельзя направлять напрямую в Nginx `auth_request`.
Все application request **и response** bytes проходят EdgeAuth proxy через UDS:
иначе Nginx-only auth_request не фильтрует upstream `Set-Cookie`. Cookie allowlist
и зарезервированные AGP cookies обрабатываются в обе стороны, trusted identity
задаётся адаптером. Прямой proxy fallback к app upstream запрещён.

Socket/state каждого процесса различаются; каталог socket не writable посторонним,
UDS доступен только EdgeAuth/Nginx accounts. Генератор использует TLS file paths
оператора и не устанавливает PKI/config. Установка вручную: закрытый трафик → review
vhosts/paths/certificates → `nginx -t` → controlled reload → allow/deny/logout smoke.
Native EdgeAuth tests и реальный четырёх-origin HTTPS/HTTP2 сценарий входят в
[общий S0 harness](v2/testing.md#текущий-пакет-s0-команды-и-границы); WAF и production
reload этими стендовыми результатами не квалифицируются.

## Path-Based Модель

Legacy v1/S0.2a модель: один публичный portal host и много защищённых paths.
Secure S0 pilot использует отдельные management/login/application hostnames и EdgeAuth
по разделу ниже; path-based legacy bundle не включает эти гарантии.

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
