# Постоянный тестовый стенд текущего AGP

`prepare.py` — отдельный явный путь для разрешённого тестового стенда, не замена
`install.sh`/`update.sh` и не подтверждение поддержки Ubuntu 26 публичным релизом.
Он использует настоящие текущие CP, independent journal, PostgreSQL, Auth mTLS и
embedded Angular UI. Mock-сервисы и legacy profile не запускаются.

Перед запуском оператор проверяет хеши собранных `agp`, `agpctl`,
`agp-security-journal`, PostgreSQL и Nginx runtime. Все executable paths и предки
должны принадлежать root и быть недоступны другим пользователям на запись.
Nginx runtime содержит `bin/nginx`, `lib/ld-linux-x86-64.so.2` и проверенную library
closure. Использование Ubuntu 24 userspace на Ubuntu 26 kernel не квалифицирует
Ubuntu 26 как релизную платформу.

```bash
sudo python3 /root/reviewed/prepare.py prepare \
  --management-host 192.0.2.19 --login-host login.agp.test \
  --portal-host portal.agp.test \
  --bin-dir /opt/agp-lab/app/bin \
  --pg-bindir /opt/agp-lab/postgres/usr/lib/postgresql/18/bin \
  --nginx-runtime-root /opt/agp-lab/waf-runtime
```

Подготовка создаёт `/etc/agp-lab`, `/var/lib/agp-lab`, отдельных системных
пользователей и `agp-lab-*.service`; listeners ещё не запускаются. Существующие
каталоги и service accounts отклоняются, файлы не перезаписываются.
После проверки созданных файлов:

```bash
sudo python3 /root/reviewed/prepare.py activate
```

Активация создаёт **два независимых PostgreSQL clusters**, отдельные DB owners и
непривилегированные application roles. Доступ только по Unix sockets с peer map;
TCP PostgreSQL отключён. Journal имеет собственные process/cluster/user, Ed25519
signer и mTLS PKI. Independent approval private key остаётся в root-only operators
каталоге и не передаётся CP/journal. Browser TLS и central Auth mTLS используют
отдельные CA. MFA keyring не входит в CP data directory.

Каталоги `/etc/agp-lab/cp` и `/etc/agp-lab/journal` принадлежат
`root:<service group>` с режимом `0750`: процессы читают свои private keys/keyring
(`service owner`, `0600`), но не могут подменить config files через родительский
каталог. Environment files принадлежат root (`0600`, читает systemd); journal
`config.json` — `root:agp-lab-journal`, `0640`. Offline CLI получает environment
через root-only deployment descriptor.

Nginx master и workers работают как `agp-lab-web`; единственная capability —
`CAP_NET_BIND_SERVICE` для портов 80/443. Listener key и конфигурация доступны этой
группе только для чтения (`root:agp-lab-web`, `0640`), каталог browser — `0750`.
Приватные CA keys и ключи CP/journal этому пользователю недоступны.

Bootstrap admin создаётся штатным CLI до secure authority activation; global
`config.approve` выдаётся штатным preactivation manifest. Затем включаются
`AGP_SECURE_PROFILE=true`, `AGP_CONFIGURATION_ENABLED=true`, secure cookies и
writer/journal guards. Первый вход требует настройки TOTP; пароль без MFA не даёт
management session. Скрипт не печатает пароль, seed, private key или environment.

Вход: **`https://192.0.2.19/config-ui/`**; directory UI — `/directory-ui/`,
authentication UI — `/auth-ui/login`. HTTP 80 перенаправляется на HTTPS 443.
Для входа в management DNS и SSH tunnel не нужны. `login.agp.test` и
`portal.agp.test` зарезервированы для отдельного login/application SSO; перед его
использованием потребуются реальные DNS/hosts records и отдельная настройка EdgeAuth.

Это частная лабораторная CA, браузер без её установки покажет предупреждение.
Публичный CA certificate: `/etc/agp-lab/public/browser-ca.pem`; private CA keys
доступны только root. Начальный пароль лежит в
`/etc/agp-lab/operators/bootstrap-admin.password` (root `0600`), username — `admin`.
Получайте пароль через доверенную административную сессию, не сохраняйте в отчётах.
TLS leaf certificates действуют 90 дней, CA — 365 дней; автоматического renew нет.

Checkpoint files в `/etc/agp-lab/operators/stage-*` позволяют продолжить после
ошибки, но **не обеспечивают автоматический rollback**. Если CLI/PG операция
прошла, а запись checkpoint не произошла, остановитесь и сопоставьте фактическую
БД/authority с маркером; не удаляйте данные и не повторяйте activation вслепую.
Скрипт не сбрасывает существующие clusters или journal.

Проверка после установки: `systemctl is-active agp-lab-{pgcp,pgjournal,journal,cp,frontdoor}`,
`curl --cacert /etc/agp-lab/public/browser-ca.pem https://192.0.2.19/auth/v2/bootstrap`,
реальный browser login → TOTP → config/directory UI и запрет management API без
cookie. Не объявляйте развёртывание успешным только по завершению скрипта.

Для остановки сначала `systemctl stop agp-lab-frontdoor agp-lab-cp`, затем journal
и clusters. Не откатывайте journal вместе с CP backup. Эксплуатационные процедуры
находятся в [operations.md](../../docs/operations.md). Скрипт не изменяет SSH,
firewall, GRUB, существующие app units, публичный release repository или DNS.
