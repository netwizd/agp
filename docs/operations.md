# Эксплуатация AGP

## S0 pilot: активация и восстановление

Для оператора ограниченного single-node стенда с доступом к CP, отдельному journal,
PKI/key store и service manager. Нужны проверяемые backup и окно обслуживания.
Это инструкции, не выполненная установка/выкладка. Systemd units
[CP](../deploy/systemd/agp.service), [journal](../deploy/systemd/agp-security-journal.service),
[EdgeAuth](../deploy/systemd/agp-edge-auth@.service) — templates; пользователи, права,
PKI, firewall и доступ Nginx к private UDS подготавливаются отдельно.

Предпосылки: CP подключается **напрямую к PostgreSQL primary**; PgBouncer
transaction/statement pooling не квалифицированы для session advisory lease.
Journal требует отдельного PostgreSQL cluster/data-dir, собственной учётной записи
и restore domain: другой database в CP cluster недостаточно. Credentials, CA и
Ed25519 signing key отдельные; independent approver key не передаётся CP/journal signer.
MFA keyring хранится отдельно от CP backup: приватный regular `0600` JSON
`{"active":"key1","keys":{"key1":"<32 bytes base64url без padding>"}}`.
Пример содержит placeholder, не готовый ключ. Его потеря не устраняется обходом MFA.

### Активация

1. Закройте внешний трафик, остановите/drain **все** старые CP writers/listeners и
   in-flight mutations. Сохраните CP DB/downloads/config, journal/head и ключи
   раздельно. Не запускайте старый binary параллельно новому: он не знает новых guards.
2. Подготовьте journal из [example JSON](../configs/security-journal.example.json),
   заменив все placeholders и настроив trusted approver registry. В его отдельном
   environment задайте `AGP_JOURNAL_DATABASE_DSN`; проверьте authority/key IDs и PKI:

   ```bash
   agp-security-journal migrate -config /etc/agp-journal/config.json
   agp-security-journal verify -config /etc/agp-journal/config.json
   agp-security-journal serve -config /etc/agp-journal/config.json
   ```

   Последняя команда запускает отдельный foreground service. `verify` проверяет
   chain, не заменяет readiness CP или restore drill.
3. В CP environment из [example env](../configs/agp.example.env) задайте
   `AGP_SECURE_PROFILE=true`, отдельные HTTPS management/login origins, `AGP_PORTAL_HOST`,
   MFA keyring, Auth mTLS listener и все семь `AGP_JOURNAL_*` client variables.
   Управление, login и app hostnames различаются даже при разных портах.
   До первой активации существующий локальный administrator обязателен; если его нет,
   разрешён явный bootstrap при закрытых listeners:

   ```bash
   AGP_SECURE_PROFILE=false agpctl create-admin -username bootstrap-admin
   agpctl identity-profile --preview
   agpctl identity-profile --activate --revoke-sessions
   agpctl security-state ready
   ```

   `create-admin` читает пароль из stdin и не нужен, если administrator уже существует;
   после secure activation он запрещён. Preview читает head/config без активации,
   не доказывает готовность всей установки. Activate применяет embedded migrations,
   требует пустой новый journal и атомарно фиксирует profile/authority/grants/reset.
   Existing authority восстанавливается по процедуре ниже, не повторной активацией.
4. Соберите auth assets **до Go binary**, поскольку они embedded:
   `npm --prefix web/console-prototype run build:auth`. Запустите новый CP только
   с совпадающим environment; проверьте `/readyz` и management `/auth-ui/login`.
   Password-only доступа нет: завершите TOTP enrollment, сохраните recovery codes
   вне browser/session и проверьте fresh MFA login. Создание final-password users,
   admin password reset и расширение privileged grants пока отклоняются; delivery
   общий positive-grant approvals workflow ещё не реализован. Invitations/setup и
   supervised recovery реализованы в описанном ниже интегрированном срезе.
5. Создайте/проверьте resource в management UI. Для регистрации gateway остановите
   CP: CLI использует тот же writer lease. `S0_RESOURCE_ID` ниже — реальный ID
   этого ресурса, остальные значения должны совпадать с private EdgeAuth JSON:

   ```bash
   agpctl gateway-register --id gw_example --node node_local_1 \
     --origin https://app.example.com --callback https://app.example.com/_agp/callback \
     --resource "$S0_RESOURCE_ID" --generation dep_000017
   agp-edge-auth -config /etc/agp-edge/example/config.json
   ```

   Последняя команда — отдельный service по [example](../configs/edge-auth.example.json).
   Для второго приложения нужны свои IDs, cert identity, UDS и state path. Родитель
   socket не writable другими accounts; stale/existing socket не удаляется startup.
   Разрешите UDS только нужным Nginx workers; не публикуйте его по TCP.
6. Верните CP. При закрытом трафике установите reviewed TLS/vhosts: management/login
   направляются в CP, приложение — целиком в EdgeAuth, включая request/response bytes.
   App snippet можно подготовить без установки/reload:

   ```bash
   agpctl nginx-edge --origin https://app.example.com \
     --socket /run/agp-edge-example/edge.sock \
     --certificate /etc/nginx/ssl/gateway/cert.pem \
     --key /etc/nginx/ssl/gateway/private.key > edge-example.conf
   ```

   Замените пути фактическими из своего config. Legacy snippet/bundle API в secure
   profile возвращает `409 edge_auth_configuration_required`; v1 workflow ниже
   не применяют для обхода EdgeAuth.
   Выполните `nginx -t`, controlled reload и smoke login→MFA→handoff→allow/deny,
   logout/revoke, journal outage fail-closed; затем открывайте трафик.
   [Namespace и границы Nginx](nginx-recommendations.md#edgeauth-для-secure-s0-pilot).

### Контролируемый CP restore и rollback

Остановите/fence все CP writers **до** подготовки epoch, закройте трафик и сохраните
текущие CP данные. Независимый journal/keys не откатывайте. Нужны совместимый CP dump,
реальный trusted writer cutoff и проверенная bound clock skew. `RESTORE_FENCED_AT`
(RFC3339Nano) и `RESTORE_MAX_CLOCK_SKEW` (duration) ниже — локальные переменные примера;
не подставляйте текущее время вместо доказанного окончания жизни старого writer.
CLI принимает cutoff не старше 5 минут и skew от 0 s до 5 min; при задержке заново
подтвердите fencing, а не редактируйте подписанный JSON.

```bash
umask 077
agpctl security-state head
agpctl security-state prepare-restore --actor restore_operator --writers-fenced \
  --writer-fenced-at "$RESTORE_FENCED_AT" --max-clock-skew "$RESTORE_MAX_CLOCK_SKEW" \
  > restore-request.json
```

Независимый approver проверяет запрос и подписывает его своим ключом отдельно:

```bash
agp-security-journal approve --request restore-request.json \
  --approval-key /secure/approver.pk8.pem --approval-key-id restore_approver_1 \
  --approver distinct_approver > restore-approved.json
```

Approver/key/kind должны быть зарегистрированы в journal; actor и approver различаются.
В CP operator environment выполните append **до native restore**. Следующая команда
`pg_restore --clean` разрушительна: заранее настройте приватный libpq service
`agp_cp_restore` только для выбранной fenced CP БД; backup и текущие данные сохранены.
Этот service не должен ссылаться на journal. Credentials храните в защищённом
service/passfile, не подставляйте password-bearing DSN в argv.

```bash
agpctl security-state append-approved --request restore-approved.json
pg_restore --clean --if-exists --no-owner --no-acl \
  --dbname='service=agp_cp_restore' /secure-backups/cp.dump
agpctl security-state replay
agpctl security-state ready
```

При конфликте head подготовьте и согласуйте новый запрос; после потери append response
CLI разрешает committed operation по ID/digest. Replay материализует restrictive history;
ready остаётся закрыт до journal `releaseAfter`: CLI задаёт cutoff + 90 s + verified skew
+ 1 s. Дождитесь этого срока и повторите `ready`; не обнуляйте epoch/floors/pending.
Затем запустите текущий совместимый CP, проверьте `/readyz`, новый MFA login, старые
sessions/password/TOTP/recovery rejection, gateway allow/deny и audit, затем открывайте
трафик. Backup/restore journal и восстановление всех ключей — отдельная процедура.

`ready` подтверждает актуальность security projection и окончание quarantine, а не
наличие пригодных credentials в старом backup. Если восстановленный hash/seed ниже
floor, вход останется закрытым. Универсальный административный credential reset
в pilot не реализован: нужен отдельный проверенный план восстановления доступа;
вручную повышать version старого материала или снимать floor запрещено.

Binary rollback разрешён только на проверенную совместимую secure сборку с тем же
profile/journal/keyring; старый CP dump требует описанного replay. `session-profile`
reset в legacy после secure activation запрещён. Pre-009 binaries и совместный rollback
CP+journal/VM snapshot вне restore guarantees; автоматического обнаружения любого
restore и HA здесь нет. При неполной проверке оставьте трафик закрытым.

## Контакты и SMTP (opt-in)

Для оператора secure PostgreSQL CP с доступом к service manager и отдельному key store.
Это optional AS-IS contact confirmation; invitations/supervised recovery добавлены
отдельным integration stage ниже.
До включения нужны доверенные SMTP hostname/CA, разрешённые egress CIDRs, test mailbox
и окно перезапуска CP. Сохраните прежние environment/config и раздельные backups CP DB
и key store. Перезапуск теряет volatile outbox keys: прежние задания не отправляются
заново; пользователь запрашивает новый код. На production эта процедура пока не квалифицирована.

1. Подготовьте absolute clean paths без symlinks. Config, secret manifest, email keyring
   и password должны быть regular files с mode `0600` или строже и читаться effective
   UID CP. Владельцы — root либо UID CP; предки не должны разрешать запись group/others.
   CA также должна иметь проверенные owner/path и не быть доступной посторонним на запись.
   Не храните ключи/пароль внутри CP DB/backup, исходников или browser storage.
2. Создайте отдельный keyring `agp.email-keyring/v1alpha1` с полями `activeEncryption`,
   `activePepper`, `encryption` и `peppers`. Последние два — maps `keyId → base64url`
   **без padding**, каждое значение кодирует независимые случайные 32 bytes. IDs и bytes
   между двумя email namespaces различаются; bytes не совпадают с MFA keys. Existing ID
   сохраняет immutable bytes;
   retained encryption keys нужны для прежних contacts, peppers — как минимум для
   текущих challenges и часового target budget. Генератор keyring CLI пока не поставляется.
3. Подготовьте immutable secret references. Пример manifest ниже содержит placeholders:
   замените каждый digest точным SHA-256 **bytes файла**, включая перевод строки, если он
   присутствует. Password читается как bytes без trim; его файл не должен содержать
   случайный завершающий newline. CA file содержит доверенный PEM bundle.

   ```json
   {
     "apiVersion": "agp.external-secrets/v1alpha1",
     "secrets": [
       {"versionId":"smtp_pass_1","purpose":"smtp_password","file":"/etc/agp/email/smtp-password","contentDigest":"sha256:<64 lowercase hex>"},
       {"versionId":"smtp_ca_1","purpose":"smtp_ca","file":"/etc/agp/email/smtp-ca.pem","contentDigest":"sha256:<64 lowercase hex>"}
     ]
   }
   ```

4. Создайте protected config; hostnames, адреса и CIDR ниже синтетические и требуют
   замены на installation policy. `allowedCidrs` содержит canonical prefixes; **все**
   DNS answers SMTP hostname должны входить в них. TLS проверяет исходный hostname.

   ```json
   {
     "apiVersion": "agp.email/v1alpha1",
     "keyringFile": "/etc/agp/email/keyring.json",
     "secretsManifest": "/etc/agp/email/secrets.json",
     "allowedCidrs": ["192.0.2.0/24"],
     "smtp": {
       "host":"smtp.example.test", "port":465, "transport":"implicit_tls",
       "helloName":"agp.example.test", "from":"agp@example.test",
       "authentication":"plain", "username":"test-sender",
       "passwordVersionId":"smtp_pass_1", "caVersionId":"smtp_ca_1",
       "operationTimeoutSeconds":15
     }
   }
   ```

   Допустимы только `implicit_tls` или `required_starttls`, без plaintext fallback;
   timeout обязателен, `1..30` seconds. Для явного trusted relay profile допустим
   `authentication=none` с пустыми `username`/`passwordVersionId`; CA остаётся обязательной.
   Unknown JSON fields отвергаются. SMTP fields не принимаются через HTTP API.
5. В CP environment задайте `AGP_EMAIL_CONFIG_FILE=/etc/agp/email/config.json`, затем
   выполните согласованный restart существующего `agp` service. Startup проверяет
   файлы/ссылки/hash, но не соединяется с SMTP и не подтверждает доставку. Проверьте
   `/readyz`, повторный primary+MFA login и own-contact confirmation на test mailbox.
   Для изменения contacts primary и MFA должны быть не старше пяти минут. Успешная
   замена адреса отзывает прежние sessions: нужен новый login и подтверждение адреса.

При `email_configuration_rejected` проверьте path/owner/mode, closed JSON, immutable
version/purpose/digest и отдельные key namespaces. `email_unavailable` не раскрывает
SMTP diagnostics/credentials. Final SMTP `250` означает acceptance, а не доставку;
публичный `failed` может означать потерянный ответ после DATA. Не переотправляйте такой
outbox job вручную и не меняйте его state: запросите новый challenge через приложение.

Rollback: остановите/drain CP и верните прежний installation config либо очистите
`AGP_EMAIL_CONFIG_FILE`, затем запустите **совместимый** binary. Не удаляйте migrations,
не откатывайте journal/floors и не возвращайте старые key bytes под новым смыслом.
Замена secret bytes/manifest требует согласованного нового startup; очередной restart
не восстанавливает volatile DEKs. Отсутствие corporate SMTP приёмки остаётся OPEN.

## Приглашения, активация и recovery (stage)

Для оператора, пользователя setup и независимого recovery approver.
Код перенесён в основной workspace; production установка и combined lifecycle acceptance
не заявляются. Нужны secure PostgreSQL profile, независимый journal, отдельный SMTP
профиль/ключи из предыдущего раздела и backup/key store вне общей области restore.
Новые lifecycle services используют текущий identity runtime; отдельный env toggle для
обхода pending/floors не вводится. Build auth/directory assets выполняется до Go binary.

1. В management `/directory-ui/?view=identity` создайте pending local user без финального
   пароля и permission-bearing grants. Username сохраняется lowercase по текущей local
   policy. `POST /api/v2/users` возвращает `201` и ETag. Normal login/session/EdgeAuth
   не допускают `lifecycleState=invited`.
2. Выдайте invite на утверждённый адрес: `POST /api/v2/users/{id}/invites` требует exact
   `If-Match`, idempotency key, current actor/target и fresh primary/MFA. Ответ `201`
   содержит только invite/delivery IDs и expiry. Проверяйте status через
   `/api/v2/identity-deliveries/{id}`; raw 256-bit token не восстанавливается из API/logs.
   Unknown SMTP outcome не повторяйте вручную: согласуйте новое приглашение.
3. Пользователь открывает `/auth-ui/activate` из письма. Reservation привязывает token
   к одному rotated flow/browser binding. Последовательность обязательна: пароль →
   восьмизначный `invite_confirmation` на saved contact/version → TOTP enrollment →
   сохранение recovery codes → complete. Пропуск email proof запрещён. Finalization
   после durable floor receipts атомарно активирует credentials/principal и consumes
   invite, но session/handoff не выдаёт. После завершения выполните обычный login.
4. Для обычного local password reset используйте `/auth-ui/reset-password`. Public
   `POST /auth/v2/password-reset-requests` принимает username/email и возвращает
   одинаковый `202` с пустым body, без указания существования account или доставки.
   Получатель выбирается из verified contact. Email token сам недостаточен: требуется
   действующий TOTP; exact factor version и proof time проверяются при finalization.
   Directory password меняется средствами организации.
5. Если независимый factor утрачен либо target привилегирован, создайте purpose-specific
   recovery plan: `replace_mfa`, local `reset_password` или invited-only `restart_activation`.
   Второй approver сверяет exact digest/target/action; executor повторно подтверждает
   current primary/MFA/permissions. Live AD evidence нужна также для автора, reviewer,
   target и executor. После restrictive receipts ticket первых двух actions выдаётся
   custodian один раз и используется на `/auth-ui/recovery-ticket`. Ticket не возвращается
   повторно после потерянного ответа. Restart activation ticket не выдаёт: после applied
   создайте обычный новый invite и повторите весь password/email/TOTP setup.

При `identity_preconditions_changed` обновите current object/ETag и проверьте floors;
не понижайте версии и не редактируйте token reservation прямым SQL. При потерянном binding,
cancel или expiry выпустите новый invite; unclaim не поддерживается. Перезапуск теряет
volatile delivery keys и не переотправляет старое письмо. Runtime cleanup удаляет
истёкшие anonymous flows и стирает staged secrets. После восстановленного invited snapshot ниже durable floors
нужен approved `restart_activation`, а не повторное включение старых credentials.

Rollback: закройте listeners и остановите/drain все writers, сохраните CP/config и
независимые journal/key backups раздельно. Возвращайте только schema-compatible binary;
не удаляйте migrations 029–031 и не откатывайте journal/floors вместе с CP snapshot.
Restore выполняется по [S0-процедуре](#контролируемый-cp-restore-и-rollback).
Stage tests не квалифицируют actual corporate AD DS/SMTP, root VM либо GA.

## AD-backed OIDC (opt-in)

Для оператора secure PostgreSQL CP, trust administrator и независимого approver.
Нужны работающий live AD connector, отдельные HTTPS management/login origins и
корпоративный IdP с code/PKCE S256, RS256 и `client_secret_basic`. OIDC использует
существующую AD identity, не заменяет AD live check и не создаёт link по email/UPN.
Этот runbook описывает локальный AS-IS; corporate IdP/AD DS приёмка ещё OPEN.

1. Подготовьте protected installation files по owner/mode/path правилам
   [SMTP-раздела](#контакты-и-smtp-opt-in): config, manifest и state keyring — `0600`
   или строже, без symlinks и writable ancestors, с доступом effective UID CP.
   Сохраните config/key store отдельно от CP backup и запланируйте окно restart.
   Формат state keyring:

   ```json
   {
     "apiVersion":"agp.oidc-state-keyring/v1alpha1",
     "activeKeyId":"oidc_state_1",
     "keys":{"oidc_state_1":"<32 independent random bytes as unpadded base64url>"}
   }
   ```

   Это placeholder, не готовый ключ. Поддерживается от 1 до 16 immutable key IDs;
   active ID присутствует в `keys`, bytes уникальны и не совпадают с MFA/email
   encryption/pepper keys. Не удаляйте ключи, нужные ещё действующим pending flows.
2. В `agp.external-secrets/v1alpha1` manifest добавьте отдельные secret references
   для login и management: `purpose=oidc_client`, разные immutable version IDs,
   paths и фактически разные secret bytes. Для доверенного CA PEM используйте
   `purpose=oidc_ca`. Reference содержит `versionId`, `purpose`, absolute `file`
   и `contentDigest=sha256:<точные 64 lowercase hex>` — как в SMTP manifest выше.
   Password/client secret читается без trim. Не помещайте secret bytes в provider JSON.
3. Подготовьте connector policy; синтетические hostname/CIDR заменяются реальными
   trusted installation values. Origin allowlist включает issuer и все origins
   authorization/token/JWKS endpoints. Все DNS answers обязаны входить в CIDR allowlist;
   TLS всегда проверяет исходный hostname/CA.

   ```json
   {
     "apiVersion":"agp.oidc-connector/v1alpha1",
     "stateKeyringFile":"/etc/agp/oidc/state-keys.json",
     "secretsManifest":"/etc/agp/oidc/secrets.json",
     "httpsOrigins":["https://idp.example.test"],
     "allowedCidrs":["192.0.2.0/24"],
     "operationTimeoutSeconds":10,
     "maximumConcurrent":4
   }
   ```

   Timeout обязателен, `1..10` seconds; concurrent operations — `1..16`. Unknown
   fields, HTTP/plaintext, непроверенные redirects или environment proxy не являются
   fallback. В CP environment задайте `AGP_OIDC_CONNECTOR_FILE=/etc/agp/oidc/config.json`
   и выполните согласованный restart совместимого binary. Startup проверяет protected
   policy/key files; реальную доступность IdP подтверждает отдельный provider test.
4. На management `/directory-ui/?view=oidc` создайте disabled provider. Для его exact
   issuer зарегистрируйте два разных IdP client IDs: `login` и `management`. В каждом
   IdP client разрешите только соответствующий callback:
   `https://<configured-origin>/auth/v2/oidc/providers/<providerId>/callback`.
   Origin и provider ID должны совпадать с CP; пользовательский return URL не подставляется.
   Предложите immutable version с exact authorization/token/JWKS pins и разными secret
   references, выполните server-side test и отдельное independent approval/activation.
   Нормативные поля: [OIDC profile](v2/identity.md), [schema](v2/schemas/oidc-provider.schema.json).
5. Согласуйте explicit issuer/sub link к уже существующей DirectoryIdentity. Отдельный
   approver подтверждает exact link/target/digest; current AD account/groups/floors
   перепроверяются. В обоих origins проверьте OIDC primary → обязательный AGP TOTP →
   session и её отказ после revoke link/provider. `acr/amr` IdP не заменяют TOTP AGP.

`oidc_connector_configuration_rejected` требует проверки protected paths, closed JSON,
key namespaces и transport policy. Provider test не должен исправляться расширением
allowlist на произвольные hosts: сверяйте exact endpoints, CA, distinct clients/secrets
и DNS policy. Изменение manifest/secret bytes закрывает resolver до нового startup.
Не повторяйте code exchange после неизвестного результата. При потерянном callback
response приложение выполняет GET reconciliation только с уже полученным новым
binding cookie; если cookie не пришёл, начните новый login. `session_state` не задаёт
AGP session и не реализует IdP logout.

Startup закрывает interrupted `exchanging` и old-epoch `pending`, стирая их encrypted
proofs. Valid pending текущей epoch с retained state keys не отменяется только из-за
restart. Периодический cleanup удаляет terminal/expired proofs; остановка runtime
отменяет и ожидает worker. При замене keys сохраняйте immutable прежние bytes до
завершения/expiry связанных flows; старые коды не переобмениваются автоматически.

Rollback: при необходимости закройте OIDC вход, остановите/drain CP, верните проверенные
installation files либо очистите `AGP_OIDC_CONNECTOR_FILE` и запустите совместимый binary.
Не возвращайте старые CP/journal snapshots, floors или прежний enabled link прямым SQL.
Очистка connector env отключает новые OIDC exchanges, но сама по себе не отзывает
уже выданные sessions: текущие provider/link guards и live AD check сохраняются.
Для отзыва применяйте штатную disable/revoke операцию provider/link с journal floor;
local/email fallback не заменяет их. Поддерживаемая local bootstrap identity остаётся
отдельной процедурой.

## S1 authoring pilot

Опциональный редактор полного desired snapshot требует уже активированного S0 secure
PostgreSQL и доступного journal. Полный snapshot требует global `config.read/edit`;
existing admin сохраняет совместимость read/edit. Данные этого раздела — AS-IS pilot;
полная модель scopes/approval/publication из ТЗ сохраняется TARGET.
`AGP_CONFIGURATION_ENABLED=false` по умолчанию сохраняет S0. Запись требует exact
Origin, CSRF и MFA не старше 5 минут. Parser принимает closed JSON и ограниченный
safe YAML; [ограничения формата](v2/development.md#текущий-срез-s1--authoring-pilot).

Перед включением сохраните CP backup/config, выделите окно для остановки writer и
соберите `npm --prefix web/console-prototype run build:config` **до Go binary**.
Задайте `AGP_CONFIGURATION_ENABLED=true` в том же secure environment и запустите
новую сборку: embedded migration `012_configuration_core.sql` создаёт draft/revision/
catalog storage. Management entry — `/config-ui/`; пока persisted profile не активен,
canonical authoring не меняет существующую live configuration и не закрывает legacy CRUD.

1. Откройте editor после MFA login/step-up. Нормализуйте полный Configuration,
   создайте draft; autosave сохраняет версии с quoted ETag. При `412` сохраните локальный
   текст и явно загрузите server version либо создайте новый draft от актуального head.
   Повтор старого request key не заменяет новую запись.
2. Импортируйте immutable declared catalog и выполните preview. В
   [примере](v2/examples/catalog-authoring-pilot.json) Sites/nodes/inputs и повторяющиеся
   digest bytes — безопасные placeholders, согласованные с
   [example Configuration](v2/examples/configuration.json). Group ID должен ссылаться
   на **существующую** identity group: замените его одновременно в Configuration/catalog.
   Замените остальные IDs/digests своими declared references; `published` здесь не
   публикует WAF/certificate и не доказывает node/native qualification.
3. Создайте immutable full revision из конкретной версии draft. Base revision должна
   совпадать с текущим global head; stale draft/base получает конфликт. Прочитайте
   validation report: `authoringValid` и `deployable` имеют разный смысл. Даже при
   успешной authoring проверке pilot всегда `deployable=false`; artifacts нельзя
   устанавливать как квалифицированный Nginx/WAF bundle.
4. Для явного cutover canonical-only authoring остановите/drain CP и выполните тем же
   новым `agpctl` с тем же environment:

   ```bash
   agpctl configuration-profile --preview
   agpctl configuration-profile --activate
   agpctl configuration-profile --preview
   ```

   Preview read-only и требует уже применённой migration. Activate использует S0
   writer lease/journal barrier, требует существующий immutable head и фиксирует
   persisted DB fence/audit. Повторная активация — no-op; после неё preview `enabled:true`.
   Верните новый CP с env flag=true, проверьте head/draft/report и `409
   configuration_revision_required` для неподдерживаемых legacy resource writes.
   Restrictive disable/revokes сохраняются. Cutover не запускает reload/apply.

**Rollback:** после persisted activation env flag=false не отключает fence и новый
binary не стартует с такой конфигурацией. Не удаляйте marker и не снимайте DB triggers.
Допустим только совместимый binary с сохранённым canonical profile; возвращение
legacy writer или backup до cutover требует отдельного проверенного плана. Новых
privileged grants/approval workflow этот CLI не создаёт.

### Реализованный API S1

Все пути ниже находятся на management origin; prefix — `/api/v2/config`.
Кроме normalization `POST /documents`, persist/preview/validation POST и PUT требуют
`Idempotency-Key` по OpenAPI (16–128 букв/цифр/`_`/`-`). Повтор того же actor/operation/key с другим
содержимым — `409 idempotency_conflict`. Mutable version передаётся только как quoted
`If-Match`, например `"0"`; отсутствие — `428`, устаревшая версия — `412`.

| Метод / путь после prefix | Вход → результат |
| --- | --- |
| `GET /profile` | `enabled`, `headRevisionId?` persisted profile |
| `GET /access` | Текущие `principalId`, `authorityEpoch`, global/Site read/edit; optional `globalApprove`/`sites[].approve` показывают только явные grants и отсутствуют при false |
| `POST /documents` | `{format:"json"|"yaml", document:string}` → `content`, `contentDigest`, `canonicalJSON`, `yaml`; без сохранения |
| `POST /drafts`, `GET /drafts/{id}` | `{baseRevisionId?,content}` при create → полный `Draft` + ETag |
| `PUT /drafts/{id}` | `{content}` + If-Match → новая draft version/ETag |
| `POST /drafts/{id}/revisions` | `{}` + If-Match → immutable full `Revision` |
| `POST /drafts/{id}/previews` | `{catalogSnapshotId?}` → pinned `ValidationReport` |
| `POST /catalog-snapshots`, `GET /catalog-snapshots` | `{format,document}` при import → immutable metadata; list возвращает до 200 последних |
| `POST /revisions`, `GET /revisions`, `GET /revisions/{id}` | Полные create/list/read требуют global scope; `?gatewayId=` возвращает scoped `gatewayView` без `content`; `gatewayChange` сливается сервером под global CAS |
| `POST /revisions/{id}/validations` | `{}` → `202 AcceptedOperation`, Location/statusUrl ведёт к report |
| `GET /validations/{id}` | Ранее сохранённый report с exact target version/digests |

`GET /api/v2/operations/{operationId}` возвращает существующий `Operation` contract.
`AcceptedOperation` содержит `operationId`, `resourceId` отчёта, `statusUrl`,
`submittedAt`. Operation `succeeded` означает завершение расчёта, не deployability.
Report хранит `targetKind/targetId/targetRevision`, config/catalog/compiler pins,
issues/diff/preview и время. Draft preview при отсутствии ID берёт последний imported
catalog; revision validation также использует последний. Отчёт immutable: после
следующего autosave создавайте новый preview с новым key и сравнивайте target version.
Отсутствующий catalog возвращает report с `catalog_required`, а не ложный успех.

Catalog wire format — внутренний `agp.catalog/v1alpha1`: `id`,
`sourceKind=operator_declared`, `sourceRef`, UTC `recordedAt`, `sites`, `nodes`, `groups`,
`inputs`. Node содержит Site/labels/node groups. Input kinds: `access_policy`,
`waf_policy`, `ruleset`, `component_profile`, `certificate`, `policy_profile`,
`assignment_resolution`; запись pin-ит `kind/id/digest/siteId?`, `state=published`,
`baseExceptionCount`. Поле `profile` требуется только для kind `policy_profile`.
Повтор ID с иными bytes отклоняется; metadata `recordedAt` отражает время server import.
[Operator schema](v2/schemas/authoring-catalog.schema.json), [actual parser](../internal/configmodel/catalog.go), [API contracts](v2/api/openapi.yaml).

## S1b: scoped authoring и review зон

Для первоначального оператора PostgreSQL pilot. Scopes подготавливаются **до первой
secure authority activation** при остановленных CP writers, с backup и доступным
независимым journal. Нужны уже существующие unblocked principals; manifest не создаёт
пользователей. В шаге 3 активации S0, **перед** `identity-profile --activate`, выполните:

```bash
AGP_SECURE_PROFILE=false AGP_CONFIGURATION_ENABLED=false agpctl configuration-access \
  --bootstrap-manifest /secure-bootstrap/configuration-access.json
```

Manifest — strict JSON, не более 4 MiB; `grants` и `ownership` содержат до 10 000 записей.
Замените IDs реальными principals/Gateways/Sites. Минимальная форма для Site editor:

```json
{
  "grants": [
    {"principalId":"existing_editor","permission":"config.edit","scopeType":"site","scopeId":"site_msk"}
  ],
  "ownership": [{"gatewayId":"gw_portal","siteId":"site_msk"}]
}
```

Допустимы `config.read`, `config.edit`, `config.approve` и scopes `global|site`;
для global `scopeId` — пустая строка, `id` grant не задают. CLI атомарно сохраняет
epoch-bound grants/immutable Gateway→Site ownership и audit, выводит `bootstrapped:true`
с epoch/counts. После secure activation DB запрещает новые INSERT независимо от env;
действующий secure S0 не получает новые Site grants этой командой. Existing admins
сохраняют global read/edit **без implicit approve**. Отзыв grant материализуется из
journal `revoke_role_binding`; catalog не может выдать или перенести scope.

После обычного MFA login `GET /api/v2/config/access` показывает текущую область.
Site editor читает exact revision только с `?gatewayId=...`; response содержит
`viewScope=gateway`, `gatewayView`, digest **полного** snapshot и не содержит `content`.
Для записи `POST /api/v2/config/revisions` передают `{baseRevisionId,gatewayChange:{gatewayId,content}}`:
сервер сохраняет соседние объекты и проверяет global-head CAS. Site/Node selector,
ownership, component profile и TLS scoped editor не переносит. При `412` перечитайте
актуальный base; полный draft/report требует global scope, catalog import — current admin.

Для WAF authoring используйте `/api/v2/waf`:

| Путь | AS-IS |
| --- | --- |
| `GET /authoring-zones?siteId=...` | Site-filtered heads, `ZoneAuthoringSummary[]`, без fake desired state/counts; TARGET `/zones` пока недоступен (`404`) |
| `POST /zone-revisions`, `GET /zone-revisions/{id}` | TARGET `WafZoneRevision` без internal metadata extras; `zoneId/siteId/ownerId` читают из `content.metadata`. Следующий POST содержит exact текущий zone `baseRevisionId`; head mismatch — `412` |
| `POST /zone-revisions/{id}/previews`, `GET /zone-previews/{id}` | Exact `baseRevisionId`, `catalogSnapshotId`, `capacityProfile`, `action=reconcile|retire`, optional `replacementAssignments` → frozen hypothetical preview, TTL 30 min |
| `POST/GET /zone-previews/{id}/authoring-reviews` | POST `{previewDigest,reason}` → `purpose=draft_review`; GET — текущие/stale отметки |

POST требуют Idempotency-Key, Origin/CSRF и fresh MFA. Preview pin-ит Configuration,
catalog, resolver, все co-zone heads и exact revisions. Он всегда `deployable=false`
и не является trusted resolution. Reviewer имеет current Site edit, отличается от
zone author и preview creator. Head/co-zone/catalog/resolver/rights/epoch/expiry drift
делает review stale; создайте новый preview и независимый review. `config.approve` не
нужен для draft review и не превращает его в publication approval. Более поздний
[trusted workflow](#read-only-agent-inventory-и-trusted-waf-zones) использует отдельные
validation/approval/publication/resolution, не authoring review.

**Rollback:** authoring не меняет live bundle. Сохраняйте совместимый binary/profile
и immutable данные; не снимайте fences, ownership или grant triggers ради отката.
Поддерживаемого post-secure добавления grants/переноса ownership в S1b нет.
Единый прогон S1b подтверждён PASS 2026-11-18; [команды и границы проверки](v2/testing.md#s1b-проверки-нового-пакета).
Эта историческая проверка не квалифицирует последующие trusted workflows или apply.

## Component repository и базовые WAF policies

Пакет принят как ограниченный AS-IS 2026-11-18 по единому `scripts/test-waf-full.sh` PASS.
Он требует secure PostgreSQL
и `AGP_CONFIGURATION_ENABLED=true`; inventory/trusted zones добавлены следующим
срезом ниже. Gateway-local derivation/exceptions и helper/apply остаются TARGET. Existing
policy CRUD/validate/approve/publish contracts сохраняются. Поддерживается только
typed base policy с `exceptions=[]`; derivation/nonempty exceptions дают `422
unsupported_derivation|unsupported_exceptions`. Raw native directives запрещены.

Trust administrator отдельно готовит публичный anchor и private durable repository
вне CP backup/restore. Trust config содержит `root` (полный TUF root), `releaseKeys`
(ID → base64 public Ed25519 key), `releaseThreshold`, Ubuntu 24.04 amd64 `platform`,
строковые `minimumSequence`/`securityFloor`. Все TUF roles и release keys разделены;
ephemeral fixture roots нельзя переносить в installation trust. Нужны backup trust
state/keys и проверенный путь восстановления, не общий snapshot с CP.

Offline bundle содержит `bundle.json` с `manifestPath`/`rootVersions`, metadata
timestamp/snapshot/targets, release manifest и полную `objects/<sha256>` closure.
Metadata ограничены 4 MiB, один artifact — 256 MiB, вся release closure — 1 GiB.
Import выполняется отдельной учётной записью с правом записи store и настроенным
journal client из S0; он требует свежего подписанного head даже для offline bundle:

```bash
agpctl waf-repository --trust-config /etc/agp-waf/trust.json \
  --store /var/lib/agp-waf-repository --import-bundle /secure-import/waf-release
```

Ожидайте `imported:true`, exact release/manifest/profile digests и expiry. Verifier
проверяет TUF, независимую JCS/Ed25519 подпись manifest, complete CAS closure,
qualification corpus/harness/Go renderer/raw report и SBOM/license coverage; запись
metadata/floors durable. Ошибка не разрешает обход через unsigned local catalog.
CP получает только read-доступ к anchor/store; выдачу filesystem read после import
настройте отдельно, scratch принадлежит CP и не разделяется с app users. В CP env:

```env
AGP_WAF_TRUST_CONFIG=/etc/agp-waf/trust.json
AGP_WAF_REPOSITORY_DIR=/var/lib/agp-waf-repository
AGP_WAF_TEMP_DIR=/var/lib/agp-waf-scratch
```

Provider повторно читает trust config/objects/floors и получает fresh signed journal
time. Journal outage, expiry, release replacement или pin drift закрывают current proof;
локальный wall clock fallback отсутствует. Поддержан ровно tuple Ubuntu 24.04 amd64 /
Nginx 1.30.7 / connector 1.0.4 / libModSecurity 3.0.17 / CRS 4.30.0. Native corpus
прошёл 25/25 mandatory cases без SKIP; общий runtime acceptance завершился PASS
2026-11-18 на Ubuntu 24 userland и host kernel `7.0.0-38-generic`.
PRoot build не квалифицирует иной kernel или clean offline VM.

В этом tuple response-phase CRS 959100 закрывает TCP до HTTP status line: клиент
получает EOF и ноль response bytes, upstream уже обработал запрос. HTTP status
для такого блокирования не отправляется; body-limit reject подтверждён как HTTP 403.
Health checks/клиенты должны учитывать этот протокольный исход.
Native validation/current checks разделяют один nonblocking slot на CP process;
при `503 native_waf_busy` сервер даёт `Retry-After: 1`. Повторите запрос после паузы,
сохранив Idempotency-Key для того же действия.

Разработчик может отдельно получить текст typed native policy без запуска/import:

```bash
agpctl waf-render --policy /secure-input/base-policy.json \
  --bundle /opt/agp-waf-candidate --work /var/lib/agp-waf-scratch \
  --mode detection > /tmp/agp-waf-policy.conf
```

Это render-only output; он не является proof и не устанавливается как live config.
Production provider исполняет exact renderer artifact по `RendererDigest` из
verified closure под комплектным Ubuntu 24 loader, как квалифицированный corpus.
На management API сохраняется immutable base revision с per-policy CAS; validation
возвращает существующий `AcceptedOperation`. `GET /api/v2/waf/validations/{id}` читает
report с exact policy/qualification pins и динамическим `current`; `deployable=false`.
Proof pin-ит также manifest digest/release sequence: новый release с теми же profile/
evidence инвалидирует старый proof. Независимый approver имеет current read и явный
`config.approve`, fresh MFA и отличается от author; публикация повторяет head/rights/
epoch/proof checks. Published state не меняет live Gateway и не заменяет zone resolution.

**Rollback:** сохраняйте independent trust highwater/floors при откате CP. Не копируйте
старый store поверх текущего и не снижайте sequence/security floor; используйте новый
совместимый проверяемый release. `native_qualification_required` требует исправления
trust/provider prerequisites и новой validation, а не снятия guards. [Native harness](../tests/native-waf/README.md),
[границы проверки](v2/testing.md#component-repository-и-native-waf-принятый-as-is).

## Read-only agent inventory и trusted WAF zones

Для оператора secure PostgreSQL pilot и разработчика management API. Нужны работающий
independent journal, активный configuration profile, existing Gateway→Site ownership,
явные Site/global grants независимому approver и текущий signed WAF repository выше.
Новых grants/ownership после secure activation этот срез не выдаёт. Перед изменением
listener/PKI сохраните runtime environment, CP backup и независимые trust/registry
данные отдельно; запланируйте окно перезапуска CP. Команды ниже — инструкция для
подготовленной площадки, не свидетельство production deployment.

### Предварительная регистрация и запуск

1. Внешний PKI administrator заранее выпускает отдельный agent client certificate:
   ровно URI SAN `spiffe://agp/agent/{nodeId}`, только clientAuth, digitalSignature,
   не CA, без DNS/IP/email SAN. Agent key не используется для EdgeAuth. Регистрируются
   exact leaf DER SHA-256, SPKI SHA-256, issuer DER SHA-256 и lowercase hex serial.
   Validity всей цепочки должна покрывать ближайшие 120 секунд. Это external registry
   режим; альтернативный managed enrollment описан в следующем разделе.
2. Подготовьте strict JSON registry формата `agp.agent-registry/v1alpha1`:
   `authorityId` и `nodes`. Для каждого node обязательны `nodeId`, `siteId`, `name`,
   `labels`, `groupIds`, `certificatePem`, `certificateDigest`, `publicKeyDigest`,
   `issuerDigest`, `serial`, строковый `issuanceEpoch`. Authority/epoch берутся из
   текущего independent journal. `labels`/`groupIds` принадлежат installation registry,
   агент их не назначает. Дубликаты IDs/certificates/SPKI запрещены.
3. Registry находится вне CP restore domain: absolute clean path, regular file,
   владелец root или CP user, без group/other write; то же для всех предков, без
   symlinks. `/tmp` разрешён только root-owned sticky и с непосредственным private
   child текущего user; это исключение для disposable lab. Не делайте рабочий
   registry доступным на запись другим пользователям. Public cert/registry данные
   и trust floors восстанавливаются независимо от CP; private keys не входят в JSON.
4. Задайте **все пять** env и перезапустите подготовленный CP:

   ```env
   AGP_AGENT_MTLS_ADDR=127.0.0.1:8445
   AGP_AGENT_MTLS_CERT_FILE=/etc/agp-agent-ingress/server.pem
   AGP_AGENT_MTLS_KEY_FILE=/etc/agp-agent-ingress/server.key
   AGP_AGENT_MTLS_CLIENT_CA_FILE=/etc/agp-agent-ingress/client-ca.pem
   AGP_AGENT_REGISTRY_FILE=/etc/agp-agent-ingress/registry.json
   ```

   Listener port отличается от HTTP/EdgeAuth; ingress cert/key также отдельные.
   Certificate должен соответствовать имени agent HTTPS origin. Частичный набор env,
   relative paths или shared listener закрывают startup. TLS 1.3 clientAuth обязателен;
   agent routes не публикуются через browser management listener.
5. Соберите `go build -o agp-agent ./cmd/agp-agent` (Go 1.25+). На Linux node с
   защищёнными absolute paths к заранее выданным CA/cert/key запустите:

   ```bash
   set -euo pipefail
   AGP_AGENT_CA_FINGERPRINT="sha256:$(openssl x509 -in /etc/agp-agent/server-ca.pem -outform DER | sha256sum | cut -d ' ' -f 1)"
   ./agp-agent --url https://agent.example.net:8445 \
     --ca /etc/agp-agent/server-ca.pem --ca-fingerprint "$AGP_AGENT_CA_FINGERPRINT" \
     --certificate /etc/agp-agent/client.pem --key /etc/agp-agent/client.key --once
   ```

   Замените origin своими параметрами TLS/DNS; пример не настраивает сеть или issuer.
   Key принадлежит root/agent user и не доступен группе/остальным (`0600`); protected
   ancestors и отсутствие symlinks проверяются также для client files. `--once`
   выводит receipt JSON и завершает процесс. Без него interval по умолчанию 30 s,
   допустим `--interval 10s..60s`. Redirects/proxy env не используются.
   Optional `--component-profile /absolute/profile.json --runtime-root /absolute/bundle`
   задаются вместе: profile — exact public bytes verified repository, файлы regular,
   защищены от подмены, до 1000 файлов / 256 MiB каждый / 1 GiB суммарно. Collector
   читает OS/boot/disk/hash facts, не исполняет shell, service probes или helper.

Ожидается immutable receipt с positive monotonic `sequence`, `capabilityDigest`,
`observationDigest`, `receivedAt`/`expiresAt` с интервалом 120 s. Challenge живёт 60 s
и single-use; exact Submission retry возвращает старый receipt без продления lease,
изменённое тело/повтор nonce отвергается. Registry, certificate chain/expiry, epoch и
revoke проверяются на каждом запросе, включая keep-alive; journal outage закрывает приём.
Profile/file/OS/kernel matching выполняет server по текущей signed closure, а не по
version string. Authenticated observation не является remote attestation или active state.

Current admin видит `GET /api/v2/agent-inventory` и вкладку inventory в `/config-ui/`.
Ответ `{items:[...]}` содержит identity/connectivity и optional last seen/capability
pin; applied/health остаются unknown. Site `config.edit` не даёт доступ к fleet list.

### Trusted zone workflow

Все management POST требуют exact Origin, CSRF, Idempotency-Key и fresh MFA.
Read/edit scoped по Site; approval/publication требуют **явный** `config.approve`,
независимого от author approver и current read. Путь начинается с `/api/v2/waf`:

| Операция | Тело и результат |
| --- | --- |
| `POST /zone-revisions/{id}/validations` | `{}` → `202 AcceptedOperation`; `resourceId` указывает report, `statusUrl` — operation |
| `GET /zone-validations/{id}` | Exact dependency/native pins, `valid/current`, `deployable=false` |
| `POST /zone-revisions/{id}/approvals` | `{contentDigest,reason}` → `201 {approvalId,contentDigest}` |
| `POST /zone-revisions/{id}/publications` | `{contentDigest}` → exact published revision; потребители ещё не меняются |
| `POST /zone-revisions/{id}/resolutions` | `{baseRevisionId,capacityProfile,action,replacementAssignments?}` → `202`; report читается `/zone-resolutions/{resourceId}` |
| `POST /zone-changes` | Typed `WafZoneChange` из [schema](v2/schemas/waf-zone-change.schema.json) → `202`; `/zone-changes/{resourceId}` содержит `resultRevisionId` |

Resolution живёт 30 минут и включает полную Site closure, в том числе departing и
receiving zones. Сервер выбирает members из canonical Configuration, immutable
ownership, exact published base policies/co-zones и current qualified inventory;
operator-declared catalog не является trust source. Стабильный inventory digest не
содержит heartbeat timestamps, но freshness/identity/epoch/revoke перепроверяются при
materialization. Все affected bindings/zone assignments сохраняются в **одну полную
immutable desired ConfigRevision** под head CAS+seal; частичная запись запрещена.
Обычный authoring не наследует approved assignment при изменении security inputs;
нужен новый controlled resolution workflow. Изменение display names допустимо.

Поддержаны existing owned Gateways и base policies без local exceptions. Derived
policies, непустые `profileAssignments` и new Gateway onboarding явно отклоняются.
`materialized` не означает node apply, healthy или published live bundle; compiler
preview сохраняет `deployable=false`. Managed enrollment и локальный syntax probe
описаны ниже; TARGET remote validate-only/helper,
CaptureBaseline и rollout этим срезом не закрыты.

### Диагностика и rollback

`403 agent_identity_required` требует проверки role/certificate, CA, exact registry
pins и текущего epoch/revoke; browser cookie не заменяет mTLS. `409` challenge/conflict
требует новой challenge либо exact исходного retry; stale receipt обновляется новым
наблюдением, не изменением времени в БД. `503` означает недоступный journal/registry
или иной trust dependency; восстановите источник. `412` head mismatch требует чтения
нового base и нового resolution. Pin/OS/kernel/file drift требует квалифицированного
набора и повторной validation/resolution, а не редактирования доказательства.

Rollback listener: остановите collector, удалите **все пять** agent env и перезапустите
совместимый CP в согласованном окне. Existing inventory receipts/publications и desired
revisions сохраняются; это не откат БД или trust floors. Новые trusted writes без fresh
inventory закрываются. Для изменения desired WAF создайте successor через новый
controlled resolution; не удаляйте provenance и не снимайте authoring fences. Live
Nginx не менялся этим workflow. [Проверки и ограничения](v2/testing.md#read-only-agent-и-trusted-zones-проверки).

## Управляемая agent identity и локальная проверка синтаксиса

AS-IS на 2026-11-20 для оператора PKI/secure CP и разработчика агента. Нужны secure
PostgreSQL/configuration profile, independent journal, signed component repository и
доверенная внешняя доставка CA/pins. Установку и запуск сервисов выполняет оператор:
готовый production installer, AD/SMTP и remote helper/apply этим пакетом не поставлены.
Перед сменой listener/identity source сохраните CP backup и environment, отдельно
issuer ledger/issuing key/journal trust state; запланируйте окно перезапуска CP.
Совместный rollback этих независимых областей нарушает защиту от restore.

### Подготовка issuer и CP

1. Внешний PKI administrator готовит issuing CA chain/key у отдельного issuer account,
   offline root private key остаётся вне сервисов. Ledger directory — существующий
   private `0700`, private keys — `0600`, protected absolute clean paths без symlinks
   и group/world-writable предков. CP user не читает issuing key или ledger.
2. Подготовьте отдельные TLS 1.3 identities: issuer server URI
   `spiffe://agp/node-issuer/agent`, CP writer URI
   `spiffe://agp/control-plane/node-issuer`, CP registry reader URI
   `spiffe://agp/control-plane/agent-registry`. Writer/reader cert/key различны;
   issuer transport, signing и journal keys также различны. Issuer использует
   собственный read-only journal credential и свежий challenge-bound signed head.
3. JSON `/etc/agp-issuer/issuer.json` задаётся отдельному процессу
   `agp-issuer --config /etc/agp-issuer/issuer.json`. Ниже **шаблон**: замените
   public key/authority/key ID и пути по доверенному installation profile.

   ```json
   {
     "listenAddress": "127.0.0.1:8447",
     "tlsCertificateFile": "/etc/agp-issuer/transport.pem",
     "tlsKeyFile": "/etc/agp-issuer/transport.key",
     "clientCAFile": "/etc/agp-issuer/client-ca.pem",
     "issuer": {
       "ledgerFile": "/var/lib/agp-issuer/ledger.sqlite",
       "issuingCertificateFile": "/etc/agp-issuer/issuing-chain.pem",
       "issuingKeyFile": "/etc/agp-issuer/issuing.key",
       "certificateLifetimeSeconds": 86400,
       "renewalOverlapSeconds": 300
     },
     "journal": {
       "url": "https://journal.example.net:8444",
       "authorityId": "installation_authority",
       "keyId": "installation_journal_key",
       "publicKey": "<64 lowercase hex characters of the trusted Ed25519 key>",
       "certificateFile": "/etc/agp-issuer/journal-reader.pem",
       "keyFile": "/etc/agp-issuer/journal-reader.key",
       "caFile": "/etc/agp-issuer/journal-ca.pem",
       "serverName": "journal.example.net"
     }
   }
   ```

   Certificate lifetime допустим 3600..86400 s; renewal overlap — 0..900 s.
   Ledger хранит issuance/reservation/revocation/high-water вне CP restore domain.
4. Protected CP JSON `/etc/agp-agent-ingress/issuer-client.json`:

   ```json
   {
     "url": "https://issuer.example.net:8447",
     "serverName": "issuer.example.net",
     "certificateFile": "/etc/agp-agent-ingress/issuer-writer.pem",
     "keyFile": "/etc/agp-agent-ingress/issuer-writer.key",
     "registryCertificateFile": "/etc/agp-agent-ingress/registry-reader.pem",
     "registryKeyFile": "/etc/agp-agent-ingress/registry-reader.key",
     "caFile": "/etc/agp-agent-ingress/issuer-server-ca.pem",
     "caFingerprint": "sha256:<64 lowercase hex characters of trusted CA DER>",
     "timeoutSeconds": 10
   }
   ```

   В примерах `example.net` — placeholder, не рабочий сервис. CA fingerprints/key pins
   приходят по доверенному внешнему каналу, не из первого непроверенного подключения.
5. Сохраните четыре `AGP_AGENT_MTLS_*` предыдущего раздела. Очистите external
   `AGP_AGENT_REGISTRY_FILE` и задайте managed source и отдельный enrollment listener:

   ```env
   AGP_AGENT_REGISTRY_FILE=
   AGP_NODE_IDENTITY_CONFIG=/etc/agp-agent-ingress/issuer-client.json
   AGP_ENROLLMENT_TLS_ADDR=127.0.0.1:8446
   AGP_ENROLLMENT_TLS_CERT_FILE=/etc/agp-agent-ingress/enrollment-server.pem
   AGP_ENROLLMENT_TLS_KEY_FILE=/etc/agp-agent-ingress/enrollment-server.key
   ```

   Enrollment port/cert/key отличаются от browser, EdgeAuth и agent mTLS. Listener
   использует server-auth TLS 1.3 без client cert для первичного bootstrap, принимает
   только enrollment POST; cookies/Origin/Authorization не допускаются. Взаимоисключение
   managed/external source и неполные listener настройки закрывают startup.

### Первый enrollment и renewal

Соберите `go build -o agp-agent-identity ./cmd/agp-agent-identity` и
`go build -o agp-agent-validate ./cmd/agp-agent-validate` (Go 1.25+). На узле оператор
заранее создаёт private identity directory `0700`; CLI не перезаписывает существующие
key/CSR/certificate. В примере `/var/lib/agp-agent/identity-v1` уже подготовлен:

```bash
./agp-agent-identity keygen --directory /var/lib/agp-agent/identity-v1
```

Ожидается только публичный `publicKeyDigest`; key.pem/request.pem остаются на узле.
В management `/config-ui/` current admin создаёт node в существующем Site, затем
получает token роли `agent` (default 600 s, 60..900 s). Запись требует fresh MFA
не старше 5 минут. Token показывается один раз; metadata-only idempotent retry
не восстанавливает секрет. При потере первого ответа отзовите authorization и
создайте новую. Доставьте token без argv/URL/history/audit в private `0600` file
под private directory узла либо через stdin.

Задайте `ENROLLMENT_CA_PIN` и `IDENTITY_CA_PIN` из заранее доверенных pins; это
публичные fingerprints, не скачанные при bootstrap значения. Затем:

```bash
./agp-agent-identity request --directory /var/lib/agp-agent/identity-v1 \
  --url https://enrollment.example.net:8446 --node node_pilot \
  --ca /etc/agp-agent/enrollment-ca.pem --ca-fingerprint "$ENROLLMENT_CA_PIN" \
  --identity-ca /etc/agp-agent/identity-ca.pem --identity-ca-fingerprint "$IDENTITY_CA_PIN" \
  --token-file /var/lib/agp-agent/identity-v1/enrollment-token
```

Ожидается `csr_pending`, exact publicKeyDigest и requestDigest. Владелец сверяет
fingerprint с локальным keygen по независимому доверенному каналу, явно утверждает
оба digest в UI. После approval повторите команду с `enroll` вместо `request`:
появится certificate.pem с проверенными chain, node URI, SPKI, serial и expiry,
а использованный token file будет удалён. Exact request/enroll retry возвращает ту же
issuance; другой CSR с тем же token закрывается. Token, key или CSR не печатаются CLI.

Renewal: подготовьте новую private directory, выполните `keygen`, затем `renew`
с теми же CA/identity pins, `--url https://agent.example.net:8445`,
`--directory /var/lib/agp-agent/identity-v2` и
`--current-directory /var/lib/agp-agent/identity-v1`. `--token-file` при renewal
не используется. Новый key обязателен. CLI сохраняет проверенный новый certificate;
переключение inventory agent на новую directory — отдельное действие оператора.
Предусмотрите переключение в configured overlap; при нулевом overlap старый cert
перестаёт принимать новые запросы сразу, а точный renewal retry может завершиться.

Node revoke из UI/`POST /api/v2/nodes/{id}/revocations` пишет независимый journal;
202 содержит statusUrl для `/api/v2/node-identity-operations/{id}`. Он закрывает
renewal/inventory обеих generations. Это не остановка процесса, не удаление software
и не network isolation. Declared node остаётся в полной Site closure и при pending,
expiry или revoke; для новых зон отсутствие qualified inventory вызывает отказ.

### Локальный native syntax probe

Ручной installation profile заранее готовит signed repository/anchor, exact public
component profile/runtime files, отдельный read-only journal credential, private
receipts `0700` и scratch. Выполняйте CLI как dedicated nonroot account; root supervisor
должен явно указать nonzero `--execution-uid` и `--execution-gid`. Input JSON соответствует
[схеме](v2/schemas/agent-local-syntax.schema.json): actual current epoch/capability digest,
exact release/profile/tuple/evidence/renderer pins и typed policy без exceptions.
[Пример](v2/examples/agent-local-syntax.json) содержит фиктивные digests и не является
готовым production request. Команда читает только stdin, не принимает arbitrary argv
или paths из запроса:

```bash
./agp-agent-validate --repository /var/lib/agp-waf-repository \
  --anchor /etc/agp-waf/trust.json --component-profile /etc/agp-agent/component-profile.json \
  --runtime-root /opt/agp-runtime --receipts /var/lib/agp-agent/syntax-receipts \
  --scratch /var/lib/agp-agent/syntax-scratch \
  --journal-url https://journal.example.net:8444 --journal-authority installation_authority \
  --journal-key-id installation_journal_key --journal-public-key "$JOURNAL_PUBLIC_KEY_HEX" \
  --journal-certificate /etc/agp-agent/journal-reader.pem \
  --journal-key /etc/agp-agent/journal-reader.key --journal-ca /etc/agp-agent/journal-ca.pem \
  < /var/lib/agp-agent/local-syntax-request.json
```

Успех: exit 0, `state=validated`, `nativeSyntaxOnly=true`,
`executionLocation=local_process`, `isolation=unprivileged_private_workspace`,
`nodeDeploymentSequence="0"`; local result не содержит nodeId/identityDigest.
Проверяются signed bytes и capability/journal до/после настоящего `nginx -t`.
Private tree/непривилегированный subprocess и resource/output/time limits не дают
kernel filesystem/network sandbox. Remote NodeBundle/helper/task receipt/apply/reload
и health этим не реализованы; CP diagnostic Service не опубликован HTTP endpoint.

### Отказы, reconciliation и rollback

`403 step_up_required` требует fresh MFA; `node_identity_required` — проверки current
admin/certificate/epoch/revoke, не выдачи config.edit. `409 node_identity_conflict`
требует проверки exact node/CSR/request digest; не создавайте другой CSR при неизвестном
результате. `429` учитывайте по Retry-After; `503` при недоступном journal/issuer
не обходится локальным cached allow. При issuer restart тот же ledger обязателен.
Для локального syntax `local_syntax_precondition_changed` требует нового current
request; `local_syntax_request_conflict` — сверки payload. Intent без result даёт
`local_syntax_result_indeterminate`: остановите автоматический повтор, сохраните
private state для расследования, устраните причину и авторизуйте новый request ID.
Не удаляйте intent ради автоматического повторного исполнения.

Rollback: остановите managed enrollment, сохраните independently managed ledger,
trust floors и journal revocations, верните согласованные listener/environment/binary
только после проверки совместимости схем. External registry нельзя подставлять из CP
backup или использовать для оживления revoked/old-epoch identities. Local syntax probe
не меняет active Nginx tree, поэтому apply rollback не нужен; result остаётся
историческим фактом. Production service unit, backup/recovery issuer и clean VM install
требуют отдельной квалификации площадки.

## Основа допуска helper

AS-IS на 2026-11-24 предназначен разработчику: `internal/helper` — библиотека Linux
admission/store без executable, socket или root executor. Операторского enable/apply
CLI и production procedure пока нет. Проверка из корня checkout с Go 1.25+:

```bash
bash scripts/test-helper-foundation.sh
```

Библиотека создаёт ledger только в существующем пустом private каталоге 0700 с
защищёнными ancestors; task не задаёт этот путь. `CreateStore` и `OpenStore` разделены:
повторная инициализация существующего ledger запрещена. Trusted directory descriptors
и exclusive flock удерживаются до `Close`; intent, high-water и admission receipt
сохраняются одним fsync snapshot. Обязательный `Installation.Baseline` закрепляет
revision/bundle/sequence из trusted installer input, не снимает фактическую базу.
Admission всегда `noExecution=true` и не доказывает
active generation или здоровье Nginx. [Контракт и ограничения](v2/protocols.md#основа-допуска-helper).

`helper_task_conflict` требует сверки exact task ID/key/digest;
`helper_reconciliation_required` блокирует другую задачу до будущего reconciler.
`helper_state_locked` требует закрытия другого владельца store;
`helper_state_unavailable` запрещает продолжать работу повреждённым handle.
Сохраните ledger для расследования; удаление lock/state или повторный `CreateStore`
не является recovery. `RequireRecovery` лишь повышает блокировку. Доказуемого
completion/clear API и rollback процедуры для task здесь нет: библиотека не изменяет
active tree, а возврат прежнего ledger снижает защитные counters. Actual apply/rollback,
installer/ownership verification и pilot reboot qualification остаются TARGET.

## Локальная проверка owned tree

AS-IS на 2026-11-25 для разработчика и оператора Linux: `agp-owned-tree` проверяет
существующее дерево по заранее утверждённому локальному manifest. Это read-only
диагностика перед будущим CaptureBaseline, без apply/reload, backup и изменения CP.
Библиотечный opt-in gate описан в [контракте](v2/protocols.md#локальный-owned-tree-manifest-и-наблюдение).

Предпосылки: Linux с рабочим `statx` mount-ID proof; проверенный root-owned binary
и root-доступ для CLI; root-owned protected manifest, его canonical ownership digest
из отдельного trusted installation source и уже существующее дерево. Manifest v1
перечисляет всё текущее содержимое root, включая каталог `.` и все parents.
Manifest и observation из [примеров](v2/examples/owned-tree.json) — вымышленные
structural fixtures, не installation input. Генератор/подписание manifest и готовый
installer в этом срезе не поставлены.

Для проверки CLI help в checkout с Go 1.25+ root не требуется:

```bash
go run ./cmd/agp-owned-tree -h
```

Ожидается usage с двумя обязательными flags `-manifest` и `-ownership-digest`,
пояснением read-only/root и кодом выхода 0. Для наблюдения оператор уже должен
располагать проверенным binary вне writable директорий непривилегированных users.
В следующем примере `AGP_OWNED_TREE_BIN`, `AGP_OWNED_TREE_MANIFEST` и
`AGP_OWNERSHIP_DIGEST` — локальные shell variables с фактическими путями и trusted
digest; CLI environment variables с такими именами не читает. Из root shell:

```bash
"$AGP_OWNED_TREE_BIN" \
  -manifest "$AGP_OWNED_TREE_MANIFEST" \
  -ownership-digest "$AGP_OWNERSHIP_DIGEST"
```

Успех: exit 0 и одна JSON observation в stdout, с `purpose=filesystem_observation`,
`noExecution=true`, `runtimeValidated=false`, manifest/tree digests и metadata entries.
Output не содержит file bytes; node/site/пути/metadata могут быть внутренней
информацией, поэтому храните результат с ограниченным доступом. Не публикуйте его
как runtime baseline. Timeout 30 секунд cooperative; output ограничен 4 MiB.
Проверка читает до 64 MiB файлов; учитывайте локальную I/O нагрузку. Окно
переключения сервиса не требуется, поскольку команда конфигурацию не меняет.

При ошибке exit 1 и fixed error в stderr. `owned_tree_invalid_local_arguments`
требует сверки flags и отдельно доверенного digest; `owned_tree_local_root_required`
означает отсутствие root. `owned_tree_observation_unavailable` объединяет ошибки
manifest/tree/mount proof: сверяйте защищённую ancestry, ownership/modes, полный
список entries и содержимое с trusted manifest; не снижайте права или проверки
ради получения результата. Через библиотеку mount-proof failure дополнительно
доступен как `owned_tree_mount_proof_unavailable`.

При drift не обновляйте trusted digest по обнаруженным файлам автоматически.
Сначала установите причину и сохраните диагностические данные; восстановление
файлов требует существующей проверенной внешней резервной копии и отдельной
процедуры. Эта CLI не создаёт backup и не предлагает restore. Rollback самой
проверки не нужен: она не меняет дерево; удалять/сбрасывать helper ledger нельзя.
Она не снимает baseline blockers, не проверяет active generation/health Nginx и
не подтверждает готовность приложения к публикации. Lifecycle manifest после
будущего apply, qualified CaptureBaseline и safe apply/rollback остаются TARGET.

## Предложения плана и независимый review

AS-IS на 2026-11-24 для разработчика и оператора secure configuration pilot.
Нужны secure S0/PostgreSQL, включённый S1, migration
`023_plan_proposals.sql`, current desired ConfigRevision, server catalog,
trusted agent inventory и published native WAF policies. Предполагаются две разные
учётные записи: автор с global `config.read/edit` и reviewer с global `config.read`
и явным global `config.approve`. Site-only grants пока недостаточны для раскрытия
полной конфигурации узла. Admin без approval grant не может согласовывать.
Выпуск execution Plan, permit/StartProof, применение и rollout этим workflow не включаются.

1. В `/config-ui/` откройте вкладку «Подготовка развёртывания». Выберите текущую
   неизменяемую ревизию, укажите Site, exact target node IDs, canary IDs и причину.
   Пустой canary выбирает первый target. UI сохраняет policy: parallel 1,
   unavailable 0, observation 60 секунд, failure action `pause`; другие допустимые
   параметры доступны через typed API. Сервер получает полный trusted Site
   inventory и native WAF source closure, затем сохраняет immutable proposal с
   full-node preview digests. Baseline/evidence вручную не передаются. Унаследованные
   profile assignments и route WAF exceptions пока блокируют этот срез.
2. Просмотрите targets, весь список Gateway/secret version IDs, resolved inputs и
   blockers. Proposal всегда `purpose=planning_review`, `deployable=false`,
   `noExecution=true`. Сохранение не меняет active generation и не расходует sequence.
3. Под другой учётной записью проверьте тот же exact proposal digest и выполните
   review с причиной. Все mutations требуют CSRF, exact Origin, MFA не старше
   пяти минут и Idempotency-Key. Повтор потерянного ответа использует тот же key/body;
   текущие права/session/floors/epoch и источники всё равно перепроверяются.
4. При настроенном dedicated signer reviewer может получить и скачать signed
   planning review. Подпись охватывает полный proposal/review; UI явно сообщает,
   что криптографическую подлинность в браузере не проверял. `review.current=true`
   внутри скачанного immutable envelope отражает момент подписания, а не будущие права.

Подпись optional: без ключа proposal/review доступны, signature POST отвечает 503.
Для её настройки заранее требуется отдельный Ed25519 PKCS#8 PEM `PRIVATE KEY`,
не reused journal/issuer/helper execution key. Генератор ключа этим пакетом не
поставляется; provision и backup выполняются принятым операторским способом вне CP DB.
Файл до 8192 bytes должен быть regular, private (рекомендуется 0600), доступен
service account, принадлежать ему либо root и находиться в защищённом дереве без symlinks.
Обе переменные обязательны вместе, только при secure configuration profile:

```dotenv
AGP_PLAN_REVIEW_KEY_ID=planning-review-example
AGP_PLAN_REVIEW_KEY_FILE=/absolute/private/path/planning-review-key.pem
```

Это placeholders, не команда provisioning. Изменение runtime environment и restart
выполняйте в согласованном окне обслуживания по процедуре secure S0, предварительно
сохранив CP DB/config и ключ отдельно. Невалидный или небезопасный файл блокирует
startup. Исполнитель/helper по-прежнему отсутствует. Реальные API и response DTO —
в [протоколе](v2/protocols.md#подписанный-plan-и-planning-review) и
[OpenAPI](v2/api/openapi.yaml).

При `current=false` либо 409/412 обновите фактические inventory/revision/catalog/
native qualification и создайте новое предложение; не подменяйте frozen pins.
403 требует проверки global grants, независимости reviewer, session и MFA;
503 — доступности independent journal/inventory/native provider и optional signer.
Устаревший inventory либо потеря подтверждённой identity оставляют proposal/review
видимыми с `current=false`; недоступность inventory возвращает ошибку доступности,
а не успешный исторический ответ.
Исторические proposal/review остаются читаемыми с current global read, включая
удалённого автора/reviewer; новые согласования и повторы review/sign после потери
прав соответствующего участника блокируются.
Удалять immutable строки или возвращать старую БД для снятия blocker нельзя.
Для отключения optional signing уберите обе переменные и выполните контролируемый
restart: подписи перестанут выпускаться, данные сохранятся. Это не rotation procedure
и не rollback применённой конфигурации; live apply здесь отсутствует.

## Изоляция management: S0.2a

Эта процедура относится только к legacy/S0.2a **до secure authority activation**.
Она не является rollback secure S0 pilot; для него используйте раздел выше.

Опциональный режим отделяет административный UI/API от legacy portal/apps.
Это процедура для оператора с доступом к service manager, runtime environment и БД;
она требует согласованного окна обслуживания и завершает все существующие sessions.
Полные login/application isolation, gateway handoff, MFA/AD и restore barrier этим
режимом не реализованы. Команды ниже применимы к новому binary с migration
`008_session_profile.sql`; текущий `agp` и `agpctl` должны быть одной сборки.

До начала сохраните проверяемый backup БД, downloads, runtime environment и Nginx
config; проверьте наличие совместимого binary для отката. Подготовьте отдельный
management hostname с доверенным HTTPS-сертификатом и ограничением доступа из
административной сети. Он не должен совпадать с hostname portal или любого resource,
даже при разных портах. Origin канонический: lowercase hostname, без `/`, query,
fragment и явного `:443`; иной порт разрешён. `AGP_COOKIE_SECURE=true` обязателен.

1. Остановите входной трафик и **все** старые AGP instances/listeners, включая
   резервные; дождитесь завершения in-flight mutations. Не допускайте mixed-version
   запуска: binaries до 008 не знают profile barrier и не блокируются им.
2. Примените expand-only migration 008 новым `agp` до preview. Для первого перехода
   с legacy запустите новый binary с прежним runtime environment, пустым
   `AGP_MANAGEMENT_ORIGIN` и только закрытым loopback listener. После успешного
   `/readyz` штатно остановите этот процесс. Миграции выполняются при startup;
   отдельного `migrate` CLI нет. Создавать администратора ради миграции не требуется.
3. Подготовьте целевое environment с прежними параметрами БД/portal/cookies и новым
   origin (замените пример своим hostname/портом):

   ```env
   AGP_MANAGEMENT_ORIGIN=https://management.example
   AGP_COOKIE_SECURE=true
   ```

   В этом environment выполните:

   ```bash
   agpctl session-profile --preview
   ```

   Preview по умолчанию read-only, не применяет миграции. Ожидайте `applied:false`
   и перед первым переключением `reset_required:true`. Проверьте requested profile,
   fingerprint и отсутствие resource-host conflicts. Не запускайте новый listener
   с целевым profile до explicit apply.
4. С тем же environment выполните reset и повторную проверку:

   ```bash
   agpctl session-profile --apply --revoke-sessions
   agpctl session-profile --preview
   ```

   Profile, отзыв всех sessions и событие `session.profile.changed` фиксируются
   атомарно. Apply возвращает `applied:true` и число `revoked_sessions`; повторный
   preview должен дать `reset_required:false`. Apply неизменного profile — no-op.
5. Запустите только новый binary с совпадающим environment и проверьте `/readyz`.
   При закрытом внешнем трафике вручную установите прошедший review Nginx/TLS config
   для нового профиля с действительными certificate paths; выполните `nginx -t`
   и контролируемый reload. Затем проверьте новый login через management HTTPS origin,
   закрытый admin API на portal origin,
   portal login и разрешённый/запрещённый resource. Management cookies должны быть
   `__Host-agp_management` и `__Host-agp_management_csrf`, host-only и `Secure`.
   Для management login/mutations нужен точный `Origin`; mutations с session также
   требуют `X-CSRF-Token`. Public downloads и приложения на management host запрещены.
   Открывайте внешний трафик после успешного smoke.

`session_profile_mismatch`/ошибка startup означает несовпадение сохранённого profile
с environment: закройте трафик, сравните preview/fingerprint и параметры portal,
origin и cookie names. Не удаляйте marker из БД. Ошибка отсутствующей таблицы при
preview требует шага 2; конфликт resource-host — исправления конфигурации до reset.
UI читает runtime mode и имя CSRF cookie из `/api/v1/public/runtime`; custom legacy
CSRF cookie сохраняется, CSRF в localStorage не используется.

**Rollback:** снова закройте трафик, остановите и drain все процессы. Теми же
**текущими** `agpctl` и binary загрузите сохранённое legacy environment с пустым
`AGP_MANAGEMENT_ORIGIN`; выполните preview → `--apply --revoke-sessions` → preview.
Это ещё один global session reset, возвращающий legacy профиль. Запустите текущий
binary, восстановите соответствующий legacy Nginx/TLS config, выполните `nginx -t`
и контролируемый reload при закрытом внешнем трафике; затем проведите legacy smoke
и открывайте трафик. Более старый binary допустим
только после отдельной проверки совместимости с расширенной схемой; его простой
запуск не является rollback. Migration 008 автоматически назад не удаляется.

Стендовая приёмка: [команды и границы S0](v2/testing.md#текущий-пакет-s0-команды-и-границы).

## Установка и обновление из GitHub

Текущие `install.sh` и `update.sh` используют новый application release package
из публичного `https://github.com/netwizd/agp`. Они не устанавливают старый код
из ветки `main`. Поддерживаемая платформа bootstrap — Ubuntu 24.04 amd64 с systemd;
приёмка Ubuntu 24 userspace на сервере Ubuntu 26 не расширяет эту платформу.
Пакеты с описанным ниже форматом ещё требуют отдельной сборки и публикации текущего
проекта. Пример команд — в [README](../README.md#установка-на-ubuntu).

**Доверие и подготовка.** До запуска от root получите через независимый доверенный
канал точную версию и SHA256 архива, а также самого `install.sh` или `update.sh`.
Скрипт не доверяет автоматически скачанному рядом checksum-файлу. Это ручное
закрепление пакета оператором, а не готовый application TUF updater. TUF, release
signature, security floor и отдельный native WAF repository сохраняют свои правила.
Готовность всего приложения к публикации этой автоматизацией не подтверждается.

Нужны Python 3, systemd, `useradd`, PostgreSQL client tools `pg_dump`/`pg_restore`,
подготовленная CP БД и env root-owned с закрытыми правами и защищёнными родительскими
каталогами. В env допустимы однострочные `NAME=value`, без shell expansion/escapes;
`AGP_DATABASE_DRIVER` задаётся явно, backend слушает `127.0.0.1:<port>`.
Для SQLite допускается только путь внутри `/var/lib/agp`; production secure profile
по-прежнему требует PostgreSQL и отдельный journal. Private profiles, PKI, TLS и
внешний Nginx готовятся до открытия сервиса пользователям.

Архив `agp_<tag>_linux_amd64.tar.gz` содержит `release.json`, девять `bin/*` и три
`systemd/*` шаблона. Проверяются внешний hash, точная версия/platform, полный
inventory, размеры, режимы и hashes всех файлов; ссылки, traversal и специальные
файлы не принимаются. Пакет ограничен 256 MiB, файл — 128 MiB, распакованный
комплект — 768 MiB. Все девять компонентов устанавливаются в root-owned
`/opt/agp/releases/<version>-<commit>`; единая ссылка `/opt/agp/current` переключает
комплект атомарно. Автоматически включается только `agp.service`. Запуск journal,
EdgeAuth, agent/helper и issuer требует их отдельных профилей и процедур.

**Обновление.** `update.sh` работает только с управляемой установкой этого формата.
Конфигурация `/etc/agp/agp.env`, загрузки, ключи и служебные counters сохраняются.
Активные дополнительные AGP-службы требуют согласованного обновления и блокируют
обычный CP updater. Перед переключением останавливается CP, затем создаётся
приватная копия БД и конфигурации в `/var/backups/agp/updates/<id>`:
PostgreSQL custom dump с `pg_restore --list` либо SQLite backup с проверкой целостности.
Контролируются `/healthz` и `/readyz`; повторная установка тех же version/commit/hash
не запускает миграции или restart. Понижение версии и изменение bytes существующего
релиза отклоняются.

Если попытка нового запуска могла применить миграции, сервис остаётся остановленным
и сохраняется `/var/lib/agp-release/recovery-required.json` с путём к backup.
При обработанном отказе updater оставляет `current` на новой версии и создаёт
`recovery-blocked.json` в том же защищённом каталоге; условие systemd блокирует
обычный повторный запуск и автозапуск. Старые бинарники остаются в резервной копии.
Обрыв процесса или питание требуют отдельной проверки состояния; полной reboot/
power-loss приёмки bootstrap ещё нет.
Автоматический запуск старой версии и автоматический restore БД не выполняются.
Восстановление CP проводится по [процедуре fencing/epoch и replay](#контролируемый-cp-restore-и-rollback);
journal, его БД, ключи и durable helper state не восстанавливаются из CP backup.
Само удаление recovery marker не означает, что БД совместима и можно запускать сервис.

**Проверка без установки.** Оба скрипта поддерживают `--verify-only` без root;
`--archive /path/to/archive.tar.gz` использует заранее скачанный пакет. Обязательны
`--version` и доверенный `--sha256`. Проверка не включает запуск сервисов.

**Сборка сопровождающим.** `scripts/build-release.sh --version <tag> --output-dir <dir>`
требует чистый Git checkout, совпадение `VERSION`/tag/HEAD и обязательные native/PG
inputs для `release-check.sh`. Из Git snapshot собираются auth/config/directory UI и
все девять Go roles с `CGO_ENABLED=0`. `scripts/package-release.py` проверяет статические
ELF amd64, создаёт архив, `install.sh`, `update.sh`, inventory и SHA256SUMS как release
assets. Inventory содержит migration digests и frontend notices; это не полный
license audit/SBOM. Сборка не создаёт tag, не подписывает и не публикует файлы.
Checkout без Git identity не может стать релизом через этот builder.

## Observability

Backend пишет структурированные JSON-логи в stdout. В systemd deployment они
попадают в journald:

```bash
journalctl -u agp -f
journalctl -u agp -n 200 --no-pager
```

Nginx ведет отдельные access/error logs для портала и ресурсов.

HTTP probes:

| Endpoint | Назначение |
| --- | --- |
| `/healthz` | процесс AGP отвечает на HTTP |
| `/readyz` | storage backend доступен |
| `/metrics` | дешевые Prometheus-style liveness metrics |

`/metrics` должен быть доступен только localhost или monitoring network.

## Минимальные Alerts

- процесс `agp` остановлен;
- `/readyz` не отвечает;
- рост HTTP 5xx;
- серия failed logins;
- частые `access_denied` или `ip_denied`;
- ошибка backup timer;
- Nginx reload failed;
- истечение TLS certificate.

## Диагностика Новых Точек Входа

Если новый ресурс после клика возвращает пользователя обратно в портал, сначала
проверьте, применен ли актуальный Nginx bundle. AGP хранит ресурс в БД, но Nginx
не узнает о новом `public_path`, пока администратор не обновит config.

```bash
sudo nginx -T 2>/dev/null | grep -n "location \\^~ /anything-needed"
```

Если location отсутствует, скопируйте новый bundle из админки, проверьте
`nginx -t` и выполните reload. Если location есть, смотрите audit events и
Nginx logs: причина может быть в группах, CIDR allowlist, disabled resource или
недоступном upstream.

## Backup

Production backup включает PostgreSQL и downloads directory:

```bash
sudo install -o root -g root -m 0755 scripts/agp-backup.sh scripts/agp-restore.sh /usr/local/bin/
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.service /etc/systemd/system/agp-backup.service
sudo install -o root -g root -m 0644 deploy/systemd/agp-backup.timer /etc/systemd/system/agp-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now agp-backup.timer
```

Ручной запуск:

```bash
sudo -u agp AGP_BACKUP_DIR=/secure-backups AGP_DATABASE_NAME=agp /usr/local/bin/agp-backup.sh
```

Backup artifacts создаются с `umask 077`; файлы backup и checksum manifest
должны оставаться с правами `0600`.

## Restore

Ниже legacy file/DB restore. Для активированного secure profile сначала выполните
[внешнее fencing/epoch и restrictive replay](#контролируемый-cp-restore-и-rollback);
один запуск этого скрипта не восстанавливает безопасный security state.

Restore script:

- требует matching SHA-256 manifest;
- проверяет tar archive на absolute paths и `..`;
- распаковывает downloads во временную директорию;
- затем заменяет целевой каталог.

Пример:

```bash
createdb agp_restore
AGP_DOWNLOADS_PARENT=/var/lib/agp /usr/local/bin/agp-restore.sh \
  /secure-backups/agp-db-YYYYMMDDTHHMMSSZ.dump \
  /secure-backups/agp-downloads-YYYYMMDDTHHMMSSZ.tar.gz \
  agp_restore \
  /secure-backups/agp-YYYYMMDDTHHMMSSZ.sha256
```

После restore нужно проверить:

- `/readyz`;
- login администратора;
- список ресурсов;
- скачивание public downloads;
- чтение audit.

## Retention

Runtime cleanup:

```env
AGP_AUDIT_RETENTION=8760h
AGP_SESSION_RETENTION=720h
```

AGP удаляет старые audit events и expired/revoked sessions при старте. Backup
retention независим и задается политикой организации.

## Logrotate

Базовый template:

```text
deploy/logrotate/agp
```

Рекомендуемая политика:

- daily rotation;
- хранить минимум 30 дней локально;
- gzip compression;
- reload Nginx после rotation.
