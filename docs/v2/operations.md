# AGP v2: установка, эксплуатация и восстановление

Статус: **Proposed TARGET**, 14.11.2026. Это проект процедур для реализации и последующей квалификации,
а не описание уже доступного installer/CLI и не разрешение менять действующую инфраструктуру.
См. [обзор](README.md), [архитектуру](architecture.md), [security](security.md), [протоколы](protocols.md),
[модель данных](data-model.md), [разработку](development.md) и [проверки](testing.md).
Существующий standalone/manual режим по [ADR 0001](../adr/0001-single-node-mvp.md) остаётся поддерживаемым.
Показанные defaults — проектные параметры installation profile; они не являются фактическим SLA или wire constants.

### Корпоративный identity profile: AD, 2FA, SMTP

До корпоративного пилота S2 подготовить AD DC/GC FQDN и read-only service account,
forest anchor/OU/group mappings, корпоративную CA, отдельный SMTP channel с TLS,
IdP issuer/redirect/claim mapping и локальную аварийную учётную запись с MFA.
Тестировать точный профиль signing/CBT/TLS, AD lockout/expiry/nested+primary groups;
не ослаблять DC policy для подключения. Все секреты через secret versions.
Проверка provider и preview не активируют вход. Activation/mapping/trust change проходит
digest-bound approval и independent guard floor до переключения immutable config.
Не удалять/не пересоздавать provider guard ID при ротации. Откат версии ниже floor закрыт.

При AD/GC outage нет fallback на cached groups/local password/email того же principal.
Показать provider unavailable и закрыть соответствующие решения; Nginx/WAF продолжают
работать по активной config, отдельный local break-glass с MFA остаётся доступен по policy.
Проверить TLS/секрет/лимиты/GC и очередь запросов; повторять только bounded probes.
AD disable может распространяться с replication lag; немедленный центральный revoke
выполняется через AGP deny journal. Фактический lag измеряется в целевой topology.

При SMTP сбое существующие sessions/TOTP не зависят от доставки письма. Новые email flows
показывают queued/failed/expired; не продлевать срок и не отключать MFA. Worker не отправляет
просроченные/старого epoch/generation payloads и удаляет их short-lived key.
После restore до auth readiness: fence прежний writer, advance authority epoch,
сверить provider/link/contact floors, отменить старые flows/challenges/outbox и выдержать
TOTP window barrier по trusted clock/cutoff с допустимым skew. Неизвестный cutoff или
откат часов требует supervised reconciliation, а не пропуска проверки.
Детали, TTL и приёмка — [identity](identity.md).

## 1. Профили поставки и границы поддержки

Первый предлагаемый pilot: Ubuntu 24.04 LTS, amd64, PostgreSQL 17 с закреплённым patch release;
другие ОС/architectures/major versions получают поддержку только после собственной qualification matrix.
SQLite остаётся development/manual fallback согласно ADR; distributed control/Auth и monotonic journal не опираются на SQLite.
Слово «поддерживается» в release появляется только после install/upgrade/recovery тестов конкретного tuple.

| Профиль | Состав и обязательные условия | Статус TARGET |
| --- | --- | --- |
| Standalone/manual | Backend + PostgreSQL + Nginx; оператор применяет рекомендации вручную; agent/helper не требуются | Совместимый baseline, новые managed гарантии не приписываются старому режиму |
| All-in-one managed | CP, Auth, PostgreSQL, gateway/EdgeAuth, agent/helper на одной VM; agent/EdgeAuth/helper имеют отдельные процессы/accounts/trust roles | Первый управляемый вертикальный срез; общая VM остаётся общей зоной отказа |
| Distributed | CP/Auth/PG в центре, gateways на площадках, исходящий agent mTLS и отдельный gateway→Auth mTLS | Первая распределённая поставка, central Auth fail-closed |
| Closed network / noInternet | Связность между площадками и собственными CP/Auth; packages/IdP/DNS/time из внутренних служб | Те же протоколы; запрещены скрытые внешние зависимости |
| Airgap | Собственные CP/Auth/PG/IdP или local accounts/journal; offline import полного подписанного bundle | Спроектирован, отдельная qualification до заявления поддержки |
| Split-WAF | Отдельный HTTP proxy WAF перед gateway; повторное TLS, gateway/upstream недоступны в обход WAF | Спроектирован, отдельная сетевая/security qualification |
| HA | Несколько CP/Auth, один fenced PostgreSQL writer, квалифицированный checkpoint service, внешний LB | После failure/load/restore qualification; не multi-master |

Общий процесс CP/Auth не обеспечивает независимую доступность авторизации: отказ процесса/PG может закрыть весь доступ.
Отказ только management UI при исправных Auth/PG/journal не должен останавливать пользовательские запросы.
All-in-one допустим как pilot, но не называется отказоустойчивым из-за нескольких systemd units на одной VM.
CP/Auth могут быть модулями одного binary/process/account с суммой необходимых прав; тогда их аварии и доступ к памяти не изолированы.
Раздельные CP/Auth процессы/accounts — профиль для независимого lifecycle и ограничения blast radius, не свойство разных URL в одном процессе.
Upstream приложения и их собственные данные/backup остаются вне управления AGP, кроме явно заданных probes и proxy configuration.

## 2. Inventory, DNS, сеть, время и TLS

До installation владелец площадки заполняет inventory: node/site IDs, owner/contact, OS/release/arch/filesystem,
CPU/RAM/disk, existing Nginx packages/build flags/modules/includes/listeners, routes/upstreams, DNS/TLS, firewall и proxy chains.
Отдельно фиксируются ownership managed/adopted, maintenance window, local console/recovery access и current configuration backup.
Для upstreams задаются DNS/ports/Host/SNI, допустимые IP/CIDR, health path/method/status и допустимость тестового трафика.
Нельзя автоматически считать всю RFC1918 сеть разрешённым diagnostics/egress target.

Предлагаемые DNS names: `manage.example.net`, `login.example.net`, `control.example.net`,
`auth.example.net`, `repo.example.net`, `checkpoint.example.net`, отдельные application hosts.
Имена условные; management/login/apps всегда разные origins, даже если TLS frontend/IP общие.
Installation profile фиксирует все URLs и trust roots; client не ищет control server через неподтверждённый redirect/discovery.

| Соединение / предлагаемый port | Источник → получатель | Контроль |
| --- | --- | --- |
| HTTPS TCP 443 management | Admin network → management frontend | TLS, identity/MFA, RBAC; не весь Internet |
| HTTPS TCP 443 login/apps | Browser network → login/gateway | Раздельные origins/cookies, Auth и WAF policy |
| Control mTLS TCP 9443 | Agent → control listener | Agent role certificate; gateway role не подходит |
| Auth service mTLS TCP 9445 | EdgeAuth/gateway → central Auth | Отдельный role certificate, route/generation binding |
| Journal mTLS TCP 9444 | CP/Auth → checkpoint service | Раздельные read-head/append credentials, private allowlist |
| Repository HTTPS TCP 443 | Agent/import service → trusted repository | TLS + TUF/release signatures; mirror не signing authority |
| PostgreSQL TCP 5432 | CP/Auth/journal materializer → private PG | Отдельные least-privilege roles, TLS вне local socket |
| DNS UDP/TCP 53 | Nodes/services → corporate resolvers | Явный allowlist; TCP нужен для полного DNS поведения |
| NTP UDP 123 / corporate time service | Nodes/services → corporate time | Проверенная синхронизация и alert; наружный NTP не подразумевается |
| Upstream TCP profile ports | Gateway/WAF → разрешённые приложения | Явные egress targets, TLS SNI/CA verification |
| SMTP/webhook/SIEM/metrics | Только соответствующие service accounts → named endpoints | Очередь, allowlist, отдельные credentials; monitoring private |

Входящие agent/helper management ports на gateway не требуются; SSH не является каналом control протокола.
Не следует открывать SSH или обходной HTTP listener при потере CP. Local console/SSH эксплуатации — отдельная политика владельца узла.
Предлагаемые loopback listeners: management `127.0.0.1:9080`, Auth `127.0.0.1:9081`, EdgeAuth `127.0.0.1:9082`;
Unix sockets предпочтительны там, где обеспечивают те же identity/permissions. Ports можно заменить целым installation profile.
Внешний reverse proxy не должен превращать bearer request headers в доверенную mTLS identity без защищённого внутреннего канала.

TLS проверяет hostname/SAN, chain, expiry и назначение сертификата; `insecure-skip-verify` не допускается в квалифицированном профиле.
Корпоративные CA устанавливаются доверенным bootstrap путём до передачи enrollment token.
Ошибки DNS/time/TLS показываются раздельными diagnostic reason codes, без вывода token/keys.
Рассинхронизация времени делает сомнительными certificate/approval/TUF expiry; при недостоверном времени новые privileged операции блокируются.
Назад переведённые часы не уменьшают durable task/security sequence; wall clock не используется как writer fencing.

## 3. Процессы, учётки, filesystem и доступ к секретам

Для нескольких EdgeAuth за одним application host первый профиль требует LB affinity для callback и node-bound gateway session. Переключение на другой node запускает новый handoff через сохранённую Central Auth session; не обещается сохранение локального callback при падении исходного узла. Общий session/client store требует отдельной квалификации, не отключения audience/PKCE проверок.

Названия unit/account ниже — TARGET package layout, пока не реализованный в текущих `deploy/systemd`.
Legacy unit `agp.service` не объявляется автоматически эквивалентом всех новых ролей.

| Компонент / account | Доступ | Запреты |
| --- | --- | --- |
| `agp-server` / `agp-server` | Management/config/rollout modules, application PG role, signing API по scope | Нет root/sudo, CA root key и прямой записи gateway config |
| `agp-auth` / `agp-auth` | Sessions/policies/deny materialization read, current journal head, IdP/client secrets | Не выпускает helper tasks, не читает release signing key |
| `agp-edgeauth` / `agp-edgeauth` | Pending browser flows, gateway session references, central Auth mTLS | Нет offline allow, helper socket, agent credentials |
| `agp-agent` / `agp-agent` | Свой control certificate, bounded spool/cache, helper socket | Не пишет helper binary/unit/root trust/journal/config trees |
| `agp-helper` / root | Только typed операции в owned tree, fixed validation/reload/package adapters | Нет generic shell API, произвольного пути/unit/download URL |
| Nginx master/workers | Master читает нужные TLS keys; workers имеют минимальный доступ | Не management session/key store, нет прямого client bypass к Auth |
| Checkpoint service | Отдельный host/account/storage/credentials/backup domain | Не CP restore role, нет API delete/rewrite/head reset |
| Signer/key service | Scoped CA/plan/release/encryption operations по отдельным identities | Offline roots отсутствуют в CP и build runners |

Предлагаемый layout:

| Путь | Owner/mode и назначение |
| --- | --- |
| `/etc/agp` | root-owned конфигурация/trust metadata; private credentials отдельными `0600` или scoped `0640` файлами |
| `/opt/agp/releases` | root:root, binaries/manifests immutable для service accounts; current link меняет только qualified installer |
| `/var/lib/agp/server` | `agp-server`, `0700`, локальные служебные данные без KEK/offline private keys |
| `/var/lib/agp/edgeauth` | `agp-edgeauth`, `0700`, ограниченные pending flows/session references; отдельный от agent cache |
| `/var/lib/agp/agent` | `agp-agent`, `0700`, cache/spool; содержимое всегда повторно проверяется helper |
| `/var/lib/agp/helper` | root:root, `0700`, journal, prepared/base snapshots, durable counters и recovery permissions |
| `/etc/agp/gateway` | root-owned managed effective tree; конкретные files/links перечислены в ownership manifest |
| `/run/agp-helper` | root-owned directory, socket только для approved agent UID, peer credentials обязательны |
| Log/spool volumes | Раздельные quotas для management audit и traffic/WAF; нет plaintext keys/bodies |

Managed mode может владеть только заранее перечисленными AGP paths/units/packages; adopted mode сохраняет чужие файлы и owners.
Неизвестные include, world-writable parent directories, shared packages и mutable symlinks — причина остановить adoption, а не force overwrite.
Package installer задаёт systemd sandbox/resource limits по квалифицированному профилю; параметры проверяются на целевой ОС.
Agent/server не получают root только для исправления permissions. Helper socket не заменяет проверки подписи и ownership.
Capacity preflight резервирует staging + current/base snapshots + package closure + journal emergency reserve на одном пригодном filesystem.
Atomic rename не обещается между mounts; используемый filesystem должен пройти crash/fsync/reboot tests.

## 4. Bootstrap и первая установка

Следующие шаги — обязанности будущего installer/UI/API. Команд `agpctl enroll/apply/upgrade` в baseline ещё нет;
существующие v1 scripts нельзя выдавать за реализацию этих v2 процедур.

1. Оператор подтверждает inventory, qualification tuple, owners, сеть/DNS/time и management-only доступ.
2. Release operator доставляет проверенный installation bundle и roots; до root execution сверяет manifest/signatures/lengths/digests.
3. Installer делает read-only preflight, показывает план owned paths/packages/units/ports и конфликтов, без изменения чужих конфигураций.
4. Проверяются резервные копии Nginx/PG/ownership и доступ к локальной recovery консоли. Disk/filesystem/time gates обязательны.
5. Разворачиваются PG, независимый checkpoint и key/signing service; credentials роли разделены. Fresh authority создаётся только для новой установки.
6. CP/Auth стартуют закрытыми; migration и checkpoint readiness завершаются до management mutation/user allow.
7. Создаются первый администратор и независимый emergency account; секрет bootstrap показывается один раз через защищённый локальный канал.
8. Настраиваются invite/MFA/recovery/IdP и origins; bootstrap credential consumed, session rotation и recovery codes проверены.
9. Включается read-only agent; inventory/capabilities сравниваются с операторским планом. Helper apply пока недоступен.
10. После security gates выполнить `captureBaseline`: validated закрытые bootstrap revision/bundle на чистом managed node либо сохранённый validated adopted baseline.
11. Один managed/adopted canary с non-null exact base IDs/digests, предварительной проверкой Auth generation, typed plan/approval/apply/probes.
12. Успешный canary и recovery drill открывают дальнейший rollout. UI показывает фактическую active generation и known limitations.

Bootstrap не создаёт общий default password и не отправляет credentials в логи/процессные аргументы.
До выдачи root-helper должны быть устранены baseline findings из [security](security.md) и квалифицированы strong authentication/approval.
Node enrollment использует one-time node/site-bound token, CSR proof of possession и server-assigned SAN.
Agent и EdgeAuth получают разные role certificates/private keys. Token нельзя повторно использовать для новой issuance/CSR;
это отличается от идемпотентной сверки исходной issuance при потерянном ответе и том же proof of possession.
Первичный показ token не восстанавливается из hash: idempotent replay возвращает metadata и `tokenAvailable=false`;
при потере этого ответа оператор отзывает прежний token и создаёт новую явную issuance.
Потерянный ответ issuance разрешается lookup/reconcile по идемпотентной операции, а не выдачей второго незаданного identity.
`captureBaseline` — отдельная обязанность qualified installer; неизвестный/отсутствующий base не обходится null/zero digest в обычном apply.
При потере handoff redeem response EdgeAuth закрывает доступ и начинает новый login/handoff flow;
consumed code не создаёт вторую session, orphan session истекает. UX показывает безопасный повтор входа, а не бесконечный retry callback.

### Реализованный execution runtime — AS-IS на 2026-11-26

Этот раздел предназначен для разработчика/оператора Linux с доступом к установочным
pins, service account и отдельным root-действиям. Это интерфейс для стендовой проверки;
production installer/systemd package и полная root/Nginx/cgroup/reboot qualification
ещё не подтверждены. Проектный Nginx pin — 1.30.8. Обновление действующего сервера
этим этапом разработки не подтверждается.

Предпосылки: secure PostgreSQL profile, configuration API, approved agent certificate,
независимый journal, проверенный component repository и native repository с полными
qualified bundles. Независимый qualifier должен подписать materialization, связанную с
sealed configuration/source closure, release/renderer/profile/tuple, native report и
secret versions. CP принимает такие материалы, но не реализует весь producer сервисных
и WAF-конфигураций. Profile/zone assignments в этом execution пути отклоняются.

До первого staging согласовать окно обслуживания, сохранить согласованные резервные
копии CP/managed Nginx/ownership/helper state и обеспечить локальную recovery консоль.
Independent journal и trust pins не откатываются вместе с CP. Проверить отсутствие чужих
файлов в выделенной области; staging изменяет native tree, initialize создаёт ledger.
Не выполнять команды ниже на действующем узле до отдельного разрешения на установку.

1. Установщик заранее подготавливает файлы и защищённые parent directories. Публичный
   root-owned файл `AGP_EXECUTION_CONFIG` имеет `apiVersion=agp.execution-runtime/v1alpha1`.
   Поля: `sourceCatalog`, `materialsFile`, `writerLockFile`, `repositoryDir`,
   `repositoryAnchor`, `permitKeyId`, `permitKeyFile`, `controlKeyId`, `controlKeyFile`,
   `journalPublicKey`. Catalog имеет `apiVersion=agp.execution-source-catalog/v1alpha1`,
   `writerEpoch`, `bindings`, `qualificationKeys`, `secretVersions` и `materials: []`.
   Он root-owned, находится вне CP restore domain и содержит только публичные pins.
   Все поля и вложенные имена сохраняют точное написание соответствующих Go DTO.
2. `materialsFile` — отдельный private JSON array полных подписанных materializations,
   владелец service UID, рекомендуемый mode 0600. Permit/control PKCS8 Ed25519 keys и
   заранее созданный writer lock file также private и принадлежат service UID; lock
   имеет ровно mode 0600 и root-owned parent без права записи service account.
   Остальные parent directories защищены от записи посторонними. Ключи qualification, root receipt, permit,
   control и journal разделены. PG identity lease и lifetime flock удерживаются весь
   срок CP; второй writer не допускается. Это не HA и не network filesystem locking.
3. Root-only helper config имеет `apiVersion=agp.helper-runtime/v1alpha1`, exact `anchor`,
   `trust`, `native`, `ledgerDir`, `repositoryDir`, `repositoryDigest`, `receiptKeyFile`,
   `socket`, `controlPlane`, `journal`. Вложенные поля соответствуют типам
   `internal/helperruntime`, `nativeactivation` и `inventory.ClientConfig`; общего
   генератора installer config пока нет. Config/root receipt key private root-owned;
   CP mTLS credentials — защищённая root-owned копия exact registered agent leaf,
   journal использует отдельную identity. Не помещать эти файлы в БД/публичный catalog.
4. Только для новой пустой выделенной области выполнить явный staging. Он не запускает
   Nginx. Затем оператор запускает exact квалифицированный Nginx по установочному профилю;
   универсальная команда запуска данным CLI не предоставляется.

   ```bash
   /opt/agp/bin/agp-helper stage-initial --config /etc/agp/helper-runtime.json
   ```

5. После успешных serving generation/runtime/functional probes создать ledger один раз:

   ```bash
   /opt/agp/bin/agp-helper initialize --config /etc/agp/helper-runtime.json
   /opt/agp/bin/agp-helper run --config /etc/agp/helper-runtime.json
   ```

   `run` требует существующий ledger и выполняет pending recovery перед приёмом задач.
   Его запуск не сбрасывает high-water и не повторяет initialize. Неподдерживаемый native
   manifest v1alpha1 отклоняется; миграция на v1alpha2 автоматически не выполняется.
6. В существующем окружении CP задать `AGP_EXECUTION_CONFIG=/etc/agp/execution-runtime.json`.
   У агента к уже настроенным `--url`, `--ca`, `--ca-fingerprint`, `--certificate`, `--key`
   добавить `--execution-enabled --helper-socket /run/agp-helper/helper.sock` — путь должен
   совпадать с `socket.SocketPath`, UID/GID с установленным agent account. По умолчанию
   агент сохраняет inventory-only поведение. Socket/root peer и current mTLS проверяются.
7. Убедиться, что capture принят, затем проверить один canary через create → independent
   approve → dispatch → signed receipt и observation window. Helper сначала доставляет
   outbox, затем обновляет capture. Receipt подтверждается локально только после 204 CP;
   потеря ответа требует exact retry, а не нового применения. Статус UI/plan и активное
   поколение должны совпасть. Это отдельная стендовая приёмка, не автоматический успех CLI.

При 503 проверить наличие полного opt-in, secure identity/configuration runtime и
защищённых файлов; неполная настройка делает CP startup ошибочным. При stale/capture
ошибке сверить registry, boot, pins, authority и доставку outbox. Не удалять ledger/lock,
не уменьшать counters и не подменять неизвестный active tree установленной базой.
Полное сообщение helper startup намеренно не содержит private путей/ключей.

Откат конфигурации: новый согласованный rollback Plan с новой sequence. Pending recovery
использует сохранённую exact base; неопределённое состояние оставляет блокировку и требует
локальной сверки. Повторный staging/initialize и восстановление старой копии CP/ledger
не являются откатом. Порядок backup/restore и независимого fencing остаётся обязательным.

## 5. Adoption и миграция v1 → v2

1. Сохранить проверенный v1 backup, current effective Nginx tree, version/ownership inventory и тесты доступности ресурсов.
2. Импортировать users/groups/resources с сохранением IDs/case; неподходящие legacy IDs использовать через explicit identity bridge из модели данных.
3. Migration preview показывает grants, disabled states, host/path/upstream, CIDRs, headers, TLS/WAF, redacted secret references и collisions.
4. Legacy CRUD переводится через общий revision/security service: старый API не должен обходить CAS, approval или target-level permission.
5. Path-based applications отделяются от management origin: подготовить DNS/TLS/callbacks и проверить app cookies/absolute URLs.
6. Старые management-path application URLs допускают только безопасный redirect на новый origin после миграции, без проксирования приложения рядом с UI.
7. Отозвать legacy sessions/cookies в согласованном окне; UI предупреждает о повторном входе, приложение не принимает старую portal cookie.
8. Сначала inventory-only, затем validate-only, затем один canary. Unknown directives остаются operator-owned до явного compatible migration.
9. Сверить import/revision/digest/Auth route generation на реальном пути; лишь затем переносить следующие resources/nodes.

Validate-only не устанавливает пакеты, не меняет listener/config/current links и не делает root reload.
Если непривилегированный validator не может прочитать private TLS key/adopted include, результат помечается неполным;
полная root validation выполняется только в разрешённом helper lifecycle, а не через временную выдачу агенту root.
Ручной baseline остаётся доступным профилем для несовместимого узла; UI не обещает atomic managed rollback для ручной конфигурации.
Возврат к manual выполняется через detach с передачей inventory и сохранённой безопасной авторизацией, а не удалением agent из UI.

## 6. Изменения и rollout: действия оператора

Эта процедура одинакова для UI/YAML/JSON/будущего CLI. API имеет единые schemas, semantic validation, CAS и idempotency.
Оператор никогда не утверждает «все текущие labels» вместо конкретного immutable списка узлов.

1. Editor создаёт draft и получает validation/diff: routes/auth/WAF, affected users/resources, dependencies, secrets и возможный downtime.
2. Plan фиксирует target IDs, capability digests, exact base/current sequence, compiler/artifact/secret versions и expiry.
3. Approver проверяет затронутую зону/опасность и конкретный digest; независимое approval обязательно для risky changes.
4. Deployer делает fresh step-up и preflight: права/approval, online nodes, no drift, time/TLS, disk, journal, current denies и target Auth snapshot.
5. Dispatch назначает новый per-node sequence под сериализацией; один privileged active job на node. Read-only задачи не потребляют этот счётчик.
6. Canary — один явно выбранный node либо минимальная независимая failure domain; apply выполняется helper с durable journal до switch.
7. Пробы: config syntax/effective ownership, новая generation, successful/denied auth, spoofed headers/cookies, WAF mode, upstream health и TLS.
8. Наблюдение canary — минимум полный набор probes и согласованное окно репрезентативного трафика, заданное plan, с явным результатом оператора.
9. Каждая следующая волна стартует только после успеха предыдущей и повторной проверки security/capability/base предусловий.
10. Завершение сверяет desired/applied generation всех targets, deny readiness, journal result и audit, а не только HTTP accepted от agent.

Изменение secret/capability/base/ownership/target membership аннулирует старое планирование; UI предлагает новый plan, а не force apply.
Plan/Task фиксируют `authorityEpoch` отдельно от `writerEpoch`. Перед новым privileged start нужна свежая control authorization;
offline сохранённый permit сам по себе новый start не разрешает, даже до expiry.
Missing node остаётся явно неприменённым; его позднее появление не разрешает просроченный plan или расширение target list.
После accepted mutating sequence helper fsync-ит receipt/head до side effects; даже поздний failure не освобождает номер для другого payload.
При потерянном receipt следующий privileged task блокируется до reconcile; одинаковый task ID/digest возвращает сохранённый результат.
Rollback получает новый sequence и проверяет текущий base; он не возвращает clock/security floors к значениям старого bundle.

Pause прекращает новую выдачу/продвижение waves; уже начатые действия доходят до безопасного journal checkpoint и подтверждают фактический исход.
Cancel отменяет ещё не начатые задачи и дальнейшие waves, но не убивает произвольно root process и не откатывает успешные targets автоматически.
Pause/cancel сами не гарантируют остановку task, уже durable accepted offline; UI показывает pending acknowledgment и состояние каждого node.
То же ограничение относится к отзыву privileged task при partition: уже accepted операция может закончить bounded verify/recovery.
Немедленная изоляция узла при инциденте выполняется внешним traffic/host control, а не обещанием мгновенно доставить revoke по отсутствующей связи.
Продолжение возможно только после reconciliation, действующего approval/expiry и актуальных предусловий; иначе нужен новый plan.
Timeout/потеря связи — неизвестный результат; нельзя одновременно повторно применять и начинать rollback.
Первые auth/WAF safety failures, drift, recovery failure или несовместимый tuple останавливают дальнейшие waves.
Fleet rollout частичен по природе; транзакция PostgreSQL не делает файловую систему нескольких nodes ACID transaction.

## 7. Config rollback, binary rollback и локальное recovery

Config rollback восстанавливает только проверенный exact base tree и compatible Auth snapshot поверх текущих deny/security floors.
Он не понижает release version, не выполняет down migration и не снимает emergency revoke.
Binary/package rollback — отдельный upgrade/rollback plan по compatibility matrix и выше текущего security floor.
DB restore — отдельная DR процедура с replay независимого journal; это не пользовательская кнопка «откатить конфигурацию».

При сбое после switch helper использует заранее подписанное recovery permission из начатой операции.
Оно разрешает exact base recovery после plan expiry/CP outage; новые apply/upgrade и произвольный старый snapshot не разрешены.
Проверяются durable journal, ownership, base digest, current local security floor и доступность compatible Auth generation.
Если доказательства неполны, узел не подменяет состояние догадкой: закрывает затронутый доступ и требует supervised recovery.
Оператор сохраняет redacted journal, сверяет действующий digest с CP и выбирает новый recovery plan после восстановления связи.
Нельзя удалять журнал, сбрасывать sequence/epoch, отключать подпись или вручную включать auth/WAF bypass ради зелёного dashboard.
Offline recovery не открывает management listener и не выдаёт новую node identity.
Локальная поддержка использует существующий доверенный console path и фиксированный typed recovery adapter, предусмотренный package profile.
Все local recovery outcomes досылаются в audit при восстановлении центра; незаписанная root recovery не объявляется успешной.

## 8. WAF и сетевые топологии

Первый предлагаемый WAF provider — ModSecurity v3 + OWASP CRS; модуль должен пройти qualification с точным Nginx build/ABI.
Provider selection не является заявлением о совместимости любого distribution package.
Порядок включения: validate/compile → detection → tuning → canary blocking → последовательное расширение blocking.
UI всегда показывает effective mode; detection не выдаётся за предотвращённую атаку.
Тестовый защищённый запрос должен быть разрешён, запрещённый fixture — заблокирован в blocking и виден как событие в detection.

Исключение фиксирует rule/route/parameter, причину, owner, срок review/expiry и risk approval; глобальный бессрочный disable rule запрещён default policy.
Новая exception version проходит revision/plan/canary; request payload не добавляется в exception comment/audit.
Review deadline и hard expiry различаются. Scheduler заранее формирует removal revision/safe apply либо новое утверждённое продление.
Auth snapshot содержит route/exception expiry; если old active bundle не выведен к hard deadline, central Auth закрывает affected routes для новых requests.
В UI видны overdue exception, affected blocked routes и действие «применить removal / подтвердить новую extension version».
Metadata expiry не удаляет native CRS directive без apply; доступ восстанавливается только после проверенной безопасной generation/утверждённого продления.
Приёмка отключает scheduler/apply до expiry: affected route закрывается, unrelated route работает, native bundle честно показан прежним.
Старые streams отдельно ограничиваются lifetime/drain; это не обещание мгновенного закрытия всех соединений.
False positive разбирается на минимальном redacted request fixture; сбор полных request bodies требует отдельной ограниченной процедуры и не включён по умолчанию.
WAF crash/compile failure оставляет последнюю verified generation либо закрывает затронутый route; резервный upstream без WAF не допускается.

Для split-WAF нужны firewall/LB rules, которые допускают на gateway только проверенный WAF proxy identity и блокируют прямой client/upstream bypass.
TLS завершается на WAF и снова устанавливается к gateway; pins/CA/SNI/Host/client-IP chain и timeouts фиксируются installation profile.
Нельзя доверять forwarded IP от любого private source; only configured proxy identities/CIDRs.
Проверяются direct gateway IP, alternate DNS, IPv6, alternate ports, health endpoints и fallback LB pools.
Обход после WAF health failure запрещён; infrastructure operator заранее подтверждает отказоустойчивую безопасную схему.

## 9. Release packages, offline bundles и доверие к поставке

Qualification tuple включает OS/release/arch, libc/ABI, Nginx version/build flags, module connector,
libmodsecurity/CRS/provider versions и все artifact digests. `latest` и пакет только по имени недопустимы.
Closure включает все runtime dependencies, package metadata, install/remove hooks, licences, SBOM и trust metadata updates.
Разные tuple не смешиваются; unsupported node не получает экспериментальный module в обычном production rollout.
Install/upgrade/uninstall hooks signed/allowlisted по digest и проверены на network/file/service side effects;
package manager root execution не считается обычным config apply.
OS unattended upgrade не должен неожиданно менять Nginx/WAF ABI; согласование OS patching входит в ownership пакетов и maintenance process.

Release operator получает immutable build artifacts/provenance/SBOM, проверяет тесты/compatibility и только затем разрешает отдельный signing service.
TUF root offline; targets/snapshot/timestamp роли и release-manifest key разделены. Root/trust rotation поставляется в проверяемой цепочке.
Online mirror не имеет signing key. Хеш из того же непроверенного mirror не доказывает доверие к download.
Подписанный release manifest фиксирует конкретный closure, security floor и platform tuple; обычный rollback ниже floor запрещён.
Процедуры истечения/компрометации ключей требуют отдельных trust update и approval, не «выключить проверку на один раз».

Closed network профиль использует внутренние DNS/time/IdP/SMTP/repository и проверяется с полностью заблокированным external egress.
Airgap export формируется в доверенной зоне и содержит полную TUF metadata chain, manifest, closure, SBOM/licences и trust updates.
На входе isolated contour импортёр проверяет подписи/thresholds/versions/expiry/lengths/digests и bounded extraction до публикации в внутренний repo.
Импорт регистрирует bundle digest, source/operator, время и результат; носитель не становится доверенным потому, что доставлен администратором.
Дата доставки планируется до metadata expiry и certificate renewal; внешний IdP без внутренней связности не является работоспособной airgap зависимостью.
Expired TUF metadata блокирует новое обновление; проверенный уже работающий pinned binary не удаляется автоматически.
Offline token не заменяет central Auth; внутри изолированного контура работают собственные Auth/journal или доступ закрыт.
Требования соответствуют выбранной модели [TUF](https://theupdateframework.github.io/specification/latest/); поддержка airgap подтверждается отдельным drill.

## 10. Failure matrix и действия оператора

Во всех случаях сначала фиксируются affected scope, последняя достоверная generation/sequence, время, reason code и redacted correlation IDs.
Оператор не выполняет повторный privileged task до reconciliation неизвестного результата.

| Отказ | Ожидаемое безопасное поведение | Действия и критерий восстановления |
| --- | --- | --- |
| Только CP/API недоступен | Новые изменения останавливаются; existing Nginx работает. User access сохраняется лишь при отдельных исправных Auth/PG/journal | Восстановить CP/leader, сверить outbox/leases/tasks, не менять traffic config для починки UI |
| Auth либо его PG недоступен | Новые protected requests fail-closed; last config не создаёт cached allow | Проверить процесс, DB/TLS, deny readiness и probe allow+deny до снятия incident |
| Checkpoint unavailable/lag/mismatch | Новые allows и sensitive mutations закрыты по barriers; revoke не объявляется globally committed без ack | Восстановить journal authority/head, lookup pending operation IDs, replay PG и только затем readiness |
| Agent потерял control channel | Новые tasks не выдаются, accepted task доходит до безопасного checkpoint/recovery; Nginx конфигурация сохраняется | Проверить DNS/time/mTLS/control route, reconcile local journal до следующего task |
| EdgeAuth остановлен | Gateway не разрешает browser/session flow; agent не подменяет EdgeAuth | Восстановить отдельный процесс/role cert/session dependencies; проверить handoff и auth_request |
| Node/EdgeAuth certificate истёк | Никакого insecure renewal; control/auth connections закрыты. Working Nginx не означает доступность приложений | Через доверенную локальную процедуру восстановить time/trust и авторизованный re-enrollment |
| Node revoked | Control streams закрываются, renewal/tasks запрещены, central Auth больше не доверяет identity | Изолировать traffic path; исследовать host, переустановить/перевыпустить identity после owner approval |
| Часы недостоверны | Expiry-sensitive privileged actions и допускающая авторизация не полагаются на неверное время | Исправить corporate time, подтвердить monotonic floors, повторить freshness/cert probes |
| Disk full до switch | Apply отклонён без изменения current; alert и bounded traffic loss policy | Освободить только approved expendable cache/logs, проверить reserve и создать/retry допустимый plan |
| Disk/journal failure после switch | Не успех по timeout: local recovery либо явное ручное восстановление с закрытым affected access | Сохранить журнал, проверить fsync/base/digests, восстановить exact base или approved target |
| Spool/SIEM недоступен | Management audit сохраняется в reserve; critical mutations блокируются при невозможности durable audit; traffic drops измеряются | Восстановить destination, дослать event IDs идемпотентно, не очищать management journal |
| WAF/provider упал | Последняя verified конфигурация либо закрытый route; нет silent bypass | Проверить tuple/module/limits, восстановить qualified build и blocking probes |
| PG leader/failover | Old writer fenced; выдача новых mutating tasks заморожена до новой lease/epoch | Проверить единственного writer и journal head, сверить pending tasks и agent receipts |
| Частичный fleet rollout | Применённые узлы остаются явно различимыми; дальнейшие waves остановлены | Сверить каждый node, выбрать новый forward/rollback plan по compatible Auth snapshots |
| Repository/metadata unavailable/expired | Новые installs/upgrades заблокированы, existing pinned data plane остаётся | Доставить подписанные свежие metadata/closure; не отключать expiry/signatures |
| Signer/KEK unavailable | Новые privileged permits/secret decrypt блокируются; уже доступные runtime secrets живут только по своей policy | Восстановить key service с аудитом; не экспортировать root keys в CP для обхода |
| Notifications unavailable | Очередь/retry/dedup, UI показывает задержку; доставка alert не гарантируется | Использовать независимый monitoring channel, восстановить destination, проверить backlogs |

Открытые WebSocket/stream могут пережить revoke: handshake Auth не является continuous enforcement.
Для ресурсов с требованием быстрого разрыва нужны квалифицированные drain/connection lifetime/active disconnect меры;
incident runbook различает запрет новых requests и завершение уже установленных соединений.
Readiness не становится зелёной только от живого process: проверяются authoritative dependencies, generation и security head.
Auth подтверждает каждый allow последовательностью head → PG writer decision → head; epoch/head и PG applied head должны совпасть.
Изменение head вызывает bounded retry, затем deny/unavailable. Рост retry/mismatch виден в метриках; stale read replica не заменяет writer.

## 11. Backup, PITR и disaster recovery

Резервируются PG base backup/WAL, immutable revisions/plans/ownership, object blobs/manifests, config trees,
encrypted secret versions, trust metadata, audit exports и отдельно key recovery material.
Отдельно резервируется независимый security journal с собственным доступом/storage/failure domain и проверяемым head.
PG backup не заменяет journal, а ciphertext backup не заменяет encryption keys.
Concrete first-release default журнала — отдельный Go service и собственный PostgreSQL cluster/account/storage/backup domain;
его нельзя разместить просто в другой schema CP cluster. Atomic append проверяет expected head и идемпотентный operation ID.
Предпочтительна выделенная VM. Colocated вариант допускается только с раздельным restore domain и внешним trust recovery:
возврат общей VM snapshot с обоими кластерами не доказывает security freshness.
После такого отката требуется внешний trusted head/keys либо supervised новая authority epoch с revoke всех credentials
и повторным подтверждением grants; старые grants из snapshot не становятся допустимыми автоматически.
Предлагаемый pilot default: daily PG base backup + continuous WAL archive, проверка archive lag и recovery chain;
retention backup задаётся корпоративной политикой отдельно от log retention и подтверждается storage capacity.
Logical dump полезен для переносимости, но сам по себе не даёт WAL PITR
([PostgreSQL 17: continuous archiving/PITR](https://www.postgresql.org/docs/17/continuous-archiving.html)).
Backup шифруется, имеет manifest/checksums, restricted access, неизменяемую копию и проверяемую доставку;
ключ дешифрования не хранится в том же архиве с открытым доступом.
Backup success означает сохранённую и проверенную цепочку, а не просто exit code upload.

Restore drill и реальный recovery выполняются одинаково:

1. Изолировать CP/Auth, остановить mutations/rollout dispatch и обеспечить fencing прежнего writer; protected access закрыт до проверки.
2. Сохранить current incident evidence, agent receipts и authoritative journal head; не восстанавливать journal из старого PG backup.
3. Подготовить clean verified binaries/OS tuple, нужные encryption/trust keys и независимый checkpoint authority.
4. Восстановить PG base/WAL до выбранной точки, objects/config/metadata и проверить schema/binary compatibility.
5. Сверить authority epoch/head и replay typed security events до текущего независимого head; pending append узнать по operation ID.
6. Восстановить/сверить current security floors, deny overlays, authenticator versions, credentials/grants revokes и key availability.
7. Через durable journal `advance_authority_epoch` повысить `authorityEpoch`: инвалидировать восстановленные sessions/gateway sessions/handoffs/invites/enrollment tokens/recovery codes и pre-DR планы для нового start.
8. Проверить `issuedAuthorityEpoch` (SQL `issued_authority_epoch`) против независимого current `authorityEpoch`; повторный вход/перевыпуск кодов требуют пригодного authenticator выше актуального floor.
9. Не разрешать ни user allow, ни management mutations из старого backup до выполнения barrier; старые роли не становятся вновь действующими.
10. Сверить каждый node desired/applied digest/sequence и unknown tasks; DB restore не откатывает файловую систему gateways.
11. Проверить allow/deny, MFA/recovery, generation mismatch, secret access, audit delivery и невозможность повторного принятия старого task/одноразового кода.
12. Снять traffic/management barriers по проверенным scopes, зафиксировать фактические RPO/RTO/потери и уведомить владельцев.

Password/MFA/OIDC-binding update сначала подтверждает journal `bump_authenticator_floor(principalId, authenticatorId, minimumVersion)`,
затем публикует новую credential version; ошибка второго шага оставляет старую credential непригодной.
Восстановленный старый password hash/TOTP seed/IdP link ниже floor запрещён даже для нового login; его нельзя «обновить» сменой номера version.
Нужен supervised reset после подтверждения личности; тест восстановления обязательно проверяет старые пароль/factor/link и consumed recovery code.
Для пользователей restore означает явный повторный вход и перевыпуск one-time secrets, что включается в incident communication.
Единственный security epoch — `authorityEpoch`. Его повышение не сбрасывает journal/node sequences или `writerEpoch`;
bound permit уже принятой операции допускает только её bounded finish/recovery offline, после чего новый start требует свежего подтверждения центра.

Если journal потерян/неполон или его authority key не восстановлен, сервис остаётся fail-closed.
Security disaster recovery в таком случае — отдельная supervised процедура: новый подтверждённый authority epoch,
отзыв/перевыпуск sessions/node credentials, проверка grants и floors; возврат sequence к нулю не является восстановлением.
Read-only копия старого head из backup не доказывает отсутствия более поздних revoke.
Journal retention не равен 365-дневному audit retention: действующие ограничения/floors и доказательства их актуальности не истекают по log cleanup.
Compaction journal допускается только отдельным квалифицированным checkpoint/snapshot protocol с независимым anchor, не обычным DELETE по дате.
Key rotation сохраняет decrypt capability для backup retention; старый KEK не уничтожается до окончания окна восстановления и проверенного rewrap.
Не менее одного регулярного drill восстанавливает backup, сделанный до user/node revoke, и доказывает сохранение более позднего запрета.
Операторы фиксируют фактические результаты; документ не заявляет нулевой RPO, гарантированный RTO или пройденный restore test.

## 12. Мониторинг, retention, capacity и SLO

Метрики отделяют process liveness, readiness dependencies, actual generation, business Auth decisions и control/task progress.
На dashboard: desired/applied generation, drift, Auth/deny head, pending security operations, rollout wave/unknown results,
certificate/TUF expiry, queue/spool bytes/age/drops, disk reserve, rejected tasks, WAF mode/blocks и backup/WAL health.
Labels метрик используют bounded IDs/reason codes, не raw URL/user/email/request body. Cardinality budgets задаются до load test.
Metrics endpoints доступны только monitoring network; SIEM/log transport имеет отдельную identity и bounded retry.

Предлагаемые pilot alerts: любое auth-generation/deny-head mismatch, rejected signature, journal corruption или recovery failure — critical;
certificate/TUF expiry предупреждает заранее по профилю, с отдельным critical до renewal deadline.
Для node certificate 24 h предлагается warning при остатке <6 h и critical <2 h; для внешнего TLS warning за 30/14/7 дней.
Time skew warning >30 s, critical >120 s; реальные допуски подтверждаются TOTP/certificate/freshness tests и политикой организации.
Spool high-water warning 80%, critical 95%; долгий task/backup lag/expired exception/failed canary имеют отдельные reason alerts.
Alert suppression maintenance window не отключает auth/WAF enforcement и не скрывает loss counters.
Notifications идут через outbox с dedup/retries/TTL; независимый мониторинг должен обнаруживать отказ самого CP/notification pipeline.

Предлагаемые исходные retention defaults: management/security audit 365 дней, operation logs 30 дней, traffic/WAF logs не более 7 дней.
Это параметры пилота, а не правовое требование: владелец данных подтверждает корпоративную retention/legal hold политику до production.
Session cleanup, invite/recovery state, diagnostic results, export TTL и object GC имеют отдельные политики из модели данных.
Security journal/current deny floor не удаляются по log retention. Legal hold блокирует затронутый GC и фиксируется audit event.
Traffic/WAF quota/sampling явные; при переполнении удаляется только разрешённый низкоприоритетный traffic stream с counters/alert,
а management audit не подменяется sampling. Невозможность durable critical audit блокирует соответствующие mutations.
Spool/cache предел вычисляется из available disk, reserved journal space и worst-case bundle; UI показывает эффективные лимиты до enrollment.

Три измеряемых профиля: all-in-one pilot, distributed pilot и HA qualification; размеры/нагрузки фиксируются в [testing](testing.md).
Product owner утверждает user-visible availability/revoke/delivery цели; эксплуатация отвечает за infrastructure latency/capacity/RPO/RTO,
разработчики — за protocol/error budgets и измеримость; security owner подтверждает допустимую потерю/задержку security evidence.
До qualification записываются proposed objectives, метод, percentile/window, workload, WAN latency/loss и hardware;
после прогона — фактические p95/p99 Auth latency, throughput, rollout duration, recovery time и backlog recovery.
Непроверенные цели не публикуются как SLA. Нельзя повышать availability включением offline allow или ослаблением deny freshness без нового решения архитектуры.
Capacity planning учитывает число routes/users/nodes, concurrent auth, rule compilation, package closure,
spool during outage, WAL/audit/object growth и минимум два одновременных config trees для recovery.

## 13. Upgrade, downgrade, detach и uninstall

Server/agent/protocol compatibility matrix публикуется с release: предлагаемый диапазон — текущая и предыдущая minor версия,
но поддержка конкретного tuple подтверждается fixtures, а не номером «N−1» без ограничений.
Перед upgrade fleet inventory подтверждает matrix, certificates/trust/metadata сроки и достаточный disk reserve.
Сначала backup/restore evidence и canary, затем отдельные CP/Auth/agent/helper/component waves согласно release dependency graph.
Schema изменения проходят expand → backfill → dual compatibility → проверка → contract после завершения rollback window.
Contract/drop migration не включается незаметно в routine restart; необратимый шаг имеет отдельный review и maintenance approval.
Downgrade binary допустим только при текущей schema/data/secret/protocol совместимости и выше security floor.
Down migration/DB restore не выполняются автоматически вместе с component rollback.

Detach — переход из AGP управления, а не автоматическое отключение защиты:

1. Остановить новые assignments/tasks, дождаться/reconcile active operations и зафиксировать exact applied digest/ownership/dependency inventory.
2. Согласовать, сохраняется ли central Auth; если AGP Auth удаляется, заранее подготовить и проверить новый механизм авторизации приложения.
3. Передать owner current config, pinned dependencies, backup и redacted audit export; private keys автоматически не экспортируются.
4. Удалить management binding и отозвать agent identity; EdgeAuth identity сохраняется только при явно сохранённом Auth обслуживании.
5. Локально деактивировать helper/agent по согласованному плану; offline node не считается удалённым только по нажатию кнопки в центре.
6. Сверить работоспособность/запреты и новый ownership, затем выполнить ограниченный uninstall.

В варианте keepAuth фиксируется explicit retained EdgeAuth binding: management-detached узел остаётся только доверенным Auth client
с отдельной role identity и renewal policy. Отзываются agent identity и helper access; generic `revoke_node` здесь не вызывается.
Полный node revoke/retire закрывает обе роли, agent и EdgeAuth, и потому планируется как отдельное отключение Auth/traffic.

Uninstall удаляет только принадлежащие AGP files/units/packages после проверки manifest и drift.
Adopted Nginx configs, shared packages, чужие certificates/includes и application data сохраняются.
Drift блокирует автоматическое удаление спорного объекта и требует owner resolution; «purge всё под /etc/nginx» запрещён.
Audit/backup retention и evidence сохраняются по политике; активные credentials revoke-ятся до удаления локальных references.
Certificate revoke не удаляет process с узла. Полный offline detach требует локального оператора и последующей сверки центра.
Итоговая приёмка выхода проверяет доступность приложения, сохранение защиты, ownership и отсутствие действующих лишних identities.

## 14. Массовое сопровождение WAF Zones

Нормативные состав/конфликты/таймауты заданы в [WAF Zones](waf-zones.md).
Оператор различает candidates, desired назначения и observed защиту по узлам;
число назначенных сервисов не является числом проверенных работающих сервисов.

Порядок планового обновления:

1. Создать и проверить successor base policy и zone revision, не меняя действующий
   binding. Просмотреть изменённые проверки CRS и ограничения совместимости.
2. Получить frozen resolution с TTL 30 минут; проверить entering/staying/departing
   Gateway, replacements, derived rebase и конфликты. Для межплощадочного обновления
   подготовить отдельные Site-bound resolutions/plans одной UI-командой.
3. Материализовать Configuration draft под CAS. При устаревшем head/inventory/истёкшем
   снимке сохранить авторский ввод, создать новый preview; старый approval не переносить.
4. Рассмотреть полный effective diff всех узлов. Если общий node bundle содержит
   неподтверждённую правку соседней зоны, включить её в явный review либо выполнить
   controlled rebase. Проверить limits secret versions и свободное место для двух trees.
5. Утвердить exact plan и выполнить контрольную wave на подходящих узлах; проверить
   allowed/denied/Auth/MFA/WAF probes и регрессии обычных приложений, а не только Nginx reload.
6. Продолжить bounded waves. При ошибке поставить дальнейший dispatch на паузу,
   reconcile текущие задания и сохранить точные observed versions. Повторный клик после
   timeout сначала ищет существующий operation/rollout по ID.
7. Завершить только после evidence по всем ожидаемым consumers/nodes. Недоступные
   узлы остаются partial/unknown. Если действующее исключение истекло, применять
   route-specific deny/removal runbook, не аварийный WAF off для всей зоны.

Новые сервисы/узлы появляются как кандидаты следующего batch. Автоматизация может
подготовить resolution/draft с ограниченным scope, но не расширяет подписанный plan
и не утверждает собственное dangerous изменение. Удаление зоны означает плановый
retire с заменой desired bindings; физическое удаление исторических данных не требуется.

Для `fleet-10k` перед включением нужны измерения на 1000/5000/10000 Gateway и отдельно
маршрутах/узлах: parser/normalization/compiler CPU/RAM, PG/CAS contention, bounded
selector query, p95/p99 scoped pages, full-node reload/probes и recovery. Общий snapshot
64 MiB и 100000 routes — верхние quotas, не гарантия размещения на одном узле или SLA.
Переполнение адресно блокирует план; нельзя увеличить все global limits на работающей
системе без schema/capability qualification. Старые профили остаются с прежними limits.

Backup/export сохраняет Configuration и source closure: zone/policy revisions,
resolutions, assignments, lineage, referenced CRS/profile/artifact versions. Restore
проверяет digests и актуальные security floors до выдачи tasks. Импорт создаёт drafts;
он не активирует чужие назначения и не переносит старое approval на новые IDs.
