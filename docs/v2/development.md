# Разработка и поставка AGP v2

Статус: TARGET итогового ТЗ, редакция 2026-11-17. WAF Zones приняты владельцем;
статусы архитектурных ADR и незавершённая qualification сохраняются. [ТЗ](requirements.md) определяет результат, [testing](testing.md) — доказательства приёмки.
Этот план описывает разработку, не разрешает commit/push/release/deploy без отдельного поручения владельца.

## Текущий срез S0 — AS-IS на 2026-11-18

Реализован **single-node S0 pilot**, не вся платформа TARGET и не production-ready
поставка. Legacy SQLite и его режим входа сохраняются отдельно; secure profile
включается явно через `AGP_SECURE_PROFILE=true` на PostgreSQL.

- Сохранены actor-aware guards, delegation ceiling, atomic revoke/last-admin,
  DNS pinning с исходным Host/SNI и per-location trusted Nginx headers.
- `internal/securityjournal` — отдельный PostgreSQL, mTLS и Ed25519 signed head/events,
  разные read/append identities и реестр независимых approvers. `internal/securitystate`
  связывает durable pending/barrier, append/reconciliation, restrictive replay,
  authenticator floors и grant incarnations. Identity writer lease и транзакции
  используют одно соединение с CP primary; HA этим не реализована.
- Secure local identity: password → обязательный для **всех** пользователей TOTP,
  enrollment, recovery codes, sessionless recovery и fresh step-up с заменой session.
  Angular entry `/auth-ui/login`, `/auth-ui/recover`, `/auth-ui/step-up` встроен в Go;
  это реальный auth UI; typed config/WAF UI подключён отдельно на `/config-ui/`.
- Management/login/application origins и sessions разделены. Central handoff использует
  PKCE и mTLS; отдельные EdgeAuth processes обслуживают каждый application origin через
  private Unix sockets. Все application bytes проходят request/response cookie filter,
  Central Auth проверяется при каждом решении. Стенд покрывает два приложения.
- Restore CLI разделяет внешнее fencing/approved epoch advance, native CP restore,
  restrictive replay и quarantine до `releaseAfter`. Independent journal/key store
  не восстанавливаются вместе с CP. [Активация, restore и rollback](../operations.md#s0-pilot-активация-и-восстановление).

В исходный S0 не входили invite/contact delivery и общий workflow согласования новых
grants. Последующие email и lifecycle-срезы описаны ниже; общий positive-grant workflow
описан в более позднем срезе Role bindings ниже.
В secure profile запрещены legacy user creation с готовым паролем, административный
password reset и расширение privileged grants без поддерживаемой процедуры; UI показывает
ограничение. `create-admin` допустим только как явный **pre-activation bootstrap**.
Это ограниченный AS-IS, не замена принятых identity/approval требований TARGET.
В исходный S0 не входили AD/OIDC/SMTP, root helper/safe apply и HA. Более поздние
ограниченные WAF/inventory, sandbox и direct AD срезы описаны ниже.

Исходный S0 был квалифицирован на Nginx 1.30.6, последующий пакет — на 1.30.7.
С 2026-11-25 security floor — 1.30.8: сборка и 25/25 mandatory native WAF cases
подтверждены. Последующий полный PG/HTTPS pipeline завершился exit 1 на проверке
владельцев каталогов native sandbox. Отдельное продолжение HTTPS/browser и последующий
штатный native host run прошли PASS; это не общий PASS и не qualification полноценного
Ubuntu 24 host/root bridge.
[Историческое provenance и текущий native tuple](../nginx-recommendations.md).
Единый `bash scripts/test-s0-full.sh` после финальных исправлений завершился PASS
2026-11-18: mandatory native без SKIP, реальный restore и семь HTTPS/browser групп.
Полная Go-регрессия с `-race -count=1` и `go vet ./...` также завершились PASS.
Команды и точные границы — [проверки S0](testing.md#текущий-пакет-s0-команды-и-границы).
Ветка и HEAD текущего workspace не подтверждены: `.git` не содержит читаемых объектов.

## Текущий срез S1 — authoring pilot

S1 включается отдельно: `AGP_CONFIGURATION_ENABLED=true` требует активированного
secure PostgreSQL profile. Default S0 не меняется. Полный snapshot требует global
`config.read/edit` на management origin с актуальной session/journal state; existing
admin сохраняет совместимость. Записи требуют CSRF и свежего MFA step-up. Полная
scoped RBAC-модель остаётся TARGET; ограниченный S1b описан ниже.

Parser JSON закрыт по типам/полям и bounded до DTO. YAML поддерживает **safe subset**:
approved examples и server-export round-trip; это не полный general YAML. Physical line
и block scalar ограничены 8192 bytes, multiline quoted scalars запрещены. Anchors,
aliases, tags и merge keys запрещены; quotes/flow delimiters внутри plain scalar требуют
quoting **всего** scalar. Bounded lexer выполняется до yaml AST. Для неподдерживаемого
синтаксиса используйте JSON или канонический server YAML export.

Серверный путь: bounded JSON/YAML → canonical full Configuration → versioned draft
с CAS autosave → immutable full revision под global-head CAS → validation report и
полный per-node preview. Head здесь относится к authoring, не observed/applied state.
`Draft` содержит `id`, `baseRevisionId?`, строковую `revision`,
`contentDigest`, `content`; конфликт ETag/base не перезаписывает чужие изменения.
Report фиксирует target ID/version, config/catalog/compiler digests, issues/diff и
`authoringValid` отдельно от `deployable`. `CompilerResult` фиксирует capacity profile,
resolved inputs, полные node proposals и digests артефактов; pin compiler основан на
SHA-256 **реального binary**, version и options, а не на неподтверждённом Git HEAD.

Catalog snapshot immutable и `sourceKind=operator_declared`; его ссылки/`published`
значения заявлены оператором, не доказывают connected nodes, native capabilities,
baseline или квалификацию WAF. Пример: [declared catalog](examples/catalog-authoring-pilot.json).
В этом pilot `deployable=false` у reports/results/bundles; validation operation
`succeeded` означает расчёт отчёта, а не принятую конфигурацию или право apply.

`agpctl configuration-profile --activate` при остановленном CP фиксирует DB fence
legacy resource writer после создания первой immutable revision. Это отдельная
операция: один env flag не включает fence. После активации отключение env/удаление
marker не являются rollback; [процедура и API](../operations.md#s1-authoring-pilot).
S1 не выполняет reload/apply, не выдаёт новых privileged grants и не закрывает весь
В этом S1 срезе не квалифицированы WAF publication/derivation, полная scoped authoring-модель, fleet/capacity qualification
остаются непоставленными. Единый `scripts/test-s1-full.sh` завершился PASS
2026-11-18: mandatory native без SKIP, реальные browser flows и offline cutover;
[команды и границы проверки](testing.md#текущий-пакет-s1-проверки).

### S1b: scoped authoring и review зон

AS-IS нового пакета: явный pre-secure bootstrap назначает существующим principals
`config.read/edit/approve` только в `global|site` и фиксирует immutable Gateway→Site
ownership. После secure activation новые grant/ownership INSERT закрыты; grants
привязаны к authority epoch, `revoke_role_binding` материализует отзыв. Catalog не
служит источником scopes. Existing admins сохраняют global read/edit, **без implicit
approve**; node/node-group/resource scopes и выдача новых approved grants остаются TARGET.

Scoped `GET revision?gatewayId=` выдаёт `gatewayView` без полного `content`.
`gatewayChange` проверяет ownership и прежний/новый Gateway, сливает изменение на
сервере и фиксирует полный snapshot под global CAS. Site editor не меняет Site,
node selector, ownership, component profile или TLS. Полные drafts/reports и импорт
catalog по-прежнему имеют отдельные global/admin guards.

WAF zones сохраняются как immutable authored revisions с per-zone head CAS и
Site-filtered списком. Frozen preview живёт 30 минут и pin-ит exact Configuration,
catalog, resolver и heads всех co-zones; membership **hypothetical**, `deployable=false`.
Для отметки `purpose=draft_review` reviewer отличается от zone author и preview creator,
имеет current Site edit и fresh MFA. Epoch/grant fingerprints, head/co-zones/catalog/resolver
или expiry делают review stale. Это отдельный draft review; publication approval и trusted resolution реализованы
в более позднем ограниченном срезе ниже. TARGET DTO не расширен:
authoring list использует отдельный route/summary без фиктивных desired state/counts.
[Процедура и API S1b](../operations.md#s1b-scoped-authoring-и-review-зон).
Единый `scripts/test-s1-full.sh` с S1b завершился PASS 2026-11-18: mandatory native
без SKIP, scoped MFA login, zone/review browser flows и offline cutover.
Это историческая приёмка ограниченного authoring pilot; последующие publication
и resolution описаны ниже, apply и полный TARGET не входят в эту приёмку.

### Component repository и базовые WAF policies: принятый AS-IS

Новый AS-IS код проверяет offline release через `go-tuf/v2` 2.4.2 и отдельно JCS/Ed25519
manifest, полную CAS dependency closure и file/license SBOM. Trust anchor и durable
metadata/release floors находятся вне CP restore domain; public root, четыре TUF roles
и release keys разделены. Текущее время берётся из свежего challenge-bound signed
journal head, без локального fallback. Provider повторяет проверку после native работы.

Immutable base policy workflow хранит head CAS, validation, независимый approval и
publication как отдельные факты; `config.approve` выдаётся только явно. Qualification
pin-ит exact manifest digest/release sequence, profile/tuple/ruleset/evidence/compiler
и expiry. Evidence связывает corpus, harness, Go renderer и raw native report с той же
verified closure. Даже published policy/report не разрешают live apply.
Provider исполняет exact artifact по `RendererDigest` из verified closure под
комплектным Ubuntu 24 loader, как native corpus. Native work имеет один общий
nonblocking slot на процесс; API-ошибка `native_waf_busy` имеет HTTP status 503.
Поддержаны только typed base policies с `exceptions=[]`; derivation и непустые
exceptions возвращают `422 unsupported_derivation|unsupported_exceptions`.

Исторически квалифицирована одна Ubuntu 24.04 amd64 строка: Nginx 1.30.7, connector 1.0.4,
libModSecurity 3.0.17, CRS 4.30.0. Единый `scripts/test-waf-full.sh` завершился PASS
2026-11-18: 25/25 mandatory native cases без SKIP, реальные PG/provider/restore,
три native Nginx группы и все 18 browser групп. `go test -race -short ./...` также PASS.
Принят ограниченный AS-IS: Ubuntu 24 userland на host kernel `7.0.0-38-generic`.
Привязка этого provider к authenticated inventory и trusted zone resolution/materialization
добавлена следующим срезом ниже; derivation/exceptions и helper/apply сохраняются TARGET. [Процедура](../operations.md#component-repository-и-базовые-waf-policies),
[проверки](testing.md#component-repository-и-native-waf-принятый-as-is).
Обновление 2026-11-25: tuple 1.30.8 / 1.0.4 / 3.0.17 / 4.30.0 собран в Ubuntu 24
userspace и прошёл 25/25 mandatory WAF cases без SKIP, 23 baseline unit groups и
проверку actual `-V`/required modules. Allowlist/floor обновлены после этих проверок;
полный pipeline остановился на `workspace_parent_rejected`, отдельное продолжение
HTTPS/browser и штатный native host run прошли PASS. Host Ubuntu 26.04 не становится
квалифицированным Ubuntu 24.04 host из-за выбранного runtime userspace.

### Read-only agent inventory и trusted WAF zones — AS-IS на 2026-11-19

Optional `agp-agent` отправляет ограниченное Linux inventory через исходящий TLS 1.3
на отдельный role listener. Identity берётся из installation-owned реестра публичных
сертификатов вне CP restore, с exact `spiffe://agp/agent/{nodeId}`, issuer/SPKI/serial,
Site/labels/groups и authority epoch. Это **external preregistration**, не enrollment
или issuing service TARGET; новые privileged grants и ownership не создаются.
На каждом запросе проверяются current journal, registry, цепочка/expiry, epoch и revoke.
Challenge действует 60 секунд и потребляется один раз; immutable receipt имеет
монотонную sequence и freshness 120 секунд. Exact retry возвращает прежний receipt
и не продлевает freshness. Capability snapshot отделён от boot ID/free bytes/last seen.

Collector не выполняет команды, helper/apply или health probes. Optional typed
component profile задаёт bounded список файлов для хеширования. Runtime adapter
сопоставляет exact profile bytes, file hashes, наблюдаемые OS/arch/kernel с текущей
подписанной repository closure и native evidence; это не attestation и не доказательство
active/healthy state. `/api/v2/agent-inventory` — только read-only для current admin;
`config.edit` не даёт node/enrollment authority. В `/config-ui/` inventory показывает
connectivity/identity, сохраняя applied/health как unknown.

Zone validation → независимый `config.approve` → publication использует exact published
same-Site base policy и current native proof. Frozen resolution на 30 минут строится
по полной Site closure из canonical Configuration, immutable ownership, published
co-zones/policies и current authenticated inventory. Operator catalog остаётся
`operator_declared`; он не подменяет trusted источник. Стабильный inventory digest
не содержит heartbeat timestamps/receipt ID, но freshness, expiry, epoch и revoke
повторно проверяются при materialization. Head/scope/source/pin drift закрывает запись.

`WafZoneChange` атомарно создаёт **одну полную immutable desired ConfigRevision**
с global-head CAS, seal и pinned assignments/provenance; это не draft-only merge и
не применение на узле. Обычный authoring не может унаследовать approved assignment
после изменения security inputs Gateway/маршрутов или profile assignments; display
names разрешены. Для изменения защиты нужен новый controlled resolution workflow.
Поддержаны existing owned Gateways; new onboarding, derived policies/local exceptions
и nonempty `profileAssignments` явно отклоняются. Compiler preview по-прежнему
`deployable=false`. Последующий пакет ниже добавляет agent identity и локальный syntax probe; helper, capture baseline, rollout,
реальные health/applied proofs и остальной TARGET предстоит реализовать.

[Активация, API и rollback](../operations.md#read-only-agent-inventory-и-trusted-waf-zones),
[команды и фактические границы проверок](testing.md#read-only-agent-и-trusted-zones-проверки).
Последующий инкремент agent identity и локального syntax probe описан ниже;
квалификация helper и local safe apply остаётся по исходным требованиям TARGET.

### Approved agent identity и локальный syntax probe — AS-IS на 2026-11-20

`nodeidentity`, `nodebootstrap`, отдельный `agp-issuer` и узловые CLI реализуют
ограниченный **agent-role pilot**. Management nodes/read/enroll/revoke доступны
только current admin; запись требует fresh MFA (5 минут), exact Origin, CSRF,
idempotency key и повторной проверки current session/core authenticator incarnation
в fenced transaction. Это не полный scoped `nodes.*` RBAC и не выдача EdgeAuth identity.

Token: 256 случайных бит, default TTL 600 s, допустимо 60..900 s; в CP и issuer
сохраняется hash, plaintext показывается только первым ответом. Узел создаёт Ed25519
key/CSR локально, отправляет token в отдельный server-authenticated TLS 1.3 enrollment
listener. Первый CSR фиксируется как pending; владелец сверяет SPKI fingerprint по
доверенному каналу и явно утверждает exact request digest. Только после этого выдаётся
сертификат `spiffe://agp/agent/{nodeId}`. Повтор того же CSR возвращает прежний результат;
другой CSR, устаревшая epoch, revoke или смена approver incarnation закрывают выдачу.
Private issuer request также фиксирует точные authority/epoch/sequence/digest из
проверки approver в CP. Issuer сверяет их со своим свежим signed journal head до
подписи и повторно проверяет head перед commit: emergency restriction между
проверкой CP и выдачей не создаёт сертификат. CP и issuer обновляются согласованно;
запрос старого private protocol без этого pin отклоняется.

Issuing CA key и durable SQLite ledger принадлежат отдельному процессу/аккаунту вне CP
backup/restore. CP имеет разные mTLS credentials для issuer write и registry read;
offline root private key в эти процессы не загружается. Renewal требует текущего
agent certificate и **нового ключа**, допускает bounded overlap 0..900 s; повтор
завершает ту же issuance и при нулевом overlap. Generic node revoke проходит независимый
journal, закрывает обе agent certificate generations и не удаляет объявленный узел.
Site universe включает pending/expired/revoked nodes: отсутствие свежего inventory
не позволяет молча сократить trusted-zone closure.

`agp-agent-validate` — отдельный one-shot **локальный** typed WAF syntax probe:
подписанные repository/renderer/profile bytes, exact capability/pins, текущий journal,
private workspace, nonroot child и лимиты ресурсов. Durable intent/result переживают
перезапуск; exact retry не исполняет subprocess повторно, незавершённый intent даёт
`local_syntax_result_indeterminate`. Sequence всегда `"0"`. Результат фиксирует
`nativeSyntaxOnly=true`, `executionLocation=local_process` и
`isolation=unprivileged_private_workspace`; это не kernel sandbox, remote NodeBundle
receipt, helper, apply или health proof. Внутренний CP diagnostic Service не опубликован
HTTP endpoint; работа без qualified process limits не разрешается.

В `/config-ui/` admin получает создание node, first-only token, pending fingerprint
approval и revoke; UI различает identity, connectivity и неизвестные applied/health.
Trusted provisioning CA/pins/credentials пока ручной, готовый installer не заявляется.
Корпоративная приёмка AD/SMTP, qualified remote helper, capture baseline, safe apply,
clean VM/offline install, HA/DR и fleet SLO остаются TARGET. [Процедура](../operations.md#управляемая-agent-identity-и-локальная-проверка-синтаксиса),
[приёмка](testing.md#agent-identity-и-локальный-syntax-probe-проверки).

### Основа допуска helper — AS-IS на 2026-11-24

`internal/helper` реализует отдельный Linux-пакет допуска `apply_config` и
`rollback_config` к локальному журналу. Закрытый envelope связывает task с узким
подписанным permit, installation/baseline pins, exact bundle/profile/release/tuple/
compiler digests, approval и recovery base. `TrustDigest` закрепляет три разных
ключа и назначения: permit, current control authorization и independent journal.
`Installation.Baseline` обязателен как trusted installer input с revision ID, bundle
digest и sequence; фактические bytes базы здесь не снимаются и не проверяются.
Перед новым допуском helper сам создаёт challenges и проверяет signed journal head →
короткоживущий signed `StartProof` → новый signed head того же состояния.

Intent, admission receipt и монотонные deployment sequence, authority/writer epochs
сохраняются одним atomic snapshot с file/directory fsync. Store удерживает доверенные
directory descriptors и exclusive flock весь срок открытия; подмена дерева или ошибка
durability блокирует дальнейшую работу этого handle. Exact retry возвращает прежний
`agp.helper-admission/v1alpha1` с `noExecution=true`, включая истечение task и отсутствие
сети. Другой task блокируется до будущего доказуемого reconciliation;
`RequireRecovery` лишь усиливает блокировку, API завершения или очистки intent нет.

В этом пакете нет binary, Unix socket, executor, доступа к active configuration,
reload, probes или перехода в applied/healthy. Pins не доказывают проверку ownership
tree или qualification native artifacts. Полный wire DeploymentPlan и отдельный CP
planning-review и последующий execution runtime описаны ниже. Qualified installer
и pilot reboot qualification остаются TARGET. REQ-11/REQ-12 этим admission-only срезом
не закрываются. [Протокол](protocols.md#основа-допуска-helper),
[проверки](testing.md#основа-допуска-helper-проверки),
[граница эксплуатации](../operations.md#основа-допуска-helper).

### Подписанный Plan и planning review — AS-IS на 2026-11-24

`internal/deploymentplan` реализует закрытые полные `agp.plan/v1alpha1` и
`agp.plan/v1alpha2`, canonical digest, Ed25519 envelope `agp.signed-plan/v1alpha1`
с `purpose=execution`. Нормализация сортирует set-поля без изменения caller-owned
массивов; повторяющиеся targets/inputs/secrets, unknown fields, numeric UInt63,
изменённый digest и подпись другого назначения отклоняются. План закрепляет exact
targets, baseline/bundle/capability/secret versions, inputs, epoch, deny floor и rollout
policy. Сам контракт не подтверждает согласование или пригодность к исполнению:
его текущая схема не содержит отдельных compiler manifest/release tuple digests,
нужных для полной approval closure.

Helper требует полный подписанный v1alpha1 Plan для каждого нового допуска и
сверяет его с task, выбранным target и installation component profile. Используется
тот же pinned CP permit key с отдельным prefix `AGP-DEPLOYMENT-PLAN-v1`.
Исторический exact retry проверяется раньше нового gate и сохраняет доступность
старого `noExecution=true` receipt без `signedPlan`; это не разрешение на исполнение.
Plan v1 ограничен 2 MiB, request — 2 MiB + 64 KiB, state — request + 32 KiB.
Пакет Plan поддерживает fleet v2 до 50 000 inputs/32 MiB, но helper принимает только v1.

CP `internal/configuration/plan_proposals*.go`, migration `023_plan_proposals.sql`
и вкладка «Подготовка развёртывания» в `/config-ui/` реализуют отдельный workflow:
current ConfigRevision → frozen proposal → независимый review → optional signed
planning review. Сервер проверяет полный declared Site через trusted inventory,
native published WAF closure и свой catalog, затем закрепляет full-node preview
digests выбранных targets. Caller не передаёт evidence, baseline или runtime claims.
Унаследованные profile assignments и route WAF exceptions в этом срезе не поддержаны.

Доступ пока global-only: `config.read`, для создания также `config.edit`, для review
и подписи — явный global `config.approve`. Admin не обходит independent approval;
автор и reviewer различаются. Session/source session, security/password floors,
права обоих участников, epoch и независимые dependencies перепроверяются до exact-key
replay. Writes требуют CSRF/Origin, fresh MFA и Idempotency-Key. Изменение состояния
даёт историческому proposal/review `current=false` и блокирует новые согласования.
IDs автора/reviewer сохраняются как исторические значения и не препятствуют удалению
учётной записи; удаление делает прежнее согласование неактуальным.

Результат подписи — `agp.signed-plan-review/v1alpha1`, `purpose=planning_review`,
`deployable=false`, `noExecution=true`, с полными proposal/review и отдельным
`AGP-PLAN-REVIEW-v1` signature domain. Dedicated key задаётся optional
`AGP_PLAN_REVIEW_KEY_ID`/`AGP_PLAN_REVIEW_KEY_FILE`; без него подпись отвечает 503.
CP runtime не выпускает execution Plan, permit или StartProof. Actual baseline,
полная runtime qualification и execution authorizer остаются blockers; последующие
owned-tree/sandbox пакеты ниже не создают права исполнения.
Полное приложение по ТЗ ещё не готово к публикации; следующие доказательства нужны
для helper/apply/rollback, корпоративной AD/SMTP приёмки и квалифицированной установки/восстановления.
[Контракты](protocols.md#подписанный-plan-и-planning-review),
[проверки](testing.md#подписанный-plan-и-planning-review-проверки).

### Read-only owned tree — AS-IS на 2026-11-25

`internal/ownedtree` проверяет существующее дерево по закрытому
`agp.owned-tree/v1alpha1`: node/site, absolute root, полный список relative paths,
UID/GID, mode, file size и SHA-256. Manifest digest поступает отдельно из trusted
installation input; документ не разрешает сам себя. Обязательны root entry `.` и
явные родительские каталоги. Manifest ограничен 1 MiB/4096 entries, relative path —
1024 bytes/16 levels, файл — 4 MiB, сумма файлов — 64 MiB.

Linux reader удерживает descriptors всей ancestry и entries; no-follow открытия,
сверка имён с pinned inode/device/metadata, exact child lists и `statx` mount IDs
проверяются повторно. Все entries принадлежат root либо effective UID процесса;
group/other write, executable files, links, special files и mount переходы внутри
дерева отвергаются. Отсутствие kernel mount proof закрывает проверку. Обнаруженное
несоответствие делает handle непригодным до закрытия; context cancellation сама по
себе handle не отравляет.

Новый opt-in `helper.NewGateWithOwnedTree` сверяет node/site/manifest digest с
`Installation.OwnershipDigest`, проверяет дерево до сбора fresh authorization и
повторно после него, до нового intent. Drift не потребляет sequence. Прежний
`NewGate` сохраняет admission foundation без filesystem gate; ни один constructor
не предоставляет executor. Exact historical replay возвращает прежний
`noExecution=true` receipt до новой filesystem/network проверки.

`cmd/agp-owned-tree` — отдельная root-only read-only CLI с локальными `-manifest`
и `-ownership-digest`, без network/API, subprocess или изменения дерева. Результат
`agp.owned-tree-observation/v1alpha1` имеет `purpose=filesystem_observation`,
`noExecution=true`, `runtimeValidated=false`; это unsigned metadata/hashes с локальным
временем. File bytes и резервная копия не сохраняются. Наблюдение не доказывает
активную конфигурацию Nginx, validated baseline, ownership delegation или approval;
CP его не принимает и baseline blockers остаются.

V1 manifest привязан к конкретному содержимому базы. Последующий native executor
и capture описаны ниже; это не расширяет полномочия read-only owned-tree CLI.
Installer и полная root/pilot qualification остаются TARGET.
[Локальная процедура](../operations.md#локальная-проверка-owned-tree),
[форматы](protocols.md#локальный-owned-tree-manifest-и-наблюдение),
[проверки и ограничения](testing.md#read-only-owned-tree-проверки).

### Native sandbox и managed bootstrap — AS-IS на 2026-11-25

`ownedtree.Tree.Capture` копирует и хеширует одни и те же manifest-approved bytes
через pinned descriptors. Snapshot существует только в памяти, отклоняет JSON
serialization и очищает собственные buffers при закрытии. Это локальные потенциально
секретные данные; caller отвечает за очистку полученных копий. Durable backup не создаётся.

`internal/nativesandbox` выполняет только фиксированный Linux `nginx -t` profile:
отдельные user/IPC/PID/network/UTS namespaces, запрет вложенных user namespaces,
пустые capabilities, очищенное environment и явный nonroot execution UID/GID.
Root supervisor отдельно сбрасывает supplementary groups. Trusted root-owned
bubblewrap проверяется по digest и исполняется через FD; runtime/config передаются
как sealed memfd snapshots. Корень, `/runtime`, `/config` и `/dev` доступны только
для чтения; writable `/scratch` ограничен 64 MiB. Host filesystem и сеть недоступны;
native diagnostics отбрасываются с лимитом 64 KiB. Direct-exec fallback отсутствует.

`BootstrapValidator` принимает только точные bytes закрытого
`agp.managed-bootstrap/v1alpha1`; произвольная adopted конфигурация не переводится
в этот profile. Проверяются signed release/tuple/evidence/renderer, ownership/tree,
свежий независимый journal до/после syntax probe и неизменность дерева/host boot.
`agp.baseline-candidate/v1alpha1` содержит exact pins, sandbox tool/profile digest,
execution UID/GID, фактические OS/kernel и boot digest. Результат имеет
`purpose=baseline_candidate`, `provenance=managed_bootstrap`, `syntaxValidated=true`,
но `activeConfigurationVerified=false`, `baselineVerified=false`, `deployable=false`
и `noApply=true`. Baseline revision ID не создаётся; CP planning и helper не принимают
его как verified baseline. Несовпадение host с qualified runtime явно отражается
в `runtimeHostQualified`, а не скрывается Ubuntu userspace bundle.

`cmd/agp-bootstrap-candidate` — отдельный root-only local adapter с protected
installation config и явным child UID/GID. Actual signed syntax candidate на tuple
Nginx 1.30.8 с финальным execution-identity profile прошёл локальную проверку. Root bridge на настоящем Ubuntu 24.04 host ещё
не квалифицирован. Active master/generation proof, durable exact backup,
promotion в immutable baseline, apply/reload/probes/recovery остаются TARGET.
[Проверки и необходимые ресурсы](testing.md#native-sandbox-и-bootstrap-candidate-проверки).

### Direct AD и управление provider — AS-IS на 2026-11-25

`internal/identity/directory*.go`, миграции 024/025, management API и `/directory-ui/`
реализуют disabled registration, immutable CAS versions, server-side connector test
и digest-bound activation с независимым approval. Guard floor фиксируется через
независимый journal до CAS materialization; recovery не возрождает старую configuration.
Legacy admin не заменяет явный `config.approve`.

Реальный LDAP client поддерживает LDAPS/StartTLS с проверенной CA/hostname, отдельный
user bind, forest/object GUID и BASE `tokenGroups`. Referrals и plaintext fallback
закрыты; DC/IP и egress prefixes задаются trusted installation, секреты — защищёнными
immutable version references. `AGP_DIRECTORY_CONNECTOR_FILE` выбирает локальную
конфигурацию; без connector server test/enable и directory login закрыты.
Direct AD primary proof проходит обязательный TOTP и общий session/handoff/EdgeAuth
путь. JIT создаёт только непривилегированного principal, совпадение UPN не связывает
его с локальной учётной записью. Текущие provider/identity versions и live account/groups
перепроверяются; local password и stale membership не заменяют AD при outage.

SQLite/PG, TLS LDAP wire и browser fixture проверки описаны в [testing](testing.md#direct-ad-и-provider-проверки).
Финальные management guards и historical author/reviewer proofs прошли отдельный
review. На SQLite и native PG подтверждены 24 сценария реального TLS LDAP → identity →
WAF configuration с текущими provider/link floors и отказом при outage; portal writes
проверены отдельно на обеих БД. Синтетический LDAP сервер не заменяет настоящий AD DS.
OIDC identity backend добавлен следующим срезом; корпоративная приёмка остаётся OPEN.
По решению владельца
от 2026-11-25 внешние тестовые ресурсы будут созданы после готовности реализации;
их отсутствие не останавливает локальную разработку и не превращает приёмку в PASS.

### Контакты, email-коды и SMTP — AS-IS на 2026-11-25

Opt-in `AGP_EMAIL_CONFIG_FILE` требует secure PostgreSQL profile и protected installation
files. Миграции 026/027 разделяют время primary authentication и MFA, добавляют
зашифрованные контакты, purpose-bound challenges и outbox. Время primary не выводится
из `created_at` или MFA; старые sessions с неизвестным primary time не получают права
изменять контакты без повторной аутентификации.

Собственные контакты доступны на login или management origin с соответствующей session.
GET возвращает masked address; создание/замена требуют primary и MFA не старше пяти
минут, CSRF, а замена — exact CAS revision. AES-GCM использует отдельный keyring и AAD
principal/contact/version. Замена сначала поднимает независимый journal floor, затем
меняет ciphertext и сбрасывает verification; старые challenges и sessions отзываются.

Email-код содержит восемь криптографически случайных цифр, действует до пяти минут и связан с purpose,
flow, principal, contact/version, audience, epoch и generation. Реализованы single consume,
пять попыток на flow, до трёх выдач, resend не ранее 60 s и общий лимит пять выдач
на нормализованный адрес за час между flows.
`verify_email` и подтверждение в уже авторизованном recovery flow не выдают session,
handoff или MFA; arbitrary invitation/recovery ticket не поддерживается.

Outbox хранит только ciphertext, а одноразовый DEK — в bounded RAM vault. После restart
утраченный DEK не восстанавливается из DB/backup: job становится terminal, пользователь
явно запрашивает новый код. SMTP выполняет одну submission через проверенный implicit
TLS или обязательный StartTLS; DNS/IP pinning, CA/hostname и egress policy обязательны.
Неопределённый результат после DATA не повторяется автоматически; публичный `failed`
может означать неподтверждённую доставку, а SMTP acceptance не доказывает доставку письма.

Backend SQLite/native PG, DNS/TLS/SMTP composition, HTTP origins/CSRF/CAS и protected
runtime/secret files прошли локальные проверки и отдельный review. Это синтетические
wire fixtures, не приёмка корпоративного SMTP. Реальный Angular UI `/auth-ui/contacts`
реализует masked list, create/replace и подтверждение без хранения адреса/кода в browser
storage; отдельные email и auth browser fixtures прошли локальную проверку.
Invitations/password setup и supervised recovery добавлены следующим интегрированным срезом.
Согласование role bindings описано ниже; полный business lifecycle secret versions остаётся OPEN.
[Проверки](testing.md#контакты-email-коды-и-smtp-проверки),
[установка и ограничения](../operations.md#контакты-и-smtp-opt-in).

### Invitations, initial activation и recovery — AS-IS на 2026-11-25

Этот срез перенесён из integration stage в основной workspace;
общий прогон завершился exit 1 на native sandbox guard после успешных backend suites.
Миграции 029–031 добавляют lifecycle,
one-time token registry, activation stages и recovery operations/capabilities.
Pending local user создаётся без пароля и permission-bearing grants; username приводится
к lowercase по существующей local-primary policy. Это не реализация полной TARGET
Unicode normalization. Normal login/session/handoff/management требуют `active`;
исключение для invited доступно только private typed setup context.

Invite API требует management origin, CSRF, current actor/target, fresh primary/MFA,
idempotency key и `If-Match`, возвращает `201` с metadata доставки без raw token.
256-bit email token резервируется за одним rotated flow/binding. Далее обязательны
password setup → сохранённый flow-bound восьмизначный `invite_confirmation` → staged
TOTP enrollment → atomic complete. Email сам не засчитывается как primary/MFA.
После independent floor receipts одна TX публикует credentials/active state и consumes
invite; completion не создаёт session/handoff. Потерянный binding, cancel и expiry
не разрешают unclaim; нужен новый invite. Запрос public password reset возвращает
`202` с пустым body без account/contact/delivery metadata.

Обычный local reset требует verified-contact token и действующий TOTP с точной factor
version и proof time; замена фактора или устаревший proof закрывают completion.
Supervised actions разделены: `replace_mfa`, local `reset_password` и invited-only
`restart_activation`. Distinct approval, target/policy/version pins и restrictive floor
steps повторно проверяются перед materialization; live AD evidence охватывает target,
автора, reviewer и текущего executor, если это разные principals. Ticket выдаётся один
раз только для первых двух actions. Restart оставляет invited без credentials и требует
нового обычного invite; active account им не понижается.

Legacy recovery code даёт только MFA replacement capability с детерминированным guard,
связанным с flow/principal/binding/epoch: restore не создаёт новый guard вместо уже
spent/cancelled. Runtime удаляет истёкшие anonymous setup flows и staged secrets,
проверяет final enrollment deadline; delivery использует прежний bounded SMTP transport
и volatile DEKs без автоматической повторной отправки.

Backend paired SQLite/PG, actual HTTP, TLS LDAP wire и локальные Chromium fixtures
подтверждают отдельные части среза. Финальная UI-правка revocation и canonical-receipt
проверена отдельной management browser suite, typecheck и build. Backend suites общего
прогона и отдельное HTTPS/browser продолжение прошли PASS; общий результат остаётся FAIL
из-за native sandbox guard в том запуске; последующий отдельный штатный native run прошёл
PASS. Корпоративные AD DS/SMTP, root VM и GA остаются OPEN.
[Проверки](testing.md#invitations-activation-и-recovery-проверки),
[процедура](../operations.md#приглашения-активация-и-recovery-stage).

### AD-backed OIDC — AS-IS на 2026-11-25

Реализованы disabled provider registration, immutable versions, bounded server-side
connector test и digest-bound activation с независимым approval. Exact `(issuer, sub)`
связывается только с существующей AD DirectoryIdentity/principal через согласованный
link, stable guards и независимые journal floors. Email/UPN и произвольные claims не
создают link или привилегии. Live AD account/groups, текущие provider/link versions и
floors проверяются также при использовании полученных flow/session projections.
Изменение OIDC link само по себе не делает все исторические AD-authored reviews
невалидными; principal-level restrictive checks сохраняются.

Первый профиль допускает RS256, `client_secret_basic`, code + PKCE S256 и только
`mfaClaimMode=none`: после OIDC primary обязателен AGP TOTP. Login и management имеют
разные client IDs, immutable secret versions и фактически разные secret bytes; endpoints
проверяются по exact pins. Отдельный `AGP_OIDC_CONNECTOR_FILE` фиксирует trusted HTTPS
origins/CIDRs, bounded transport и отдельный protected state keyring; он не использует
MFA/email keys. Primary time берётся из проверенного `auth_time`, а не из времени MFA
или callback.

Authorization связывает 256-bit state hash с server-selected flow/provider/audience/
browser, nonce и PKCE verifier шифруются. До трёх явных starts на flow отменяют
предшественника. Callback обменивает code один раз, затем меняет flow ID/binding и
возвращает fixed `303` на `/auth-ui/?flow=...`; session выдаётся только после MFA.
Terminal/expired proofs очищаются; startup закрывает interrupted exchanging и old-epoch
pending без повторного exchange. Valid current-epoch pending с retained state keys
не отменяется лишь из-за restart. Cleanup worker принадлежит runtime и останавливается
вместе с ним. При потерянном
callback response допустим только GET reconciliation, если новый binding cookie уже
получен; без него нужен новый login. Bounded `session_state` отбрасывается и не является
реализацией logout/session management IdP.

Management UI `/directory-ui/?view=oidc`, lazy login-method loading и callback continuation
реализованы. Transport, HTTP boundaries и actual HTTPS→signed IdP→TLS LDAP composition
прошли локальные проверки. Финальный backend race-прогон на SQLite/native PG прошёл
без SKIP/FAIL; отдельные OIDC Chromium suites и browser continuation прошли проверки.
Backend suites после интеграции lifecycle и отдельное HTTPS/browser продолжение прошли
PASS; общий pipeline завершился exit 1 на native sandbox guard.
Wire fixture использует trusted SQL setup, in-memory journal и ручную обработку cookies,
поэтому не заменяет corporate AD DS/IdP qualification. [Проверки](testing.md#ad-backed-oidc-проверки),
[настройка](../operations.md#ad-backed-oidc-opt-in).

### Role bindings и scoped node management — AS-IS на 2026-11-25

В основной workspace перенесены immutable versioned role presets, typed bindings во
всех пяти scopes и workflow create → independent approve → execute с exact request
digest. Положительный grant публикуется атомарно в current fenced TX; отзыв закрепляет
в независимом journal tombstone конкретного binding. Текущие role incarnation, expiry,
session/primary/MFA, epoch/floors и ownership source pins проверяются повторно.
Management admission и identity readers потребляют effective grants; scoped permission
не превращается в global. NLGate Angular UI `/directory-ui/?view=roles` поддерживает
назначение, согласование, выполнение и отзыв с GET reconciliation потерянного ответа.

Paired SQLite/PG race, HTTP, Chromium fixture и независимые review подтвердили этот
ограниченный срез. AD aliases одного forest/object не считаются разными согласующими;
проверки также добавлены в recovery, AD/OIDC и configuration approvals. Scoped node
read/enroll/revoke подключены к сервисам и HTTP; global role authority — к защищённым
legacy mutations с typed target ceiling. Проверены exact session pins, frozen creation
receipts, private enrollment approval и issuer deadline перед CA commit. Configuration
Gateway read/edit поддерживает global/site и node/group: каждый receiving node должен
быть покрыт текущим объединением grants; пустой состав не даёт разрешения. Sealed
ownership и полная label universe перечитываются перед финальным Head, без зависимости
от собственного config CAS. `GET /api/v2/gateways` фильтрует объекты до pagination и
закрепляет revision; Angular получает exact object read/edit без расширения до Site.
Scoped редактор сохраняет соседние Gateway и блокирует смену selector/ownership/TLS/
component profile. Resource-only grant даёт чтение и замену одного существующего
маршрута по sealed resource/Gateway/route tuple; остальные размещения того же ресурса
сохраняются. Список закрепляет revision и фильтрует placements до pagination. Сервер
проверяет old/candidate, смену победителей segment-prefix маршрутизации и пересечение
доверенных получателей Gateway при общем hostname; неизвестный источник закрывает
операцию. Свежие resource metadata и receiver pins перечитываются перед последним
Head. Angular `/config-ui/` предоставляет отдельный редактор маршрута с exact access,
сохранением локальных полей, идентичным retry и явным rebase. Исторические Gateway
сохраняют прежнюю читаемость; неподдерживаемый префикс не получает узкого routing proof.
Resource grant не даёт whole-Gateway access. Assigned WAF сохраняет штатный trusted
resolution barrier: display-name-only допускается, security edit требует нового
resolution. Resource-aware WAF resolution и scoped planning/approval остаются TARGET.
Отдельные paired runtime suites и focused review пакета завершены;
общий pipeline после переноса и расширения этого пакета ещё не запускался.

### Согласование, применение и откат — AS-IS на 2026-11-26

Добавлены отдельные `rolloutexecution`, execution ledger в `helper` и файловый/runtime
адаптер `nativeactivation`. Это opt-in компоненты, а не включённый production executor.
`/api/v2/config/execution-plans` имеет отдельный контракт: точный immutable Plan,
независимое согласование его digest, явная выдача задачи и подписанный root helper
результат. Права `rollouts.create`, `rollouts.cancel`, `rollouts.rollback` отдельны от
редактирования и поддерживают global/site/node_group/node без расширения resource grant.
Согласование повторно проверяет текущих участников, роли, сессии, MFA и source pins.
Поддерживается последовательная политика 1/1 с остановкой при ошибке и observation window;
другие политики отклоняются явно. TARGET асинхронные fleet API этим контрактом не заменены.

Immutable installation, текущая здоровая конфигурация и accepted high-water хранятся
раздельно. Неуспешная принятая операция не возвращает счётчик назад. Explicit rollback —
новый Plan, согласование и задача с новым номером; локальное аварийное восстановление
разрешено только к заранее сохранённой точной базе. Перед переключением после fsync
повторяются live head/proof/same-head и проверка срока разрешения; native adapter
проверяет короткий deadline непосредственно перед атомарным изменением указателя.
Здоровый target сохраняется при потере ответа. Неопределённое состояние блокирует
следующие операции и требует recovery/containment. Терминальный exact replay не
повторяет файловые или runtime эффекты; outbox хранит подписанный результат до ACK.
Ledger ограничен 1024 результатами и не удаляет историю автоматически.

Native adapter закрепляет полные qualified bytes и runtime manifest, сохраняет base,
атомарно меняет указатель, использует фиксированный Nginx master и проверяет поколение,
свежий challenge и route/auth-deny/WAF-deny ответы через установленный Unix socket.
Manifest `agp.native-generation/v1alpha2` и storage slot связывают content generation
с номером операции, поэтому A→B→A не переписывает старое поколение. `TreeDigest`
определяет содержимое без sequence; manifest/slot сохраняют точную sequence.
Старый prototype v1alpha1 отвергается; автоматической миграции/сброса нет.
Recovery после process crash проверяет точную пару
base/target; аварийная изоляция ограничена installer-pinned cgroup. Обычная agent mTLS
идентичность не позволяет подделать отдельную подпись root helper результата.

Planning-only proposals/reviews и прежний admission-only `Gate` сохраняют свои границы.
YAML/JSON остаются форматами импорта и экспорта; исполняемое решение связывается с
канонической версией, digest и историей в БД. Сам файл YAML не является согласованием.

`internal/executionsources` соединяет sealed SQL revision, текущие роли/ownership,
approved agent mTLS inventory и signed qualified release с отдельно подписанным полным
native materialization. Root-owned SourceCatalog содержит только pins, bindings и
пустой `materials`; полные материалы, включая возможные TLS bytes, читаются из отдельного
private файла service UID. Каталог и файлы перечитываются на операциях; qualification
key не принадлежит CP. Наличие signature не заменяет сверку полной source closure.
Profile assignments и zone assignments сейчас закрывают этот execution путь; полная
материализация сервисов/WAF Zones и producer квалифицированных материалов не заявлены.

Штатный CP подключает этот Sources только при `AGP_EXECUTION_CONFIG`, secure PostgreSQL
identity runtime и configuration API. Требуются существующий PG identity lease и
lifetime flock с проверкой inode; это один writer на одном host, без HA. Отсутствие
настройки сохраняет 503, неполная/недопустимая настройка останавливает startup.
`agp-agent --execution-enabled --helper-socket ...` передаёт неизменяемую задачу через
Unix socket. Root helper проверяет SO_PEERCRED, сам запрашивает current StartProof и
journal head по своему challenge, отправляет signed outbox прямо в CP и подтверждает
локальную доставку только после фактического пустого 204. У агента нет ACK операции.

`agp-helper stage-initial|initialize|run --config ...` разделяет staging первой базы,
создание ledger после проверки реально обслуживаемого поколения и daemon. `run` не
создаёт/не сбрасывает ledger, сначала восстанавливает pending attempt; capture подтверждает
точную установленную базу, boot и монотонные counters, не разрешая apply. Дивергентная
база блокируется. [Процедура](operations.md#реализованный-execution-runtime--as-is-на-2026-11-26),
[wire-контракт](protocols.md#доставка-задач-и-подтверждение-базы--as-is-на-2026-11-26).
`BootstrapCandidate` и compiler proposal не превращены в verified baseline или qualified
Nginx bundle. `make build` включает agent/helper; release-check проверяет оба entrypoint.
Воспроизводимый `make test-execution-wiring` завершился exit 0: парные Sources/HTTP,
helper/native/runtime, Unix/agent/client, challenge-bound mTLS и scoped vet прошли.
Root-only writer-lock lifecycle явно пропущен; настоящая root/Nginx/cgroup/reboot
qualification остаётся нужна. [Команда и границы](testing.md#execution-wiring-воспроизводимая-проверка--as-is-на-2026-11-26).
Controlled-adapter и файловые composition tests не подтверждают готовность к
публикации. Нагрузочный сервер владелец подготовит отдельно;
AD-приёмка отложена, SMTP будет подключён после подготовки ресурсов.
Новый CP требует обновить issuer первым: старый issuer отвергает deadline field.
Положительный AD enrollment всей цепочки и dynamic ownership не квалифицированы;
legacy hard-delete role-bound principal закрыт immutable FK. После CA commit отказ CP
сохраняет внешний ledger и требует reconciliation, без обещания CA rollback.
Это промежуточная реализация, а не готовность к публикации по полному ТЗ.

## 1. Организация кодовой базы

Сохраняем Go-модуль и существующие пакеты до обоснованной миграции. Перенос Git на корпоративный сервер не требует немедленного переименования всех Go imports.
Backend — модульный монолит, агент/helper/EdgeAuth — отдельные роли исполнения с разными permissions и failure domains.

```text
cmd/agp/                 server / выбранные server roles
cmd/agpctl/              типизированный CLI к management API
cmd/agp-agent/           исходящий management transport и reconcile
cmd/agp-helper/          минимальный root executor
cmd/agp-edge-auth/       callback/session adapter к Central Auth
internal/identity/       local/AD/OIDC links, MFA, limited flows, invites/codes, sessions
internal/identity/ad/    read-only AD DS connector, stable GUIDs, live state/groups
internal/access/         route generation, effective policy, deny application
internal/configmodel/    DTO, parser, normalization, references
internal/compiler/       deterministic bundles, supported native directives
internal/controlplane/   revision/plan/approval services
internal/wafzones/       typed zones/selectors, frozen resolution, derivation/rebase
internal/rollout/        dispatcher, leases, waves, reconcile
internal/agent/          durable task runner и spool
internal/helper/         operation allowlist, filesystem-safe apply
internal/edgeauth/       browser handoff и auth_request adapter
internal/repository/     CAS, TUF client, compatibility/release manifests
internal/securitylog/    independent journal protocol и reconciliation
internal/notifications/  typed channels, retry/dedup/maintenance
internal/storage/       небольшие domain repositories + transactions
internal/httpapi/        transport adapters, без business rules
internal/frontend/      существующая v1 UI/Go embedding до управляемой миграции
web/                    новый Angular frontend v2 и общий UI/help layer
tests/contract/          schema/API/compiler compatibility fixtures
tests/integration/      disposable PG, Nginx/WAF/PKI/AD/IdP/SMTP стенд
tests/e2e/              реальные browser + rollout/fault scenarios
```

Это целевая структура, не перечень уже существующих директорий. Разделять процессы на микросервисы до необходимости не требуется.
По решению владельца от 2026-11-17 новый frontend v2 строится на **Angular + TypeScript**,
standalone components, typed Reactive Forms и общем design system. Детали и HelpTip/manual —
[ui-design](ui-design.md); [интерактивный пример](../../web/console-prototype/README.md).
Новый UI подключается к тем же typed API/CAS/security contracts. Existing v1 UI сохраняется
до отдельного проверяемого cutover, без немедленной замены embed assets во время создания макета.

## 2. Принципы реализации

- Domain services не импортируют HTTP/router, CLI и SQL-driver; transport не принимает решения доступа самостоятельно.
- Доменные ID/Sequence/Epoch/Digest/Duration — разные типы; string/int64 не передаются между доменами без validation constructor.
- Critical state хранится реляционно; JSONB — canonical documents и ограниченная metadata, не замена PK/FK/constraints.
- Репозитории небольшие: IdentityRepository, RevisionRepository, PlanRepository, TaskRepository и явный UnitOfWork.
- Контекст/таймаут есть у каждого I/O. Секреты и тела credentials не входят в errors/log fields.
- Typed commands запускают фиксированные binaries без shell. Helper не принимает raw paths/argv/native snippets из API.
- Compiler детерминирован: одинаковая canonical model + resolved inputs + version/profile дают одинаковые bytes/digest.
- Новый UI/API/CLI использует один service layer. Старый CRUD становится адаптером drafts/read-only, не вторым writer.
- Один смысл состояния — одно имя в schema/БД/UI. Unknown не превращается в success/failed без observed evidence.
- Нет транзакции «PostgreSQL + весь fleet»: durable intent, receipts, idempotency, fencing и reconciliation обязательны.
- Каждый security-sensitive путь проверяет permissions на target principal/object, delegation ceiling и current step-up, а не только кнопку UI.
- Любой read model/dashboard может отставать; авторизация и dispatch никогда не доверяют отстающей аналитической проекции.

## 3. Этапы и зависимости

| Этап | Вертикальный результат | Зависимости / выход |
| --- | --- | --- |
| S0 Baseline | Исправлены четыре baseline-пробела; disposable PG CI; management isolation и privileged lifecycle tests | Без root helper; явные миграции origins и session reset |
| S1 Configuration Core | Реальный resource в canonical revision, UI/YAML round-trip; WAF zone authoring/resolution и массовый preview; capacity-profile parser | Schema/type/CAS/compiler/membership tests; никакого автоматического reload |
| S2 Identity / agent read-only | AD DS и AD-backed OIDC, pending MFA/email flows; node enrollment/mTLS/rotation/revoke, inventory/validate-only | Реальные AD/IdP/SMTP tests, GUID/groups/TLS/outage/restore; PKI/role separation/replay |
| S3 Local safe apply | Один квалифицированный managed/adopted canary, helper, functional probes и local rollback | MFA/recovery/RBAC/approval, fsync/fencing, независимое review helper |
| S4 WAF/artifacts | Qualified Nginx/ModSecurity/CRS tuple, TUF, zone-base/derived policies, rebase, rules/exceptions, offline dependency closure | Positive/negative corpus, no label escape, expiry gate, tamper/ABI tests |
| S5 Fleet | Frozen zone membership/targets, полный node diff, canary/waves/reconcile, cross-Site UI coordination, fleet-10k qualification | Security journal/SSO/EdgeAuth до защищённого трафика; actual node caps, no implicit future approval |
| S6 HA/lifecycle | Single-writer failover/fencing, PITR/key-store recovery, detach/upgrade compatibility; отдельная qualification split-WAF/airgap | Измеренные SLO/RPO/RTO, DR/restore из старого backup, no revived grants; anti-bypass и signed import |
| S7 Regional | Regional Auth/relay и автономность авторизации | Отдельные contracts/qualification, принятая staleness/revoke и ownership модель |

Части identity/MFA/SSO из v1.1 не откладываются до S6: strong identity нужна до S3, cross-host handoff/EdgeAuth — до первого соответствующего canary.
Корпоративный пилот S2 требует квалификации обязательных AD/2FA/одноразовых кодов
по [identity](identity.md); OIDC-only mock не закрывает direct AD connector acceptance.
Independent security journal и replay — dependency любого нового security mutation; его нельзя добавлять после включения distributed auth.
WAF signatures/TUF должны работать до root installation произвольного компонента, а не появляться после массового update.
Можно разрабатывать модуль S5 с mocks раньше, но нельзя объявлять его эксплуатационно готовым без зависимостей.

### Первые рабочие пакеты

| Пакет | Ответственность | Результат для review |
| --- | --- | --- |
| Identity hardening | Backend/security | target principal guard, group/permission delegation, session revoke tests |
| Origin/SSO | Backend/frontend | отдельные cookies/origins, handoff flow и негативные browser tests |
| Typed model | Backend/frontend | branded SDK types, bounded parser, canonical fixtures |
| Data foundation | Backend/DB | миграция dev schema, repository constraints, transactions и identity bridge |
| Preview/compiler | Backend/Linux | semantic diff, dependency resolution, bundle without apply |
| UI first slice | Frontend | resource editor → save draft → validation → preview, no live mutation |
| WAF Zones | Backend/frontend/QA | zone → typed selector → immutable resolution → exact diff/targets; local derivation/rebase и «?»/manual |
| Capacity profiles | Backend/DB/QA | v1alpha1 неизменён; v1alpha2 bounds/converters/fixtures, datasets 1000/5000/10 000 Gateway |
| CI harness | Release/QA | ephemeral PG, schema/SDK drift check, no production credentials |

Каждый пакет проверяется на общий вертикальный сценарий, а не принимается только по наличию файлов.
Оценка сроков/людей делается после декомпозиции и первого среза; документ не обещает выдуманную дату готовности всей платформы.

### Вертикальный срез WAF Zones

1. Реализовать [WafZone/resolution/change contracts](waf-zones.md) и typed storage;
   zone versions неизменяемы, membership не разрешается в агенте или во время apply.
2. Проверять Site/object scopes для полного эффекта, AND-match/default/ambiguity,
   protected labels, parent locks/minimum и explicit replacement для выходящих участников.
3. Создавать shared base и per-Gateway derived policies с provenance; rebase сохраняет
   совместимые local changes, конфликты остаются явными, expiry не продлевается автоматически.
4. Под CAS материализовать exact bindings в полный Configuration и source closure.
   Native output остаётся обычным полным node bundle; изменения других зон раскрываются.
5. Реализовать Zones-first UI, server pagination/frozen «все результаты», impact preview
   и отдельные site plans. Сохранить individual editor и dirty draft/manual поведение.
6. Завершить [приёмку](testing.md): stale/new members, label escape, common nodes,
   partial rollout, new node, перенос/retire, rollback expiry, caps/migration и load datasets.

Нельзя повысить только `maxItems` одной schema: parser, HTTP request/response budgets,
canonical storage, SDK, compiler memory, resolved-input count и qualification меняются
согласованно по версии. `fleet-10k` сохраняет 1000 Routes/Gateway, 500 nodes/plan и
100 secret versions на узел; превышение требует placement conflict либо отдельной
версии task/agent profile, а не игнорирования cap. Конвертер v1alpha1→v1alpha2 делает
preview без live эффекта; обратная конверсия разрешена только при соблюдении старых
ограничений. Старый consumer получает unsupported version до изменения состояния.

## 4. Разработка БД и миграций

[database.sql](database.sql) — reference модель в отдельной `agp_v2`, не production migration и не команда установки.
Реальная миграция строится малыми versioned scripts: expand → backfill → validate → cutover → contract.
Existing public users/resources/groups IDs сохраняются либо отображаются через audited identity bridge; не требовать массового rekey для красивого типа.
Для каждой операции описать transaction boundary, locks, unique constraints, deadlock retry и outbox commit.
Один migration lock на writer; server startup не запускает конкурирующие fleet-wide migrations несколькими instances.
Окно совместимости old/new binary проверяется интеграционно; старый бинарник не является автоматическим rollback несовместимой схемы.
Destructive contract после проверенного backup, завершения rollback window и отдельного разрешения.
Backfill пакетный, resumable, с контрольными counts/digests и защитой от повторного включения отключённых ресурсов.
GC не удаляет revisions/artifacts, на которые ссылаются live nodes, active plans, rollback floor, audit/legal hold или незавершённый journal.

## 5. Frontend и комфорт управления

Единые tokens/components/labels и `HelpTip(topicId)` обязательны для нового Angular frontend.
У ключевых параметров — вопросительный знак в кружке, краткое объяснение и точный переход
во внутренний versioned manual. Справка доступна клавиатурой/touch и не теряет dirty draft.
Рабочий per-resource пример находится в `web/console-prototype`; demo adapters не
подключаются к production и не объявляются реализацией WAF Zones. Целевой основной
экран WAF — зоны → приложения → effective protection по [UX](ux.md).

Frontend хранит draft model отдельно от live/observed state, повторно использует schema-generated types и machine error codes.
Form/YAML переключение не теряет поля; данные, неизвестные schema, не сохраняются скрытно для будущего исполнения.
Autosave сохраняет только draft с CAS и индикатором версии; публикация остаётся отдельным явным действием.
UI отображает effective policy/provenance, targets, diff, risk, approvals и recovery path до начала rollout.
Bulk selection после plan фиксируется; фильтр списка и «выбрать все» не меняют уже согласованную волну.
UI не запрашивает secrets value для заполнения edit forms. Empty secret field означает «оставить», rotation — отдельная операция.
Keyboard/screen-reader и narrow viewport проверяются на реальных сценариях, включая конфликт, ошибку и долгое ожидание.
Backend permissions обязательны при каждом запросе; скрытая кнопка — помощь пользователю, не security boundary.

## 6. CLI и automation

CLI — клиент того же API, не прямой SQL/native config editor. Все команды ниже TARGET, текущий agpctl их ещё не содержит.

```text
agpctl config validate -f gateway.yaml
agpctl config diff -f gateway.yaml --base rev_000016
agpctl plans create --revision rev_000017 --nodes node_msk01 --reason ...
agpctl plans inspect plan_000008
agpctl plans approve plan_000008 --digest sha256:...
agpctl rollouts start --plan plan_000008 --digest sha256:...
agpctl operations watch op_example
agpctl rollouts pause roll_000008 --reason ...
agpctl rollouts cancel roll_000008 --reason ...
agpctl rollouts rollback-plan roll_000008 --nodes node_msk01 --reason ...
```

`--dry-run` не создаёт task/approval и не меняет систему; server-side preview требует read/validate permissions и фиксирует версии исходных данных.
Пароли/tokens/private keys вводятся stdin/TTY/секретным файлом, не command line arguments и не shell history.
Machine output JSON следует wire types; progress/log messages идут отдельно, exit codes distinguish validation/conflict/permission/unknown execution.
Automation identity не получает постоянную human MFA exemption: отдельные scoped credentials/approval policy, без broad admin token.

## 7. CI/CD и supply chain

Корпоративный bare Git не запускает GitHub Actions сам по себе; выбор CI runner/service — отдельная инфраструктурная работа.
PR pipeline использует disposable PostgreSQL/test IdP/CA без production DSN, signing keys и постоянных инфраструктурных credentials.
Обязательные jobs: formatting/static checks → unit → contract/schema → disposable PG → compiler/native integration → security/dependency checks → build.
S3/S4 добавляют helper/fault/native WAF/browser e2e; объединённый test report хранит версии qualification tuple.
Release job запускается отдельно из доверенного ref, формирует binaries/packages/SBOM/provenance, release manifest и TUF metadata.
Actions закрепляются SHA, toolchain/build environment и base images — проверяемыми versions/digests; обновление этих pins проходит review.
Подпись release не даёт права конфигурации/PKI: независимые ключи и разрешения сохраняются.
Reproducibility: одинаковые inputs/toolchain дают одинаковый payload; изменяемые timestamps/signatures хранятся отдельно от deterministic component digest.
Нативная сборка Nginx/module/ModSecurity/CRS квалифицируется вместе; test на одном Nginx не сертифицирует другую сборку.
Не переносить старые уязвимые зависимости в TARGET только ради совпадения с go.mod baseline: обновления планируются и проверяются отдельно.

## 8. Definition of Done

Изменение готово, когда есть воспроизводимый пользовательский сценарий, typed contract и migration/compatibility story.
Нужны meaningful tests на права, scope, duplicate/conflict/failure; новые state transitions не принимаются только happy-path тестом.
Изменения helper/auth/PKI/compiler имеют независимое security review; архитектурные изменения — проверку контрактов и failure domains.
Документы, fixtures и native/compiler output согласованы; изменение schema не оставляет старый frontend/generated client.
Есть observable outcome, bounded logs, метрики без high-cardinality secrets, понятная ошибка UI и runbook recovery.
Production readiness подтверждается стендовыми evidence по testing.md; успешный parser/документ не закрывает runtime finding.
В итоговом описании: что изменилось, что проверено, ограничения, следующий шаг. Отдельные журналы/Gate-реестры без необходимости не создаются.
