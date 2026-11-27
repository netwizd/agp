# AGP v2: безопасность и границы доверия

Статус: требования **TARGET принятого владельцем ТЗ**, редакция 2026-11-18;
статусы отдельных архитектурных ADR сохраняются по [обзору](README.md).
Документ задаёт требования к реализации и отдельно отмечает AS-IS первого пакета S0;
он не является результатом полного security scan или разрешением на production deployment.
См. [обзор](README.md), [ТЗ](requirements.md), [архитектуру](architecture.md), [протоколы](protocols.md),
[модель данных](data-model.md), [эксплуатацию](operations.md) и [приёмку](testing.md).
Принятый [ADR 0001](../adr/0001-single-node-mvp.md) и [план v1.1](../v1.1-plan.md) сохраняют силу:
ручное применение остаётся поддерживаемым режимом; новые требования к привилегированному v2 apply не отменяют legacy исключения MFA.
Слово «обязательно» ниже означает условие реализации и квалификации TARGET, а не наличие контроля в текущем коде.

## 1. Границы проверки и подтверждённые ограничения baseline

Проверены существующие документы и относящиеся к границам безопасности участки Go/Nginx-кода.
Сетевая эксплуатация, production PKI/IdP, фактические настройки корпоративного CI и работа внешних систем не проверялись.
Исторический baseline архитектурного проекта — `6eac09e62b2de2730d8d3fc194fdb5827b21ccc2`;
доступный workspace не содержит читаемого Git object store, поэтому соответствие текущих файлов этому commit заново не доказано.
### S0 pilot: реализованная граница

AS-IS на 2026-11-18 — один CP writer на **прямом PostgreSQL primary**, независимые
journal PostgreSQL/service/signing key и отдельные EdgeAuth processes. Наличие пакетов
не означает реализацию всей нормативной модели разделов ниже. SQLite/legacy mode
не приобретают гарантии secure profile автоматически.

| Путь baseline | AS-IS в secure profile | Граница |
| --- | --- | --- |
| Privileged identity | Actor/current/proposed target и delegation ceiling проверяются в транзакции; journal-backed revoke, authenticator floors и grant incarnations сохраняют restrictive state | В исходном S0 отсутствовали invite/contact delivery; последующий email-срез описан ниже. Invitations/recovery реализованы в последующем integration stage ниже; общий positive-grant approval workflow ещё отсутствует. Legacy final-password creation/reset и расширение privileged grants отклоняются; bootstrap CLI только до активации. |
| Browser isolation | Разные management/login/app hostnames, host-only audience-bound sessions, PKCE/mTLS handoff и отдельный EdgeAuth на приложение | Legacy path mode остаётся legacy; защита application cookies требует прохождения **всех** bytes через EdgeAuth, без прямого Nginx bypass к upstream. |
| Proxy identity/cookies | Per-location identity headers; EdgeAuth request allowlist cookies и response Set-Cookie filtering, private UDS и native Nginx tests | Внешний app listener использует `/_agp/*`; Central Auth JSON доступен только на отдельном mTLS listener. WAF/agent/helper этим не реализованы. |
| Diagnostics DNS | TCP/HTTP dial по одному проверенному набору IP, исходные Host/SNI, без environment proxy/redirect | Infrastructure ACL и production egress policy требуют проверки площадки. |

Secure profile требует MFA для **всех** локальных пользователей: пароль не создаёт
session/handoff; TOTP enrollment, replay protection, recovery codes/sessionless recovery
и fresh step-up выполняются через pending flows и journal. Это правило текущего pilot,
а не изменение принятых TARGET MFA policies или legacy исключений.
Angular auth UI встроен по `/auth-ui/`; console editor остаётся отдельным prototype.
Management/login unsafe requests требуют точного Origin и flow/session CSRF;
management не публикует app content/downloads, private EdgeAuth endpoints не доступны
через public management/login listener. [Конфигурация и активация](../operations.md#s0-pilot-активация-и-восстановление).

Journal проверяет mTLS client roles, signed head challenge, event chain и зарегистрированные
approver keys/allowed kinds. Restore epoch/deny lift не авторизуются одним строковым
`approverId`: нужна подпись независимого registered approver, отличного от actor.
Durable pending intent закрывает auth/mutations до reconciliation. CP identity lease
и `WriteIdentity` используют одно PostgreSQL соединение; transaction/statement pooling
не квалифицированы. Это single-writer pilot, не HA/failover qualification.

Restore требует фактического fencing прежних writers и свежего доверенного cutoff с
проверенной clock-skew bound, external approved epoch advance **до** CP restore,
restrictive replay и ожидания journal `releaseAfter` (не менее 90 s + skew, с запасом CLI).
Исторические grant/authenticator floors не возвращают старые password/TOTP/recovery
proofs. Это контролируемая процедура; автоматическое обнаружение любого restore не
заявляется. Совместный rollback CP+journal/VM snapshot и запуск pre-009 binaries
на восстановленной БД находятся вне этих гарантий. [Restore/rollback](../operations.md#s0-pilot-активация-и-восстановление).

Текущий security floor/pin — 1.30.8; native WAF и baseline checks PASS,
полный PG/HTTPS pipeline на новом tuple ещё OPEN.
Исторические native результаты 1.30.7 и provenance 1.30.6 —
[Nginx](../nginx-recommendations.md), [границы новой проверки](testing.md#nginx-обязательный-security-baseline).
Состояние свежего общего прогона и команды — [testing](testing.md#текущий-пакет-s0-команды-и-границы).
В границах S0 root-helper/safe apply, AD/OIDC/SMTP, WAF/fleet и HA не квалифицированы;
последующие ограниченные WAF/agent пакеты описаны ниже.
Корпоративный CI runner и его secrets/permissions этим workspace не подтверждены.

### S1 authoring pilot: текущие ограничения

Opt-in `AGP_CONFIGURATION_ENABLED` доступен только с secure PG profile. Полный
snapshot требует global `config.read/edit`, catalog import — current admin; service
повторно проверяет session/epoch/security version, idle bound и fresh MFA для записи
через ту же journal barrier. Ограниченные S1b scopes описаны ниже. Scoped view не
подменяется выдачей частичного документа как полного. Draft CAS и полный revision-head
CAS не разрешают lost update.
Catalog — только immutable operator declaration; наличие digest или `published` label
не повышает его до trusted capability/qualification. Report и compiler output всегда
non-deployable, artifacts не исполняются. Секреты представлены только version IDs,
не значениями. Persisted configuration-profile fence закрывает legacy resource writes;
старые binaries, не знающие fence, по-прежнему должны быть остановлены оператором.
[Активация и ограничения rollback](../operations.md#s1-authoring-pilot).

S1b добавляет bootstrap-only `global|site` grants и immutable Gateway→Site ownership,
отдельные от declared catalog. Current epoch/grants проверяются через journal barrier;
отзыв `cgrant_*` проектируется из `revoke_role_binding`, post-secure grant INSERT закрыт.
Admin compatibility даёт read/edit, но не `config.approve`. Scoped read возвращает
Gateway view без соседнего content; scoped edit сохраняет инфраструктурные pins и
проверяет оба targets до server merge/global CAS. Node/group/resource scopes остаются TARGET.
Активный scope grant текущей epoch допускает management login без legacy flat
permissions; обязательные MFA и обычные session/journal guards сохраняются.

Zone preview — отдельный non-deployable authoring DTO с hypothetical membership и
TTL 30 минут, не `WafZoneResolution`. Draft review не авторизует publish/apply:
reviewer отличается от zone author и preview creator, имеет current Site edit и fresh
MFA. Exact pins, epoch и fingerprints обоих участников проверяются повторно; изменение
heads/co-zones/catalog/resolver/rights/expiry делает отметку stale. Последующий
trusted-zone пакет реализует отдельные validation/independent approval/publication,
frozen resolution и атомарную desired revision; draft review их не заменяет.

Новый base-policy пакет реализует отдельные validation/approval/publication факты,
не меняя смысл S1b `draft_review`. Публикация требует current read и явный
`config.approve`, approver, отличного от author, fresh MFA, актуальных epoch/grant fingerprints,
policy head и native proof. Admin compatibility не создаёт approve grant.
Пакет принят как ограниченный AS-IS 2026-11-18: единый native/provider/browser
прогон PASS, включая 25/25 mandatory native cases без SKIP. Qualification ограничена
Ubuntu 24 userland на host kernel `7.0.0-38-generic`; весь TARGET этим не закрыт.

Release доверяется только после TUF и независимой JCS/Ed25519 подписи, complete CAS
closure и SBOM coverage. Anchor/metadata highwater/release floors хранятся вне CP
restore domain; CP читает их, offline import выполняет trust administrator. Время —
свежий подписанный journal head; outage или clock rollback не заменяются wall clock.
Provider pin-ит manifest digest/sequence, exact profile/evidence/compiler/ruleset;
смена release инвалидирует старый proof даже при тех же profile/evidence. Evidence
включает hashes corpus/harness/renderer/raw report. Synthetic fixture keys/pins не
являются production trust. Native subprocess выполняется в private validation scratch;
renderer исполняется из exact `RendererDigest` artifact verified closure под
комплектным Ubuntu 24 loader, как в native corpus. Один общий nonblocking slot
ограничивает native работу всех Provider instances в процессе.
Trusted inventory и zone materialization реализованы отдельным ограниченным пакетом;
exceptions/derivation и privileged apply остаются TARGET.

### Agent identity и локальная проверка: текущая граница

AS-IS на 2026-11-20: node management доступен только current admin. Mutable операции
повторно проверяют management session, epoch, security/password incarnations, revoke,
5-minute MFA и CSRF; наличие `config.edit` не даёт enrollment authority. Token содержит
256 случайных бит, хранится hash-only, показывается один раз; CSR привязан в независимом
ledger до owner approval exact SPKI/request digests. Повтор выдачи не раскрывает token.
Администратор получает fingerprint узла по независимому доверенному каналу.
Положительная выдача привязана к точным authority/epoch/sequence/digest проверки
approver: независимый issuer сверяет этот pin со свежим journal head до подписи
и проверяет неизменность head до commit. Principal restriction между проверкой CP
и запросом issuer блокирует новую выдачу, включая внешнюю registry admission.

Отдельные TLS 1.3 enrollment/agent/EdgeAuth/browser listeners не взаимозаменяемы.
Exact agent URI role, verified chain/expiry, current journal epoch/revoke и registry
проверяются на каждом запросе. CA signing key/issuer ledger и trust floors находятся
вне CP restore, issuer writer/registry reader имеют разные сертификаты и ключи.
Обновление identity требует нового SPKI; bounded overlap 0..900 s включает безопасное
завершение точного повтора при zero overlap. Site universe не удаляет pending/revoked/
expired nodes ради успешной resolution. Generic revoke не доказывает остановку node.

Узловые CLI pin-ят TLS CA и identity CA до отправки token, не следуют redirects,
не принимают token через argv и не перезаписывают keys/certificate. Успешный enroll
удаляет только тот private token file, который был использован. Локальный syntax CLI
проверяет подписанные bytes, journal и capability до/после native `nginx -t`, применяет
process limits, nonroot execution и bounded output. Private workspace **не является
kernel sandbox**; local result не считается remote receipt, applied/healthy state
или разрешением helper. Незавершённый durable intent требует reconciliation и не
перезапускает исполнение автоматически. CP-local diagnostic Service не экспонирован
по HTTP. Корпоративные AD/SMTP, least-privileged DB grants, helper/apply, HA/DR и
clean VM install этим пакетом не квалифицированы.

### Основа допуска helper: текущая граница

AS-IS на 2026-11-24 — admission без executor или privileged transport. Закрытый task и
подписанный permit связываются с trusted installation/baseline pins. Разные pinned
keys и purpose signatures отделяют permit, свежий control `StartProof` и journal head.
Saved permit не заменяет current proof: helper создаёт challenges, проверяет head →
proof → same-state head, epoch/deny floors/`ReleaseAfter` и монотонные counters.
Actual node revoke, actor scopes/MFA, approval и writer lease должен проверять будущий
control authorizer; реализация `Sources` и её transport ещё не поставлены.

Linux store работает через проверенные directory descriptors, no-follow, mode/owner/
inode checks и lifetime exclusive flock. Snapshot атомарно сохраняет intent и counters
с fsync файла/каталога; ошибка durability блокирует handle. Exact retry выдаёт только
исторический admission с `noExecution=true`; новый task блокируется, а
`RequireRecovery` может только усилить блокировку. Это не доказательство защиты от
восстановления всего старого node state volume, захвата root или квалификации ownership
manifest. Полная approval closure, apply/reload/probes/recovery, reboot/power-loss tests на
pilot filesystem и независимая root-helper qualification остаются обязательными.
Последующие read-only filesystem/sandbox пакеты не предоставляют executor.

### Read-only owned tree: текущая граница

На 2026-11-25 отдельный `internal/ownedtree` сравнивает существующие bytes и metadata
с separately pinned content-bound manifest. Node/site/manifest digest связываются
с installation только в opt-in `NewGateWithOwnedTree`; legacy `NewGate` этой
проверки не добавляет. No-follow descriptors, полный child list, inode/device,
UID/GID/mode/size/time/link count и kernel mount IDs проверяются до/после чтения.
Unknown entries, symlink/hardlink, special file, небезопасные права и mount drift
закрывают новое admission без изменения sequence. Отсутствие `statx` mount proof
не заменяется сравнением одного device number. Reader доверяет root/effective UID;
тест self-owned дерева не доказывает изоляцию production agent от root.

Проверка до и после current authorization сокращает окно drift, но не защищает
будущий эффект от последующего изменения файлов: executor обязан проверять его
отдельно. Root-only CLI выдаёт unsigned `filesystem_observation` с локальным
временем, `noExecution=true` и `runtimeValidated=false`; результат не является
authorization, active-runtime proof, резервной копией или verified CaptureBaseline.
Полнота effective Nginx includes для adopted configuration, runtime qualification,
generic ownership lifecycle, apply/rollback и реальные root/mount/power-loss сценарии остаются TARGET.
Observation содержит пути и metadata: хранить локально с ограниченным доступом;
публикация в CP этим пакетом не предусмотрена.

### Native sandbox и candidate: текущая граница

На 2026-11-25 `ownedtree.Capture` добавляет bounded volatile copy одних и тех же
прочитанных/хешированных bytes без JSON serialization. Snapshot и возвращённые копии
могут содержать секреты; закрытие очищает owned buffers, а caller очищает свои копии.
Это не резервная копия и не доказательство активной Nginx generation.

Фиксированный bubblewrap profile исполняет только syntax probe с отдельно pinned
root-owned tool, explicit nonroot UID/GID, no-new-privileges, нулевыми capabilities,
private namespaces и отключёнными nested user namespaces. Captured runtime/config
передаются sealed FD, host filesystem/network не монтируются, root/runtime/config/dev
read-only; writable scratch и process/output limits ограничены. Diagnostics не
сохраняются. Отсутствующие kernel/tool guarantees закрывают запуск без fallback.
Actual unprivileged isolation tests не квалифицируют root supervisor/drop identity.

Managed bootstrap принимает только exact closed profile без произвольных includes;
он не переписывает adopted configuration. Candidate связывает signed release,
ownership/tree, execution UID/GID, sandbox digests и actual host/boot, но всегда
`baselineVerified=false`, `activeConfigurationVerified=false`, `deployable=false`,
`noApply=true`. Root-only CLI и trusted installation config не повышают его до
approval или verified baseline. Root bridge, active master proof, durable backup и
привилегированное применение ещё требуют отдельной qualification.

### Direct AD: текущая граница

Реализованы immutable provider versions, current actor/MFA/CSRF/CAS guards,
independent digest approval и journal-first provider guard floor. Browser не может
подменить server test, egress allowlist, secret reference bytes или TLS trust.
LDAPS/StartTLS проверяют hostname/CA; отдельный user bind и stable forest/object GUID
не допускают связывание по одному UPN. Token groups читаются заново; referrals,
plaintext fallback, local-password fallback и stale membership allow закрыты.
Direct AD primary proof не выдаёт полноценную session до обязательного TOTP.

Локальные TLS LDAP wire/SQLite/PG/browser проверки не заменяют настоящий AD DS.
Historical author/reviewer proofs и final management guards прошли независимый
review и SQLite/native PG проверки, включая actual TLS LDAP → WAF configuration.
Это не квалификация настоящего AD DS. OIDC identity backend реализован следующим
срезом; внешняя приёмка остаётся OPEN. Требования разделов 5–6 ниже сохраняются.

### Контакты, email-коды и SMTP: текущая граница

Собственные contacts доступны только текущей login/management session, GET маскирует
адрес. Создание/замена требуют CSRF и отдельно подтверждённых primary/MFA не старше
пяти минут. Неизвестный primary timestamp старой session не заменяется её временем
создания. AES-GCM keyring отделён от MFA, AAD включает principal/contact/version;
замена поднимает независимый journal floor до materialization и отзывает прежние
sessions/challenges. Контакт не является identity link или MFA factor.

Восьмизначные OTP хранятся как purpose-bound HMAC с внешним pepper. Проверяются flow,
principal, contact/version, audience, epoch/generation, expiry и общие attempt/resend/
target budgets. Email confirmation не создаёт session/handoff и не удовлетворяет MFA;
recovery confirmation допустим только внутри уже авторизованного recovery flow.
Invitations и supervised recovery реализованы в stage-срезе ниже; общий grants workflow остаётся OPEN.

Outbox ciphertext не содержит восстанавливаемого DEK: одноразовые ключи существуют
только в bounded volatile vault. Restart/restore не возрождает queued message keys;
interrupted/unknown SMTP outcome terminal, automatic retry отсутствует. SMTP endpoint,
egress policy, secret versions и trust roots выбираются protected installation, TLS
проверяет исходное hostname/CA. Публичный `failed` не утверждает, что письмо точно не
доставлено. Secretfiles manifest привязывает version к purpose и SHA-256; замена bytes
или manifest закрывает resolver до нового startup. Это не полный secret-version
business lifecycle или подтверждение внешнего secret store.

Синтетические SQLite/PG, SMTP wire, HTTP/runtime tests и отдельный review подтверждают
этот локальный срез. UI `/auth-ui/contacts` также прошёл отдельные browser fixtures.
Production SMTP, корпоративный AD DS, root bridge и полный release pipeline остаются
предметом отдельной приёмки.

### Invitations и recovery: текущая граница stage

Invited principal не имеет live credentials и не проходит обычные allow paths.
Pending creation не выдаёт permission-bearing group/role grants. Invite token содержит
256 случайных бит, наружу доступна только metadata; reservation навсегда связывает его
с одним server-selected flow/binding. Setup требует password → восьмизначный email
proof на saved contact/version → staged TOTP. Только final TX после durable floors
делает credentials активными; setup/recovery никогда не выдаёт session/handoff.
Public reset возвращает одинаковый `202` с пустым body, не меняя human floors при
одном anonymous запросе. Real password/factor change имеет отдельные restrictive floors.

Обычный reset требует текущий factor version и proof time; stale proof после ротации
не разрешает новый password. Supervised intent/approval ограничивает ровно один action:
`replace_mfa`, local `reset_password` либо invited-only `restart_activation`. Перед
publication проверяются current target, policy, epoch, floors и live AD evidence автора,
reviewer, target и executor; distinct approval не заменяется одним admin boolean.
Restart не активирует пользователя и не выдаёт ticket. Legacy recovery capability
имеет стабильный guard, поэтому replay materializer после restore не воскрешает spent
MFA authority под случайным новым ID. Deadline/cleanup закрывают старые setup secrets,
включая anonymous flows. Последний UI revocation fix очищает stale access/target/ticket
до отказа permission и прошёл targeted browser/build проверки. Corporate и полный stage
qualification ещё OPEN.

### AD-backed OIDC: текущая граница

Disabled registration, immutable versions/test и независимое activation/link approval
не позволяют browser подменить trusted egress, secret bytes, endpoints или issuer.
Login/management clients имеют разные IDs, references и фактически разные secret bytes;
RS256/basic/S256 — закрытый первый профиль. Exact issuer/sub связывается только через
согласованный link с существующей AD identity/principal. Email/UPN mapping отсутствует.
Live AD state/groups и текущие provider/link floors проверяются на flow/session paths;
OIDC primary обязательно дополняется AGP TOTP, IdP `acr/amr` не удовлетворяют MFA.
Primary timestamp — проверенный `auth_time`, а не callback/TOTP time.

256-bit state хранится как hash, nonce/verifier — как purpose-bound ciphertext под
отдельным state keyring без переиспользования MFA/email keys. Flow/provider/origin/
audience/browser binding выбирается сервером; optional callback `iss` проверяется.
Новый явный start отменяет предшественника; code обменивается один раз, автоматического
retry нет. Успех меняет flow ID/binding и ведёт только на fixed local continuation.
Потерянный callback response допускает GET recovery лишь при полученном новом cookie;
без него начинается новый login. Terminal/expired proofs очищаются; interrupted
exchanging при startup не превращается в повторный code exchange. `session_state`
ограничен и отброшен; IdP logout/session management не заявляются.

OIDC link change не инвалидирует все исторические AD-authored reviews автоматически:
проверки principal и исторических author/reviewer subjects остаются обязательными.
Независимый review, scoped transport/HTTP/wire tests и финальный backend race-прогон
на SQLite/native PG подтверждают этот срез. Повторная OIDC browser suite, full pipeline
и corporate IdP/AD DS qualification ещё OPEN; это не production-ready статус.

## 2. Активы, противники и доверенные зоны

Защищаемые активы: права пользователей; сессии; secret versions и ключи; конфигурации маршрутов/Auth/WAF;
root-действия на узлах; репозиторий поставки; неизменность deny history; audit; доступность защищённых приложений.
Рассматриваются внешний клиент, скомпрометированное upstream-приложение, делегированный администратор,
скомпрометированный агент, MITM/зеркало артефактов, вредоносный пакет и оператор, восстанавливающий старый backup.
Ошибки, reboot, потеря питания, часы, сеть и disk full рассматриваются наравне с намеренными воздействиями.

| Зона | Доверие и разрешённые переходы |
| --- | --- |
| Browser пользователя | Все HTTP поля, URL, cookie и request bodies недоверенные. Наличие VPN не даёт административного permission. |
| Management UI/API | Отдельный origin, только administrative network; user/session authentication, CSRF, object-level authz на каждом действии. |
| Login/SSO | Отдельный origin; знает identity, но не получает право выпуска root task. IdP claims проходят явное mapping. |
| Auth Plane | Разрешает доступ только при известной generation, authoritative session и текущем deny head. Не управляет helper. |
| EdgeAuth | Отдельный gateway процесс/service account для browser handoff, callback и opaque gateway session; не management agent и не offline Auth. |
| Control Plane | Создаёт revisions/plans/tasks; не получает произвольный shell/root. Подпись task не расширяет ownership узла. |
| Agent | Непривилегированный процесс. Получает только свои задачи/артефакты/секреты, обращается к helper через локальный socket. |
| Helper/Nginx master | Минимальная root-зона, проверяет локальные и подписанные предусловия независимо от агента. |
| Application/WAF traffic | Upstream и payload недоверенные; отдельные origins/credentials, фиксированные proxy trust chains. |
| PostgreSQL/object storage | Разные учётки; DB backup не хранит master keys и не является доказательством свежести security state. |
| Security checkpoint service | Отдельные credentials, durable journal и restore domain; не восстанавливается вместе с CP database. |
| Signing/key service | Отдельные роли CA, plan, release, TUF, encryption. CP process не владеет offline root private keys. |

Компрометация root узла означает потерю доверия к его gateway и локальным данным: агент не может доказать чистоту хоста.
Компрометация одновременно CP и разрешённого signing service позволяет выпускать допустимые привилегированные операции;
ограничения helper снижают область ущерба, но не обещают защиту управляемого узла от полностью захваченного управления.
Одна организация — граница первой поставки. Multi-tenancy и защита независимых tenants этим проектом не заявляются.

## 3. Abuse cases и обязательные контроли

| Попытка | Контроль | Свидетельство приёмки |
| --- | --- | --- |
| Editor меняет свой role/group или чужой site через ID | Scope filters плюс проверка объекта после загрузки; delegation ceiling и privileged-target guard | IDOR tests для read/list/write/export/task/secret, включая вложенные IDs и batch |
| Утверждённый selector захватывает новые узлы | Plan содержит immutable target IDs и digest capabilities/base/secrets; selector после approval не вычисляется | Узел, добавленный после plan, не получает task |
| Скомпрометированный agent подсовывает shell/path | Закрытая tagged union task payload; helper независимо проверяет policy и безопасное дерево | Unknown kind/field, traversal, symlink/hardlink, raw directives и unit injection отклонены |
| Старое задание приходит после нового rollout | Durable writer epoch, node deployment sequence, task identity и replay result | Duplicate/reorder/crash tests не повторяют побочный эффект |
| Restore возвращает старого администратора или сессию | Independent checkpoint, startup barrier, deny replay и восстановление ключей до допуска mutations/allow | Restore старого PG backup сохраняет более поздние блокировки |
| WAF или Auth недоступны | Никакого error-to-allow fallback; последняя конфигурация не означает разрешение без Auth | Auth 5xx, timeout, TLS failure и WAF crash не обходят защиту |
| Зеркало подменяет пакет или архив | TUF, pinned manifest/digests, bounded extraction, проверенный component tuple | Подмена/expiry/downgrade/zip bomb/escape отклонены до root side effect |
| Diagnostics/webhook используется как SSRF | Egress allowlist, IP pinning, исходный SNI/Host, лимиты, нет environment proxy | DNS rebinding и metadata/loopback/link-local targets недоступны |
| Приложение присылает identity headers/cookie | Gateway удаляет зарезервированные поля, сам задаёт проверенную identity; cookie filter | Upstream не получает management/gateway tokens или поддельный X-AGP |
| Сбой скрывает частичный apply | Durable journal до switch, подтверждённый base recovery, reconcile unknown result | Fault injection на каждом durable checkpoint |

## 4. RBAC, scopes и разделение обязанностей

Permission codes — стабильные идентификаторы TARGET; role name служит удобным preset, а не отдельным обходом проверок.
Legacy `users.superadmin.manage` при миграции явно сопоставляется с новым `users.privileged.manage`;
нельзя молча считать одинаковыми произвольные строки из старого и нового API.
Wire scopes: `global` — вся организация; `site`, `node_group`, `node`, `resource` — явно перечисленные IDs.
Site/NodeGroup grant покрывает его текущие объекты, но применение всё равно ограничено зафиксированными IDs plan.
Ресурсный grant не разрешает менять общие listener/CA, другие ресурсы или весь node bundle.
Для составной revision сервер проверяет semantic diff и косвенные эффекты по всем затронутым объектам,
включая shared listeners, precedence и inherited policy; неизменённые части разрешённого full bundle не считаются правом их редактировать.

| Permission | Scope | Preset / что разрешает |
| --- | --- | --- |
| `config.read` | global/site/node_group/node/resource | Viewer, Editor, Approver, Deployer, Auditor: redacted configuration/plan preview |
| `config.edit` | global/site/node_group/node/resource | Editor: draft/import/validation/revision; без выполнения |
| `config.approve` | global/site/node_group/node/resource | Approver: approval конкретного plan digest |
| `rollouts.create` | global/site/node_group/node | Deployer: запуск, продвижение/возобновление утверждённого rollout |
| `rollouts.cancel` | global/site/node_group/node | Deployer: pause/cancel дальнейшей выдачи задач |
| `rollouts.rollback` | global/site/node_group/node | Deployer: новый rollback plan/task; обычное approval не обходится |
| `nodes.read` | global/site/node_group/node | Viewer/Editor/Deployer: inventory, status и redacted diagnostics |
| `nodes.enroll` | global/site | Infrastructure administrator: bound enrollment token; не перенос узла между sites |
| `nodes.revoke` | global/site/node_group/node | Infrastructure administrator: отзыв identity и остановка выдачи |
| `secrets.manage` | global/site/node_group/node/resource | Secret administrator: создать/rotate/revoke version; не чтение plaintext через API |
| `audit.read` | global/site/node_group/node/resource | Auditor: доступ к разрешённому audit slice |
| `audit.export` | global/site/node_group/node/resource | Auditor: асинхронный redacted export с аудитом выгрузки |
| `users.read` | global | Identity administrator/Auditor: redacted users/groups/roles/permissions |
| `users.manage` | global | Identity administrator: lifecycle обычных пользователей в delegation ceiling |
| `users.privileged.manage` | global | Privileged administrator: lifecycle privileged principals и их assignments |

Узлы, роли инфраструктуры и группы пользователей для доступа к приложениям — разные доменные сущности.
Выдача `users.manage` не даёт произвольной выдачи остальных permissions.
Любое назначение role/scope проверяет одновременно: право actor управлять целью, grantable permissions ceiling,
grantable scopes ceiling и отсутствие запрещённого self elevation. Объединение grants не обходит эти проверки.
Privileged principal — любой пользователь/service account с инфраструктурными, identity, secret, approval либо privileged-management правами,
а не только legacy boolean superadmin. Защищены создание, password reset, MFA reset, recovery, email/IdP rebinding,
block/unblock/delete, membership, role и token issuance. Удаление последнего пригодного аварийного администратора запрещено.
Service accounts не имеют интерактивных sessions/MFA exemption; их короткие credentials и audience ограничены конкретным integration API.

Чтение коллекции фильтруется на сервере до pagination/count; отдельный GET не подтверждает существование чужого объекта.
Проверки повторяются при создании approval, dispatch и helper apply; потеря actor permission аннулирует pending approval/plan.
Изменение scopes, site membership, capabilities или secrets требует нового plan при несовпадении его предусловий.
Опасные планы — ослабление auth/WAF, новый privileged grant, trust anchor, массовый upgrade, deny lift — требуют второго человека.
Автор не утверждает собственный опасный plan; наличие обеих permissions у одного человека не заменяет разделение действий.
Approval связывает actor, auth strength/time, plan digest, immutable targets, preconditions и expiry, а не только revision ID.
Перед dispatch проверяются отсутствие withdrawal, текущие права approver/deployer и свежесть security state.
Emergency deny/revoke не ждёт обычной rollout-очереди; снятие ограничения проходит отдельное подтверждение.

Уточнение positive role grants: `POST /role-bindings` создаёт только immutable pending
`grant_role_binding`; distinct human approval закрепляет полный `roleGrantRequest` digest.
Grant target — только active principal. Author и reviewer — разные люди; target не может
согласовать собственное повышение. Create/approve/execute требуют текущих primary/MFA,
principal/password floors, policy/epoch, actor/author/reviewer permissions и полного target
и proposed grant scope ceiling. Старый approval не переживает потерю этих предусловий.
`config.approve` для независимого reviewer должен быть explicit global grant; legacy admin
сам по себе не создаёт approval. Scoped permissions никогда не flatten в global permissions.

Scope closure строится из authoritative ownership/membership sources, не из operator-declared
catalog/labels. Все пять TARGET scopes сохраняются; отсутствие проверенного source закрывает
конкретный grant. Первый runtime профиль закрепляет graph через typed offline/pre-secure
BootstrapManifest, сохраняя существующие bootstrap-only ограничения; later graph mutations
требуют отдельного approved workflow. Canonical Resource ID связывается с route явно.
Текущий Site/NodeGroup состав раскрывается как pinned closure; изменение source до исполнения
требует нового плана. Resource permission не разрешает shared listener/CA или весь node bundle.

Положительный binding публикуется атомарно с applied operation/audit при fresh independent
head, `journal_mode=none_positive_grant`; approval queue не создаёт restriction barrier.
Журнал хранит только exact incarnation revoke, включая tombstone при отсутствующей строке.
Restore не пересоздаёт потерянный grant; старая incarnation/epoch не оживает от нового approval.
`DELETE /role-bindings/{id}` возвращает existing restriction operation с typed
`roleBindingRevokeRequest`; revoke не ждёт отдельного approval. Immutable presets доступны
через redacted `GET /roles`, assignments — `GET /role-bindings`, оба с `users.read`.
Это TARGET contract; наличие схем не означает завершённую runtime qualification.

## 5. Пользователи, sessions, MFA, recovery

Обязательное дополнение REQ-02: [AD, 2FA и одноразовые email-коды](identity.md).
Прямой AD DS использует только проверенный TLS LDAP, отдельный user bind, objectGUID,
полные security group mappings и live account check. Пароль AD не хранится и нет local/email
fallback. До завершения обязательной MFA разрешён только pending flow, без session/handoff.
Email OTP — purpose-bound proof с внешним HMAC key, TTL/attempts/resend limits; он не
объявляется вторым сильным фактором и не сбрасывает admin MFA самостоятельно.
Provider config/MFA mapping, AD links и contact versions проверяются по независимым floors;
старые flows/challenges/mail outbox инвалидируются authorityEpoch после restore.
После restore TOTP readiness дополнительно ждёт закрытия pre-restore временных окон по
trusted clock/cutoff, чтобы rollback last_accepted_step не позволил повтор старого кода.

Локальные пароли: Argon2id с versioned parameters и индивидуальной CSPRNG salt; параметры калибруются на pilot hardware,
проверяются на exhaustion и повышаются с rehash после успешного login. Нельзя логировать пароль или готовый hash.
Login/recovery/invite/enrollment имеют распределённые лимиты по actor/source/target с защитой от массовой блокировки жертвы.
При отказе limiter новые login/recovery/enrollment ограничиваются консервативным локальным ceiling; безлимитный fallback запрещён.
Ошибки login/invite/reset не раскрывают существование пользователя, email, группу или состояние MFA.

Session token: минимум 256 случайных бит; в БД — только digest, audience/origin, identity, creation/expiry, strength и revoke metadata.
Новые TARGET defaults: management absolute lifetime 8 h, idle 30 min, privileged step-up не старше 5 min;
изменение значений допускается политикой организации после проверки угроз, UI обязан показывать эффективную политику.
Session ID меняется после login/step-up/privilege change; password/MFA reset, блокировка и credential compromise отзывают связанные sessions.
Logout идемпотентен, отзывает server-side state; удаление cookie не считается отзывом.
Запросы Auth читают authoritative sessions; positive decision caching в первой v2 поставке запрещён.

v1.1 lifecycle сохраняется: admin создаёт invite без финального пароля; одноразовый token хранится как hash,
имеет не менее 256 случайных бит, expiry и атомарно consumes при завершении; password setup не создаёт session до завершения обязательного MFA.
Invite landing page не загружает сторонние ресурсы, использует `Referrer-Policy: no-referrer`, редактирует URL/token в proxy/access logs
и обменивает token на ограниченный server-side setup flow; token не становится обычной login session.
TOTP secrets шифруются; recent-step-up требуется для регистрации/замены устройства; повтор TOTP из уже принятого time step отклоняется.
Recovery codes имеют не менее 128 случайных бит каждый, показываются один раз, сохраняются как индивидуальные hashes и atomically consume;
вывод повторно невозможен. Короткие numeric codes с простым SHA-256 не заменяют высокоэнтропийные recovery secrets.
Reset MFA не исполняется только по доступу к email: нужны проверенный recovery factor или управляемая процедура с двумя администраторами,
записью причины, задержкой/оповещением по корпоративной политике и отзывом активных sessions.
IdP `acr/amr/auth_time` доверяются только через настроенный issuer-specific mapping; строка «mfa» от произвольного issuer недостаточна.

Password/MFA/OIDC-binding change сначала фиксирует в независимом journal событие `bump_authenticator_floor`
с `principalId`, стабильным `authenticatorId` и `minimumVersion`; затем публикует новую версию соответствующего authenticator.
Hash пароля, TOTP seed и external identity binding имеют собственную version, проверяемую против актуального floor при каждом использовании.
Отказ записи новой версии после повышения floor закрывает старый authenticator, а не возвращает его пригодность.
После restore старый hash/seed/link ниже floor не принимается даже для нового login; требуется supervised reset по проверенному recovery пути.
Нельзя просто присвоить восстановленному старому hash новую version, чтобы сделать проверку зелёной; journal не содержит secret material.
Приёмка восстанавливает backup до смены пароля/MFA/link и доказывает отказ старых authenticators при попытке нового входа.

v1.1 разрешает break-glass MFA exemptions; это не отменяется данным документом для legacy доступа.
Новый managed root apply/upgrade/trust change требует сильной аутентификации и свежего step-up даже для legacy exemption account.
Если IdP недоступен, используется заранее подготовленная локальная аварийная учётка с MFA и sealed recovery codes.
Если ни один strong factor недоступен, root apply через UI запрещён; остаётся локальная supervised recovery процедура владельца хоста,
которая не превращается в бессрочный сетевой MFA bypass и фиксируется после восстановления audit.
Break-glass login ограничен management network, сопровождается немедленным security alert и последующим review.

## 6. Browser, OIDC и связь gateway с Auth

Management, login/SSO и каждое приложение имеют разные HTTPS origins; path-based публикация рядом с management в v2 managed mode запрещена.
Приложения не размещаются на management origin даже с отдельным cookie Path.
Management session использует отдельную `__Host-` cookie: `Secure`, `HttpOnly`, `Path=/`, без `Domain`, с подходящим `SameSite`.
Login и каждый gateway имеют свои host-only cookies и audience; широкие `.example.net` session cookies запрещены.
Gateway удаляет свои зарезервированные session/CSRF cookies из upstream `Cookie`, сохраняя только разрешённые application cookies.
Upstream `Set-Cookie` для зарезервированных AGP cookie names отклоняется; одинаковые имена от разных источников не выбираются эвристически.
Management cookie вообще не должна поступать на приложение; filter — дополнительная защита, а не замена origins.

Основной SSO путь — центральный Auth как OIDC client корпоративного IdP; самостоятельный универсальный OIDC issuer не входит в первую поставку.
Используются Authorization Code + PKCE S256, state/nonce, точные зарегистрированные redirect URI и отдельный management client.
Проверяются issuer, audience/azp, signature/algorithm allowlist, nonce, expiry и auth strength; identity key — `(issuer, subject)`, не email.
Code обменивается backend по TLS; refresh tokens, если нужны, остаются шифрованными server-side.
Нельзя принимать произвольный discovery/JWKS URL от пользователя или редиректить на неподтверждённый return URL.
Основание: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) и [OAuth Security BCP, RFC 9700](https://www.rfc-editor.org/info/rfc9700/).
Корпоративный OIDC login и локальные accounts используют одинаковый first-party handoff из [протоколов](protocols.md), а не самодельный OAuth grant:
одноразовый code с TTL 60 s привязан к gateway identity, точному callback, state/nonce и PKCE; redeem только с mTLS и атомарным consume.
EdgeAuth на gateway хранит pending flow и opaque audience-bound cookie; это отдельные процесс, service account и role certificate.
Каждый auth_request через EdgeAuth повторно проверяет central Auth, session и deny freshness; локального allow нет.
Agent только доставляет конфигурации; он не получает EdgeAuth credentials, browser sessions, handoff codes или право user authorization.
Management session создаётся своим login/client и не возникает из gateway handoff.
Browser code не является application credential; его нельзя логировать, переиспользовать или передавать upstream.
Если ответ redeem потерян, EdgeAuth начинает новый login/handoff flow: consumed code повторно session не создаёт,
неизвестная orphan session истекает по TTL, доступ до успешного нового flow закрыт. Plaintext session не сохраняется в idempotency response cache.

Все management mutations проверяют CSRF и допустимый Origin; CORS closed by default, wildcard credentials запрещены.
CSP ограничивает scripts/frame ancestors; HTML/Markdown/имена/логи рендерятся как данные, без `innerHTML` из API.
Downloads отдаются отдельным origin/attachment с type allowlist, size limit, quarantine/scan status и проверкой ownership;
public download не получает session cookie и не является способом публикации release/root payload.
CSV exports нейтрализуют formula injection, имеют TTL и разрешаются только авторизованному получателю.

Auth endpoint доступен только доверенному gateway/service identity по mTLS; private address сам по себе не считается identity.
В all-in-one допустим защищённый root-owned Unix socket с peer credentials, если он даёт ту же проверку gateway identity.
Gateway задаёт deployment/route IDs из локального bundle; пользовательские `X-AGP-*`, original URI и forwarding headers заменяются.
Auth сверяет node/gateway identity, доступные ему routes/generation и точный snapshot, а не доверяет только route ID.
Client IP принимается только из явно заданной proxy chain; прямой клиент не задаёт `X-Forwarded-For` для CIDR policy.
Nginx получает auth_request status от EdgeAuth adapter: 204 только после проверенного Central Auth `decision=allow`,
401 при требовании login, 403 при policy deny, 503 при unavailable/timeout/неизвестном или невалидном decision.
Ответ JSON `/auth/v2/decisions` с HTTP 200 и `decision=deny` никогда не проксируется Nginx как 2xx;
прямой Nginx auth_request к этому JSON API запрещён. Для Nginx 2xx означает allow, 401/403 — deny, остальные ответы — error
([auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)).
Redirect на login только для browser flow; API получает явный unauthenticated/forbidden/service-unavailable response без циклов.
WebSocket/stream авторизуется при handshake: отзыв не гарантирует мгновенное закрытие уже открытого соединения.
Для строгих ресурсов нужны отдельные квалифицированные bounded session duration/drain/active disconnect механизмы;
UI и SLO явно разделяют «новые запросы запрещены» и «существующие соединения завершены».

WAF exception имеет review deadline и отдельный hard expiry; immutable Auth snapshot содержит binding route→exception→expiry.
Scheduler заранее готовит removal revision и safe apply либо новую ограниченную extension version с независимым approval.
Если к expiry active bundle всё ещё содержит истёкшее исключение, central Auth закрывает именно affected routes для новых запросов,
пока не подтверждена безопасная generation без исключения либо с заново утверждённым сроком.
Метаданные не удаляют native CRS directive сами: текущий bundle остаётся видимым как overdue/blocked, UI даёт причину и требуемое действие.
Стандартный auth/WAF error fallback не снимает этот запрет; существующие streams требуют отдельного drain/lifetime контроля.
Приёмка: отключить scheduler/apply у canary до expiry и доказать закрытие новых запросов на affected route,
сохранение работы незатронутого route и отсутствие заявления, что native exception была удалена без apply.

## 7. Node identity, enrollment и отзыв

До enrollment узел получает CP URL, CA pin/trust root и release trust root доверенным внешним путём.
Нельзя сначала отправить bearer enrollment token непроверенному TLS server, а затем запомнить его сертификат.
Token одноразовый, короткоживущий, hashed at rest, привязан к заранее выделенному node ID/site/allowed capabilities;
binding включает точную service role `agent` либо `edge_auth`; минимум 256 случайных бит, TTL default 10 min, максимум 15 min.
Token не передаётся через URL, shell history, process arguments или audit.
Node создаёт private key локально и отправляет CSR с proof of possession. SAN/identity назначает сервер по token binding,
клиентский CSR не выбирает site, role, другого node или wildcard SAN. Consumption token и фиксация issuance идемпотентны.
Нужны проверка rate limits, owner подтверждение fingerprint и защита от одновременного replay.
До первого plan выполняется `captureBaseline`: квалифицированный installer создаёт проверенную закрытую bootstrap revision/bundle
на чистом managed node либо сохраняет и валидирует adopted baseline. Apply/recovery всегда ссылаются на exact non-null base IDs/digests;
отсутствие конфигурации не заменяется выдуманным пустым digest или нерегламентированным root action.

Предлагаемый профиль: node certificate 24 h, renewal начинается после первой трети срока с jitter;
точные значения входят в deployment policy и проверяются на outage/offline сценариях.
Renewal подтверждает текущую identity, node status и key possession; revoked node не получает renewal.
CA root offline; issuing key в отдельном signing service, EKU/audience различают agent-control и gateway-auth/EdgeAuth.
Ролевые сертификаты и private keys agent и EdgeAuth раздельны; привилегии одного не выводятся из другого по общему node ID.
Новый ключ/CSR не наследует старый serial молча; хранится связка identity, certificate, issuance/revoke reason.
Control streams периодически перепроверяют identity и закрываются по revoke; reconnect и каждое task message снова проверяют статус.
Certificate expiry проверяется в долгоживущих streams, а не только при первоначальном TLS handshake.
Отзыв identity не удаляет software и не доказывает остановку скомпрометированного node: отключение traffic/network выполняет оператор.
Offline узел после expiry не получает control/tasks/renewal; его central Auth channel также не разрешает новые защищённые запросы.
Re-enrollment требует новой одноразовой авторизации и явной связи с прежней identity; старые keys/tasks не оживают.
KeepAuth detach отзывает только agent identity/helper access и сохраняет явно утверждённый retained EdgeAuth binding с отдельной renewal policy.
Состояние management-detached не эквивалентно generic node revoke: `revoke_node`/полный retire закрывает обе роли и пользовательский Auth path.
Сохранение EdgeAuth не оставляет права доставки конфигурации; operator-owned traffic tree после detach проверяется отдельно.

## 8. Helper и безопасное применение

AS-IS на 2026-11-24: admission-only helper проверяет полный подписанный Plan v1
перед новым допуском, сохраняя доступ к старому exact historical receipt без нового
start. CP предоставляет отдельные proposal/review/signature routes с
`purpose=planning_review`, `deployable=false`, `noExecution=true`; dedicated
review key и domain не являются execution trust. Global read/edit/explicit approve,
independent reviewer, current session/floors/epoch и фактические source dependencies
перепроверяются перед replay. Admin не обходит approval. Runtime CP не выдаёт
execution Plan, permit или StartProof. Буквальная Plan schema не связывает все
compiler/release/tuple pins; полный approval closure и runtime authorizer ещё нужны.
Далее описаны TARGET свойства исполнителя и установки, которые этот срез не закрывает.

Agent account не имеет sudo, записи в unit files, executable/helper/config trust roots или произвольного доступа к key store.
Helper слушает только root-owned Unix socket; проверяет peer UID, message bounds, closed schema, signatures и monotonic counters.
Задания не содержат shell/argv/script/произвольный путь, unit name или download URL. Разрешены только типы из [протоколов](protocols.md).
Фиксированные subprocess для Nginx test/reload/пакетного adapter запускаются с очищенным environment и без shell expansion.
`CollectDiagnostics` собирает только фиксированный redacted набор, без произвольных команд или чтения файлов по пользовательскому пути.

Compiler генерирует конфигурацию из typed AST: raw Nginx snippets, произвольные include, `load_module`, embedded scripting и filesystem directives запрещены.
Проверяется полное effective tree, включая разрешённые root-owned adopted includes; непонятный include делает adoption непригодным.
Одного `nginx -t` недостаточно: допустимая синтаксически директива может иметь опасные файловые/сетевые побочные эффекты.
Сначала unprivileged bounded validation в sandbox, затем root-helper заново проверяет digest и разрешённый профиль.
Ownership manifest фиксирует конкретные пути, типы, UID/GID/mode, inode/device assumptions и approved include tree.
Нельзя писать за пределы owned tree; symlink/hardlink, device/FIFO, `..`, absolute archive path и неожиданные mountpoints отклоняются.
Работа через trusted directory descriptors, no-follow и повторную проверку перед rename исключает check/use смену пути.
Downloads агента никогда не становятся root executable только благодаря имени файла или принадлежности агенту.

Перед switch helper fsync-ит staging files, базовый snapshot, подписанное recovery permission и журнал намерения;
потом fsync-ит directory entries. Лишь затем выполняет атомарный switch в пределах одного filesystem и фиксированный reload.
Журнал содержит exact base/target digests, plan/task identity, epoch/sequence, ownership и durable checkpoints без plaintext secrets.
Успех reload не равен успеху apply: нужны identity/auth/WAF/application probes и наблюдаемая активная generation.
Неизвестный результат после timeout не переводится в failure/success предположением: выполняется reconcile по журналу и runtime.
Повтор task возвращает durable result; новое задание с меньшим sequence/epoch отклоняется даже при совпадении config digest.
Plan/Task несут `authorityEpoch` независимо от `writerEpoch`: первый фиксирует security authority, второй — fenced rollout writer.
Перед новым privileged start требуется свежая control authorization текущих node/revoke status, epoch, plan/approval и scopes;
одна сохранённая подпись непросроченного permit не разрешает новый start при partition. Старые pre-DR планы повторно не запускаются.
Read-only inventory/validate/diagnostics используют deployment sequence `"0"` и не потребляют high-water.
Принятие mutating sequence fsync-ится до side effects; поздний отказ не позволяет переиспользовать номер с иным payload.
Потерянный receipt требует reconcile перед следующим privileged task, а не отката сохранённого high-water.
Rollback — новая операция с новым sequence; fleet не имеет общей ACID transaction.

Recovery начатого apply заранее разрешена plan только на exact проверенный base и только в сохранённом ownership.
Это разрешение переживает истечение plan, CP outage и reboot; оно не разрешает новый apply/upgrade, любой старый bundle или снятие deny.
Уже durable accepted операция может завершить ограниченный verify/recovery offline; немедленный stop отозванного task на изолированном узле не обещается.
После появления связи отзыв/новый epoch применяются до следующего privileged start; для немедленной изоляции нужен внешний traffic/host control.
Восстанавливаются current deny/security floors; нельзя восстановить разрешающий доступ snapshot при неизвестной auth generation.
Если безопасность base не доказана, узел переходит в состояние ручного восстановления и оставляет затронутый доступ закрытым.
Нехватка диска до switch запрещает apply; нехватка после switch обрабатывается резервом журнала и детерминированным recovery.
Release обязан доказать fsync/rename/reboot поведение на квалифицированном filesystem, а не только в in-memory unit test.

## 9. Monotonic security state и восстановление

Deny overlay включает user/session/node/resource/credential revoke и security floors; конфигурационный rollback его не уменьшает.
Независимый Security Checkpoint Service хранит append-only typed events и head вне CP PostgreSQL/backup domain.
Его отдельная учётка не доступна обычным migrations/restore; write API — только append с authority credentials, без delete/rewrite/set-sequence.
Concrete first-release default: отдельный Go service со своим PostgreSQL cluster, storage, account и backup domain,
а не таблица/schema в CP cluster. Append атомарно связывает expected head, unique operation ID, sequence и digest chain.
Выделенная VM предпочтительна; отдельные процессы/volumes на общей VM сохраняют независимость только процедурного restore domain.
Откат полного VM snapshot с CP и journal вместе не является безопасным restore: требуется внешний доверенный head/keys
либо supervised новая authority epoch, revoke всех credentials и повторное подтверждение grants; старые grants не возвращаются по умолчанию.
В первой версии допустим один такой durable journal service с отказом доступности при его потере;
HA требует доказуемо linearizable writer/fencing, независимые backups и отдельную квалификацию, не «два независимых файла».
Checkpoint содержит authority epoch, sequence и hash chain head; wire counters — decimal strings uint63, как в [протоколах](protocols.md).

Порядок security mutation един для API, legacy adapter и emergency operations:

1. PG transaction создаёт pending SecurityOperation/outbox и deny barrier для affected scope; ограничения actor проверены до записи.
2. Journal атомарно и идемпотентно выполняет append по operation ID, expected authority/head, digest и typed payload; sequence назначает journal.
3. PG transaction материализует событие/deny state и applied head; только после этого операция завершена и barrier снимается по правилам события.
4. При timeout append результат неизвестен: сначала lookup operation ID/reconcile, затем retry с тем же digest, без новой независимой операции.

Между хранилищами нет общей транзакции; durable pending operation и deny barrier закрывают окно рассогласования.
После journal commit deny нельзя отменить удалением outbox или восстановлением PG: материализация возобновляется идемпотентно.
Любой allow в первой поставке выполняет свежий head read → decision read на PG writer → второй свежий head read.
Epoch/head обоих ответов должны совпасть с applied head использованного PG snapshot; affected barriers отсутствуют,
`issuedAuthorityEpoch` sessions/tokens соответствует текущему `authorityEpoch`, authenticator floors актуальны. Decision snapshot читается между этими проверками.
Если head изменился, разрешён bounded retry целиком; исчерпание retry означает fail-closed, не выдачу старого решения.
Это задаёт доказуемую точку принятия решения относительно конкурентного revoke; не обещает отозвать уже доставленный response или stream.
Старый подписанный checkpoint не доказывает свежесть: response связан с request challenge/identity и текущим authority epoch.
Cached allow/lease-based freshness не входят в первую поставку. Недоступен checkpoint, недоказана свежесть или DB отстаёт — новые allow прекращаются.
Локальный отказ/блокировка допустимы при недоступном journal, но операция revoke не показывается как globally committed до durable acknowledgment.
Для аварии может применяться более широкий fail-closed barrier; UI показывает, какие scopes закрыты и почему.

Снятие deny — семейство типизированных lift operations (`unblock_principal`, `enable_resource`, `clear_route_deny` в DDL),
ссылающихся на исходный deny event, с новым sequence и вторым approval; `deny_lift` — название family, не дополнительный wire enum.
Lift не удаляет историю и не снимает независимые запреты на тот же объект. Обычный restore/config rollback не создаёт lift.
Restore CP database запускается с общей barrier для Auth и management mutations; нельзя выдать роль/сессию из старого backup до проверки.
Требуются replay до authoritative head, восстановление key availability/authority identity и проверка membership/credential revoke semantics.
До снятия restore barrier journal через `advance_authority_epoch` монотонно повышает `authorityEpoch`; все восстановленные sessions,
gateway sessions, browser handoffs, invites, enrollment tokens и recovery codes инвалидируются независимо от сохранённого `consumed_at`.
Каждый такой объект хранит `issuedAuthorityEpoch` (SQL `issued_authority_epoch`), равный текущему независимому `authorityEpoch`;
значение из backup не авторитетно. Единственный security epoch — `authorityEpoch`; pre-DR Plan/Task не допускаются к новому start.
Повышение `authorityEpoch` не сбрасывает journal sequence, per-node sequence или `writerEpoch`; already accepted local recovery ограничена прежним permit.
Новые login/setup/enrollment/recovery batches выдаются только после проверки актуальных authenticator floors и разрешённой процедуры.
Это намеренная цена restore: повторный вход и перевыпуск one-time secrets вместо возможного воскресения уже использованных кодов.
Приёмка восстанавливает backup до consumption каждого вида one-time secret и доказывает, что старый код/session с прежним epoch не принимается.
Если journal/head/key recovery недоказаны, сервис остаётся закрытым; разрешение старых sessions «на время восстановления» запрещено.
Потеря самого независимого journal — отдельный security disaster: безопасный recovery может потребовать новой authority epoch,
массового отзыва credentials/sessions, переиздания identity и повторного подтверждения grants, а не возврата sequence к нулю.

## 10. Артефакты, пакеты и CI/CD

Ключи разделены: node identity, issuing CA, plan signing, release signing, TUF root/targets/snapshot/timestamp и data encryption.
Trust bootstrap доставляет root до enrollment. TUF проверяет роли/пороги, metadata versions/expiry, hashes/lengths и rollback/freeze protection;
release manifest дополнительно связывает component tuple, dependency closure, SBOM и security floors.
Airgap использует ту же проверку подписей/сроков и плановую доставку metadata; отключение expiry запрещено.
Offline root хранится вне build runner; online roles имеют отдельные ограниченные ключи и процедуры ротации.
Это выбранная модель на основе [TUF Specification](https://theupdateframework.github.io/specification/latest/), а не новый самодельный update protocol.
Config, release и CA signatures не взаимозаменяемы; сертификат узла не даёт права подписать пакет.

Root package install отделён от обычного configuration apply и требует отдельного typed upgrade plan.
Пакеты/maintainer scripts квалифицируются по digest и allowlist: install/uninstall hooks могут выполнять root-действия,
поэтому произвольные hooks от администратора запрещены, а штатные scripts одобренного пакета проходят отдельный review/test.
Особенность Debian package lifecycle подтверждена [Debian Policy](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html).
Post-install downloads из интернета, auto-upgrade во время rollout и незакреплённые dependencies запрещены.
Archive extraction ограничивает compressed/unpacked size, object count и depth; content type/path/mode проверяются до помещения в owned tree.

PR jobs не получают production DSN, release/CA/plan credentials или доступ к корпоративной сети управления.
PostgreSQL для PR поднимается одноразово с временной учёткой; secret release DSN не является dependency тестов.
Runner одноразовый либо очищается до доверенного состояния; caches/artifacts от untrusted PR не исполняются в signing job.
GitHub Actions: минимальные job permissions, actions/reusable workflows pinned по полному commit SHA,
без privileged checkout untrusted PR в `pull_request_target`; input передаётся как данные, не shell template.
Правила соответствуют [GitHub secure use guidance](https://docs.github.com/en/actions/reference/security/secure-use).
Для GitLab применяются эквивалентные protected refs/runners/variables и pinned includes; конкретная платформа CI ещё подлежит выбору.
Build производит immutable digest artifacts, SBOM, dependency/license report и provenance; signing job использует только проверенный build identity/digest.
Release signing — отдельный защищённый job/service с approval; CI не содержит offline roots. Short-lived signing identity предпочтительна.
SAST/SCA/secret scanning и Go vulnerability checks обязательны; scanner findings triage-ятся по affected path и не игнорируются глобальным allow-all.
DAST выполняется на disposable стенде, без production пользователей/targets. Security fixtures и negative tests входят в [приёмку](testing.md).
Прохождение этих checks не заменяет helper/identity/recovery review перед первой привилегированной поставкой.

## 11. Секреты, данные, аудит и недопустимые утечки

Envelope encryption использует versioned AEAD с CSPRNG nonce и associated data, связывающими secret ID/version/type/recipient scope.
Предлагаемый профиль — AES-256-GCM из поддерживаемой криптобиблиотеки; nonce reuse при одном key запрещён.
DEK/KEK version и algorithm хранятся в metadata; KEK/key service credentials находятся вне БД и её backup.
Ключи CA/release/plan не служат ключами шифрования; node не получает ключи других nodes или организационный KEK.
Node-bound secret выдаётся только разрешённой identity/task по mTLS, сохраняется root-owned с минимальным mode и очищается по lifecycle.
Idempotency storage не сохраняет plaintext token/secret response: для first-only enrollment/recovery выдачи replay возвращает metadata и `tokenAvailable=false`.
Потерянный первичный ответ не оправдывает обратимое хранение token; требуется revoke и новая явная issuance.
TLS private keys для reload должны быть доступны только нужному master/helper, не world-readable и не агентскому export endpoint.
Rotation создаёт immutable SecretVersion, новый plan и период overlap; revoke не означает удаление истории/ключей, необходимых для backup recovery.
Потеря encryption keys делает ciphertext backup невосстановимым; recovery keys проверяются отдельным drill.

PII profile fields инвентаризируются и шифруются согласно v1.1; UI показывает только необходимое role/scope.
Audit фиксирует actor, permission/scope, object IDs, operation/plan/task, redacted diff, result/reason и correlation ID.
Не фиксируются passwords, cookies, bearer/recovery/invite/enrollment codes, Authorization, private keys, unredacted bodies/query strings.
Ошибка parser/driver/upstream преобразуется в ограниченный error code; raw request/DB arguments не попадают в логи «для диагностики».
Redaction происходит до записи на диск, stdout, spool и отправки в SIEM; UI redaction после хранения недостаточна.
Audit append-only по application role; export/чтение чувствительных полей/retention changes также аудируются.
Hash chain помогает обнаружить повреждение при наличии независимого anchor; одна цепочка в той же DB не доказывает защиту от DBA/root.
Traffic/WAF logs имеют отдельные quotas, sampling, counters потерь и storage; management audit не вытесняется request bodies.
Если критическое изменение нельзя надёжно аудировать, оно блокируется. Локальная preauthorized recovery пишет durable journal и досылает audit позже.
Log/spool limits, retention/legal hold и alert routing заданы в [operations](operations.md); секрет не включается в notification payload.

## 12. Порядок реализации и условия допуска

Сначала закрываются подтверждённые baseline дефекты и lifecycle MFA/recovery; затем typed parser/permissions/revisions и read-only agent.
До root-helper обязательны независимый review helper/signature/ownership/recovery и fault injection на реальной pilot ОС/filesystem.
До distributed apply обязательны authoritative deny journal, generation-bound Auth, monotonic task sequencing и canary stop semantics.
До package/WAF/airgap — qualification component tuple, signed supply chain и offline dependency closure.
До HA — writer fencing, checkpoint disaster recovery, independent key backups и нагрузочные failure tests.
Точные fixtures, критерии и этапы заданы в [testing](testing.md) и [development](development.md).
Остаётся непроверенным: actual production host hardening, PKI/IdP, корпоративный CI, package matrix, масштаб и операционная приёмка.
Security документ согласует границы реализации; production-ready статус появляется только после соответствующих доказательств.

## 13. WAF Zones: обязательные свойства группового управления

Принятая модель описана в [WAF Zones](waf-zones.md), [REQ-14/24](requirements.md)
и ADR-V2-09. Zone — authoring group Gateway внутри Site, не новая доверенная identity,
RBAC scope либо разрешение на доступ к приложению. AD/MFA/Central Auth независимы.

- `config.read/edit/approve` проверяются по фактической полной области Site/Gateway/Route/Node
  на каждом этапе. Владелец зоны — ответственное лицо, а не получатель permissions.
  Label/selector/default/membership edits считаются изменением защиты; обычные metadata
  permissions не позволяют незаметно снять или ослабить WAF.
- Exact published zone/policy versions, fixed membership и inventory/source digests входят
  в immutable assignment resolution и plan. Опубликовать новую версию не означает
  переключить consumers. Новые совпадения selector либо новые nodes не входят в старое approval.
- Пересечение зон и отсутствие назначения блокируют публикацию; site-default выбирается
  явно при отсутствии ordinary matches. Нельзя вычислять приоритет по порядку SQL либо
  автоматически выключать WAF. Transfer/retire требует следующего валидного binding
  в той же атомарной Configuration transaction, с closure всех затронутых зон.
- Общая зона использует baseline без route exceptions. Derived policy закреплена за одним
  Gateway/Site и exact base zone policy; first derive/rebase передаёт закрытый API envelope.
  Сервер вычисляет diff и lineage, проверяет rule IDs, scope, expiry, floor и locks.
  Локальное исключение не переносится соседу и не расширяется wildcard-условием.
- Mode относится к Gateway binding, затем разрешается существующей цепочкой Profiles.
  Снижение PL, повышение threshold, off/detection вместо обязательного blocking,
  новые исключения либо обход lock/floor требуют адресного отказа или dangerous workflow
  согласно действующей политике. «Самая строгая политика» не вычисляется сравнением
  произвольных разных CRS versions; не доказанное ужесточение считается опасным.
- Full node bundle содержит все обслуживаемые приложения. Изменения соседней зоны,
  попавшие в итоговое дерево, должны быть видны и авторизованы в точном diff; иначе rebase.
  Canary node не выдаётся за изолированное переключение одного приложения.
- Frozen resolution и его children запечатываются одной transaction, далее append к
  нему запрещён. SQL immutable/draft/creation-transaction guards дополняют сервисные
  cross-row checks; production DB permissions должны запрещать обход writer procedure.
- Scoped list/count/cursor/provenance не раскрывают чужие объекты. Full canonical read/export
  требует scope всей closure; отфильтрованная страница не выдаётся за исходный body/digest.
  Источник родительского ограничения вне read scope имеет redacted ID, но разрешённый
  читателю итоговый constraint остаётся объяснимым.

Audit связывает zone revision, resolution/request/config/plan digests, автора и approver,
добавленных/уходящих consumers, target nodes и source of local overrides. Проверки
scope/права повторяются после очереди и перед waves. Истёкшее исключение в действующей
generation закрывает только затронутые routes через Central Auth, без отключения всей зоны.
Rollback использует актуальный deny/floor/expiry и не воскрешает ослабление.
Source closure зон входит в GC roots/backup/restore: одних flattened Gateway bytes
недостаточно для восстановления lineage и доказательства прежнего согласования.
