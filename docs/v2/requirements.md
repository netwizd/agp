# AGP v2 — техническое задание

Статус: **Итоговое ТЗ / принятые владельцем требования TARGET**, редакция 2026-11-17.
Владелец подтвердил логику WAF Zones и формирование итогового ТЗ; ранее принятые
AD, 2FA, одноразовые email-коды и Angular UI сохраняются. Это задание для реализации,
а не описание поставленной версии и не подтверждение production readiness.
Читатели: владелец продукта, backend/frontend/QA, инженеры безопасности и эксплуатации.
Для разработки достаточно доступа к репозиторию и тестовому стенду; production-доступ
и изменение инфраструктуры данным документом не предоставляются.

## 1. Основания и применимость

Основания: [исходный проект v2](../distributed-platform.md), пользовательское описание
распределённой платформы и текущие исходники `cmd/`, `internal/`, `deploy/`, `configs/`.
В baseline `6eac09e62b2de2730d8d3fc194fdb5827b21ccc2` подтверждены Go 1.22,
PostgreSQL/SQLite, локальная аутентификация, группы/permissions, портал, downloads,
аудит, диагностика и ручные рекомендации Nginx. `VERSION`: `v1.0.0-dev`.
Наличие этих механизмов не подтверждает устранение обнаруженных ограничений безопасности.
Агент, helper, distributed rollout, WAF management, OIDC и подписанный offline repository
в этом baseline отсутствуют. [ADR 0001](../adr/0001-single-node-mvp.md) остаётся принятым:
single-node и ручное применение поддерживаются. Автоматическое применение — отдельный opt-in v2.
[План v1.1](../v1.1-plan.md) сохраняет MFA, invite/password setup и уведомления.

Если документ отличается от принятого ADR, инженер явно показывает конфликт владельцу;
новое описание не меняет статус ADR автоматически. Контракты и схемы v2 проектные.
Групповое управление WAF: [WAF Zones](waf-zones.md), решение ADR-V2-09 в [архитектуре](architecture.md).
Нормативные типы: [модель данных](data-model.md), [API](api/openapi.yaml),
[протоколы](protocols.md). Интерфейс: [UX](ux.md); эксплуатация: [operations](operations.md).
Слово «должен» далее означает критерий соответствующего этапа TARGET.

## 2. Продукт и границы

AGP — единая система публикации внутренних приложений, проверки доступа, управления
шлюзами/WAF, безопасных обновлений, аудита и наблюдаемости. Пользователь находит
доступный сервис; администратор понимает эффективную политику и последствия изменения;
оператор видит доказанное фактическое состояние и управляет восстановлением.

Принципы:

1. Одна canonical model для UI, API и YAML/JSON; все изменения проходят общую валидацию.
2. Безопасность проверяется на каждом пути, включая legacy API, rollback и recovery.
3. Настройка, утверждение и применение — разные действия с отдельными полномочиями.
4. «Сохранить черновик» никогда не означает «изменить работающий шлюз».
5. Последняя исправная конфигурация не даёт права работать с недостоверной авторизацией.
6. Управление не является универсальным shell, package manager или orchestration engine.
7. Отказ и неизвестное состояние отображаются явно; система не обещает недоказанную защиту.

Первый Linux-пилот предлагается для одной организации, Ubuntu 24.04 amd64,
центрального Auth Plane, PostgreSQL 17 и закреплённого проверенного component profile.
Это выбор стенда для квалификации, а не заявление текущей поддержки этих версий.
Другие ОС/архитектуры, мультиарендность, SAML, Regional Auth и универсальные Linux-задачи
не входят в первую распределённую поставку; предусмотренные поздние этапы указаны ниже.
Kubernetes не является обязательной предпосылкой. DNS, LB, firewall и почта предоставляются
инфраструктурой; AGP проверяет условия, но не меняет их без отдельной интеграционной задачи.

### Профили эксплуатации

| Профиль | Что поставляется | Что нельзя предполагать |
| --- | --- | --- |
| Standalone manual | Go/PG/Nginx, генерация рекомендаций, ручные backup/test/reload | Наличие агента и автоматическое применение |
| Single-node managed | CP/Auth/PG и управляемый gateway на одном сервере | Отказ management не затронет auth в общем процессе |
| Distributed central Auth | Центральные CP/Auth, удалённые шлюзы, исходящий mTLS агента | Автономный доступ при потере Auth Plane |
| noInternet | Внутренняя связь с CP/Auth и проверенным зеркалом | Возможность обращения к публичным package repositories |
| Split-WAF, позднее | Отдельный HTTP WAF proxy перед gateway, защищённый межузловой участок | Удалённый ModSecurity без прокси и разрешённый прямой обход |
| Airgap, позднее | Собственные CP/Auth/PKI, проверяемый импорт комплекта | Онлайн-управление из отсутствующего центрального соединения |

Режимы Nginx: `managed` — выделенная область владения AGP; `adopted` — существующая
установка с согласованными include/service boundary; inventory-only не выдаёт право записи.

## 3. Участники и обязательные сценарии

| Участник | Задачи и границы |
| --- | --- |
| Пользователь | Вход/SSO/MFA, каталог доступных сервисов, свои сессии, помощь, выход |
| Identity administrator | Invite, группы доступа, блокировка, recovery; не может повышать собственный delegation ceiling |
| Configuration editor | Черновики, diff, validation в разрешённых Site/Node/Route |
| Approver | Независимая проверка конкретного plan; опасную собственную правку не утверждает |
| Deployer | Запуск/пауза rollout по утверждённому plan без его изменения |
| Operator | Inventory, диагностика, maintenance, recovery в назначенном scope |
| Auditor | Redacted история/экспорт без полномочий изменения |
| Break-glass administrator | Локальный аварийный вход с MFA, контролируемый recovery и обязательный аудит |
| Automation principal | Ограниченный API scope, expiry/rotation; не браузерный superadmin token |

Один человек может иметь несколько назначений в пределах политики. Разделение действий
обязательно проверяется сервером; скрытая кнопка не считается авторизацией.

Команда реализует завершённые сценарии, а не только CRUD-формы:

- Новый стенд → prerequisites → администратор/PKI → отдельные origins → restore test → ready.
- Новый узел → enrollment → fingerprint review → inventory → validate-only → opt-in apply.
- Публикация приложения → hostname/TLS/upstream → доступ/WAF → diff → plan → canary → verify.
- Изменение доступа → эффективная политика → current deny → подтверждение → отзыв сессий.
- Новый сотрудник → invite → пароль/MFA либо OIDC → группы → каталог → аудит доступа.
- Обновление CRS/компонента → compatibility/release validation → canary → waves → recovery.
- Изменение WAF-зоны → зафиксированный состав → полный diff узлов → approval → waves → подтверждённое состояние.
- Новый сервис → определение WAF-зоны → проверка обязательного минимума → отдельное назначение/публикация.
- Отказ центра/узла/БД/ключей → объяснимое закрытие доступа → reconciliation → восстановление.
- Принятие существующего Nginx → inventory/backup → ownership boundary → controlled adoption.
- Выход из управления → freeze → передача inventory/config → отзыв identity → detach.

## 4. Этапы поставки

Каждый этап включает документацию, миграцию, негативные проверки и демонстрацию
в изолированной среде. Обозначения S0–S6 продолжают исходный план v2, S7 — отдельное расширение.

| Этап | Обязательный результат до перехода дальше |
| --- | --- |
| S0 — baseline | Четыре hardening-проблемы исходного проекта закрыты; identity lifecycle/MFA/break-glass, origin isolation, PG integration и restore drill; root-helper ещё не допускается |
| S1 — Configuration Core | Типизированная модель, bounded parser, revisions/CAS, migration preview, UI/API/YAML round-trip, plan preview без root apply |
| S2 — read-only agent | Enrollment/mTLS/revoke/renew, inventory, validate-only, отсутствие remote shell |
| S3 — single-node apply | Независимое review helper, managed/adopted, durable journal, probes/rollback, fault injection |
| S4 — WAF/artifacts | Pinned совместимость, WAF Zones/политики/исключения, detection/blocking, подписанные комплекты, noInternet dependency closure |
| S5 — fleet | Canary/waves, поколения маршрутов и auth, актуальный deny, audit outbox, notifications/SIEM |
| S6 — HA/lifecycle | Writer fencing, restore/PITR/keys, upgrade/detach, квалификация split-WAF и airgap по отдельным профилям |
| S7 — regional | Отдельно принятая модель автономной авторизации/отзыва и региональной синхронизации |

Статусы `succeeded`, «WAF блокирует», «восстановлено» разрешены только после проверок
соответствующего уровня. Нельзя рекламировать поздние этапы как часть текущей поставки.

## 5. Проверяемые требования

Каждый REQ сохраняет идентификатор при уточнении. Семейства проверок ниже: unit,
contract, integration, security, e2e, fault, load, DR, compatibility, accessibility.
Матрица автоматизации и состав обязательных проверок — [testing](testing.md).

### REQ-01. Совместимость и безопасная миграция

Этапы: S0–S3. Сохранить standalone manual и существующие user/group/resource references.
Импорт сначала строит canonical revision и семантический diff host/path/auth/cookies,
не применяя конфигурацию. Неизвестные include/directives не принимаются автоматически.
Legacy CRUD должен обращаться к тому же revision service, исключая обход проверок.
Изменение origins требует управляемой повторной аутентификации и отзыва legacy cookies.
Приёмка: копия v1 БД импортируется без потери связей; несовместимые элементы имеют
адресные ошибки; отмена preview не меняет Nginx; downgrade проверяется по матрице.
Проверки: integration, compatibility, e2e, DR.

### REQ-02. Identity lifecycle, MFA и SSO

Этапы: S0, S2, S5. **Требование владельца от 2026-11-17: AD, 2FA и одноразовые
токены/коды обязательны; email — поддерживаемый канал доставки.** Поддержать локальных
пользователей, прямой AD DS через LDAPS/обязательный StartTLS и корпоративную AD-backed
OIDC-федерацию; квалифицированный корпоративный профиль обязателен до пилота S2.
Поддержать одноразовые invite/setup/reset tokens, email verification codes,
TOTP/recovery codes, обязательный MFA для привилегированных субъектов и break-glass.
Пароли хранятся как Argon2id hashes; tokens/codes как проверяемые hash, sensitive profile
fields как ciphertext с key reference. Короткий email OTP хранится как keyed MAC с внешним
pepper, с TTL, attempts, purpose/browser/contact binding и атомарным consume. Email-код
не удовлетворяет обязательной 2FA и не даёт самостоятельного admin MFA reset.
Прямой AD: стабильный forest/objectGUID, явные group mappings, live account/group check
и fail-closed при недоступности DC; нет fallback на local/email для того же пользователя.
Пароль AD не хранится. До завершения 2FA существует только ограниченный pending flow,
полная session/handoff не выдаётся. Подробные контракты — [identity](identity.md).
OIDC subject связывается с проверенным issuer/subject; совпадение email не даёт автолинковку.
Центральный Auth — OIDC client, не универсальный issuer; локальный и OIDC login используют
first-party handoff с отдельным EdgeAuth на gateway, host-only cookie и mTLS redeem code.
Если ответ redeem потерян, одноразовый code не восстанавливает raw session: flow входа
запускается заново, без скрытого создания второй сессии по повтору прежнего code.
Приёмка: AD rename/recreate/disable/lockout, nested/primary groups, DC/GC/TLS failure,
email resend/expiry/replay/parallel consume и восстановление старого backup имеют негативные
сценарии; first-factor-only не даёт доступ. Блокировка, смена групп, утрата MFA и отзыв
сессии проверяются; потеря AD/IdP не отключает отдельный локальный break-glass с MFA.
Проверки: security, contract, integration, e2e.

### REQ-03. Scoped RBAC и независимое утверждение

Этапы: S0–S3. Разделить read/edit/approve/deploy/recover/identity/export и ограничивать
объекты Site/Node/Route. Группы доступа пользователей отделить от инфраструктурных ролей.
Полномочия проверять для субъекта и целевого объекта на всём lifecycle, включая пароль,
блокировку, членство, grant, bulk action и target superadmin. Delegation ceiling не превышается.
WAF-зона не является новым RBAC scope: доступ проверяется для Site и каждого затронутого Gateway/Route.
Селектор не расширяет полномочия; изменение защищённых меток, выводящее сервис из зоны,
проверяется как изменение защиты. Нельзя скрыто выполнить разрешённую часть массовой операции.
Ослабление защиты, trust anchor change и массовое обновление требуют step-up и второго
уполномоченного лица; автор опасной правки не может утвердить свой plan.
Приёмка: прямой API и изменение group membership не обходят ограничения; отозванное
право запрещает approve/start даже при открытой странице и существующем plan.
Проверки: security, integration, e2e.

### REQ-04. Браузерные границы и сессии

Этап: S0. Разделить management, login/SSO и application origins. Cookies host-only,
Secure/HttpOnly; management session не попадает в upstream или shared Domain cookie.
Gateway credential удаляется перед приложением; разрешённые application cookies сохраняются.
Применять CSRF/Origin/CORS/CSP по контексту; заголовки портала не навязываются приложениям.
Session revocation и проверка blocked/current membership работают на каждом auth decision.
Приёмка: вредоносное upstream-приложение не читает/не использует management session;
spoofed identity headers и CSRF отклоняются; после logout повтор сессии закрыт.
Проверки: security, integration, browser e2e.

### REQ-05. Площадки, узлы и enrollment

Этап: S2. Реализовать Site/Node CRUD, labels, ownership, capabilities и immutable snapshots.
Удаление Site/Node с активными ссылками запрещается до переноса/отключения зависимостей.
Enrollment token ограничен scope/capabilities, одноразовый и hash-only; закрытый ключ
генерируется узлом, оператор проверяет fingerprint. После mTLS работают renew и revoke.
Connectivity, config drift, service health и maintenance хранятся/показываются отдельно.
Приёмка: token replay не создаёт второй узел; revoked identity закрывает активный stream;
offline не превращается в «Nginx остановлен» без наблюдения; inventory-only не пишет файлы.
Проверки: contract, integration, security, fault.

### REQ-06. Gateway/Route lifecycle

Этапы: S1–S3. Реализовать create/read/update/retire Gateway/Route с явными references
на узлы, TLS, AccessPolicy и WafPolicy. Проверять hostname/path collision, normalized URI,
reserved management/login namespaces, SSRF boundary и совместимость listener/upstream.
Удаление активного route — ревизия с impact preview; ID не переиспользуется для иной сущности.
Все прикладные маршруты первой поставки защищены Auth Plane; public downloads — отдельный тип.
Приёмка: конфликтующий host/path, неизвестный reference, скрытый direct upstream bypass,
unsupported directive или URL с credential отклоняются до plan; CRUD не выполняет reload.
Проверки: unit, contract, integration, e2e.

### REQ-07. AccessPolicy, поколения и актуальные запреты

Этапы: S1, S3, S5. Зафиксировать route и immutable auth snapshot одним deployment generation.
Auth decision использует точную generation, текущую сессию/членство и current deny overlay.
Unknown generation, недостоверная deny freshness, Auth/storage failure дают fail-closed.
Отзыв/блокировка записываются до связанного rollout и не откатываются вместе с bundle.
Security sequence/epoch сверяются с независимым high-water journal после restore;
отсутствие доказанной свежести не разрешает доступ даже на last healthy config.
Отзыв запрещает новые auth decisions; уже открытые WebSocket/stream требуют отдельной
квалифицированной политики срока/разрыва соединения и не объявляются мгновенно завершёнными.
Приёмка: одновременно старый/новый route корректны при rollout; revoked user остаётся
закрыт после config rollback/старого backup; CP-only outage и Auth outage различаются.
Проверки: security, integration, fault, DR.

### REQ-08. Единая декларативная модель

Этап: S1. UI/API/YAML/JSON используют одинаковую validation/normalization/compiler pipeline.
JSON Schema фиксирует закрытые поля/типы; YAML ограничен JSON-compatible subset без
aliases/tags/merge/duplicate keys. Лимиты bytes/depth/objects/time задаются до парсинга.
Defaults, CIDR/URI и порядок множеств нормализуются до digest; shell/raw Nginx/inline secret
запрещены. Bootstrap-конфигурация отделена от централизованной managed-модели.
Typed inheritance: global → Site → NodeGroup → Node → Route/Resource, с immutable provenance;
конфликт overlapping NodeGroups одного priority — ошибка, security floor не ослабляется.
Приёмка: эквивалентные UI/JSON/YAML дают один canonical digest; неизвестные поля,
двусмысленные boolean/numeric values и oversized input дают адресную ошибку без записи.
Проверки: unit, contract, security, round-trip integration.

### REQ-09. Ревизии, CAS и идемпотентность

Этап: S1. Сохранение создаёт новый draft revision с неизменяемым содержимым; публикация переводит его в состояние published без перезаписи body.
Статусы ConfigRevision: `draft|validated|approved|published|superseded`.
Изменение содержимого сбрасывает предыдущую validation/approval, сохраняя историю.
CAS защищает от потери чужой записи. Idempotency key связан с actor/scope/request digest:
тот же запрос возвращает прежний результат, иной payload с тем же key отклоняется.
Приёмка: два редактора не перезаписывают друг друга; повтор после timeout не создаёт
дубли; публикация и outbox фиксируются атомарно, immutable revision нельзя PATCH-нуть.
Проверки: integration, contract, concurrency, fault.

### REQ-10. Неизменяемый DeploymentPlan

Этапы: S1–S3. Plan фиксирует exact node IDs, base/target/capability/compiler/artifact digests,
secret versions, route/auth generation, security floor, expiry, wave/probe/recovery policy.
Статусы: `draft|validated|approved|expired|superseded`. Label selector вычисляется до approval;
новый узел не включается автоматически. Изменение значимого предусловия требует нового plan.
Перед dispatch проверяются актуальные права, freshness и fencing; approval не даёт бессрочное право.
Приёмка: смена labels/сертификата/capability/base после approval не меняет утверждённую
цель; неподходящие узлы отклоняются с причиной; применённый digest совпадает с рассмотренным.
Проверки: integration, security, contract, fault.

### REQ-11. Typed agent и минимальный helper

Этапы: S2–S3. Agent работает без root и принимает только типизированные задания
`inventory|validate_config|apply_config|upgrade_components|rollback_config|collect_diagnostics`.
Helper проверяет peer identity, подписанный plan, node/scope/expiry/epoch/sequence/digests,
ownership и допустимые операции над закреплёнными каталогами. Нет arbitrary argv/script/URL.
Защитить path traversal, symlinks, TOCTOU, environment и unlimited output/time.
Приёмка: компрометация agent socket не даёт write вне allowlist; старое/чужое/подменённое
задание отклоняется; duplicate/reordered task не возвращает узел к прошлой конфигурации.
Проверки: security, contract, fault, независимое review helper до S3.

### REQ-12. Доказуемое apply и recovery

Этап: S3. Перед изменением проверить полный config tree закреплённым Nginx/WAF tuple,
free space, secrets, base, drift и live auth snapshot. Intent/journal fsync предшествует switch.
До первого managed/adopted plan выполняется явный CaptureBaseline: подтверждённая base
revision и bundle обязательны. Пустой managed-узел получает квалифицированную закрытую
bootstrap revision/bundle; `null` вместо base не разрешает первый apply.
Проверять worker generation и real-listener allowed/denied/revoked-session probes;
для WAF отдельно проверять detection/blocking. Один `nginx -t` или reload signal не достаточен.
Rollback — новая операция с новым sequence, совместимостью и current deny; последний
healthy bundle не оправдывает bypass. Неопределённый reload требует reconciliation.
Приёмка: crash/reboot после каждого durable checkpoint приводит к доказанному applied,
`rolled_back` или `recovery_required`; секреты не попадают в журнал и диагностику.
Проверки: fault, security, integration, recovery e2e.

### REQ-13. Fleet orchestration

Этап: S5. Freeze targets → prepare → canary → observe/probe → bounded waves.
Concurrency/maxUnavailable и stop conditions задаются plan, отражая реальный LB capacity.
Pause запрещает новую dispatch, но не прерывает опасный локальный checkpoint; cancel
останавливает будущие работы и не означает автоматический rollback уже успешных узлов.
Состояния Rollout: `queued|running|paused|cancelling|succeeded|failed|cancelled|recovery_required`.
Приёмка: ошибка canary не выпускает следующую wave; partial/unknown/offline видны поузлово;
повтор start не создаёт второй rollout; rollback затронутых узлов — новый проверенный plan.
Проверки: fault, integration, security, e2e.

### REQ-14. WAF Zones, policies и топологии

Этапы: authoring/preview — S1, native WAF — S4, массовое применение — S5;
split-WAF — S6. **Решение владельца от 2026-11-17: основной способ управления WAF —
зоны приложений с общей политикой; индивидуальное управление сохраняется для диагностики
и локальных исключений.** Полный контракт — [WAF Zones](waf-zones.md).

`WafZone` группирует логические Gateway в пределах одной Site. Это не NodeGroup,
сеть, DNS-зона, группа доступа пользователей или новый уровень наследования PolicyProfile.
Одна primary zone на Gateway. Состав задаётся явными Gateway IDs, AND-селектором меток
либо одной явной `siteDefault` зоной. Два совпадения основных зон — конфликт, публикация
запрещена; ноль совпадений — Site default либо onboarding с запретом публикации.
В zone-managed контуре отсутствие назначения не означает `WAF off`. Ручной v1 сохраняется;
его перевод в зоны начинается с контролируемого import/preview, без live изменения.
Изменение селектора/меток не переключает
активные назначения в обход нового resolution, CAS, проверки прав и плана.

Версия зоны закрепляет exact `policyRevisionId` и желаемый режим `detection|blocking`.
WafPolicy хранит pinned engine/ruleset, PL/пороги и typed исключения; режим относится
к назначению, материализуемому в `Gateway.spec.waf`, а не к `WafPolicy.spec`.
Базовая политика зоны общая и не содержит route-specific исключений. Индивидуальные
особенности создают производную immutable политику конкретного Gateway с происхождением
от базы и списком локальных изменений. Обновление базы требует rebase: совместимые
изменения переносятся с проверкой, конфликты блокируют затронутое назначение. Ни потеря
исключений, ни неограниченное сохранение старой базы не происходят молча.
Существующие Global/Site/NodeGroup/Node/Route profile locks и security floor действуют
после materialization; запрос зоны не даёт права их ослаблять. Полная WAF-политика
пока назначается Gateway: разная полная политика для отдельных его Routes не входит
в этот контракт; узкое route exception не является отдельной полной политикой.

Preview фиксирует immutable состав, исходные zone/config/label revisions, membership
и source digests, итоговые назначения и точные узлы. Approval относится к этому
составу и полному native bundle каждого узла. Новые совпадения селектора после approval
попадают в следующий plan, а не в прежнее согласование. Исключение участников,
удаление/retire зоны и перенос в другую зону требуют явных replacement assignments
под CAS, без промежуточного `off`; работающие назначения сохраняются до безопасного
применения. Общий узел с изменениями других зон показывает все изменения либо
останавливает подготовку до их разделения/согласования.

Одна UI-команда может подготовить обновление нескольких Site, но создаёт отдельные
site-scoped планы и показывает их независимые результаты. Canary выбирает узлы и
все обслуживаемые ими приложения; разделение доли трафика одного приложения этой
функцией не обещается. Частичное применение, offline и unknown остаются видимыми.
Повтор и rollback используют exact observed base, новые планы и актуальные floors;
слепого fallback на более слабую политику нет.

Provider interface отделяет capabilities/compile/validate/probe/events от Control Plane;
исходный CRS не редактируется. Исключение ограничено Route, конкретными rule IDs,
типом/буквальным именем поля; обязательны owner/reason/reviewAt/expiresAt. Zone-wide
wildcard исключения и произвольные native snippets запрещены. Ослабление включает blocking → detection/off, снижение PL, повышение порога, новое
исключение и изменение зоны/default/меток с таким эффектом; оно требует impact preview,
step-up и независимого approval. Права проверяются для всех косвенно затронутых
Gateway/Routes полного node bundle, а не только выбранной зоны.
`expiresAt` — hard deadline: scheduler заранее создаёт removal revision/rollout;
если active generation всё ещё содержит expired exception, Central Auth закрывает
только затронутые Routes до safe apply удаления либо нового approved extension.
Наступление времени само по себе не удаляет native CRS правило. AD/MFA остаются
независимыми; detection не означает публичный доступ.

В split-WAF gateway доверяет только проверенному WAF proxy; direct/alternate route закрыт.
Приёмка: массовое обновление не требует выбора каждого сервиса; неоднозначное назначение,
выход через метки, stale resolution, несовместимый ABI и shared-node hidden diff блокируют
публикацию. Проверены rebase, новые участники/узлы, перенос/удаление, partial rollout,
rollback с истёкшим исключением и отсутствие обхода WAF. Detection не объявляется
блокировкой; blocking probe реально отклонён. Матрица — [testing](testing.md).
Проверки: contract, security, compatibility, integration, e2e, fault, load.

### REQ-15. Сертификаты, секреты и PKI

Этапы: S0–S4. TLS issuer/storage выбирается явно: не подставлять Let's Encrypt paths.
SecretVersion immutable, envelope encrypted, scoped node/task delivery; decrypt key отделён
от БД/backup. Node/CA/plan/release/TLS keys не взаимозаменяемы; root CA offline.
Rotation создаёт новую version и plan, отображает сроки/потребителей, допускает dual trust;
emergency revoke не ждёт штатную wave. Нельзя автоматически заменить expired secret старым.
Приёмка: mismatch SAN/key/chain/expiry не допускается в apply; старый plan не забирает
новую secret version; revoke закрывает stream; restore без key store не заявляет success.
Проверки: security, integration, fault, DR.

### REQ-16. Артефакты, установка и обновления

Этапы: S4; noInternet S4, airgap S6. Release manifest/TUF metadata, digest/length/expiry,
anti-rollback floor, SBOM/licenses и dependency closure обязательны для component profile.
Config/CRS/исключения/agent/server обновляются независимо в пределах compatibility matrix;
Nginx и ABI-coupled modules — одним tested tuple. Нет `latest`, скрытой сети/package hooks.
Install/upgrade и contract migration имеют backup, prerequisites, recovery и окно обслуживания.
Приёмка: tampered/expired/downgraded/неполный bundle отвергается; noInternet clean VM
устанавливается с заблокированным external egress; неверный OS/arch не «исправляется» системой.
Проверки: compatibility, security, install e2e, fault, DR.

### REQ-17. Аудит, SIEM и приватность

Этапы: S0, S5. Immutable admin/security events содержат event/actor/target/request IDs,
before/after digest, result/reason и UTC time; task attempt и operator action различимы.
Transaction outbox/spool допускает at-least-once delivery с dedup ID и явным backlog.
Secrets/cookies/Authorization/request body не журналируются; query/profile/IP редактируются
по retention/access policy. Критическое изменение без durable audit не подтверждается.
Приёмка: одинаковые events дедуплицируются; overflow/loss counters видны; фильтр/экспорт
ограничен scope и permission; CSV формулы экранированы, экспорт не обходит redaction.
Проверки: security, integration, fault, e2e.

### REQ-18. Dashboard, метрики и уведомления

Этапы: S0, S5. Показывать connectivity, desired/applied, drift, Nginx/Auth/WAF health,
freshness, certificates, rollout, backlog и отказ авторизации отдельно. Метрики экспортируются
в Prometheus; подробная аналитика может быть внешней Grafana. Разделить alerts и audit.
Категории включают login, вход в ресурс, инфраструктуру, security/WAF, config/rollback,
updates и certificate expiry; получатели/дедупликация задаются policy, а не каждым HTTP request.
SMTP/webhook/Alertmanager, позднее Telegram adapter: routing, dedup, retry, ack, maintenance;
channel secrets версионируются, egress проверяется. Нет канала — нет обещания доставки.
Приёмка: stale data помечены временем; outage Auth не скрыт зелёным agent online;
test notification содержит delivery result, SSRF попытка блокируется, retry не меняет event ID.
Проверки: integration, security, fault, e2e.

### REQ-19. Хранение, типы и жизненный цикл данных

Этап: S1, развивается до S6. PostgreSQL — production writer; normalized references/CAS
отделены от immutable canonical JSON и крупного object/artifact storage. JSONB не заменяет FK.
IDs — case-sensitive opaque text `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`; legacy IDs сохраняются
без lowercasing, вне профиля — через explicit identity bridge. Sequences/revisions/epochs/bytes — uint63 в SQL bigint,
на JSON wire decimal strings; время — RFC3339 UTC `Z`; digest — `sha256:` + lower hex.
Nullable/absent/empty различаются schema; retention/GC учитывает active deployment/hold/backup.
Приёмка: значение больше JS safe integer сохраняется точно; orphan references, лишние поля,
negative/overflow counters отвергаются; GC не удаляет bundle/secret, нужный для recovery.
Проверки: contract, integration, security, DR.

### REQ-20. Backup, DR, HA и fencing

Этапы: S0, S6. Backup охватывает PG/PITR, objects/ciphertext, trust metadata/key recovery,
inventory и отдельный security journal. Установка из старого backup не понижает deny floor.
После DR/PITR новый authority epoch делает восстановленные sessions/invites/enrollment
и recovery codes недействительными. Credentials ниже независимого security floor
отключаются до supervised reset; требуется повторный вход либо восстановление доступа.
Один authority writer с fencing epoch; active/standby CP не означает автоматически HA Auth/PG.
Реплика не принимает write/tasks до доказанного writer ownership; clock uncertainty видна.
RPO/RTO задаются владельцем до HA-приёмки, а достигнутые значения измеряются drill.
Приёмка: потеря writer/PG/key store, network partition и restore старого backup не создают
split-brain или старые разрешения; процедуру выполняет другой оператор по runbook.
Проверки: fault, security, DR, load.

### REQ-21. Сетевая безопасность и диагностика

Этапы: S0–S4. Доверенные identity headers перезаписываются в каждом proxy location;
client IP определяется только от известных proxy. Agent API имеет отдельную trust boundary.
Diagnostics/webhooks/upstream probes используют egress allowlist, проверенный IP с исходным
Host/SNI, контролируемые redirects, timeout/output bounds и не наследуют proxy environment.
Нельзя превратить diagnostics в internal scanner либо отдать operator network credentials.
Приёмка: DNS rebinding, metadata/link-local/loopback, alternate redirect и forged X-AGP
тесты отрицательны; redacted diagnostics пригодна для support, не содержит ключи/тела запросов.
Проверки: security, integration, fault.

### REQ-22. Удобство управления и доступность

Этапы: S1–S5. Поддержать завершённые wizard/edit/review/apply/recovery сценарии [UX](ux.md).
Безопасные defaults и effective-policy provenance видны; bulk actions показывают blast radius.
Русский интерфейс, клавиатура/screen reader, понятные ошибки, empty/loading/offline/conflict
states; целевой уровень [WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/) требует проверки.
UX не навязывает shell/raw directives и не прячет необратимое действие за нейтральной кнопкой.
Принятое требование владельца от 2026-11-17: единый современный лёгкий Angular UI.
Основной экран WAF — зоны, затем приложения и эффективная защита; счётчики различают
Gateway, Routes и узлы, а просмотр локального отклонения показывает его происхождение.
Ключевые параметры имеют кнопку «?» в кружке: краткая справка и ссылка на точный раздел
внутреннего manual. Keyboard/touch доступны; переход к помощи сохраняет незавершённую форму.
Визуальные правила и пример — [ui-design](ui-design.md).
Приёмка: оператор без знания native Nginx создаёт draft/plan и понимает failure/recovery;
пользователь находит разрешённый сервис среди 100 карточек; основной flow доступен без мыши.
Проверки: usability e2e, accessibility, security, browser integration.

### REQ-23. API и автоматизация

Этап: S1, расширение S2–S6. Версионированный management API фиксирует DTO, permission,
scope, pagination, CAS/idempotency, async operation/result и stable error codes.
Любой UI action имеет тот же серверный путь контроля, что прямой API; browser/agent/auth
listeners не смешиваются. CLI v2 проектируется по контрактам, не объявляется текущим help.
Приёмка: generated client и schema fixtures совпадают; 401/403/conflict/rate limit/unknown
operation отличаются; retry после timeout reconciles operation вместо дублирования effects.
Проверки: contract, integration, compatibility, security.

### REQ-24. Ёмкость и измеряемые SLO

Этапы: parser/model — S1, пилот — S3, fleet-квалификация — S5–S6.
Управление 1000+ сервисами — обязательный TARGET: серверные поиск/фильтры/pagination,
выбор всех результатов запроса через зафиксированный сервером состав, групповые WAF
изменения, объяснимое наследование и progress/reconciliation вместо поштучных операций.
Логические Gateway, Routes, физические узлы и пользователи считаются отдельно.

Контракты имеют два профиля ёмкости. Верхняя граница допустимого документа не является
гарантией производительности либо права отключить проверки безопасности.

| Ограничение | `pilot-500` — config/plan v1alpha1 | `fleet-10k` — config/plan v1alpha2 |
| --- | --- | --- |
| Gateway на полный Configuration | 500 | 10 000 |
| Routes на один Gateway | 1000 | 1000 |
| Routes на полный Configuration | Ограничены числом Gateway, per-Gateway и общим byte budget | 100 000 суммарно |
| Размер полного UTF-8 snapshot | 2 MiB | 64 MiB |
| Profile assignments | 1000 | 20 000 |
| Узлы одного site-scoped plan | 500 | 500 |
| Размер canonical plan | 2 MiB | 32 MiB |
| Resolved inputs одного plan | 1000 | 50 000 |

v1alpha1 сохраняет прежние лимиты и не получает незаметно расширенные defaults.
v1alpha2 явно содержит `capacityProfile: fleet-10k`; schemas:
[Configuration](schemas/configuration-v1alpha2.schema.json), [DeploymentPlan](schemas/plan-v1alpha2.schema.json).
Парсер проверяет размер stream и cumulative counts до крупных allocations, ограничивает
depth 32, время/память и работу resolution/compiler. Один snapshot остаётся полным;
UI-pagination не превращает его в несколько независимо применяемых фрагментов.
Per-node `secretVersionIds` остаётся ограничен 100: размещение, превышающее cap,
получает адресный capacity conflict и требует распределения по узлам либо отдельной
версии task/agent profile. `fleet-10k` не обещает 10 000 сервисов на одном узле.
Canonical size измеряется по реальным canonical bytes: storage JSONB text имеет
отдельный headroom 4 MiB/128 MiB для pilot/fleet, не заменяющий cap 2 MiB/64 MiB.
CompiledBundle resolved-input projection имеет storage budget 256 KiB/16 MiB; размер
самого bundle artifact определяется отдельным qualified component profile.

Обязательные qualification datasets: 1000, 5000 и 10 000 Gateway с соответственно
10 000, 50 000 и 100 000 Routes; отдельно граничные и превышающие лимиты случаи.
В отчёте фиксируются узлы/площадки, плотность сервисов на узле, policy revisions/исключения,
profile assignments, resolved inputs, users/sessions, RPS/concurrency/request sizes,
event rate/retention, железо и component versions. Измерять auth/management latency,
compiler/plan duration, memory/DB saturation, apply convergence, deny freshness,
spool/notification delay, backup/restore; публиковать p50/p95/p99, errors и failure profile.

До production владелец принимает численные SLO/RPO/RTO на основании измерений.
Начальный стенд 25 nodes, 100 routes и 5000 users остаётся отдельной малой нагрузочной
выборкой, а не подтверждением fleet-10k. Security freshness не выводится из heartbeat.
Отсутствие численных SLO блокирует GA, но не S1-разработку; результат mock/Schema PASS
не объявляется прохождением capacity qualification.
Проверки: contract, load, fault, DR, browser e2e.

### REQ-25. Разработка, совместимость и качество

Этапы: все. Монорепозиторий Go с ограниченными module boundaries; новый frontend — Angular
и TypeScript по [development](development.md), общий design system/help layer. Contract/schema
fixtures, migrations expand/backfill/contract, compiler golden tests и release matrix обязательны.
Server/protocol/agent/component compatibility фиксируется до upgrade; unsupported feature
не игнорируется молча. Документы, SBOM и воспроизводимый build входят в release evidence.
Приёмка: CI проходит обязательные проверки этапа; PostgreSQL не заменён SQLite-only тестом;
breaking schema change имеет version/converter, rollback window и compatibility fixtures.
Проверки: unit, integration, contract, compatibility, security.

### REQ-26. Adoption, detach и uninstall

Этапы: S3, S6. Adoption начинается с read-only full-tree inventory/backup и явной области
владения. Чужой include drift блокирует apply; автоматическое переписывание запрещено.
Detach замораживает dispatch, завершает/reconciles локальные операции и передаёт config,
dependencies/ownership inventory. В `retainAuthorization` отзывается agent role и отключается
helper; явно сохраняется разрешённая EdgeAuth binding. Generic node revoke отзывает обе роли.
Замена Auth обязательна до полного выхода; отзыв agent не означает сохранение EdgeAuth по умолчанию.
Uninstall удаляет только подтверждённые AGP-owned файлы/units, сохраняя shared packages.
Приёмка: existing nginx/custom include переживает adoption/detach; offline revoke не
выдаётся за удаление агента; без нового auth boundary выход не открывает защищённые ресурсы.
Проверки: integration, security, lifecycle e2e, DR.

### REQ-27. Пользовательский портал и downloads

Этапы: S0–S1. После входа открыть каталог доступных пользователю сервисов с поиском,
категориями и новым окном приложения. Unknown/forbidden route дают одинаковый отказ.
Верхнее меню: портал/скачать/помощь, identity и выход; администрирование доступно по правам.
Public downloads имеют административное имя, размер/hash, публикацию, тип/size policy;
это отдельный public content, не разрешение на незащищённый proxy route.
Приёмка: запрещённый сервис не появляется в поиске/счётчиках; карточка не раскрывает
internal_url; опасный HTML/SVG upload не исполняется на management origin.
Проверки: security, e2e, integration, accessibility.

### REQ-28. Regional Auth и предел автономности

Этап: S7, отдельное архитектурное решение. Локальный auth/relay и региональное хранилище
должны иметь authority, bounded staleness, отзыв/keys/sessions conflict model и DR.
Наличие mirrors/spool/последнего bundle не включает offline allow. До принятия модели
работает только central Auth fail-closed. Нельзя обозначить сетевой partition «автономным режимом».
Приёмка: согласованы допустимая задержка отзыва и risk owner; partition/merge/revoke/restore
доказаны тестами до показа переключателя Regional Auth в production-интерфейсе.
Проверки: security, fault, DR, load; реализация не блокирует поставку central Auth.

## 6. Общие правила приёмки и завершённости

Для закрытия требования нужны change и автоматизированное/ручное свидетельство,
включая отрицательный сценарий и восстановление. «Документ написан», «endpoint отвечает»
и «nginx -t прошёл» не заменяют функциональной приёмки. Неподдерживаемая комбинация
отклоняется до начала изменения, а не переводится в менее защищённый режим.
Сквозной demo на соответствующем этапе: восстановленный стенд → новый узел → route →
план → независимое approval → canary → denied/revoked/WAF probes → отказ → recovery → audit.
Для ручного профиля вместо agent apply демонстрируется перенос проверенных рекомендаций
оператором; результат не выдаётся за автоматическую проверку applied generation.

## 7. Уточнения, которые не мешают начать разработку

Можно начинать S0/S1 и проектирование S2 на этом baseline в test-only среде без изменения
production и без утверждения каждого внутреннего класса/функции владельцем. Открытые
выборы оформляются в существующей архитектуре; принятые ADR не подменяются.

До подключения первого root-helper требуется подтвердить supported OS/component tuple,
PKI/trust anchor/key recovery, scopes/operator roles и независимое security review.
Продуктовая логика WAF Zones, Angular и обязательных AD/2FA/email-кодов уже принята
владельцем и не требует повторного интервью. До production rollout владелец определяет численные SLO, RPO/RTO, audit/log retention,
notification recipients, окна обслуживания и ответственность за DNS/LB/firewall.
До S6 отдельно принимаются split-WAF trust boundary, airgap import authority и HA fencing;
до S7 — максимальная устарелость авторизации и риск несвоевременного отзыва.
Рекомендуемые defaults: одна организация, central Auth fail-closed, OIDC first external IdP,
локальный MFA break-glass, Ubuntu 24.04 amd64 pilot, ручной профиль сохранён.
Эти defaults позволяют команде начинать вертикальный срез, не выдавая непроверенное за SLA.
