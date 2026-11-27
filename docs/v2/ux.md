# AGP v2 — спецификация интерфейса и сценариев управления

Статус: **TARGET итогового ТЗ**, редакция 2026-11-17; для frontend/backend/QA,
продуктового дизайнера, оператора и инженера безопасности. Это функциональная спецификация,
а не реализованный макет. Требования связаны с [ТЗ](requirements.md), типы — с
[моделью данных](data-model.md), запросы — с [OpenAPI](api/openapi.yaml).
Поддерживаемые функции и этапы определяются [планом](README.md); непройденный этап
не изображается работающей кнопкой, демонстрационные данные явно помечаются.

## 1. Принципы удобного и проверяемого управления

Интерфейс отвечает на четыре вопроса: что сейчас работает, что предполагается изменить,
кто и что утвердил, как проверить результат/восстановиться. Без этих ответов нельзя
предлагать оператору массовое изменение или кнопку «Повторить».

- Пользователь видит разрешённые сервисы, своё имя, помощь и выход; инфраструктура ему не нужна.
- Оператор работает с Site/Node/Gateway/Route, а native config доступен как read-only evidence.
- Основной путь — понятная форма/wizard; YAML/JSON — равноценное представление того же draft.
- Defaults безопасны и видны до validation; сохранение, publication и apply обозначены разными глаголами.
- Любая цифра состояния имеет scope, время наблюдения и источник; stale/unknown не закрашиваются зелёным.
- Снижение защиты — отдельный рассмотренный change, а не обычный switch в списке ресурсов.
- Bulk action показывает точные цели и blast radius до approval; фильтр списка сам по себе не утверждение целей.
- Ошибка объясняет последствие и следующее разрешённое действие, не требует угадывать внутреннюю архитектуру.

Предлагаемый основной язык — русский; API identifiers/enums сохраняются для поддержки.
Встроенный текущий UI — HTML/CSS/JavaScript, это AS-IS. По решению владельца от 2026-11-17
новый v2 frontend — **Angular** с единым лёгким стилем, design tokens и общей библиотекой
компонентов. Визуальные правила, контекстная справка и manual — [ui-design](ui-design.md).
Визуальные tokens/компоненты должны быть едины; логика safety и права всегда находятся на сервере.

## 2. Контексты, навигация и доступ

### Пользовательский портал

После интерактивного входа пользователь, в том числе администратор, попадает в каталог.
Верхнее меню: «Портал», «Скачать», «Помощь», имя/учётная запись, «Выйти».
«Администрирование» появляется при соответствующих правах и ведёт на отдельный management origin.
При переключении EdgeAuth узла балансировщиком может потребоваться повторный handoff через Central Auth; UI показывает «Восстанавливаем вход», сохраняет безопасный return path и не зацикливает callback. Это не означает потерю черновика или необходимость отключить проверку node/audience.
Прямая разрешённая management-ссылка открывает нужный экран после отдельной проверки сессии.
Название приложения на карточке — публичное административное имя; internal URL не показывается.
Сервис открывается в новой вкладке; кнопка предупреждает об этом доступным текстом.

### Management workspace

Постоянная панель: текущая организация/область, поиск по разрешённым объектам,
уведомления, help и профиль с MFA/sessions/logout. Scope отображается на всех экранах;
переход из фильтра Site в detail не расширяет права и не теряет контекст.

| Раздел | Экраны |
| --- | --- |
| Обзор | Состояние площадок, активные rollout, проблемы, сроки сертификатов, backlog |
| Инфраструктура | Sites, NodeGroups, Nodes, inventory, trust/agent identity, maintenance |
| Шлюзы и ресурсы | Gateways, Routes/каталог, listeners/upstreams/TLS, зависимости |
| Политики | AccessPolicy, PolicyProfile, effective configuration |
| WAF и защита | Зоны, политики/версии, срабатывания, route exceptions, effective protection |
| Изменения | Черновики, ревизии, diff, планы, approval queue, rollout, recovery |
| Доступ и пользователи | Users/invites, AD/OIDC directories и mappings, access groups, management roles/scopes, MFA/sessions |
| Сертификаты и секреты | Metadata, потребители, версии, expiry, rotation, revoke |
| Дистрибутивы | Component profiles, verified releases, mirrors/import, совместимость |
| События | Audit/activity, WAF events, alerts, delivery status, exports |
| Настройки | Portal branding/downloads, notification channels, IdP, bootstrap inventory |

Меню строится по capabilities пользователя, а не по флагу «admin».
Viewer видит состояние без mutation controls; editor — draft/validate; approver — review;
deployer — разрешённые start/pause/cancel; auditor — фильтры/export с отдельным permission.
Недоступное действие внутри уже разрешённого объекта объясняется причиной и нужной ролью.
Объекты вне scope не раскрываются через поиск, counters, autocomplete, history или errors.
Изменение прав во время сессии обновляет интерфейс, но сервер проверяет каждый запрос независимо.

### AD, 2FA и одноразовые коды

Способы входа подписаны явно: «Корпоративная учётная запись AD», «Корпоративный SSO»,
«Локальная учётная запись». Локальный аварийный вход доступен по policy и не является
автоматическим продолжением неуспешного AD login. Форма AD показывает каталог/домен,
формат имени и ссылку на корпоративную процедуру смены пароля. Пароль не сохраняется
между вкладками; ошибка не раскрывает существование account.

После primary login отдельный экран TOTP: label, paste/autocomplete, время и кнопка
завершения; код не сохраняется в draft/localStorage/телеметрии. До обязательной 2FA
каталог и management не открываются. Закрытие страницы не завершает pending flow;
просроченный flow требует повторного входа. При недостаточном IdP MFA UI запрашивает
TOTP AGP. Step-up показывает конкретное действие и scope, не становится бессрочным.

Email challenge показывает назначение, маскированный адрес только в разрешённом flow,
доступное поле восьмизначного кода, expiry, ожидание до resend и состояние доставки.
Paste работает с клавиатурой и screen reader; autofocus не отправляет форму.
Resend объясняет, что прежний код перестал действовать. SMTP accepted показывается
как «Передано почтовому серверу», а не «Письмо доставлено». Задержка/ошибка почты
сохраняет контекст, но не продлевает flow и не отключает MFA. Email-код подписан
«Подтверждение адреса/приглашения/восстановления», а не «2FA выполнена».
Потеря TOTP ведёт в проверяемый recovery flow без кнопки обхода через письмо.

Мастер AD provider: название/домен/forest anchor → DC/TLS/CA → read-only secretRef и OU →
test TLS/bind/account/groups → preview mappings и эффективного доступа → approval → activation.
Тест не включает provider и не меняет доменные учётные записи. Видны только metadata
secret versions. Mappings показывают AD group GUID/name, AGP access group и provenance;
Domain Admins не превращается в superadmin. Изменение mappings создаёт новую версию.
User detail показывает directory/objectGUID и время последнего наблюдения; оно не
подтверждает текущее разрешение. При отказе DC: «Каталог недоступен; доступ временно
закрыт», correlation ID и инструкция без бесконечных bind/retry. Точные правила — [identity](identity.md).

## 3. Общие элементы и взаимодействие

### Контекстная справка и внутренний manual

Рядом с ключевыми параметрами — кнопка «?» в кружке с единым поведением. Открывает
краткое объяснение назначения/последствий и ссылку «Открыть в руководстве →» на конкретную
внутреннюю тему. Работает click/Enter/Space/touch; закрывается Esc/снаружи, возвращает focus.
Интерактивная ссылка не помещается в недоступный native title. Manual открывается поверх
текущего контекста, не сбрасывает значения, dirty state, validation errors и scroll формы.
«Назад к настройке» возвращает пользователя в то же поле. Тексты поставляются локально
с приложением и соответствуют версии AGP; отсутствие внешнего Интернета не лишает помощи.
Критические ограничения остаются видимыми у поля. Контракт и темы — [ui-design](ui-design.md).

### Списки и карточки

Server-side pagination/cursor, сортировка и фильтры сохраняются в безопасных URL-параметрах;
token/секрет/личные данные туда не попадают. Выбор строки открывает detail с breadcrumbs.
Таблица показывает имя и стабильный ID, scope, состояние, owner и последнее изменение.
Для версии/digest есть copy и полное значение в details; сокращённый hash не идентификатор approval.
Поиск работает по разрешённым именам/ID/labels, одинаково с клавиатуры и мышью.
Скрытые фильтром выбранные объекты отображаются в selection summary с количеством.
«Выбрать все результаты» требует серверного snapshot целей; меняющийся live query не замена snapshot.
Перед bulk action список целей раскрывается и скачивается как redacted manifest.

### Формы и validation

Каждое поле имеет label, назначение, пример на `example.net`, default и адресную ошибку.
Placeholder не заменяет label. Required/optional и источник наследования обозначаются текстом.
Client-side validation даёт раннюю подсказку; server-side schema/semantic validation обязательна.
Ошибка показывается у поля и в summary со ссылкой/фокусом; введённые несекретные данные сохраняются.
Для secret ввода пользователь видит только «сохранена версия …», повторного plaintext echo нет.
Выбор reference показывает разрешённые версии и их статус, а не предлагает придумать raw ID.
Форма имеет «Сохранить черновик», «Проверить», «Посмотреть изменения»; apply в editor отсутствует.

Общие типы полей совпадают со [shared schema](schemas/shared.schema.json):

| Поле | Поведение формы |
| --- | --- |
| ID | Case-sensitive opaque 1–128 символов, `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`; не lower-case и не переименовывается при смене display name |
| Revision/sequence/epoch/bytes | Decimal string uint63, не JS `Number`; сравнение/форматирование не теряет точность |
| Timestamp | Wire UTC RFC3339 `Z`; UI может показывать timezone пользователя с полным UTC в details |
| Digest | Полное `sha256:` + 64 lower-hex, readonly после фиксации |
| Host/path/CIDR/reference | Typed normalization/semantic validation сервера; Unicode hostname показывается вместе с canonical ASCII |
| Optional/nullable | «Не задано», inherited и явное пустое значение различаются; UI не добавляет implicit null |

Лимиты конкретных name/labels/URL/path берутся из версии schema, а не дублируются
разными константами frontend. Превышение лимита сообщает максимально допустимое значение.

### Действия и безопасные подтверждения

Read-only операции не требуют формального подтверждения. Dangerous action требует:
точного имени/ID объекта, причины, полномочий, step-up при необходимости и independent approval.
Диалог показывает число узлов/ресурсов/пользователей, разницу защиты, сроки, probes,
backup/base digest и конкретный recovery path. Не использовать generic «Вы уверены?».
Typed confirmation применяется к массовому удалению/revoke/trust changes, не ко всякому Save.
Нельзя прятать «отключить авторизацию/WAF» в checkbox «продолжить при ошибке».
Операция над объектом с зависимостями сначала показывает reverse references и запрет/порядок удаления.

## 4. Первое включение и готовность установки

Wizard доступен только в bootstrap-контексте через утверждённый защищённый канал;
первый посетитель публичной страницы не становится администратором.
Локальная установка требует оператора с доступом к стенду; UI не получает универсальный root shell.

1. «Профиль»: standalone manual / single-node managed / distributed central Auth.
   Advanced late profiles показываются только после их квалификации, с условиями поддержки.
2. «Предпосылки»: DNS/точное время/TLS origins, PostgreSQL, storage/backup и egress.
   Для каждой проверки: источник, observed time, result и кто исправляет проблему.
3. «Администратор»: setup локального admin, обязательный MFA/recovery, запрет общего пароля.
   Recovery codes показываются один раз и не пишутся в обычный activity log.
4. «Вход»: локальный lifecycle и обязательные для корпоративного профиля AD/2FA/email-коды;
   выбор direct AD DS либо AD-backed OIDC с квалификацией TLS/groups/claim mapping по [identity](identity.md).
   Management session/client отделены от portal/gateway; «тест входа» не выдаёт лишнюю роль.
5. «Сертификаты»: выбрать явный issuer/import/external-key-store profile и проверить SAN/chain.
   Не подставлять Let's Encrypt, production DNS или секретный file path по догадке.
6. «Хранение и восстановление»: показать состояние backup/key recovery/security journal;
   evidence restore drill подтверждается оператором/автоматизацией, не создаётся кликом «готово».
7. «Сводка»: проверенные prerequisites, блокирующие ошибки, разрешённые следующие действия.

Успех wizard означает готовность конкретного тестового профиля, а не SLA всей установки.
При ошибке можно продолжить редактирование независящих полей; managed apply блокируется,
если обязательные проверки не завершены. Отмена не удаляет внешний PG/PKI/системные пакеты.

## 5. Подключение и жизненный цикл узла

Wizard «Добавить узел»:

1. Выбрать Site/NodeGroup, имя, owner, labels и будущий managed/adopted/inventory-only scope.
2. Показать поддерживаемую ОС/архитектуру и проверяемый installation bundle, trust fingerprint.
3. Выпустить scoped одноразовый enrollment token с видимым сроком; показать один раз.
   Не давать команду с token в URL/CLI arguments. Инструкция использует защищённый ввод
   в поддерживаемый installer/credential source; конкретный синтаксис берётся из shipped help.
4. Дождаться CSR/fingerprint, сверить с локальным оператором, подтвердить привязку.
5. Получить read-only inventory: OS/arch, версии, listeners, paths, capabilities, free disk,
   actual config digests, time trust и предупреждения об unsupported setup.
6. Выбрать «Оставить inventory-only» / «Проверять конфигурации» / «Подготовить adoption».
   Enrollment сам по себе не разрешает helper писать Nginx.

Token нельзя перечитать после закрытия; потеря требует revoke/reissue, replay показывает отказ.
Неподтверждённая fingerprint/несовпадение scope не выдаются за успешное подключение.
Detail узла: overview, observed inventory, desired/applied, service health, tasks,
owned/unmanaged files, identity/renewal/revocation, audit и recovery.
«Удалить узел» отличается от «Отозвать identity» и «Detach»: UI объясняет эффект каждого.
Revocation закрывает management streams, но не обещает удаление offline-агента с диска.
При generic node revoke явно указать отзыв обеих ролей — agent и EdgeAuth — и закрытие
затронутого доступа. Detach с `retainAuthorization` отдельно показывает сохраняемую
EdgeAuth binding, отзыв только agent role и отключение helper; это не неявное исключение.

До первого managed/adopted plan wizard содержит обязательный шаг «Зафиксировать базовое
состояние» (CaptureBaseline): observed full-tree digest, проверенный backup, base revision
и bundle. Для пустого managed-узла выбирается квалифицированная закрытая bootstrap revision
с bundle; поля base не могут быть пустыми. CaptureBaseline не объявляется применением
целевой конфигурации; до его завершения создание первого apply plan блокируется.

### Adoption существующего Nginx

Перед применением UI показывает full-tree inventory, unknown includes/modules и backup evidence.
Оператор явно согласует AGP-owned include/service paths и сохраняемые сторонние файлы.
Validation охватывает целое дерево; конфликт listeners/auth bypass/unsupported ABI блокирует adoption.
«Принять как есть» без compiler mapping не разрешено; можно сохранить inventory и выйти.
Drift отображает изменённый файл/digest и варианты «Импортировать в draft» / «Подготовить
восстановление управляемой ревизии». Автоматическое затирание ручной правки запрещено.
Emergency local change имеет owner/reason/time и reconciliation, не становится центральной истиной.

## 6. Создание Gateway и публикация приложения

Wizard проходит одинаковые серверные проверки при создании и редактировании.

| Шаг | Поля/решения | Validation и результат |
| --- | --- | --- |
| Размещение | Site, exact candidates/selector preview, Gateway, ownership, component profile | Доступный scope, совместимые capabilities; окончательные node IDs фиксируются plan |
| Адрес | Display name/category, public hostname/path | Нормализованный hostname/path, уникальность, reserved origins, preview внешнего URL |
| TLS | CertificateVersion/reference, expiry, SAN, issuer | Никаких guessed paths; chain/key match и допустимая validity |
| Upstream | Scheme/host/port/path, TLS trust/SNI, bounded timeout/profile | URL без credential, egress/SSRF validation, проверка по pinned IP/Host/SNI |
| Доступ | AccessPolicy, groups/CIDR, обязательный MFA/прочие supported constraints | Показ effective allow/deny и provenance, запрет unknown group/reference |
| WAF | Версия политики/ruleset, detection/blocking, узкие исключения | Compatibility, expires/reason/owner, предупреждение detection ≠ blocking |
| Проверка | Схема, refs/collisions, effective policy, test request simulation | Simulation помечена как simulation, не как live authorization evidence |
| План | Полный diff, targets, probes, waves, base/target/artifacts/secrets, expiry | Создать DeploymentPlan; save не выполняет reload |

Upstream test не показывает response body/cookies и не позволяет сканировать запрещённые сети.
WAF/policy defaults раскрываются до сохранения; отключённая функция не подменяется более слабым default.
При создании отсутствующих refs можно открыть вложенный editor и вернуться в исходный draft;
публикация зависимого route блокируется до validation и фиксации exact versions.
Delete/disable route показывает влияние на каталог, текущие соединения и denial behavior.
В standalone manual финальный экран даёт read-only recommendations с отдельными prerequisites,
backup/test/reload инструкциями из профиля; кнопка не утверждает, что удалённый Nginx изменён.

## 7. Черновики, YAML/JSON и согласованность

У draft один server ID, base revision и CAS version. Вкладки «Форма», «YAML», «JSON»,
«Эффективная конфигурация», «Изменения» отображают одну модель, не независимые копии.
Новый input проходит bounded parse/validation; неизвестные поля, duplicate keys/anchors/tags
или inline secret отклоняются с путём/строкой/столбцом. Ошибка не вызывает частичный save.
Пока текст не разобран, переход в форму предлагает исправить или явно отбросить текст;
не «чинит» его незаметным удалением неподдерживаемых свойств.

Autosave сохраняет только server draft, показывает «Сохраняется»/«Сохранено …»/«Не сохранено»;
автопубликации нет. Секреты не сохраняются в localStorage, URL или crash telemetry.
Закрытие страницы с неподтверждёнными правками предупреждает о потере; save failure не выглядит success.
Повторный API save использует прежний idempotency key только для того же payload.
Изменение validated/approved draft создаёт новую редакцию и сбрасывает зависимые проверки;
published содержимое не редактируется — пользователь создаёт successor draft.

### CAS conflict

При конфликте UI сохраняет локальный input и открывает сравнение «база / ваша правка /
актуальная версия». Для каждого поля доступно выбрать значение; security weakening выделяется.
Silent last-write-wins и кнопка force overwrite без новой проверки запрещены.
После merge создаётся draft от актуальной базы, заново выполняются validation/plan/approval.
Если объект был удалён/вне scope, данные не пересоздаются автоматически; разрешён redacted export draft.

### Effective configuration и наследование

Модель предусматривает global → Site → NodeGroup → Node → Route/Resource.
Только поддерживаемые typed fields участвуют в inheritance; Region пока grouping/label Site,
а не дополнительный неописанный writer. Для каждого поля: итоговое значение, источник,
ID/версия, override и policy floor. Peer NodeGroups с конфликтующим значением одного priority
дают validation error; порядок получения данных не становится приоритетом.
Security floor нельзя ослабить дочерним override. Если поле не поддерживает inheritance,
UI показывает явное значение, а не воображаемое «унаследовано».
Provenance/compiled effective policy фиксируются с revision/compiler generation,
чтобы исторический review не менялся при следующем редактировании родителя.

## 8. Diff, approval и неизменяемый plan

Diff по умолчанию семантический: добавлены/удалены маршруты, изменён доступ/TLS/WAF,
компоненты/версии и scope. Raw canonical/native diff доступен в details; secrets redacted.
Показать исходную/целевую revisions и compiler digests, exact node IDs/count,
capability/base digests, secret versions, auth generation/minimum deny sequence,
canary/waves/probes, expiry и recovery authorization. Рассматриваются те же данные,
которые подпишет и применит backend; таблица не строится повторно из live labels.

Approval queue: автор/время, причина, риск/область, validation evidence и dependencies.
Approver может утвердить либо отклонить с причиной; не правит plan «на месте».
Независимость обязательна для опасного изменения, включая блокировку WAF, ослабление auth,
смену trust anchors, расширение egress и массовое component upgrade. Step-up не заменяет второе лицо.
Если нет второго уполномоченного лица, UI объясняет блокировку и позволяет сохранить draft;
скрытого обхода «я владелец» не существует. Аварийная процедура определяется security/runbook.

ConfigRevision: `draft → validated → approved → published → superseded`.
DeploymentPlan: `draft → validated → approved`; дополнительно `expired|superseded`.
Это canonical API значения; UI переводит их на русский, сохраняя machine value в details.
`published` означает утверждённую desired revision, а не успех всех узлов.
`approved` plan не означает apply; доступ Deployer, freshness и preconditions проверяются при start.
При изменении targets/base/capabilities/secret versions UI предлагает новый plan и diff;
нельзя «обновить» подписанное содержимое или продлить expiry без нового approval.

## 9. Выполнение, пауза, отмена и восстановление

Страница Rollout содержит immutable summary, canary/waves, список узлов и live progress.
Canonical states: `queued|running|paused|cancelling|succeeded|failed|cancelled|recovery_required`.
У каждого NodeDeployment показываются base/target/applied, checkpoint, attempt ID,
last observed time, probe evidence и authorized next action.
Canonical states: `pending|prepared|validated|activating|reloading|verifying|succeeded|rejected|failed|rollback_pending|rolled_back|recovery_required`.
Нельзя объединять `rolled_back` и `succeeded` в зелёное «всё применилось».

«Приостановить» останавливает dispatch новых заданий; уже начатый локальный safe transition
может завершаться. «Отменить» прекращает будущие dispatch, но не отменяет bytes, уже записанные
на узле, и не запускает rollback всех успешных узлов. UI показывает количество pending/in-flight/done.
Resume использует прежний approved plan только при действительных preconditions/expiry;
иначе нужен новый plan. Авторизованный bounded recovery начатой операции описан протоколом.

При сетевом timeout: «Подтверждение результата не получено; состояние уточняется».
Это представление недостоверного наблюдения, а не новый terminal enum и не автоматический `failed`.
UI получает существующий operation/task result по ID, не отправляет новую apply команду.
Повтор действия создаёт effect только по серверной idempotency policy; generic «повторить всё» отсутствует.
При stale event stream показать reconnect и last sequence; после reconnect выполнить reconciliation snapshot.

Recovery screen:

- Какой узел/ресурс затронут, последний durable checkpoint и доказанный actual digest.
- Какие generation/deny floor актуальны и почему безопасный доступ сейчас открыт/закрыт.
- Last healthy revision с предупреждением о проверке текущих secrets/auth/compatibility.
- Разрешённый ограниченный recovery, его targets/probes/maintenance и необходимые права.
- Redacted diagnostics, correlation/task IDs и ссылка на [runbook](operations.md).

Rollback — новая операция/plan с current deny, новым sequence и проверенными dependencies.
Если recovery не может доказать защищённое состояние, интерфейс оставляет
`recovery_required`; не предлагает отключить auth/WAF ради зелёного dashboard.

## 10. Состояние системы и dashboard

Обзор фильтруется текущим scope. Верхние показатели — ссылки на соответствующий filtered list.
Не использовать единственный «12/12 работают»: независимые оси важнее общей декоративной оценки.

| Ось | Что показывает UI | Что из этого не следует |
| --- | --- | --- |
| Connectivity | `online|offline|unknown`, last heartbeat/допустимый freshness | Online не означает живой Nginx/Auth/WAF |
| Config | Desired/applied revision/generation, drift и last observed digest | Equal revision не заменяет live probes |
| Nginx | Observed service/worker generation, probes и time | Process running не доказывает корректный route |
| Auth | Reachability, authoritative freshness, deny/security floor | CP API доступен не значит Auth ready |
| WAF | Installed/policy mode/engine health, detection/blocking evidence | Detection не означает блокировку |
| Maintenance | Owner/reason/начало/конец/affected alerts | Maintenance не отменяет access control |
| Delivery | Audit/spool/notification backlog, high-water/loss counters | Очередь принята не значит уведомление доставлено |

Список проблем сортируется по последствиям: protected access unavailable, recovery required,
недостоверная deny freshness, expiry, failed rollout, drift, degraded capacity.
У каждой проблемы: источник, observation time, affected objects, next action и owner.
Maintenance подавляет разрешённые повторы alerts, но не уничтожает событие/состояние.
CP-only outage и общий процесс/PG outage отображаются разными зависимостями;
dashboard не обещает продолжение auth, если тот размещён в отказавшем процессе.
Charts не строят фиктивную непрерывную линию через отсутствие наблюдений.

## 11. Identity, MFA, группы и сессии

User detail: status/issuer/source, access groups, management roles/scopes,
MFA readiness, invites, active sessions и redacted timeline. Пароль/readable token не показывается.
Форма создания предлагает invite, не требует придумать пользователю постоянный пароль.
Invite показывает expiry/delivery status/resend/revoke; resend отзывает/версионирует прежний
token по policy, а не оставляет бесконечное количество активных ссылок.
Человек видит ясные истечение/replay ошибки и безопасный путь запросить новый invite.
Account linking OIDC делается проверенным flow; одинаковый email сам по себе не объединяет аккаунты.

MFA setup: защищённый показ secret/QR → проверка первого кода → recovery codes один раз → подтверждение.
Recovery требует policy/step-up/аудит; help не предлагает отправить пароль/code администратору.
Break-glass: локальный вход с MFA, отдельная причина/alert, видимый ограниченный scope;
недоступный IdP не является основанием обойти MFA/authorization обычным пользователем.
Блокировка пользователя показывает отзыв активных сессий и влияние на доступ; результат
объявляется применённым после durable deny acknowledgement, не только закрытия modal.
Для уже открытых WebSocket/stream UI показывает отдельно «новые запросы запрещены»
и состояние завершения существующих соединений согласно квалифицированной drain policy.
Для удаления/сброса пароля target superadmin проверяется отдельное object-level permission.

Access groups и management role bindings показаны раздельно с пояснением различия.
Справочник permissions справа/в details: readable name, machine ID, что разрешено и scope.
Нельзя выдать право/роль выше собственного delegation ceiling через membership edit.
Сессии: свои — пользователю, чужие — только с правом; IP/User-Agent редактируются по privacy policy.
«Выйти» локально отзывает соответствующую сессию. «Выйти на всех устройствах» объясняет
охват portal/gateway/management sessions; logout из внешнего IdP не обещается без поддержки flow.

### Переход к приложению

Gateway получает отдельную host-only session через выделенный EdgeAuth callback/handoff,
а не management cookie и не agent. Проверяются state/PKCE, exact redirect, audience и short-lived
одноразовый code; центральный Auth поддерживает локальный и OIDC login без заявления,
что AGP является полноценным OIDC issuer. Management использует отдельный client/session.
Handoff code имеет TTL 60 s и привязку к gateway identity/callback; UI не выводит его
в error details/history/analytics и не использует как upstream application credential.
Если redeem consume состоялся, а ответ с raw session потерян, показать «Вход не завершён,
повторите вход» и начать новый flow. Повтор прежнего code не возвращает секрет и не создаёт
вторую сессию незаметно; общий retry механизм management operations здесь неприменим.
При истечении session пользователь возвращается в login и затем только на проверенный target;
произвольный return URL/open redirect запрещён. Отказ ресурсу не раскрывает его существование.

## 12. WAF, сертификаты, секреты и дистрибутивы

### Групповое управление WAF

По решению владельца от 2026-11-17 основной экран «WAF и защита» открывает **зоны**.
Верхние вкладки: «Зоны / Политики / Срабатывания / Исключения». [Контракт зон](waf-zones.md)
группирует логические Gateway одной Site, а не физические hosts, NodeGroups или DNS.
Текущий Angular per-resource prototype демонстрирует редактор WAF; групповой сценарий
ниже — TARGET для реализации, а не уже работающая функция макета.

Список зон показывает Site, владельца, желаемую policy revision/режим и отдельно
наблюдаемое применение. Счётчики различают Gateway, Routes и уникальные узлы. Состояния:
«Применено и проверено», «Требует проверки», «Частично применено», «Ожидает узел»,
«Конфликт состава», «Требует назначения», «Неизвестно»; каждое имеет время/источник.
Одна строка «Применено» недопустима, если часть потребителей остаётся на старой версии.
Список и фильтры серверные, pagination сохраняет контекст, объёмы ограничены scope.

Карточка зоны:

- «Состав»: условие отбора, зафиксированные участники, новые кандидаты, выходящие
  участники и конфликты; AND между метками написано явно, preview объясняет каждое совпадение.
- «Защита»: базовая exact policy revision, желаемый режим, обязательные locks/minimum
  и effective значения; ссылки `latest` нет.
- «Отклонения»: приложения с производной политикой, база, локальные исключения,
  состояние rebase и необходимые решения при конфликте.
- «Срабатывания»: агрегаты зоны с переходом к конкретному Gateway/Route; фильтр
  времени/версии использует контекст события, не сегодняшний состав зоны.
- «История и применение»: immutable change, зафиксированный охват, site plans,
  waves, подтверждённые версии и причины partial/unknown.

Основные действия: «Изменить политику зоны», «Проверить влияние», «Подготовить обновление».
Инженер меняет общие параметры один раз. Команда «Выбрать все результаты» запрашивает
у сервера immutable выборку с digest и числом целей; она не означает только текущую
страницу и не разрешает будущие совпадения фильтра. Если scope недостаточен для полного
эффекта, сервер отклоняет действие; интерфейс не скрывает частичный пропуск.

Wizard создания/редактирования задаёт Site, название, владельца, exact policy revision,
режим и один вариант состава: ID Gateway, AND-label selector либо явная Site default.
На Gateway допускается одна primary zone. Два совпадения показывают обе зоны и причины;
разрешение конфликта требуется до публикации. Нет совпадений — видимый onboarding либо
явный default. Кнопки «продолжить без защиты» нет. Изменение защищённых labels открывает
тот же impact preview; обычное право редактировать metadata не позволяет выйти из зоны.

Preview показывает base revisions/digests, вошедшие/вышедшие/сохранившиеся приложения,
смену policy/mode, локальные исключения/rebase, Routes и точные узлы. Для выходящих
Gateway и retire зоны требуется явное replacement assignment под CAS. Старое назначение
действует до safe apply замены; удаление зоны не превращается в `off` или молчаливый fallback.
Операция, ослабляющая режим, PL, threshold, исключения или выборку/default/labels,
помечается опасной по итоговому эффекту и требует независимого approval/step-up.

До подтверждения показывается полный diff **node bundle**, в том числе соседние
приложения и изменения других зон на общих узлах. Их нельзя скрыть за счётчиком выбранной
зоны. Canary перечисляет узлы и все обслуживаемые ими приложения; это не переключение
процента трафика одного сервиса. Одна команда нескольких Site создаёт отдельные планы:
«Площадка A — подтверждено; B — ожидает узел», без ложной общей атомарности.
Новые совпадения после approval предлагаются следующим change. Новый узел получает
защиту через отдельное placement/resolution и safe apply, без расширения старого плана.

Failure UI показывает последний достоверный observed state и разрешённые действия:
query/reconcile, новый plan или проверенный rollback. Retry не означает blind reapply;
rollback не возрождает expired exceptions, устаревший security floor или чужую конфигурацию.

### Индивидуальная защита приложения

Из списка/карточки Gateway есть переход к его эффективной защите: основная зона,
источник base policy, exact effective revision, желаемый и observed mode, профильные
locks/minimum, route consumers, исключения и последний probe result. Формулировка:
«Наследуется из зоны …; база …; локальных изменений …». Кнопка «Изменить только этот
сервис» создаёт производную immutable политику и видимое отклонение, не меняет соседей.
Полная WAF-политика назначается Gateway; route exception не обещает отдельную полную
политику маршрута. Mode материализуется в `Gateway.spec.waf`, остальные параметры —
в versioned `WafPolicy.spec`. При обновлении базы совместимые локальные изменения
переносятся с проверкой, конфликты показываются инженеру, старая база видима как отставание.

В редакторе вкладки «Политика / Срабатывания / Исключения» сохраняются. Действующая
ревизия и draft подписаны отдельно. PL 1–4 и inbound/outbound thresholds имеют справку:
PL ↑ добавляет проверки/false positives, threshold ↑ уменьшает число блокировок;
score не является вероятностью атаки. События показывают время, Gateway/Route, policy
revision/режим в момент события, правила и безопасные metadata. «Не заблокировано WAF»
не означает успешный запрос к приложению. Raw body/query/header/cookie values не выводятся.

«Создать исключение» открывает draft для конкретного Route, rule IDs и literal field
name, с owner/reason/reviewAt/expiresAt и явной временной зоной. Событие предварительно
заполняет только безопасные metadata. Нет zone-wide wildcard, global rule-disable или
редактирования оригинального CRS. Preview раскрывает каждую конечную цель, даже если
исключения подготовлены массово. AD/MFA и Central Auth не отключаются режимом detection.
Истекающее исключение предупреждает владельца; scheduler заранее готовит removal
revision и safe apply. Если после `expiresAt` active generation всё ещё содержит
expired exception, Central Auth закрывает только затронутые Routes до применённого
удаления либо нового approved extension. UI показывает причину и следующий шаг;
не утверждает, что native CRS правило удалилось по часам. Split-WAF screen показывает
оба узла/защищённый hop и bypass probe; неподдержанный profile блокируется.

Certificate detail: SAN/issuer/serial/fingerprint/validity/public chain, consumers и rotation status.
Private keys не скачиваются через обычный UI; если требуется export, он имеет отдельную policy.
Secret detail показывает metadata/version/key reference/recipients; secret значения masked.
Rotation создаёт draft с новой immutable version, consumers/dual-trust period и plan.
Revoke показывает blast radius и порядок emergency deny; просроченный secret не заменяется старым.

Repository: trusted/untrusted/quarantine, exact profile/OS/arch/digests, signature/TUF validation,
expiry/security floor, SBOM/license/dependency closure. «Загружено» отличается от «проверено».
Offline import показывает authority/trust metadata, version floor и замкнутость зависимостей.
NoInternet profile не требует внешней сети; airgap — отдельный квалифицированный import workflow.
Update wizard различает config/CRS/agent/server/Nginx+ABI modules и объясняет service impact.
Компонент, требующий неподдержанного protocol/OS/arch, не предлагается как «рекомендуемое обновление».

## 13. Аудит, activity, alerts и каналы

Audit filters: time range/timezone, actor/target/site, action/outcome, revision/plan/rollout/task IDs.
Details: readable summary, exact redacted evidence, before/after digests, correlation ID и источник.
История показывает административное действие отдельно от попыток agent и auth traffic events.
«Пользователь открыл ресурс» означает подтверждённое событие AGP, не полный мониторинг
всех действий внутри приложения. Retry/дубликаты не выдаются за повторное действие человека.
IP/имена/query и access к sensitive fields зависят от policy; raw request bodies отсутствуют.
CSV/JSON export имеет permission, scope, audit, размер/expiry и статус async generation;
воспроизводимый export сохраняет range/filter, а скачивание повторно проверяет права.

Alerts: severity/owner/ack/resolved, affected objects, latest observation и связанные events.
Ack означает принятие в работу, не устранение причины; mute имеет owner/reason/end time.
Notification channel: type, redacted destination, secret reference, scope/routing/quiet window,
retry/dedup policy. Тест канала не принимает arbitrary network URL вне egress allowlist.
SSRF validation выполняется сервером и при подключении, включая DNS/redirect changes.
Показать enqueue/delivered/failed/retrying evidence; «сохранить webhook» не равно доставить alert.
Telegram adapter позднего этапа подчиняется той же redaction/egress/secret policy.

## 14. Портал, downloads и помощь

Каталог строится только по разрешённым enabled ресурсам; поиск/категории не раскрывают
запрещённые имена или их количество. Search: имя/описание/категория, clearing filters и empty state.
Карточка: readable name, краткое описание/категория, внешний gateway URL при необходимости;
не internal address, не персональная authorization policy. На наборе 100 разрешённых карточек
QA проверяет поиск, keyboard navigation и возврат со страницы отказа.
Forbidden и unknown route получают одинаковую понятную страницу с «Вернуться в портал»;
пользователь не видит raw upstream error/stack trace или диагностический scanner.

«Скачать» раскрывается сверху как отдельный раздел/спойлер. Файл имеет административное
название, description, filename/type/size, SHA-256 и дату; ссылка не заменяет display name.
Public downloads явно помечены публичными, не содержат private keys/внутреннюю конфигурацию.
Uploads не исполняются на management origin; unsupported type/size/quarantine объясняются.
Публикация/скрытие/download metadata — отдельные административные действия с audit.
Portal branding использует safe text/approved image formats, без arbitrary HTML/script.
Ссылки помощи/support проверяются; страница для пользователя объясняет вход, доступ,
файлы, MFA/recovery и обращение в поддержку, не показывает infrastructure/root команды.

## 15. Ошибки и нестандартные состояния

| Состояние | Обязательное поведение |
| --- | --- |
| Loading | Skeleton/progress с accessible status, без преждевременного «нет данных» |
| Empty | Причина отсутствия/фильтр и доступное следующее действие |
| No permission | Не раскрывать чужой объект; для известного scope объяснить нужное право |
| Validation error | Field path и понятное исправление; текущий draft сохранён |
| CAS conflict | Base/yours/current merge, новый validation/plan |
| Network timeout | Сохранить operation ID, reconcile existing result; не повторять side effect вслепую |
| Stale/unknown | Observation time, причина недостоверности, обновить/read-only support action |
| Failed apply | Реальный checkpoint/probe error и bounded recovery, не общий «ошибка сервера» |
| Recovery required | Блок новой mutation, сохранённое evidence и runbook/operator contact |
| Session expired | Безопасный re-login; восстановление несекретного draft после проверки прав |
| DR/PITR | Новый authority epoch: восстановленные sessions/invites/enrollment/recovery codes недействительны; явно предложить re-login/reissue или supervised credential reset |
| Rate limited | Retry guidance сервера; кнопка предотвращает retry storm |
| Unsupported | Конкретная capability/version и совместимый следующий путь |

Каждая серверная ошибка: стабильный code из API, readable message, optional field errors,
request/correlation ID. В публичном экране показываются только безопасные данные;
developer/support details доступны уполномоченным, редактированы и имеют copy/export.
Нельзя выводить SQL, stack trace, certificate key, auth header или необработанный upstream body.
Toast не единственное место для важной ошибки; сообщение остаётся на экране до действия.
После DR/PITR credentials ниже независимого floor отображаются отключёнными до supervised
reset; исторический password/MFA state не обходит этот запрет. Для подтверждённо актуальных
credentials достаточно нового входа. Экран восстановления объясняет причину без раскрытия
credential version постороннему.

## 16. Доступность и проверка удобства

Цель — [WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/), включая полный путь пользователя,
wizard, approval и recovery. Это требование TARGET, не текущий сертификат соответствия.
Семантические headings/landmarks, labels и доступные имена controls обязательны.
Весь основной flow выполняется клавиатурой; focus видим, не перекрыт, возвращается
к исходному control после modal. Dialog удерживает focus и корректно закрывается.
Ошибки/status changes объявляются screen reader без частого прерывания live updates.
Цвет сопровождается icon/text; увеличение текста/reflow не скрывает destructive controls.
Поддержать paste/password managers и доступную MFA, не требовать тестов на запоминание.
Таблицы имеют корректные headers; для большой ширины — details/адаптивное представление.
Анимация умеренна, respects reduced motion; опасное действие не привязано к drag gesture.

QA проверяет клавиатуру/screen reader/zoom и automated accessibility scan; ручная проверка
нужна даже при нуле automated issues. Usability trial включает новичка-оператора и обычного
пользователя: они понимают scope/текущее состояние/последствие и восстанавливаются после ошибки.
Численные time-to-complete/ошибки фиксируются на пилоте, затем становятся целями;
здесь не объявлены вымышленные результаты исследования.

## 17. Сквозные UX-приёмки

1. **Приложение:** editor создаёт route из формы, открывает тот же draft в YAML,
   исправляет collision, approver рассматривает exact diff, deployer запускает canary.
   Успех означает реальные allowed/denied probes и applied generation; failed probe ведёт
   к проверенному rollback/recovery с сохранением current deny, а не к отключению WAF.
2. **Гонка правок:** два editor меняют один draft; второй получает conflict без потери
   ввода, делает merge и новый plan. Изменение labels после approval не добавляет третий узел.
3. **Потеря связи:** start request timeout, UI находит тот же rollout по operation ID;
   offline canary не становится failed без evidence и не запускает следующую wave.
4. **Пауза/отмена:** оператор видит pending/in-flight/succeeded, pause останавливает dispatch,
   cancel показывает фактически изменённые узлы; возврат успешных узлов требует нового plan.
5. **Identity:** invite → MFA → каталог → gateway session → block/revoke; доступ закрывается
   и после config rollback. Обычный identity administrator не сбрасывает пароль superadmin.
6. **Adoption:** неизвестный include блокирует apply; оператор читает evidence и оставляет
   inventory-only. После явного mapping/backup успешно управляется только ownership subset.
7. **Manual:** администратор получает рекомендации, видит prerequisites и применяет их
   по runbook самостоятельно; UI честно показывает отсутствие agent-applied evidence.
8. **Accessibility/портал:** пользователь без мыши находит разрешённый сервис среди 100,
   открывает в новой вкладке, возвращается после одинакового deny и завершает сессию.

Каждый сценарий выполняется через API с теми же ограничениями. Результат фиксируется
в [testing](testing.md), а оставшиеся ограничения — в release evidence и актуальном runbook.
