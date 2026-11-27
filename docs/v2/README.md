# AGP v2 — комплект для разработки

Дата редакции: 2026-11-17. Статус: **итоговое ТЗ / принятые владельцем требования TARGET**.
Владелец подтвердил WAF Zones для группового управления 1000+ сервисами; Angular, AD,
2FA и одноразовые email-коды остаются обязательными. Документы описывают результат
разработки, а не уже поставленные возможности или production-ready состояние.
Инфраструктурные параметры, численные SLO и выпуск требуют квалификации на целевой площадке.
Текущая реализация S0/S1, native base WAF, inventory/trusted zones, approved agent identity и локальная проверка синтаксиса
отмечена отдельно в [AS-IS разработки](development.md); принятый TARGET этим не сокращается.

## Как пользоваться комплектом

| Читатель / задача | Документы |
| --- | --- |
| Владелец продукта и вся команда | [ТЗ](requirements.md), [сценарии и интерфейс](ux.md) |
| UI / frontend | [Angular, единый стиль и контекстная справка](ui-design.md), [интерактивный пример](../../web/console-prototype/README.md) |
| Backend / архитектор | [Архитектура](architecture.md), [модель данных](data-model.md), [reference SQL](database.sql) |
| Backend / frontend / агент | [Протоколы и типы](protocols.md), [OpenAPI](api/openapi.yaml), [JSON Schema](schemas/gateway.schema.json) |
| WAF / 1000+ сервисов | [WAF Zones](waf-zones.md), [REQ-14/24](requirements.md), [ADR-V2-09](architecture.md), [приёмка](testing.md) |
| Identity / корпоративный вход | [AD, 2FA и одноразовые коды](identity.md), [AD schema](schemas/directory-provider.schema.json), [flow schema](schemas/identity-flow.schema.json) |
| Безопасность | [Границы доверия, права, identity и supply chain](security.md) |
| DevOps / сопровождение | [Эксплуатация и восстановление](operations.md) |
| Разработчики / руководитель команды | [Принципы и порядок разработки](development.md), [проверки и приёмка](testing.md) |

Начинать чтение: ТЗ → UX → архитектура → типы/БД → security → план разработки.
При реализации конкретного домена читать весь его вертикальный сценарий: экран → API → транзакция → агент → receipt → аудит → отказ/восстановление.
Примеры и [проверяемые fixtures](fixtures/cases.json) предназначены для contract tests; фиктивные подписи и hashes не являются release-артефактами.

## Источники и границы нормативности

1. Действующий [ADR 0001](../adr/0001-single-node-mvp.md) и [план v1.1](../v1.1-plan.md) сохраняют статус для существующего AGP.
2. Исходники baseline `6eac09e62b2de2730d8d3fc194fdb5827b21ccc2` — AS-IS. Структура `docs/v2/` — TARGET, пока не реализованный.
3. [Предыдущий эскиз v2](../distributed-platform.md) — история проработки. Его упрощённые примеры заменены подробными контрактами этого комплекта.
4. ТЗ определяет принятое поведение, UX — сценарии; schemas/OpenAPI — wire-структуру; SQL/data-model — хранение и инварианты. Решения ADR-V2-08/09 приняты владельцем; статусы других ADR указаны отдельно.
5. Schema validation не заменяет semantic/security validation, проверку подписей, реальный Nginx/WAF и тесты восстановления.
6. При расхождении исправить все затронутые контракты до merge. Нельзя молча выбрать удобный текст или объявить фактический код новым требованием.

## Зафиксированные проектные варианты

| Вопрос | Вариант для первой реализации | Ограничение |
| --- | --- | --- |
| Архитектура | Go-монорепозиторий, модульный server; отдельные agent/helper и EdgeAuth | Модули в одном процессе не получают независимости от его падения |
| Управление | UI, CLI, YAML/JSON через единый revision service | Git — канал предложений, не второй writer |
| Web UI | Angular + TypeScript, общие компоненты/tokens, «?» и внутренний manual | Прототип использует demo fixtures; v1 frontend мигрируется отдельно |
| Авторизация | Central Auth, server-side sessions, актуальное членство и независимый deny journal | Нет cached/offline allow в первой версии |
| БД | Один PostgreSQL writer, reference SQL рассчитан на PostgreSQL 17+ | SQLite сохраняется для v1/dev и локального служебного состояния; не fleet control store |
| Пилот | Ubuntu 24.04 amd64; существующий Nginx подключается только после qualification | Другие ОС/arch и точный ABI tuple не обещаны без испытаний |
| WAF | ModSecurity + CRS, Site-scoped WAF Zones с общей exact policy revision и режимом; производные политики для локальных exceptions | Одна primary zone; frozen membership/plan, profile locks/floor, полный node diff; native qualification впереди |
| Масштаб | `pilot-500` v1alpha1 сохраняется; `fleet-10k` v1alpha2 — до 10 000 Gateway/100 000 Routes/64 MiB snapshot | Envelope не является SLO; 500 nodes/plan, 1000 Routes/Gateway и task caps остаются |
| Обновления | TUF и подписанный release manifest, проверенный dependency closure | Конфигурация, компоненты, CRS и server обновляются раздельно |
| Управление браузером | Раздельные management/login/app origins; host-only cookies | Общая cookie Domain и общий admin/app origin запрещены в новом управляемом профиле |
| Identity / SSO | Обязательны AD DS (защищённый LDAP и корпоративная OIDC-федерация), local accounts, 2FA и одноразовые коды | Email подтверждает адрес/шаг setup или recovery; не снимает обязательную 2FA. AGP не OIDC issuer |
| Организации | Одна организация, права по global/site/node_group/node/resource | SaaS multi-tenancy — отдельная граница изоляции, не простое поле tenant_id |

Это основа реализации итогового ТЗ. Выбор зон, Angular и обязательной identity-функциональности
подтверждён владельцем; версии инфраструктуры остаются qualification defaults.
Документы не меняют действующие установки без отдельной миграции.
Локальные пользователи, каталог ресурсов, public downloads, help, аудит и русский интерфейс сохраняются как продуктовые функции.
Привилегированное применение включается только явным opt-in после MFA/RBAC, квалификации helper и стендовой проверки.
Реализованы компоненты согласования/исполнения/отката, экран управления и явное
подключение server → agent → root helper. На 2026-11-26 runtime включается только через
`AGP_EXECUTION_CONFIG`, защищённые installation pins, независимую подпись materialization
и подтверждённую helper базу. [Порядок подключения](operations.md#реализованный-execution-runtime--as-is-на-2026-11-26)
не заменяет квалификацию настоящего root/Nginx/cgroup/reboot и приёмку перед публикацией.

## Что можно начинать сразу

- S0: устранение подтверждённых baseline-пробелов и disposable PostgreSQL CI.
- S1: bounded parser, типы, canonical model, immutable revisions, preview/compiler и CAS.
- WAF authoring: zones/selectors, immutable resolutions, производные политики/rebase, scope/floor checks и серверный массовый preview без root apply.
- Fleet model: v1alpha2 decoder/encoder, cumulative limits и capacity datasets; переход на native WAF/массовое применение только по S4/S5.
- Параллельно: реализация контрактных fixtures, прототипы UX, миграционный read-only import.
- S2: продолжение identity/agent после реализованных inventory, approved agent enrollment и локальной проверки синтаксиса; remote helper, AD/IdP/SMTP и installer требуют отдельной квалификации.

Условия перехода к root apply, WAF blocking, fleet и HA перечислены в [плане](development.md) и [приёмке](testing.md).
Regional Auth, relay, split-WAF и airgap не потеряны: их требования и ограничения описаны, но включение требует отдельной квалификации.

## Что ещё зависит от владельца / площадки

| Область | Что нужно получить | До какого этапа |
| --- | --- | --- |
| Identity / доверие | AD/DC/GC, OU и mappings, IdP-профиль, corporate CA/secret store/SMTP, владельцы ролей и recovery | AD/MFA/email qualification до корпоративного S2; до любых root-действий |
| Нагрузка / доступность | Узлы, ресурсы, RPS, concurrent sessions/streams, retention, SLO, RPO/RTO | До capacity sizing и HA-приёмки |
| Инфраструктура | ОС/ABI inventory, сеть/LB/DNS, хранилище/CI runner, maintenance windows, offline transfer policy | До установки соответствующего профиля |

Отсутствие этих фактов не блокирует parser, БД, mocks и контрактные тесты. Оно блокирует обещания производительности и внедрение в production.
Не требуется повторно утверждать каждую мелкую правку документа; новое решение владельца необходимо при изменении принятого поведения или границы доверия.

## Проверка самого комплекта

```bash
python3 -m venv /tmp/agp-doc-validation
/tmp/agp-doc-validation/bin/pip install -r docs/v2/validation-requirements.txt
/tmp/agp-doc-validation/bin/python docs/v2/verify.py
```

Проверяются ссылки, форматы schemas/OpenAPI, положительные/отрицательные fixtures и синтаксис reference SQL.
Реальная PostgreSQL/reference DDL, Nginx, WAF, browser flows и fault injection имеют отдельные сценарии в testing.md.
Ни одна команда в этом разделе не развёртывает AGP и не применяет SQL к production.
