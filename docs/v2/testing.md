# Проверки, приёмка и трассировка требований

Статус: план приёмки итогового TARGET ТЗ, редакция 2026-11-17.
WAF Zones приняты владельцем. Основные разделы задают план; фактические границы
первого пакета S0 выделены отдельно ниже.
Требования: [ТЗ](requirements.md). Форматы: [protocols](protocols.md), [reference DB](database.sql).

## 1. Уровни доказательств

| Уровень | Что доказывает | Чего не доказывает |
| --- | --- | --- |
| Документ/Schema | Структура, согласованные типы и примеры | Корректность криптографии/БД/runtime |
| Unit/property/fuzz | Локальные правила и инварианты | Сетевые ACL, browser isolation, native WAF |
| Disposable PG | SQL constraints, транзакции, concurrency, migrations | HA/PITR и настоящий отказ носителя |
| Native integration | Реальные Nginx/helper/WAF/PKI/IdP flows | Production SLO на неподтверждённом железе |
| Fault/DR/security | Partition, reboot, expiry, restore, replay | Абсолютную защиту от всех классов угроз |
| Acceptance/load | Измеренный результат в квалифицированном профиле | Универсальное SLA для любого числа узлов/приложений |

Каждый отчёт содержит commit, OS/arch, component/profile digests, topology, seed/corpus, время, реальные assertions и ограничения.
SKIP не является PASS: отсутствующий PostgreSQL/IdP/native WAF явно отмечается и блокирует соответствующий milestone.

## 2. Contract suite этого комплекта

```bash
python3 docs/v2/verify.py
```

Нужны зависимости из [validation-requirements.txt](validation-requirements.txt), лучше в отдельном venv.
Проверка локальная: schemas, format/range, примеры, negative fixtures, ссылки, OpenAPI и SQL parser; внешняя сеть не требуется.
Custom formats `agp-uint63`, `agp-cidr`, `agp-hostname`, `agp-upstream`, `agp-path`,
`agp-relativepath` обязательны для соответствующих application validators/SDK.
Синтаксически валидная фиктивная подпись release должна не пройти crypto verification; этот тест относится к runtime suite.
Изменение examples требует пересчёта canonical/semantic fixtures, а не подгонки ожидаемого результата под произвольную реализацию.

### Текущий пакет S0: команды и границы

Основной entrypoint pilot — [scripts/test-s0-full.sh](../../scripts/test-s0-full.sh),
а не один `go test ./...`. Требуются непривилегированный Linux user, разрешённые
loopback sockets/UDS, native PostgreSQL 17+ (`initdb`, `pg_ctl`, `postgres`, `psql`,
`createdb`, `pg_dump`, `pg_restore`), Go 1.27.4+, `rg`, OpenSSL, Node.js 24+/npm,
установленные зависимости `web/console-prototype`, Playwright и Chromium.
Nginx 1.30.8 с [required modules](../../scripts/nginx-toolchain.env) должен иметь
[проверенное происхождение](../nginx-recommendations.md). Внешние test tools не
являются runtime dependencies AGP; script не устанавливает системные пакеты.
Standalone browser fixtures используют `AGP_TEST_PLAYWRIGHT_MODULE` и
`AGP_TEST_CHROMIUM_BIN`; full entrypoint сам переносит в последнюю значение
`AGP_TEST_CHROMIUM_EXECUTABLE`. Укажите реальные paths к уже установленным инструментам.

Из корня репозитория, с реальными путями к уже подготовленным инструментам:

```bash
GOFLAGS=-buildvcs=false \
AGP_TEST_PG_BINDIR=/path/to/postgresql/bin \
AGP_TEST_NGINX_BIN=/path/to/verified/nginx \
AGP_TEST_PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
AGP_TEST_CHROMIUM_EXECUTABLE=/path/to/chromium \
bash scripts/test-s0-full.sh
```

`-buildvcs=false` нужен в этом workspace без Git metadata. `GO` выбирает Go binary,
`AGP_TEST_NODE_BIN` — browser runner; `npm`/Angular также должны видеть поддерживаемый
Node через `PATH`. Suite сначала собирает реальные Angular auth/directory assets и запускает восемь
Chromium API fixtures: auth, directory, email, OIDC auth/management, lifecycle auth/management и roles. Эти fixtures
используют синтетические API; последующие Go processes собираются из тех же исходников. Она создаёт **два** отдельных PG clusters с private
Unix sockets, очищает входные production DSN/libpq variables и генерирует отдельную
synthetic PKI/credentials. Journal, CP, два EdgeAuth, Nginx HTTPS/HTTP2 и Chromium —
реальные процессы. Self-signed test PKI принимается только disposable browser context,
это не production TLS trust qualification.

Native journal/identity/restore и Nginx части требуют обязательных PASS без SKIP;
отсутствие `TestJournalNativeTransactions`, `TestJournalNativeMTLSAndLostResponse`,
`TestNativeControlPlaneRestore` либо трёх native Nginx tests останавливает проверку.
Restore test выполняет настоящий `pg_dump`/`pg_restore` старой CP БД и выдерживает
реальный quarantine; он не подменяет время mock clock. Удаление обоих clusters входит
в trap; SIGKILL/сбой runner требуют внешней уборки, при cleanup failure каталог сохраняется.
[PG harness и его ограничения](../postgresql.md#integration-tests).

После package-wide timeout расширенных identity/configuration suites harness перечисляет
все их top-level Test/Example/Fuzz names тем же race build и исполняет последовательные
группы по шесть с anchored `-run` и лимитом 10 минут на группу. Исключений по ручному
списку нет; новые tests включаются автоматически, zero-SKIP и mandatory PASS markers
сохраняются. Предыдущие timeout-прогоны не считаются PASS. Следующий full run прошёл
backend batches, но завершился exit 1 на native sandbox guard; подробности ниже.

Для локализации регрессии сохраняются отдельные команды:

```bash
go test -race -count=1 ./...
go vet ./...
GOFLAGS=-race AGP_TEST_PG_BINDIR=/path/to/postgresql/bin make test-postgres
GOFLAGS=-race AGP_TEST_NGINX_BIN=/path/to/verified/nginx make test-nginx
npm --prefix web/console-prototype run test:auth:browser
```

Без DSN/native binary обычный Go-прогон может содержать SKIP и не заменяет общий
entrypoint. Frontend fixture проверяет UI states, а не реальную journal/PKI/DB связку.
Старый `make test-management-browser` остаётся отдельной S0.2a SQLite-регрессией.

Подтверждённые компонентные результаты: journal native PG/TLS — concurrent idempotency,
lost response, roles и tamper; настоящий CP restore — старые password/TOTP seed/recovery
отклонены после quarantine 92 s; `tests/e2e/s0-full.mjs` — семь реальных HTTPS/browser
групп с четырьмя origins, MFA/step-up/recovery, двумя EdgeAuth и journal outage.
Angular fixture содержит 11 сценариев. **Единый `scripts/test-s0-full.sh` после
финальных review исправлений завершился PASS 2026-11-18**: mandatory native части
без SKIP и все семь HTTPS/browser групп. Полная Go-регрессия `go test -p 1 -race
-count=1 ./...` и `go vet ./...` также PASS. Проверены Go 1.26.8 и Node.js 24.21.0.
Contract suite комплекта S0 проверила 17 schemas, 61 fixtures и 124 OpenAPI operations.
Историческое `.deb` provenance Nginx 1.30.6 и оригинальный NLGate logo сохранены;
[asset/UI sources](../../web/console-prototype/README.md). Исторические результаты
1.30.6/1.30.7 не квалифицируют текущий harness pin 1.30.8.

Qualification ограничена single-node pilot и фактически выбранными binaries/profile.
Native/browser harness пока подключаются к PG как `initdb` owner с superuser;
least-privileged runtime grants не квалифицированы. Требование TARGET к runtime role
без superuser сохраняется и требует отдельной проверки.
Native PG 18.6 не доказывает PostgreSQL 17, WAF/AD/OIDC/SMTP, HA/fleet, общий identity
lifecycle или любой произвольный restore. Совместный откат CP+journal, pre-009 writers
и transaction-pooling вне проверенной restore модели. Ветка/commit этого workspace
не подтверждены. [Статус S0](development.md#текущий-срез-s0--as-is-на-2026-11-18).

### Текущий пакет S1: проверки

[scripts/test-s1-full.sh](../../scripts/test-s1-full.sh) строит реальные config assets,
включает S1 в тот же disposable двух-cluster S0 lab и требует
`TestConfigurationPostgres` без SKIP. Параметры окружения/PKI/toolchain и ограничения
runtime DB role — как в S0 выше. Команда из корня с теми же реальными путями:

```bash
GOFLAGS=-buildvcs=false \
AGP_TEST_PG_BINDIR=/path/to/postgresql/bin \
AGP_TEST_NGINX_BIN=/path/to/verified/nginx \
AGP_TEST_PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
AGP_TEST_CHROMIUM_EXECUTABLE=/path/to/chromium \
bash scripts/test-s1-full.sh
```

Локальные проверки frontend: `npm --prefix web/console-prototype run typecheck:config`
и `npm --prefix web/console-prototype run test:config:browser`. Fixture не заменяет
[реальный S1 browser сценарий](../../tests/e2e/s1-browser.mjs).
Единый `scripts/test-s1-full.sh` завершился PASS 2026-11-18: mandatory native без
SKIP, PG S1 (восемь групп), mTLS/lease/restore, три native Nginx tests, семь S0 и
четыре S1 browser группы, offline cutover/restart, legacy write `409` и существующий
live access `200`. Cleanup обоих clusters подтверждён. Frontend fixture (семь групп),
typecheck/build, проверка embedded assets с `-race` и `go vet ./...` также PASS. Это приёмка
authoring pilot в указанном lab, не всего TARGET.
Backend выполнил synthetic datasets 1000/5000/10 000 Gateways через полный
parser/resolver/compiler; это не fleet/WAF/SLO qualification. YAML проверяется только
в документированном safe subset, не как general YAML. WAF zone helper/resolver и
materialization primitives пока покрыты unit fixtures; zone authoring/publication API
не открывается без независимого approval workflow. Всегда `deployable=false` для
operator-declared catalog, даже при `authoringValid=true`.
Текущая contract suite проверила 18 schemas, 71 fixtures и 134 OpenAPI operations:
добавлены 10 authoring операций, typed draft/report/compiler DTO и operator catalog.
Positive preview fixtures получены actual parser/compiler с явно synthetic build pin;
negative fixtures отвергают qualification claims, deployable node/report и потерю pins.
Reference DB harness проверил 36 boundary/constraint assertions, включая все четыре
цели `validation_reports` и zone FK; он не квалифицирует runtime migrations или БД role.
[AS-IS и pins](development.md#текущий-срез-s1--authoring-pilot),
[активация/rollback](../operations.md#s1-authoring-pilot).

### S1b: проверки нового пакета

Единый `scripts/test-s1-full.sh` с S1b завершился PASS 2026-11-18 на финальных
исходниках: mandatory native без SKIP/FAIL, включая `TestScopedManagementPostgres`,
`TestScopedAuthoringPostgres`, `TestZoneAuthoringPostgres`, `TestAuthoringReviewsPostgres`,
restore, mTLS/lease, datasets 1000/5000/10 000 и три native Nginx tests. Реальный
Chromium прошёл семь S0, четыре S1 и три S1b группы плюс offline canonical cutover:
scoped MFA session, независимый draft review, scoped Gateway CAS и fail-closed publication.
Native проверки выполнены с `-race`; targeted SQLite regressions и `go vet` также PASS.
Zone tests покрывают receiving closure, SQL/JSON time round-trip, frozen pins, CAS и stale reviews.
Entry point и инструменты — те же, что для S1 выше; результаты не квалифицируют
native WAF publication или весь TARGET.

Новый contract сохраняет закрытые TARGET `WafZoneRevision`/`WafZoneSummary`:
pilot list использует отдельный authoring route/DTO, preview не проходит как trusted
`WafZoneResolution`, review — как publication approval. Least-privileged runtime
grants, native WAF publication и полный TARGET по-прежнему не квалифицированы.
Contract suite S1b проверила 18 schemas, 79 fixtures и 140 OpenAPI operations;
новые DTO fixtures содержат synthetic IDs/pins, не runtime qualification evidence.

### Component repository и native WAF: принятый AS-IS

Исторический прогон 2026-11-18 использовал Go 1.26.8 при module minimum 1.25.0
(`go-tuf/v2` 2.4.2). Текущий checkout требует Go 1.27.4+.
Signature/source checks завершились PASS. Build-stage upstream suite дала
5071 PASS, **52 SKIP**, 0 FAIL при отключённых optional features; это не zero-SKIP
прогон и не mandatory AGP native corpus. Base-policy SQLite/PG 18.6 suite с `-race`
прошла девять групп; unit qualifier fixtures не доказывают native provider trust.
Реальный Ubuntu 24 native corpus завершился **25/25 mandatory PASS, zero SKIP**
для tuple Nginx 1.30.7 / connector 1.0.4 / libModSecurity 3.0.17 / CRS 4.30.0.
Broad `go test -race -short ./...` также PASS. **Единый `scripts/test-waf-full.sh`
завершился PASS 2026-11-18**: mandatory native/PG/restore, девять policy групп,
реальный provider и три native Nginx группы без SKIP; все 18 browser групп
(S0=7, S1=4, S1b=3, WAF=3, cutover=1). Подтверждены signed test repository → real
CLI import → UI/native `202` validation → независимые read+approve-only approval/
publication, exact retry и отсутствие изменения Configuration head/live state.
CAS tamper закрывает replay publication; восстановление exact bytes возвращает
проверяемый current proof. Это приёмка ограниченного AS-IS, не всего TARGET.

Общий entry point — [scripts/test-waf-full.sh](../../scripts/test-waf-full.sh).
Он собирает реальные binaries, запускает mandatory native corpus, выбирает Nginx
из того же Ubuntu 24 bundle через комплектный loader и добавляет repository/provider/
policy и реальные HTTPS/browser проверки к S0/S1/S1b. Требуются PASS без SKIP для
`TestWafPoliciesPostgres` и `TestNativeWAFProvider`. С теми же prerequisites выше:

```bash
GOFLAGS=-buildvcs=false \
AGP_TEST_WAF_BUNDLE=/path/to/prepared/ubuntu24-bundle \
AGP_TEST_PG_BINDIR=/path/to/postgresql/bin \
AGP_TEST_PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
AGP_TEST_CHROMIUM_EXECUTABLE=/path/to/chromium \
bash scripts/test-waf-full.sh
```

Renderer, evidence, fixture repository и browser scratch размещаются в private
`<repo>/.waf.XXXXXX`; script задаёт `AGP_TEST_BROWSER_TMPDIR` для JS runner.
Для этих данных нужны свободное место и user quota на workspace filesystem:
свободный `df` сам по себе не подтверждает доступную quota. Полный путь EdgeAuth
Unix socket держите не длиннее 99 bytes, учитывая вложенный browser directory.
Два disposable PG clusters остаются в `/tmp/agp-s0-full.XXXXXX`; проверка DSN
с `/tmp` prefix и независимости clusters сохраняется. Browser scratch override
не разрешает production DSN. Trap удаляет workspace scratch; PG cleanup и его
ограничения — в описании S0 выше.

Response blocking через CRS 959100 подтверждён как TCP close до HTTP status line:
EOF и ноль response bytes, без HTTP 403; upstream уже получил запрос. Body-limit
reject вернул HTTP 403. Partial body или HTTP 200 в blocking режиме означают FAIL.

Команды и prerequisites закреплены в [native WAF harness](../../tests/native-waf/README.md).
Для квалификации нужен настоящий `agpctl waf-render`, не `--reference-renderer`;
mandatory corpus не допускает SKIP. Ubuntu 24.04 userspace собирается через PRoot;
подтверждён host kernel `7.0.0-38-generic`. PRoot не квалифицирует clean VM/offline install
или иной platform tuple. Raw report сам по себе не разрешает публикацию: подписанная
closure должна связывать profile/evidence, corpus/harness, Go renderer, raw report и SBOM.
Production provider исполняет exact `RendererDigest` artifact из этой closure через
тот же Ubuntu 24 loader; embedded renderer текущего binary не заменяет этот artifact.
Новые schemas/DTO fixtures — структурные synthetic примеры, не подписанный repository
и не native evidence. Existing release manifest остаётся Ubuntu 24.04 amd64 TARGET.

### Read-only agent и trusted zones: проверки

Entrypoint — [scripts/test-fleet-full.sh](../../scripts/test-fleet-full.sh). Он расширяет
WAF/S1/S0 suite реальным `agp-agent`, отдельным TLS 1.3 ingress, mandatory inventory/
trusted-zone PG tests и Angular/browser workflow. Prerequisites WAF suite сохраняются;
дополнительно нужны GnuPG, `dpkg-deb`, tar, Python 3, PRoot с разрешённым unprivileged
ptrace и подготовленный signed Ubuntu userspace descriptor. Подготовка из корня:

```bash
bash scripts/prepare-waf-native.sh --agent-lab-only \
  --ubuntu-keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg \
  --work /absolute/new-private-agent-lab \
  --output /absolute/new-agent-userspace.json
```

Каталоги/descriptor должны быть новыми; не используйте paths других прогонов.
Подготовка загружает locked Ubuntu 24.04.5 image и PRoot packages, проверяет точные
SHA-256 и Ubuntu image signer. `--offline` требует заранее заполненного locked
downloads cache в новом lab; существующий lab не перезаписывается. Это не установка
пакетов или сервисов на host. Lab использует настоящий Ubuntu 24 userland/ABI и
**общий host kernel**, а не VM: проверенный kernel — `7.0.0-38-generic` на Ubuntu 26 host.
Нельзя выдавать этот профиль за clean Ubuntu 24 VM или произвольный kernel.

```bash
GOFLAGS=-buildvcs=false \
AGP_TEST_AGENT_USERSPACE=/absolute/new-agent-userspace.json \
AGP_TEST_WAF_BUNDLE=/path/to/prepared/ubuntu24-bundle \
AGP_TEST_PG_BINDIR=/path/to/postgresql/bin \
AGP_TEST_PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
AGP_TEST_CHROMIUM_EXECUTABLE=/path/to/chromium \
bash scripts/test-fleet-full.sh
```

Помимо mandatory WAF corpus и прежних native/browser проверок entrypoint требует
PASS без SKIP для `TestInventoryPostgres`, `TestInventoryRealMTLSClient`,
`TestEdgeKeepAliveRejectsExpiredClientCertificate` и `TestTrustedZonesPostgres`.
Сценарий связывает реальные read-only observations и signed profile с independent
zone approval/publication, stable heartbeat, registry/runtime-file drift rejection
и атомарной full ConfigRevision materialization; exact retry не двигает head повторно.
Он также проверяет admin-only inventory, role/listener isolation и запрет ручного
обхода pinned WAF bindings. Исходники сценария —
[tests/e2e/fleet-browser.mjs](../../tests/e2e/fleet-browser.mjs).

Подтверждённые компонентные результаты 2026-11-19: inventory suite с `-race` на
PostgreSQL 18.6/real TLS, TTL/replay/expiry и monotonic receipts — PASS; trusted-zone
SQLite (девять групп) и vet — PASS; Angular typecheck/build, прежние UI fixtures и
новые девять fleet fixture групп — PASS. Fixtures используют synthetic inputs и
не заменяют полный entrypoint.

Итоговая приёмка 2026-11-19: `bash scripts/test-fleet-full.sh` — **PASS**. Пройдены
25 mandatory native WAF cases без SKIP, 23 Nginx baseline regression groups, три
native Nginx isolation cases, весь обязательный PostgreSQL/race набор (в том числе
11 групп `TestTrustedZonesPostgres`) и 23 реальные HTTPS/browser группы. Настоящий
агент собирает Ubuntu 24/host-kernel metadata и хеши защищённой копии runtime;
heartbeat с теми же facts оставляет frozen permit пригодным для materialization,
а registry/runtime drift блокирует запись без продвижения head. Точный повтор
materialization возвращает прежний результат; ручная смена pinned WAF binding
отклоняется. Полный `go test -short -p 2 ./...` и `go vet ./...` также PASS; optional
native SKIP короткого набора не засчитываются вместо mandatory full harness.
Security/architecture review findings по ancestor permissions и переносу устаревшего
provenance исправлены и подтверждены независимым адресным review. Release/deploy
этим прогоном не выполнялись.
Проверка 2026-11-19 не включала issuer/enrollment или локальный syntax CLI; их
последующая приёмка описана ниже. Remote helper/apply, active/applied/healthy state,
least-privileged DB grants, clean VM/offline install и fleet SLO остаются вне этого среза.

### Agent identity и локальный syntax probe: проверки

Entrypoint [scripts/test-node-full.sh](../../scripts/test-node-full.sh) включает весь
`test-fleet-full.sh` и реальный owner-approved identity/browser/local CLI сценарий.
Prerequisites, qualified Ubuntu 24 userspace descriptor, signed WAF bundle, PostgreSQL,
Playwright и Chromium совпадают с fleet командой выше; замените последнюю строку на
`bash scripts/test-node-full.sh`. Сценарий —
[tests/e2e/node-identity-browser.mjs](../../tests/e2e/node-identity-browser.mjs).
При ограниченной пользовательской квоте `/tmp` задайте
`AGP_TEST_LOCAL_SYNTAX_TMPDIR` на существующий private каталог на диске с достаточным
местом (0700, защищённые ancestors). Он используется isolated native worker и
node identity/browser lab; проверки владельца, permissions и symlink сохраняются.
На стенде 2026-11-20 промежуточный native worker был отклонён с
`renderer_stage_failed_quota (errno=122)`: действовала пользовательская `usrquota`
tmpfs, которую свободное место в `df` не отражает. Тот же worker на защищённом
дисковом scratch завершился PASS; проверку не заменяли synthetic результатом.

Проверяются отдельный issuer с durable ledger, первый token/metadata-only retry,
локальный keygen, pending CSR, fingerprint approval, выдача/точный повтор, renewal
новым ключом, issuer restart и journal revoke обеих generations. Проверяется admin-only
UI/API, listener/role isolation и недоступность agent execution через browser API.
Локальный CLI на настоящем Ubuntu 24 userland проверяет signed native syntax,
durable exact retry и sequence zero без remote task/apply/health утверждений.

Компонентные результаты 2026-11-20: race core, SQLite/real TLS identity tests и
native syntax detection/blocking — PASS; Angular typecheck/build, девять node UI
fixture групп и прежние fleet/config fixture suites — PASS. Fixtures используют
synthetic metadata и не заменяют native acceptance. Итог единого полного entrypoint
2026-11-20 — **PASS**: `bash scripts/test-node-full.sh` завершился успешно;
mandatory native PostgreSQL/race, real mTLS и restore проверки прошли без SKIP.
Реальный browser прошёл owner-approved enrollment, точную выдачу/повтор, Ubuntu 24
local CLI detection/blocking, durable retry, renewal новым ключом и отзыв обеих
generations до/после issuer restart. На данном стенде isolated native worker и
node lab использовали защищённый дисковый `AGP_TEST_LOCAL_SYNTAX_TMPDIR`.
Release/deploy этим прогоном не выполнялись.

Даже полный PASS этого среза не доказывает remote NodeBundle sandbox/helper,
apply/reload/rollback/health, AD/SMTP integration, clean VM/offline installer,
least-privileged DB grants, HA/DR или fleet SLO. PRoot lab разделяет host kernel
`7.0.0-38-generic`; это ограничение прежней native qualification сохраняется.

### Основа допуска helper: проверки

Проверки `internal/helper` относятся к admission/store foundation на Linux, без
привилегированного исполнителя. Из корня checkout с Go 1.27.4+:

```bash
bash scripts/test-helper-foundation.sh
```

На 2026-11-24 entrypoint завершился **PASS** с `-race`, без SKIP: закрытый decoder,
разделение подписей/ключей, current-head/challenge/pin отрицательные сценарии,
обязательная база, независимые epochs и точный UInt63 high-water, exact replay после
restart/expiry/offline, конкуренция и подмена store paths. Fault injection и реальные
аварии дочерних процессов покрыли write/file fsync/rename/directory fsync; после
publication intent и high-water сохраняются вместе, поздняя ошибка блокирует handle.
`go vet ./internal/helper` — PASS. Независимые architecture/security review завершены
для этой границы; замечание о длительности fsync уточнено в контракте.
Общая Go-регрессия `go test -short -count=1 ./...` и `go vet ./...` — PASS;
short-набор не заменяет прежний native PostgreSQL/browser pipeline.
Прежний `test-node-full.sh` PASS выше сохраняет свою область и не подтверждает helper apply.
Эти проверки foundation сами по себе не заменяют plan/CP интеграцию ниже, проверку
owned tree, kernel sandbox, functional apply/rollback probes и реальный reboot/power-loss
pilot на выбранной ОС/filesystem.

### Подписанный Plan и planning review: проверки

Из корня checkout с Go 1.27.4+, native PostgreSQL 17+ и browser tooling:

```bash
bash scripts/test-plans-full.sh
```

Нужны `AGP_TEST_PG_BINDIR`, `AGP_TEST_PLAYWRIGHT_MODULE` и
`AGP_TEST_CHROMIUM_BIN`; для native libraries используются переменные уже
подготовленного тестового окружения. Entrypoint требует unprivileged user, создаёт
disposable PostgreSQL с private Unix socket, не использует production DSN и удаляет
стенд при завершении. Ошибка cleanup считается ошибкой проверки.

Набор включает race-проверки full Plan v1/v2, 50 000 resolved inputs, canonical
sets/NFC/UInt63, tamper каждого pin и purpose separation; SQLite и PostgreSQL
proposal/review/signature lifecycle; helper admission/store; HTTP guards и
protected runtime signing key loader. Проверяются independent global approval,
full-node effects, stale scope/session/floors/dependencies до exact replay,
immutable SQL rows, historical artifacts после удаления автора/reviewer,
optional signer 503 и real Ed25519 verification полного review envelope.
Angular fixtures дополнительно покрывают create/review exact-key retry,
stale/expiry/MFA, admin без approve, пагинацию, escaped DOM, CSP и download
planning-only artifact. Fixtures с подменённым browser transport не доказывают
live Angular → PostgreSQL → trusted inventory/native WAF интеграцию.

На 2026-11-24 единый `test-plans-full.sh` завершился PASS: domain/helper,
SQLite и native PostgreSQL 18 lifecycle с `-race` без обязательных SKIP,
signature/HTTP boundary, protected-key loader, Angular typecheck/build и все
четыре browser suites. Финальное исправление обработки stale inventory отдельно
проверено с `-race` на SQLite и PostgreSQL: история сохраняется с `current=false`,
а outage остаётся ошибкой. Общие `go test -short -count=1 ./...` и `go vet ./...`
на стабильном финальном исходнике — PASS. Замечания независимых security и
architecture review исправлены и закрыты. Документальная проверка — PASS:
27 schemas, 117 fixture cases, 157 OpenAPI operations, SQL/Markdown/REQ traceability.
Синтетические signatures/digests в документационных fixtures не являются crypto
acceptance; её обеспечивают отдельные Go-проверки выше в пределах этого среза.

Срез не подтверждает live execution authorizer, actual CaptureBaseline, owned-tree
verification, sandbox, helper/apply/reload/rollback/probes, clean VM/installer,
AD/SMTP либо HA/DR. Runtime CP выдаёт только `planning_review` с
`deployable=false`/`noExecution=true`; helper admission receipt остаётся историческим
и не разрешает execution. Буквальный Plan wire пока не закрывает compiler/release/
tuple approval closure. Готовность полного приложения к публикации не достигнута.

### Read-only owned tree: проверки

Срез `internal/ownedtree`, `cmd/agp-owned-tree` и opt-in helper gate проверяется на
Linux из checkout с Go 1.27.4+:

```bash
bash scripts/test-owned-tree.sh
```

Entrypoint включает race-проверки reader/CLI, существующий helper foundation,
CLI help/отказ непривилегированному caller и scoped `go vet`. Он предназначен для
непривилегированного test user с защищённой ancestry и kernel mount-ID support;
тестовые деревья принадлежат этому effective UID. Это не запуск root helper на
production tree и не реальная mount/namespace qualification.

На 2026-11-25 единый `test-owned-tree.sh` завершился **PASS** без обязательных SKIP:
9 domain и 5 CLI test groups с `-race`, полный helper foundation с четырьмя новыми
owned-tree admission groups, process-crash checks, binary build/help/non-root
boundary и scoped `go vet`. Проверены closed manifest/parent closure/bounds,
detached metadata, hashes, links/special files/modes, pinned paths и drift,
cancel/close, protected manifest loader и fail-closed mount proof.
Отрицательные mount-ID сценарии используют детерминированную fault injection,
а не привилегированный bind-mount. Helper recheck после current authorization
отвергает drift без расхода sequence; historical replay работает после закрытия
verifier и offline. Независимые architecture/security review — PASS; замечание о
раздельных источниках root path и trusted digest исправлено в контракте.
Общие `go test -short -count=1 ./...` и `go vet ./...` на финальном исходнике — PASS;
short-набор не заменяет native PostgreSQL/browser qualification предыдущих срезов.

Документальная проверка — PASS: 29 schemas, 130 fixture cases, 157 OpenAPI
operations, SQL/Markdown/REQ traceability. Дополнительно проверены CLI help и
локальные ссылки README/операторской инструкции. Fixtures проверяют закрытую
metadata-only форму manifest и
observation, traversal/link/mode/type ошибки и невозможность присвоить
`runtimeValidated=true`, execution purpose или file bytes. Вымышленные inode/mount
IDs в примерах не подтверждают реальный filesystem. Ранее выполненные suites выше
сохраняют собственную область и не доказывают новый этап.

Даже PASS этого набора не квалифицирует runtime CaptureBaseline, effective Nginx
includes, actual active configuration, durable backup, generic ownership lifecycle
после apply, kernel sandbox, executor/rollback, root-only operational deployment,
реальные привилегированные mount attacks или reboot/power-loss. Observation
остаётся unsigned/local-clock `noExecution=true`, `runtimeValidated=false`;
baseline blockers CP и готовность полного продукта к публикации не закрываются.

### Native sandbox и bootstrap candidate: проверки

Текущий checkout требует Go 1.27.4+. Для Linux namespace suite нужны отдельно
проверенные root-owned bubblewrap executable/digest, kernel user namespaces,
возможность создать PID/network/mount isolation и непривилегированный test user:

```bash
AGP_TEST_BWRAP_BIN=/path/to/qualified/bwrap \
AGP_TEST_BWRAP_DIGEST='sha256:<verified-digest>' \
bash scripts/test-native-sandbox.sh
```

Замените placeholder digest до запуска. На 2026-11-25 actual namespace suite
завершилась **PASS**, восемь групп: filesystem/network/identity isolation,
timeout/output/normal-exit descendant cleanup, tool/input rejection, process limits
и snapshot drift. Это запуск от непривилегированного UID на Ubuntu 26.04/kernel
`7.0.0-38-generic`, не qualification root bridge или Ubuntu 24.04 host.
`ownedtree` Capture отдельно проверен с `-race`: exact bytes/metadata copies,
отказ JSON, cancel/drift без partial snapshot и concurrent close/read.

CLI unit/race, build и scoped vet — **PASS**. Первоначальный непривилегированный
запуск root bridge завершился явным отказом, а не PASS. На отдельном стенде
2026-11-26 `scripts/test-bootstrap-candidate.sh` прошёл с настоящими real/effective
root, установленными nonroot execution UID/GID и проверенным bubblewrap; границы
результата описаны в [приёмке на сервере](#приёмка-на-сервере--2026-11-26).
Root identity fixtures не заменяют эту проверку. CLI help проверяется без загрузки installation inputs:

```bash
go run ./cmd/agp-bootstrap-candidate -h
```

Actual signed bootstrap `nginx -t` на tuple 1.30.8 с финальным execution-identity
profile и проверкой journal drift завершился **PASS** (21.805 s). Проверка использовала
exact current signed closure и непривилегированный namespace worker; root-only adapter
на настоящем root этим не квалифицирован. Candidate parser проверен на отказ при
unknown fields, digest mismatch, нулевые execution IDs и попытки установить
`baselineVerified`, `activeConfigurationVerified` или `deployable`. Даже успешный
syntax candidate не доказывает active master/generation, durable backup, baseline
promotion, helper apply/reload, recovery или готовность публикации.

### Direct AD и provider: проверки

На 2026-11-25 PASS подтверждены provider lifecycle на SQLite и native PG 18.6,
TLS LDAP wire, HTTP/runtime boundaries, Angular production build и Chromium fixture.
Шесть SQLite auth групп проверили direct AD primary → TOTP → session/handoff/EdgeAuth,
stable explicit link, непривилегированный JIT, live groups и invalidation provider/link
versions. Общий identity race-прогон с PostgreSQL также завершился PASS; последующие
review fixes требуют повторной проверки затронутых guards.

Локальный срез воспроизводится из checkout с Go 1.27.4+, loopback sockets и browser
tooling из prerequisites S0:

```bash
go test -race -count=1 ./internal/identity \
  -run '^(TestDirectoryProvidersSQLite|TestDirectoryAuthenticationSQLite|TestADConnectorTLSWire|TestDirectoryProviderClosedCodec|TestDirectoryProtectedFileSecrets)$'
go test -race -count=1 ./internal/httpapi -run '^TestDirectoryManagementHTTPContractAndBoundaries$'
go test -race -count=1 ./internal/runtime -run '^TestDirectoryConnectorInstallationBoundary$'
npm --prefix web/console-prototype run test:directory:browser
```

PG tests требуют отдельную disposable БД по существующему identity test contract;
отсутствующий DSN означает SKIP. LDAP wire test использует реальный TLS/BER transport
и синтетический сервер, browser fixture — synthetic API. Они не доказывают семантику
настоящего AD DS, AD-backed OIDC, SMTP delivery или production network policy.
Historical author/reviewer proofs и final management guards прошли независимый
review. Дополнительные 24 TLS LDAP → identity → WAF configuration сценария на SQLite
и native PG с `-race` завершились PASS (97.116 s), scoped vet — PASS. Проверены valid
AD author/reviewer, disabled account, revoked link, provider/link floors и TLS outage.
LDAP fixture использует реальный TLS/BER, но синтетические directory data и WAF qualifier;
она не квалифицирует AD DS или native WAF. Отдельные portal CRUD/guard проверки на обеих
БД завершились PASS (45.146 s). Полный корпоративный identity milestone не закрыт.

### Контакты, email-коды и SMTP: проверки

На 2026-11-25 backend suite на SQLite/native PG 18.6, включая реальный DNS/TLS/SMTP
transport с синтетическими серверами, завершилась PASS с `-race` (117.346 s).
После review fixes повторены затронутые тесты (25.578 s, PASS). Проверены separate
primary/MFA timestamps, masked own read, recent factors на запись, contact CAS/floor,
purpose/source/epoch binding, одноразовое consume, общий счётчик неверных кодов,
resend/target budgets, cancel/expiry и конкурентные workers. Interrupted/unknown send
не запускается заново; утраченные при restart RAM keys не оживают из сохранённой DB.

HTTP tests подтвердили login/management origin, CSRF, CAS, fresh primary и отсутствие
session/handoff после email proof. Последующий общий HTTP boundary regression завершился
PASS (41.614 s). Protected runtime configuration и
purpose-bound immutable secretfiles проверены отдельно. Независимый review не оставил
блокирующих замечаний в этом срезе. SMTP wire tests проверяют verified implicit TLS/
StartTLS, hostname/CA, all-answer DNS allowlist, bounds/cancel и ambiguous DATA без retry.
SMTP final `250` не является доказательством доставки в mailbox.

Из checkout с Go 1.27.4+ и разрешёнными loopback sockets. В текущем workspace
независимо загруженный module cache проверен через `go mod verify`; для воспроизведения
нужен тот же проверенный cache либо новая загрузка с официальной checksum verification:

```bash
export GOMODCACHE="$PWD/.tmp-cycle-verified-mod"
go mod download
go mod verify
go test -race -count=1 ./internal/identity -run '^Test(Email|PrimaryAuthenticationTime)'
go test -race -count=1 ./internal/mailtransport ./internal/secretfiles ./internal/runtime
go test -race -count=1 ./internal/httpapi -run '^TestEmail'
```

PostgreSQL cases требуют отдельную disposable БД через `AGP_TEST_IDENTITY_DSN` либо
`AGP_TEST_POSTGRES_DSN`; без DSN они дают SKIP. Команды выше не создают внешние ресурсы
и не заменяют full entrypoint. Angular UI `/auth-ui/contacts` реализован; 23 email
Chromium fixture groups и 12 auth regression groups прошли PASS. Проверены masked list,
CAS/step-up, lost-response GET reconciliation, no automatic POST retry и отсутствие
secret browser storage. Fixtures не доказывают реальную доставку; invitations/password
setup и supervised recovery добавлены отдельным stage-срезом ниже. Воспроизведение UI после сборки assets:

```bash
npm --prefix web/console-prototype run build:auth
npm --prefix web/console-prototype run test:email:browser
npm --prefix web/console-prototype run test:auth:browser
```

### Invitations, activation и recovery: проверки

Для текущего integration stage подтверждены отдельные paired SQLite/native PG race suites:
invite — PASS (200.184 s) и scoped vet; restore cases — PASS (34.811 s); actual HTTP
boundaries — PASS (34.725 s). Recovery source suite — PASS (200.372 s) до последней
детерминизации legacy guard. Последующий paired recovery/TLS LDAP wire прогон завершился
PASS (136.586 s), scoped vet — PASS: пять wire cases на каждой БД, включая stale AD
proof при materialization, abort restrictive-only и явный новый retry. Local TLS/BER
server не является настоящим корпоративным AD DS.

Новый narrow race-прогон TTL cleanup и final enrollment deadline на обеих БД завершился
PASS (24.391 s), vet — PASS. Проверено удаление anonymous expired flows и отказ при
потере deadline до final factor publication. Проверки запрещённого повторного primary
после spent floor не трактуются как регрессия: это ожидаемый fail-closed результат. Отдельный paired
username race-прогон завершился PASS (8.996 s), vet — PASS: ASCII/Greek/İ canonical
metadata, idempotent canonical retry и отказ invalid UTF-8 до lowercase conversion.

Семь локальных Chromium fixtures дали 128 PASS groups: lifecycle management 22,
lifecycle auth 21 и прежние auth/directory/email/OIDC suites 12/22/23/12/16. Это API
fixtures с реальными production assets, не корпоративный browser/AD/SMTP стенд.
После revocation/canonical-receipt правок отдельная lifecycle management suite завершилась
PASS: 26 groups; typecheck/build — exit 0. Проверены очистка stale access/data/ticket
при deny, Greek/İ lowercase receipt и exact retry с неизменными body/key. Предыдущая
попытка с преждевременным DOM assertion была FAIL; успешный повтор проверял конкретное
enabled-state ожидание без увеличения timeout. После интеграции все backend batches
общего прогона и семь Chromium fixtures прошли PASS; общий exit 1 из-за native sandbox
описан ниже. Compile всех stage packages и
`go vet ./...` завершились exit 0 до последних узких UI/username правок; их область
дополняют отдельные targeted checks, а не общий fullcombined PASS.

При тех же Go/module-cache/socket prerequisites и отдельной disposable PG БД:

```bash
go test -race -count=1 ./internal/identity \
  -run '^Test(Invitations|InvitationBoundaries|InvitationRestore|InvitationSMTPWire|InvitationADIssuer|RecoveryLifecycle|RecoveryFault|RecoveryDirectoryWire|LifecycleEphemeralCleanup|LifecyclePendingUsername|EnrollmentFinalDeadline)'
go test -race -count=1 ./internal/httpapi -run '^Test(InitialActivationHTTP|LifecycleInventoryHTTP|PasswordResetHTTP)'
npm --prefix web/console-prototype run build:auth
npm --prefix web/console-prototype run build:directory
npm --prefix web/console-prototype run test:lifecycle:auth:browser
npm --prefix web/console-prototype run test:lifecycle:management:browser
```

Проверьте актуальные top-level test names через `go test -list . ./internal/identity`;
PostgreSQL cases без `AGP_TEST_IDENTITY_DSN`/`AGP_TEST_POSTGRES_DSN` дают SKIP, что не
закрывает native acceptance. Fixture delivery/unknown, one-time reservation, saved email
OTP, sessionless completion, current factor pin, actor/target/delegation, approvals,
restore/spent guard и cleanup не заменяют реальные корпоративные ресурсы.

Предыдущий общий main fullfinal3 завершился exit 1 из-за отсутствующего userspace input
после native/backend этапов. Отдельная continuation затем прошла native WAF 25 cases
и реальные HTTPS/browser/mTLS/Edge/recovery/S1/WAF/Fleet/Node пути в Ubuntu 24 userspace.
Это отдельное подтверждение прежнего main-среза; оно не превращает неудавшийся исходный
запуск в PASS и не квалифицирует VM/GA.

После интеграции lifecycle новый полный запуск (`.tmp-cycle-lifecycle-full-final.log`)
прошёл все backend batches и семь Chromium API fixtures, но завершился **exit 1**:
`TestActualSignedNativeSyntax` отклонил `workspace_parent_rejected`. В файловом представлении того запуска `/`
принадлежит UID 65534, а native sandbox требует root/current-user ownership всех
предков private workspace. Guard сохранён; произвольный private child не устраняет
неподходящий ancestor. Это незакрытая native host acceptance, а не разрешение ослабить
проверку владельцев. В разрешённом тестовом runner обычный UID 1001 видит `/` и `/tmp`
принадлежащими root; системные owners/permissions для этого не менялись.

Отдельное продолжение (`.tmp-cycle-lifecycle-browser-continuation.log`) на тех же 477
runtime source files завершилось **exit 0**: native WAF 25/25, три Nginx integration
группы, реальные HTTPS/browser, EdgeAuth/mTLS, restore, S1/WAF/Fleet/Node. Оба disposable
PG clusters удалены. Signed node CLI проверен в Ubuntu 24 userspace под PRoot; этот
результат не закрывает root bridge или полноценную Ubuntu 24 VM qualification.

Последующий отдельный штатный native run (`.tmp-cycle-lifecycle-native-host-plain.log`)
в разрешённом runner завершился **exit 0**: 25/25 mandatory WAF cases без SKIP и
`TestActualSignedNativeSyntax` (24.679 s). Использованы те же frozen main sources,
проверки владельцев и production process limits. Native test запускается без `-race`,
как предписано full harness: race/concurrency проверяются отдельно из-за virtual-address
shadow mappings. Временные файлы удалены. Этот отдельный PASS закрывает локальную
native-проверку; исходный combined run сохраняет exit 1. Root bridge на тот момент
оставался OPEN; его последующая приёмка описана ниже. VM/GA этим не подтверждены.

### AD-backed OIDC: проверки

На 2026-11-25 transport suite с endpoint pins, PKCE, signed JWT, claims/algorithms,
key rotation, TLS/DNS bounds и отсутствием automatic retry завершилась PASS с `-race`
(12.016 s). HTTP origins/CSRF/CAS/callback boundaries прошли отдельный regression.
Protected runtime configuration, secretfiles и config tests завершились PASS;
неудавшаяся промежуточная компиляция HTTP fixture не засчитывается как общий PASS.
Последующий `go vet ./...` на текущем checkout завершился PASS.

Actual HTTP wire suite завершилась PASS с `-race` на SQLite и native PG 18.6
(32.543 s), scoped vet — PASS. Проверены login и management → exact callback → AGP
TOTP → session/handoff/EdgeAuth, текущие provider/link revocations и signed wrong nonce.
Fixture использует реальный HTTPS, подписанные IdP JWT и TLS LDAP, но providers/links/
grants подготовлены trusted SQL, journal находится в памяти, cookies обрабатывает
Go client. Это подтверждение ограниченной композиции, не corporate IdP/AD DS, durable
journal/restore или real-browser acceptance всего пути.

После независимого review реализация включает distinct secret contents, endpoint pins,
state/nonce/PKCE binding, predecessor cancellation, один code exchange, flow/binding
rotation, final-time checks, erasure/cleanup и current projection floors. Финальный
backend прогон на SQLite/native PG завершился PASS (294.947 s, exit 0): девять top-level
OIDC groups, без SKIP/FAIL; scoped vet также PASS. Проверены provider/link lifecycle,
purpose/browser boundaries, final time, исторические AD subjects и separate state keys.
Последующие OIDC Chromium fixtures и backend batches общего lifecycle-прогона прошли
PASS. Полный pipeline завершился exit 1 на native sandbox guard; backend PASS и
отдельное browser продолжение не закрывают native host qualification.

Из checkout с Go 1.27.4+, проверенным module cache и разрешёнными loopback sockets:

```bash
export GOMODCACHE="$PWD/.tmp-cycle-verified-mod"
go test -race -count=1 ./internal/oidcclient ./internal/secretfiles ./internal/runtime
go test -race -count=1 ./internal/identity -run '^TestOIDC'
go test -race -count=1 ./internal/httpapi -run '^TestOIDC'
npm --prefix web/console-prototype run build:auth
npm --prefix web/console-prototype run build:directory
npm --prefix web/console-prototype run test:oidc:auth:browser
npm --prefix web/console-prototype run test:oidc:management:browser
```

Backend PG cases требуют отдельную disposable БД через `AGP_TEST_IDENTITY_DSN` либо
`AGP_TEST_POSTGRES_DSN`; HTTP wire может использовать отдельный `AGP_TEST_OIDC_HTTP_DSN`.
Без DSN native cases дают SKIP и не закрывают приёмку. Browser fixtures требуют
Playwright/Chromium из prerequisites S0 и не обращаются к корпоративному IdP.

### Role bindings и scoped node management: проверки текущего пакета

Workflow, exact revoke, effective readers и все пять typed scopes прошли отдельные
paired SQLite/native PG race suites. Проверены сохранённые approvals, role incarnation,
финальный expiry, delegation ceiling, stale ownership/configuration pins и отсутствие
positive journal replay. AD/OIDC independent-person regression завершилась exit 0:
98 сценариев на обеих БД, HTTP и scoped vet — PASS. Recovery final materializer при
target/executor alias сохраняет restrictive floor, не создаёт ticket/factor/session и
снимает собственный barrier. Mixed label selector с revoked node отклоняется целиком;
pending nodes без сертификата остаются в полном наборе получателей.

Roles Chromium fixture после reason/reconciliation исправления прошла 30 групп;
typecheck/build — exit 0. Directory/OIDC/lifecycle management regression fixtures также
прошли отдельно. Используются реальные production assets и synthetic API, не полный
корпоративный browser acceptance. Повторяемые entrypoints при тех же prerequisites:

```bash
go test -race -count=1 ./internal/identity -run '^TestRole'
go test -race -count=1 ./internal/securitystate -run '^TestRole'
go test -race -count=1 ./internal/rolescope
go test -race -count=1 ./internal/httpapi -run '^TestRoleBindingHTTP'
npm --prefix web/console-prototype run test:roles:browser
```

Нативные PG cases требуют disposable DSN соответствующего пакета; без него SKIP не
закрывает приёмку. Configuration full suite завершилась exit 1 (868.900 s) только на
двух history-staleness случаях. После исправления затронутые полные PlanProposals,
role readers, independent-review и historical-boundary suites на обеих БД прошли race
PASS (339.186 s) и scoped vet. Проверены сохранение истории при stale/revoked inventory,
запрет replay и ошибка без артефактов при outage. Это отдельный focused PASS, а не
повторный общий PASS. Финальная node identity/inventory race regression на обеих БД
завершилась exit 0 (251.497/94.673 s), actual-services HTTP race — PASS (18.633 s),
scoped vet — PASS. Проверены scope filtering, session pins, private approval expiry,
negative AD missing-proof/legacy fallback и post-CA local denial с retained ledger
без повторной выдачи. Это не положительная end-to-end AD квалификация.
Protected legacy roles после исправления late-final-projection expiry прошли paired
race 14 случаев (73.816 s), scoped vet и узкий independent review; restrictive replay
сохранён. Все disposable PG clusters этих прогонов удалены.
Пакет перенесён в основной workspace; общий pipeline после этого переноса OPEN.

Последующий Gateway read/edit пакет расширяет object authoring на node/group, без
расширения этих grants до Site/global или whole-Gateway доступа по resource grant.
Полный rolescope suite, включая recipient/selector authority и disposable DB guard,
прошёл paired SQLite/PG race (29.551 s). После исправления site-only known-deny regression configuration
scoped authoring, role readers и новые Gateway tests прошли paired race (120.596 s).
Проверены mixed-grant полное покрытие, скрытые соседи/pagination, свой CAS, stale base,
отзыв перед replay, structural lock и атомарный rollback revision/audit/request при
source SQL failure, расширении label match и expiry после последнего source read.
Actual-services HTTP suites прошли SQLite/PG race (16.510/4.830 s): exact object
access, CSRF/origin, запрет full snapshot/draft/catalog, idempotency и source 503.
Production Angular typecheck/build и Chromium fixture прошли exit 0, 16 групп.
HTTP origin regressions и scoped vet завершились exit 0; сборка всех Go packages
прошла compile-only (это не полный runtime suite). Штатный S1 entrypoint включает
rolescope на отдельной `agp_role_scope` БД, HTTP batches и config Chromium fixture.
Изолированная проверка этого DSN/DB пути прошла на native PG; полный S1 pipeline
после изменения entrypoint ещё не запускался.
Независимые architecture/security review завершены без открытых findings. Это
focused qualification; общий pipeline после нового пакета, scoped planning/approval
и fleet load acceptance остаются OPEN. Resource route projections проверены следующим
пакетом ниже. Полный `REQ-03` и готовность к публикации этим пакетом не подтверждены.

Resource read/edit пакет добавляет exact sealed resource/Gateway/route projection и
замену одного существующего маршрута, сохраняя другие placements. Финальный полный
`configmodel -race` прошёл (63.421 s), resource authority и receiving-node regressions
прошли SQLite/PG race (33.652 s), включая настоящий private Fleet Gateway >2 MiB.
Основная service-матрица подтвердила на обеих БД exact/read-only scope, pagination и
скрытые cursor, CAS/idempotency, отзыв/expiry перед replay, path/hostname winner effects,
межшлюзовое пересечение узлов и атомарный rollback при изменении metadata/labels,
source error и late expiry. Первый combined service run завершился exit 1 только из-за
новой WAF-фикстуры: соседние Gateway ссылались на неопубликованную policy. После
исправления подготовки только этот сценарий повторён на обеих БД — PASS (12.135 s).
Проверены display-name-only сохранение assigned WAF provenance и отказ security edit
без нового trusted resolution; производственный barrier не менялся.

Независимые architecture/security review закрыли compatibility finding: историческая
нормализация Gateway/Configuration сохранена, строгие префиксы проверяет новый
resource parser и routing proof. Новая paired service history regression прошла
(18.378 s): старые resource/Gateway/list читаются, узкое изменение неподдерживаемого
Gateway отвергается, изменение другого Gateway сохраняет старое размещение.
Actual-services Resource и Gateway HTTP suites прошли paired race (39.811 s):
management origin/session, CSRF, read-only и mixed-body отказ без записи, exact scoped
response, pagination, собственный CAS/retry и отзыв edit с сохранённым read.
Scoped vet — PASS. Angular typecheck/build и production-assets Chromium fixture —
exit 0, 21 группа, включая пять новых resource groups. Общая Go compile-only проверка
прошла; это не полный runtime suite. OpenAPI содержит 185 операций; S1 включает новые
resource authority/Fleet/service/history/HTTP PostgreSQL assertions. Полный S1 после
этого изменения не запускался, corporate/native apply/rollback и release acceptance
остаются OPEN. Все disposable PostgreSQL clusters этих focused прогонов удалены.

### Согласование, применение и откат: локальная проверка компонентов

На 2026-11-25 новая матрица `rolloutexecution` прошла SQLite/PostgreSQL race
(125.746 s): независимое exact approval, отсутствие неявного admin/config-edit права
запуска, конкурентный idempotent dispatch, отмена без выдуманного отката, отзыв роли/
сессии/узла, unavailable source и атомарный rollback SQL. После результата canary
проверены актуальность оставшегося узла и следующая выдача. Roundtrip использует
настоящий `helper.Executor` и ledger, текущие подписанные StartProof и root receipt;
installation source и native driver в этом CP-тесте контролируемые.

Окончательная HTTP boundary матрица отдельно прошла обе БД (11.924 s): настоящие
management sessions, Origin/CSRF, отказ browser listener для agent paths и отсутствие
повышения node scope до global. Проверка общей mTLS identity boundary прошла SQLite/
PostgreSQL race (5.652 s), включая отзыв сертификата на той же TLS connection.
Это разные focused проверки; общий S1 pipeline после изменения не запускался.

`scripts/test-helper-foundation.sh` завершился exit 0: прежние admission/store
сценарии и 17 новых execution-групп, race 14.279 s плюс vet. Проверены accepted
high-water после отказа, точный replay/outbox, interruption/recovery, независимый
recovery context при отмене, неизвестное состояние/containment, ошибка durability
после эффекта, отзыв во время fsync и deadline внутри активации. Native adapter
прошёл package race (9.679 s) и vet: настоящий helper/ledger и файловые деревья с
контролируемым runtime покрывают A₁→B₂→A₃, recovery A₁ при принятой sequence 2 и
новую задачу 3, реальный subprocess crash/reopen, более 256 recovery records,
подмену tree и остановку закреплённой cgroup при stale/reused/исчезнувшем master.
Kernel kill и настоящий Nginx reload в этих controlled tests не выполнялись.

Angular production build/typecheck прошли; окончательный Chromium-прогон дал 21
прежнюю config-группу и 11 новых execution-групп. Проверены явный запуск, отдельное
согласование отката, exact access, `204` cancellation, отсутствие исполнителя,
потеря ответа с замороженным исходным retry, tab preservation и отказ malformed/
пустого dispatch acknowledgement. Подписанный receipt в browser fixture — форма
доверенного серверного ответа, не самостоятельная криптографическая проверка браузером.
Все Go packages прошли compile-only; scoped vet — PASS. Контрактная проверка:
34 schemas, 202 fixtures, 194 OpenAPI operations — PASS.

Независимые security/architecture review закрыли исправленные composition/recovery
findings. В исходном foundation-срезе qualified Sources, signed baseline capture,
daemon и доставка задач/outbox ещё не были подключены; следующий runtime описан ниже.
По умолчанию execution остаётся выключенным. Этот foundation-срез не проверял
настоящие root/Nginx/cgroup; отдельная приёмка 2026-11-26 описана ниже. Reboot/fault,
весь S1, нагрузка, корпоративные интеграции и release/HA/DR остаются OPEN. AD
отложен, SMTP будет подключён при подготовке ресурсов. Этот набор не закрывает весь
REQ-03 и не подтверждает публикационную готовность.

### Execution wiring: воспроизводимая проверка — AS-IS на 2026-11-26

Добавлены concrete Sources, signed baseline challenge/capture, штатное opt-in
подключение CP, Unix agent/helper transport и прямая доставка helper outbox. Это
[отдельный runtime](development.md#согласование-применение-и-откат--as-is-на-2026-11-26),
сохраняющий default-disabled поведение без `AGP_EXECUTION_CONFIG`.

Runner `scripts/test-execution-wiring.sh` требует Linux, непривилегированного пользователя,
Go из проекта, `rg` и native PostgreSQL 17+ (`initdb`, `pg_ctl`, `createdb`) с доступными
runtime libraries. Запуск из корня репозитория:

```bash
AGP_TEST_PG_BINDIR=/path/to/pg/bin GO=/path/to/go bash scripts/test-execution-wiring.sh
```

Эквивалентный target: `make test-execution-wiring` с теми же переменными окружения.
Runner сам создаёт private `/tmp` PostgreSQL cluster и три БД; TCP listener выключен,
Unix socket имеет mode 0700. Внешние DSN/PG connection variables сбрасываются. Profiles,
ключи и qualification evidence синтетические; native runtime adapters контролируемые.
После прогона cluster останавливается и удаляется; при ошибке остановки lab сохраняется
и runner возвращает ошибку.

Матрица включает paired SQLite/PostgreSQL Sources и HTTP, helper/native/runtime,
Unix transport и CLI, agent/client, challenge-bound journal mTLS, runtime loader и vet.
Обязательные paired test names проверяются явно. Root-only writer-lock lifecycle
в этом nonroot runner отмечается `SKIP`; это не результат его root-проверки.
Финальный запуск 2026-11-26 завершился exit 0: Sources SQLite/PostgreSQL, HTTP на
обеих БД, helper/native/runtime, Unix/CLI, agent/client mTLS, journal challenge и
loader прошли `-race -count=1`; scoped `go vet` также прошёл. Единственный явный
`SKIP` — `TestInstalledWriterLockLifecycle`, которому нужен root-owned установочный
стенд. Контрактный набор: 34 schemas, 218 fixtures, 196 операций OpenAPI — PASS.
Все пакеты Go прошли compile-only; CP, agent и helper собраны. Это приёмка кода с
синтетическими квалифицированными материалами и контролируемым native adapter,
а не подтверждение реального root/Nginx, нагрузочного стенда или готовности публикации.

Сама эта матрица не квалифицирует настоящий root/Nginx/cgroup/reboot, production
установку, service/WAF materialization producer, весь S1, HA/DR и нагрузку. Результаты
отдельной root-проверки приведены ниже; для публикации остаётся обязательной
[внешняя приёмка](#ресурсы-для-обязательной-внешней-приёмки) в полном объёме.

### Приёмка на сервере — 2026-11-26

С разрешения владельца исходники и инструменты переданы на выделенный SSH-стенд:
Ubuntu 26.04.1 amd64, kernel `7.0.0-44-generic`, 4 vCPU, 7.2 GiB RAM. Использованы
Go 1.27.4, portable PostgreSQL 18.6 и bubblewrap 0.11.1 из подписанного Ubuntu archive;
рабочие каталоги — `/srv/agp-lab` и `/opt/agp-lab`, системный PG cluster не создавался.
Runtime сохраняет Ubuntu 24 userspace/ABI на общем host kernel; это **не квалификация
релиза для Ubuntu 26**, platform allowlist не расширен. Release-ключи и подписанные
квалификационные материалы тестовые и не дают права production publication.

**PASS**: восемь native sandbox групп; настоящий root→nonroot bridge; отдельный
`TestInstalledWriterLockLifecycle`, который nonroot runner по-прежнему пропускает;
полный execution wiring runner с SQLite/PostgreSQL, `-race` и scoped vet; native WAF
25/25 без SKIP с Go renderer. Новый
[scripts/test-native-activation-root.sh](../../scripts/test-native-activation-root.sh)
через production constructors прошёл за 13.713 s: реальный root Nginx master и nonroot
worker, изолированный `nginx -t`, SIGHUP, A1 → B2 → exact A1 и `cgroup.kill`. После
намеренного `os.Exit` supervisor внешний процесс очистил scope реальных master/worker
через закреплённый cgroup descriptor. Статусы 401/403 этого activation-теста синтетические;
проверка настоящего WAF выполнена отдельным корпусом.

Повторный root-прогон допускается только на disposable host с заранее установленным
root-owned runtime (каталоги 0700, data files 0400, executables 0500), каноническим
полным `[]RuntimeEntry` descriptor и отдельными pins, явными nonroot UID/GID,
проверенным bubblewrap и writable cgroup v2 parent; runner проверяет обязательные
переменные окружения и не устанавливает runtime. Полный
service/WAF materialization producer, сквозной service apply, нагрузочные SLO,
реальный reboot/fault, корпоративные AD/OIDC/SMTP и release/HA/DR остаются **OPEN**.
Перезагрузка стенда не выполнялась; предварительно нужно разобраться с существующим
сбоем `grub-initrd-fallback.service` (`invalid grubenv`).

### Application package и service candidate — 2026-11-27

Текущие `install.sh`/`update.sh` принимают новый публичный GitHub release package
с девятью Go roles и тремя systemd templates. Новый packaging suite проверяет полный
inventory, hashes/modes, воспроизводимость и отказ от неполного/динамического ELF.
Все девять настоящих Go binaries собраны с `CGO_ENABLED=0`; оба standalone scripts
прошли `--verify-only` на полученном тестовом архиве и отвергли неверный внешний SHA.
Тестовый commit в этом архиве фиктивный; это не релиз и не доказательство provenance.
Релизный builder требует настоящий чистый Git/tag и на текущем source snapshot без
Git identity отказывает. Подготовка пакетов не означает их публикацию на GitHub.

36 изолированных installer tests и 8 packaging tests — PASS. Проверены установка/
обновление всех ролей, сохранение
env, SQLite backup с WAL, отказ до переключения при сбое backup, ветки до/после
попытки startup migrations, повторный запуск, downgrade/tag replacement, hostile tar
и protected paths. Эти tests подменяют systemd/host adapter; полноценная установка
и обновление на Ubuntu 24.04 с systemd остаются отдельной внешней приёмкой.
Отдельно на настоящем disposable PostgreSQL 18.6 выполнен вызов updater backup:
custom dump с правами 0600 восстановлен в другую временную БД, исходные строки
сохранились. Использован приватный Unix socket; существующие БД не затрагивались.
Application bootstrap использует явно доверенный оператором SHA256; production
application TUF/signing pipeline и лицензионный аудит этим не реализованы.

Новый `internal/nativematerialization` компилирует детерминированный **неподписанный
кандидат** service/WAF configuration. В нём другой apiVersion и `deployable=false`;
подписанные execution materials, SQL authority и private secrets он не выпускает.
Unit suite — PASS; scoped `-race` с actual Nginx 1.30.8/ModSecurity/CRS — PASS 4.928 s
без SKIP, scoped vet — exit 0. Проверены TLS, routing, private EdgeAuth, фильтрация
identity/cookies, отказ при недоступном Auth и реальная блокировка атак до upstream.
Central Auth в native test — контролируемая зависимость: login/redeem/mTLS/AD не
квалифицированы. Несколько hostname на один Gateway отклоняются до реализации
совместимого Central Auth binding. Profile/zone assignments, exceptions, adopted
ownership и live selectors не выдаются за поддержанную materialization; transport
и identity lifecycle gaps остаются явными blockers. Независимый signed producer,
сквозное применение сервисов и остальные внешние этапы остаются **OPEN**.

### Ресурсы для обязательной внешней приёмки

По решению владельца от 2026-11-25 ресурсы готовятся отдельно. На предоставленном
2026-11-26 SSH-стенде выполнена описанная выше часть native/root-проверок; остальные
сценарии остаются OPEN. Оператору нужны изолированные от production ресурсы и доступ:

| Ресурс | Назначение и предпосылки |
| --- | --- |
| Ubuntu 24.04 amd64 qualification host | Настоящий root для root→nonroot bridge, разрешённые bubblewrap namespaces, отдельный syntax UID/GID, reboot/mount/fault tests и возможность восстановить disposable host. CP/journal data и restore должны иметь раздельные области отказа. |
| Настоящий AD DS | DNS/time sync, TLS DC с доверенной CA, read-only bind account, синтетические пользователи и security groups. Нужны управляемые disable/lockout/expiry, вложенные группы, stable GUID и TLS/outage сценарии. |
| AD-backed OIDC IdP | HTTPS issuer и два test clients login/management с разными IDs и secret bytes; exact callbacks зарегистрировать по contract. Проверить подписи/rotation, state/nonce/PKCE, `auth_time`, AD linkage и outage. |
| SMTP и test mailboxes | Проверенный TLS transport, выделенный test sender/recipient domain, доступ к доставленным письмам и возможность задержки/отказа. Production recipients и реальные пользовательские коды не использовать. |

Дополнительно нужны раздельные management/login и два application origins с DNS/TLS,
native PostgreSQL и независимый journal, разрешённые test egress и проверяемая clock
synchronization. Версии и topology фиксируются при подготовке стенда. Секреты передаются
только через защищённые installation files/version references; в чат, команды и test
reports их не включать. После тестов отозвать временные credentials и удалить disposable
данные; production rollback из этих ресурсов не выполнять.

### Nginx: обязательный security baseline

На 2026-11-25 pins/lock и security floor переведены на **1.30.8**.
[Stable changelog](https://nginx.org/en/CHANGES-1.30) от 2026-11-23 содержит исправления
избыточной загрузки CPU при `ssl_early_data` (CVE-2026-132779) и SSL backend connections;
[advisory](https://nginx.org/en/security_advisories.html) оценивает первый дефект как medium.
Source archive SHA-256 —
`f867314ada32e717b949930859656c48a72dc6657aec598db58af2f98a40e1c1`, detached signature
проверена с signer `D6786CE303D9A9022998DC6CC8464D549AF75C0A`. На новых bytes
сборка в Ubuntu 24 userspace, 25/25 mandatory native WAF cases без SKIP,
23 baseline unit groups и actual `-V`/required module flags завершились **PASS**.
После этих проверок обновлена qualified allowlist. Actual signed bootstrap candidate
на новом tuple также прошёл локальную проверку. Первая попытка полного PG/provider/
HTTPS pipeline остановилась по timeout расширенных Go packages; последующий
package-wide лимит 600 s также оказался недостаточным для aggregate identity/configuration
suite. Эти попытки не считаются PASS. Harness теперь запускает все перечисленные tests
группами по шесть с лимитом 10 минут. Новый общий прогон завершился exit 1 на
`workspace_parent_rejected`; отдельное HTTPS/browser продолжение и последующий штатный
native host run завершились exit 0.
Границы этих результатов описаны в lifecycle-разделе выше. Production
Nginx не обновлялся этим локальным прогоном.
Исторический floor/qualified tuple 1.30.7 от 2026-11-19 и provenance 1.30.6 сохраняются
как свидетельства соответствующих прогонов, а не разрешение нового release.

```bash
python3 scripts/check-nginx-baseline.py --source-only
python3 scripts/check-nginx-baseline.py --binary /path/to/verified/nginx
python3 scripts/test-nginx-baseline.py
```

Gate сверяет `nginx-toolchain.env`, security floor, reviewed versions и native lock,
затем exact runtime `-V` и configure flags auth_request/SSL/HTTP2. Он обязателен для
S0/WAF/full Nginx и release entrypoints; отсутствие binary больше не скрывает native
проверку через SKIP. В историческом прогоне 1.30.7 проверены 23 baseline test группы,
включая negative cases, actual bundle file hashes, реальный `-V`/modules и три native
Nginx группы — PASS. Gate не опрашивает upstream
автоматически и не доказывает происхождение произвольного binary. Более новый релиз
требует advisory review, обновления pins/lock и новой native qualification; одного
изменения версии недостаточно. Текущие installer default и module minimum согласованы
на Go 1.27.4; прежние результаты Go 1.26.8 сохраняют историческую область.

Дополнительная проверка SQL в двух изолированных PostgreSQL-движках без настоящего сервера:

```bash
npm install --prefix /tmp/agp-doc-pg --ignore-scripts --no-audit --no-fund @electric-sql/pglite@0.5.16
node docs/v2/check-reference-db.mjs /tmp/agp-doc-pg/node_modules/@electric-sql/pglite/dist/index.js
```

Это документационный harness, не зависимость runtime AGP. В нём CP и journal создаются в разных in-memory БД.
Он проверяет исполнение DDL и выбранные FK/UNIQUE/CHECK/monotonic boundary cases; не квалифицирует физическую durability, native PostgreSQL 17 или DR.

## 3. Матрица REQ → семейство проверок

Для REQ-02 обязательны реальные AD DS/IdP/SMTP integration и browser tests по
[identity](identity.md): rename/recreate GUID, disabled/locked/expired account, nested и
primary security groups, incomplete tokenGroups/GC failure, referral/TLS/StartTLS downgrade,
LDAP injection/empty password, DC timeout/replication lag и отсутствие local/email fallback.
MFA suite доказывает отсутствие доступа после одного фактора, issuer-specific mapping,
TOTP replay/step-up/recovery. Email suite проверяет HMAC/purpose/contact/browser binding,
parallel consume, committed wrong-attempt counters, resend без сброса общего budget,
отложенную доставку, block/policy change во время flow и отсутствие plaintext secrets.
DR suite восстанавливает backup до consume/contact/provider/link change; старые flows,
коды и конфигурации ниже floor закрыты. Отдельный restore в текущем TOTP window
доказывает, что readiness ждёт barrier и прежний код не используется в новом login.
Недоступный AD/SMTP стенд означает SKIP и незавершённую приёмку, а не PASS.

| Требование | Минимальные проверки |
| --- | --- |
| REQ-01 Baseline/migration | v1 manual остаётся работоспособен; import не меняет live route; IDs/disabled flags сохранены |
| REQ-02 Identity | local/AD/OIDC; AD GUID/groups/live check/TLS outage; pending MFA denial; OTP expiry/replay/resend/limits/DR; no email takeover/MFA bypass |
| REQ-03 RBAC | Target principal guards, scoped delegation, self-approval запрет опасного плана, revoke прав до dispatch |
| REQ-04 Browser isolation | App JS/backend не получает management cookie/session; forged Origin/CSRF и cookie tossing закрыты |
| REQ-05 Nodes | Token replay/CSR SAN spoof/role confusion/serial revoke/renew/expired re-enroll |
| REQ-06 Gateway/Route | Host/path conflicts, disabled state, upstream URL/network policy, prefix/redirect/cookie rewrites |
| REQ-07 Auth revision/deny | Старый/новый bundle оба однозначны; неизвестная generation закрыта; emergency deny переживает rollback |
| REQ-08 Config model | JSON/YAML/forms round-trip, duplicate/alias/tag/unknown rejection, deterministic normalization |
| REQ-09 CAS/idempotency | Гонка двух editors → 412/409, один effect; ключ+иной body конфликт; secret retry не раскрывает значение |
| REQ-10 Plan/approval | Frozen node IDs/input digests; label/secret/capability drift инвалидирует plan; exact approved bytes |
| REQ-11 Agent/helper | No shell/raw config/path escape; role cert isolation; old sequence/task/permit отвергнут |
| REQ-12 Apply | Full tree nginx -t, реальный reload/probes, fsync до switch, local recovery при потере CP/expiry |
| REQ-13 Fleet | Canary → waves, pause/cancel semantics, bounded unavailable, partial partition/unknown receipt reconcile |
| REQ-14 WAF | Zones membership/conflicts/scopes/labels; derived policy rebase; frozen targets/full node diff; native detection/blocking/expiry; retire/rollback/anti-bypass |
| REQ-15 Secrets/PKI | At-rest encryption, rotation overlap, recipient scope, no log/diff/export secret, lost key recovery |
| REQ-16 Artifacts | Tamper/wrong ABI/missing dependency/expired TUF/floor/downgrade rejected; offline install closure |
| REQ-17 Audit/privacy | Durable management event+outbox, redaction, export formula injection, duplicate events, legal hold |
| REQ-18 Monitoring | Connectivity != health != applied; retries/dedup/maintenance, channel SSRF, spool overflow видим |
| REQ-19 Storage/types | PK/FK/UNIQUE/CHECK, case-sensitive ID, uint63 >2^53, CIDR canonicalization, GC pins |
| REQ-20 DR/HA | Single-writer fencing, journal allocation, restore to old DB cannot revive revoke/grants, measured RPO/RTO |
| REQ-21 Security/network | DNS rebinding/redirect/proxy bypass, forged X-AGP-* reaching actual upstream, native config escape |
| REQ-22 UX | Zones-first Angular; server pagination/frozen all-results, target counts/provenance; «?»/manual без потери draft; keyboard/mobile/error/unknown, no invisible mutation |
| REQ-23 API/SDK | OpenAPI generated DTO compatibility, error codes, path/body identity match, pagination scope |
| REQ-24 Capacity | pilot-500/fleet-10k bounds/compatibility; datasets 1000/5000/10 000 Gateway, total Routes/count/bytes; compile/DB/auth/rollout/restore measured, task caps retained |
| REQ-25 Delivery | Isolated PR credentials, reproducible build, signed release, protocol N/N-1, migrations rollback window |
| REQ-26 Ownership | Adopted preserves external files/packages, drift stop; detach retains auth until handover verified |
| REQ-27 Portal/downloads | Only permitted deployed resources visible; login redirect/help/search; scan before publish/file path safety |
| REQ-28 Autonomy | CP down vs Auth down vs internet down; no silent cached allow; advanced regional assumptions explicit |

Test families в ТЗ и этой матрице — ссылки на поведение, не утверждение о существующих тестовых функциях в коде.

## 4. Парсер, типы и compiler

- Одинаковая модель в form/JSON/YAML даёт одинаковые canonical bytes и digest; изменение значимого поля меняет digest.
- `9223372036854775807` допустим, следующее значение отвергнуто; числа >2^53 не округляются в browser/API/export.
- ID с uppercase base64url и UUID начинается с цифры, сохраняет значение; ID вне profile требует bridge, не silent lowercase.
- Duplicate keys, aliases, recursive anchors, multi-document YAML, unexpected type coercion, huge depth и unicode spoofing corpus отвергаются bounded-time.
- Property tests route normalization/path traversal/encoded slash, IPv4/IPv6/CIDR, URI userinfo/query/fragment и invalid ports.
- Compiler запрещает arbitrary includes/modules/scripts/directives; одинаковые resolved versions дают одинаковые native outputs.
- При пересечении route prefixes авторизация и Nginx выбирают один routeId; tests включают slash/redirect/query и normalized path.
- Base/time-dependent references не подменяются поздним lookup во время apply; exact qualified profile закреплён в plan.

## 5. PostgreSQL и concurrency

Reference DDL исполняется в пустой disposable БД PostgreSQL 17 и следующей заявленной версии, с runtime role без superuser.
Проверить все FK/UNIQUE/CHECK, nullable defaults, migration lock, запрет UPDATE immutable content и роль-only state transitions.
Проверить cross-site plan/target и cross-revision route/policy: если ограничение service-level, создать интеграционный negative test.
Одновременный approve/publish, duplicate Append/outbox dispatch, lease expiration и два writers не дают двойного privileged task.
Plan expected sequence, DB allocated sequence и node accepted high-water различаются; lost/late receipt не сбрасывает ни один из них.
Изменение ролей во время approval/apply проверяется заново; read replica не используется для authoritative permit/deny.
Security append после backup от неизвестного actor replay-ится без восстановления активного пользователя/прав.
Истечение idempotency cache не означает разрешения заново применить старый task: durable task journal имеет отдельную retention/pins.

## 6. Browser/SSO и UX acceptance

Стенд: management, login и минимум два application origins, отдельные cookies, local user и реальный test OIDC provider.
Happy path: открыть app → login → callback → gateway session → permitted route; затем logout/revoke → доступ закрыт.
Negative: чужой state/verifier/node/gateway/redirect, code replay/expiry, issuer mismatch/key rotation/algorithm confusion, missing MFA, account link по чужому email.
Отдельно проверить native Nginx → EdgeAuth → CentralAuth: `HTTP 200 {decision:deny}` даёт 401/403 на adapter, malformed/unknown/timeout — 503, только validated allow — 204. Прямого Nginx proxy к JSON endpoint нет.
App backend записывает входные headers/cookies в тестовую память: management/gateway credential туда не попадает; только проверенные identity headers.
Вредоносная app page пытается вызвать management API, читать CSRF и устанавливать cookies для другой audience — доступ закрыт.
UI scenario: editor сохраняет draft, другой editor меняет base, первый получает конфликт и восстанавливает diff без потери локального текста.
Скрытие/повтор кнопок, обновление страницы, обрыв SSE и двойной click не создают второй rollout.
Голос/keyboard traversal, focus после ошибки, screen-reader live status, цветовая независимость и narrow layout проверяются по [WCAG 2.2](https://www.w3.org/TR/WCAG22/).

## 7. Safe Apply / failure injection

| Момент отказа | Ожидаемый результат |
| --- | --- |
| Download/подпись/validation | Active config не изменён; rejected/failed receipt и причина |
| До durable intent | Side effect отсутствует; следующий attempt безопасен |
| После intent/fsync до pointer switch | Reboot видит pending operation и исходный active tree |
| После switch до checkpoint/reload | Reconcile доказывает actual state и завершает либо exact-base recovery |
| Reload принят, новые workers не готовы | Не Succeeded; functional probes и bounded recovery |
| Probes failed / permit expired / CP lost | Pre-authorized local rollback без снятия текущих deny/floor |
| Commit успешен, receipt потерян | Узел остаётся на healthy target, CP query/reconcile; нет слепого rollback |
| Rollback failed / disk full / external adopted drift | recovery_required, остановка wave, affected route закрыт, redacted diagnosis |

Использовать реальные процессы/reboot/файловую систему, а не только mock return errors. Для power-loss evidence нужен целевой durable storage profile.
Проверять allowed user, denied user, revoked user, CIDR и реальный WAF block/event через тот же listener, что обслуживает клиентов.
Credentials synthetic probes ограничены, краткоживущие и не выдаются приложению/логам.
Нужно отличать graceful reload от restart; проверяются existing streams и срок drain, не обещается вечная бесшовность.

## 8. Journal / restore / HA

1. Создать user/session/role, сохранить backup PG; после backup отозвать session/role/node и записать independent head.
2. Восстановить старую PG отдельно; до head verification/replay ни Auth allow, ни privileged management mutation не проходят.
3. Replay после backup включает actor, отсутствующего в восстановленной БД; событие сохраняется как историческое, active principal не воссоздаётся.
4. Сравнить checkpoint challenge/head, epoch, local materialized head; старый подписанный head и unavailable journal не принимаются за актуальный.
5. Rollback config и восстановление старого volume агента не возвращают revoked rights/security floor; stale node требует recovery/re-enrollment.
6. Прервать каждый шаг pending/barrier → append → materialize; retry по operationId даёт одну запись, pending не снимается по timeout.
7. Split-brain PG/dispatcher: fenced writer/task rejected, sequence не используется повторно, application auth не читает stale replica.
8. Восстановить secret/PKI/repository/key store и проверить реальный login/route/release verification, а не только успешный pg_restore.

DR evidence включает measured downtime/data loss и зависимости внешнего journal/key store. Потеря всех authority данных не маскируется reset epoch.

## 9. WAF / offline / supply chain

Qualified tuple фиксирует OS/arch, Nginx build flags/ABI, connector/libmodsecurity/CRS и digests; каждое сочетание испытывается отдельно.
Нормальный traffic corpus приложений проверяет false positives; attack corpus — нужное срабатывание, не обещание защиты от всех атак.
Exception expiry test: до deadline removal plan/alert; после deadline active old generation не даёт новых protected запросов, native rule не объявляется автоматически удалённой.
Tampered bytes, missing dependency, archive traversal/symlink/device, wrong signer, expired metadata, revoked key и stale floor не устанавливаются.
Airgap install начинается с чистого поддерживаемого host без internet/DNS наружу; package scripts не скачивают зависимости не из bundle.
Подмена mirror не меняет доверие; metadata root/key rotation проверяется без отключения expiry для удобства.
Split-WAF client пытается обратиться к gateway/upstream напрямую, подделать forwarded identity и использовать fallback route — обход отсутствует.

### WAF Zones: обязательная сквозная приёмка

Сценарии выполняются через UI и прямой management API, с реальными PostgreSQL
транзакциями; native outcomes требуют квалифицированного Nginx/WAF стенда. Таблица —
план assertions, не отчёт о существующих PASS. Zone source closure/digests и полный
node diff связываются с plan/approval. Проверки трассируются на REQ-03/08/09/10/14/22/24.

| Сценарий | Ожидаемый результат / свидетельство |
| --- | --- |
| 1000+ Gateway, AND labels/explicit IDs | Одна операция по зоне, точный server-frozen состав, все цели в preview; pagination не ограничивает выбор первой страницей |
| Две зоны / ноль совпадений | Два non-default match блокируют publish; ноль даёт explicit default либо onboarding; нет скрытого `off` |
| Protected label edit / selector default change | Прямой API не выводит приложение из защиты; effective weakening требует scopes/step-up/independent approval |
| Косвенный scope общего узла | Редактор зоны без права на затронутое соседнее приложение не получает скрытый partial apply; раскрыт полный node effect или операция отклонена |
| Изменение состава/config между resolve и publish | CAS/digest mismatch блокирует stale change; exact target list старого approval не меняется |
| Новый match после approval / новый узел | Отдельный resolution/plan; старое согласование не расширено, active generation однозначна |
| Shared-node pending change другой зоны | Полный node diff показывает обе правки; требуется полное разрешение/approval либо разделение, незаявленный change не уходит на узел |
| Обычный пользователь новой зоны | Членство в WAF Zone не даёт доступ к приложению и не заменяет AD/MFA/RBAC |
| Derived policy / новая base policy | Сохранены local route exceptions/provenance; совместимый rebase проверен, конфликт блокирует; другие Gateway не получили чужие исключения |
| PL↓ / threshold↑ / новый exception | Dangerous эффект определяется семантически, включая косвенное изменение зоны/labels/default; нельзя обойти нейтральным названием команды |
| Частичный rollout / lost receipt / offline | Per-node observed revisions, unknown и stale видны; reconcile вместо blind retry; нет ложного «всё применено» |
| Canary на общем узле | Preview перечисляет все обслуживаемые приложения, не обещает процент запросов выбранного сервиса |
| Выход/перенос/retire активной зоны | Explicit replacement assignments и CAS, старое назначение до safe apply; ни `off` gap, ни случайного fallback; referenced history не удалена |
| Rollback / expired exception | Старый bundle с истёкшим исключением не открывает Route; закрыты только affected Routes, current security floors сохранены |
| Несколько Site под одной UI-командой | Независимые site plans/500-node bounds, partial outcomes объяснены; нет ложной распределённой atomicity |
| Legacy → zone-managed | Сначала read-only preview, сохранены IDs/mode/exceptions/disabled state; материализация без live эффекта, cutover/rollback имеют явную базу |
| PolicyProfile locks/minimum | Более слабое zone/local значение отвергнуто; provenance объясняет inherited/locked/effective value |
| Zone-wide wildcard exception | Невалидные route/rules/field/expiry отклонены; массовая подготовка раскрывает каждую точную конечную цель |

Положительные и отрицательные fixture cases обязаны дополнительно покрывать типы
zone/resolution/change; semantic tests доказывают то, что schema не проверяет: ownership,
AND match, source closure, scoped references, rebase и полной effect validation.

## 10. Capacity и завершение этапа

Контрактные проверки двух профилей выполняются отдельно:

- v1alpha1/`pilot-500`: старые лимиты 500 Gateway/2 MiB/1000 assignments/1000 resolved
  inputs сохраняются. Boundary +1/overflow получает адресную ошибку до allocations/side effects.
- v1alpha2/`fleet-10k`: 10 000 Gateway/100 000 total Routes/64 MiB/20 000 assignments/
  50 000 resolved inputs; 1000 Routes/Gateway, 500 nodes/plan и 100 secrets/node
  не повышены. Проверить cumulative counts, Unicode UTF-8 bytes, JSON escaping/headroom,
  decoder/HTTP/storage/SDK limits и bounded rejection hostile stream. Отдельные caps:
  canonical plan 2 MiB/32 MiB, config JSONB text storage 4 MiB/128 MiB с фактическим
  canonical_size_bytes, bundle resolved-input projection 256 KiB/16 MiB; artifact size
  проверяется своим qualified profile. Zone authored body 2 MiB и resolution canonical
  64 MiB не смешиваются с размером страниц чтения (до 200 записей).
- Upgrade с preview сохраняет canonical meaning и legacy IDs; downgrade отклонён при
  превышении любого старого лимита. Старый consumer отвергает новую версию до mutations.
- Размещение множества сервисов на одном узле не обходит secret/task caps; capacity
  conflict содержит причину и требует placement change или нового версионированного profile.

Обязательные измеряемые datasets:

| Dataset | Gateway | Routes суммарно | Что зафиксировать |
| --- | --- | --- | --- |
| F1000 | 1000 | 10 000 | Nodes/Sites, policy/exception/profile cardinality, users/sessions, трафик |
| F5000 | 5000 | 50 000 | Те же параметры, плотность на узле и workload seed |
| F10000 | 10 000 | 100 000 | Те же параметры; граничный snapshot и плановые зависимости |

Это qualification targets, а не результаты испытаний и не обещанные SLO. Отдельно
измеряются byte-heavy и pathological-match/exception cases в пределах выбранных caps.
Синтетический набор без native traffic не доказывает WAF blocking или auth availability.
До load acceptance владелец задаёт N_nodes, concurrent sessions/streams, auth RPS,
event rate, retention и цели p95/p99/error budget/RPO/RTO.
Измерять отдельно hot auth path (включая journal head), compiler/plan resolution, fleet waves, DB locks/indexes, event spool и backup/restore duration.
Нагрузочный стенд не ослабляет deny/journal checks ради красивого RPS. Порог насыщения и поведение деградации входят в результат.
Этап принимается по соответствующей строке S0..S7, всем затронутым REQ и отсутствию незакрытых blocker findings.
Успех документационных validators не закрывает security defects baseline и не даёт разрешения production rollout.
