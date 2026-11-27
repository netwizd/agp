# AGP — пример инженерной консоли на Angular

Интерактивный макет нового v2 frontend, отдельный от действующего Go/v1 UI.
Все шлюзы, события, AD-проверки и изменения — **демонстрационные данные**.
Макет не подключается к инфраструктуре, AD, SMTP или backend API.

Логотип и иконка — оригинальные файлы с сайта НЛГЕЙТ:
[logo-header.png](https://nlgate.com/logo-header.png) и
[favicon128x128.png](https://nlgate.com/favicon128x128.png), получены 2026-11-18.
Они включены локально в `public/` и в действующий Go/v1 UI; автономный export
встраивает изображения в HTML и не обращается к сайту за ними.

## Запуск

Требуется совместимая Node.js: `^22.22.3`, `^24.15.0` или `>=26.0.0`.
Проверено окружение Node.js 24.21.0, Angular 22.2.6 и CLI/build 22.2.7.
Зависимости фиксирует `package-lock.json`; после установки внешняя сеть интерфейсу не нужна.

```bash
cd web/console-prototype
npm ci --ignore-scripts --no-audit --no-fund
npm start
```

Открыть `http://127.0.0.1:4310`. Dev server слушает только loopback.
Для удалённого рабочего каталога нужен обычный SSH port forward либо локальный запуск
на компьютере, где открыт браузер; чужой loopback сам по себе не доступен.

## Сборка и автономный пример

```bash
npm run build
npm run export:preview
```

Build — `dist/agp-console/browser/`. Export дополнительно создаёт `preview.html`:
тот же Angular UI со встроенными JS/CSS, который можно открыть отдельным файлом без npm,
backend и внешних CDN. Сначала выполните export; сгенерированные файлы не входят в исходники.
Exporter откажет при неподдержанной split-bundle структуре, а не выдаст неполный HTML.

## Что попробовать

1. В «Шлюзы и ресурсы» найти приложение по имени/домену и отфильтровать площадку/состояние.
2. Открыть шлюз, перейти в редактирование либо нажать «Создать шлюз».
3. Оставить обязательное поле пустым и проверить адресные ошибки формы.
4. Ввести значения, нажать «?» у ключевого параметра и «Открыть в руководстве →».
5. Вернуться из manual: значения и контекст редактирования сохраняются.
6. Сохранить черновик, открыть изменение, посмотреть semantic diff и передать на согласование.
7. Перейти в «Доступ и AD»: посмотреть TLS/groups/2FA/email и выполнить demo connection test.
8. Нажать режим WAF в строке Zabbix или открыть «WAF и защита»: выбрать режим, PL и пороги.
9. Открыть «Срабатывания», раскрыть событие и подготовить исключение для правила/поля маршрута.
10. Указать причину и UTC-сроки, добавить исключение в редакцию, сохранить и проверить diff.
11. Передать WAF-редакцию на согласование; открыть тот же снимок из общего журнала изменений.
12. Открыть «Руководство», найти тему и перейти по deep link `#/manual/ad_tls`.

Сохранение не меняет работающий шлюз. «На согласовании» не означает «Применено».
WAF mode входит в назначение ресурса; параметры и исключения — в отдельную копию политики.
Срабатывания сохраняют исходный режим, даже когда черновик переведён в блокировку.
Демо состояние живёт в памяти страницы; reload возвращает исходные fixtures.
Не вводите настоящие credentials: этот макет предназначен для обсуждения интерфейса.

## Структура

```text
src/app/app.*          shell, экран шлюзов, форма, изменения, AD и manual
src/app/waf-panel.*    политика ресурса, срабатывания, исключения и WAF draft
src/app/waf-data.ts    типы policy/binding и безопасные WAF fixtures
src/app/help-tip.ts    переиспользуемая контекстная справка «?»
src/app/help-topics.ts  типизированный реестр короткой справки и статей manual
src/app/icon.ts        локальные SVG icons одного начертания
src/styles.css        общие tokens, typography и accessibility
```

В малом прототипе shell и базовые экраны собраны в App, WAF вынесен в самостоятельный компонент. Для продукта декомпозиция features,
общие UI/help-компоненты, Router и real adapters определены в [UI design](../../docs/v2/ui-design.md)
и [development](../../docs/v2/development.md). Данные fixtures не являются generated API DTO.
Реальные политики и модели определяются [ТЗ](../../docs/v2/requirements.md) и [identity](../../docs/v2/identity.md).

## Проверки

Проверено 2026-11-17:

- Production build Angular со strict templates и автономный export — PASS.
- 12 браузерных сценариев в Chromium 158 — PASS: поиск/фильтры/empty state,
  ошибки формы, справка/manual/focus/Escape без потери draft, dirty close guard,
  draft → validate → approval без apply, явный demo AD test, manual search/deep link,
  mobile 390 px, автономный HTML без сети; JS errors/failed assets/external requests — 0.
- Контракты документации — PASS. Accessibility уровня продукта этим не подтверждена.
- Дополнительно после финальной сборки: touch target «?» ≥44 px, tap → manual → возврат
  с сохранением формы и автономный manual без сети — PASS.
- 12 дополнительных WAF-сценариев в Chromium 158 — PASS: переход из ресурса,
  effective/draft, результат события независимо от режима draft (включая score ниже
  порога при blocking), узкий prefill, ограничения полей/порогов, manual без потери
  формы, dirty resource switch, повторная проверка после правки, immutable pending,
  точное открытие из общего журнала, mobile 390 px и offline WAF deep link.
  JS errors/failed assets/external requests — 0; [результаты](preview/waf-checks.json).

Локальные результаты: [открыть автономный макет](preview.html),
[основной экран](preview/desktop.png), [редактор](preview/editor.png),
[внутренний manual](preview/manual.png), [мобильная версия](preview/mobile.png).
WAF: [политика](preview/waf-policy.png), [срабатывания](preview/waf-events.png),
[исключение](preview/waf-exception.png), [снимок на согласовании](preview/waf-review.png),
[мобильный экран](preview/waf-mobile.png).
Сгенерированные preview файлы доступны после export/QA, не включены в Git исходники.
Production accessibility, реальный AD/SMTP/backend, роли/permissions/CAS и применение
Nginx/WAF здесь не квалифицируются.
Дедлайны и блокировка маршрута в макете иллюстрируют контракт; промышленный UI
получает подтверждённый статус expiry/deny от backend, а не рассчитывает безопасность
по локальным часам браузера.

## Production auth entry

Отдельный Angular project `agp-auth` в том же lockfile/toolchain обслуживает реальный
same-origin `/auth/v2` API. `auth-src/` не импортирует demo fixtures и не превращает
`agp-console` в production-консоль. Поддержаны локальный пароль, TOTP/enrollment,
recovery с заменой фактора и отдельный step-up; AD/OIDC/email UI в этот срез не входят.

```bash
npm run typecheck:auth
npm run build:auth
```

Production output: `internal/frontend/static/auth/`, встраивается Go embed и доступен
по `/auth-ui/login`, `/auth-ui/recover`, `/auth-ui/step-up`. Из корня репозитория:
`make frontend-auth`. Обновляйте source и generated assets вместе перед Go build.
`generate-auth-contracts.mjs` получает FlowView/PrimaryProof/StartFlow/TotpProof из
утверждённого JSON Schema; клиент дополнительно проверяет runtime ответы и binding.

CSRF остаётся в host-only cookie/памяти; sessionStorage содержит только flow ID,
purpose/audience и отметку выдачи recovery codes. Пароль, TOTP, provisioning seed,
recovery codes и CSRF туда не записываются. После reload статус проверяется сервером;
потерянный seed требует новой неподтверждённой настройки, коды повторно не выдаются.
Recovery completion не переводит пользователя в management и предлагает новый login.

Набор `npm run test:auth:browser` проверяет production bundle в Chromium с fixture API
и действующей строгой CSP. Он требует существующий Playwright (`AGP_TEST_PLAYWRIGHT_MODULE`)
и при необходимости путь `AGP_TEST_CHROMIUM_BIN`. Это клиентская проверка маршрутов,
форм, обработки ошибок, секретов и CSRF; server MFA/recovery/SSO безопасность проверяется
отдельным реальным HTTPS/backend acceptance, а не fixture ответами.
