# Native WAF qualification

Стенд собирает точный tuple из `configs/waf-native.lock.json`: Nginx 1.30.8,
ModSecurity 3.0.17, connector 1.0.4, CRS 4.30.0. Floating tags и системная
установка пакетов отсутствуют. До исполнения проверяются SHA256/length,
detached PGP signatures и полный connector Git tree из подписанного commit.

На 2026-11-25 это выбранный security floor после
[исправлений 1.30.8 от 2026-11-23](https://nginx.org/en/CHANGES-1.30), включая
CVE-2026-132779. Новая сборка и 25/25 mandatory native WAF cases завершились PASS
без SKIP; baseline unit/runtime checks также PASS. Полный PG/provider/HTTPS pipeline
на новом tuple ещё не повторён. Исторический PASS tuple 1.30.7 не переносился на
1.30.8: artifact/evidence hashes получены заново тем же harness.

```sh
bash scripts/prepare-waf-native.sh \
  --work "$PWD/.tmp-waf-native-build" \
  --output "$PWD/.tmp-waf-native-bundle"
bash scripts/test-waf-native.sh \
  --bundle "$PWD/.tmp-waf-native-bundle" \
  --renderer /absolute/path/to/agpctl \
  --evidence /tmp/agp-waf-native-evidence.json
```

Для сборки Go renderer требуется Go 1.27.4+. Для native harness нужны
непривилегированный x86_64 пользователь, Python 3.11+, `gpg`, `tar`,
`dpkg-deb`, `readelf`, сеть для первой загрузки, разрешённый `ptrace` для PRoot
и loopback sockets для HTTP-тестов. PRoot host tools закреплены для Ubuntu
26.04 amd64; GCC/build dependencies извлекаются в Ubuntu 24.04.5 rootfs.
`apt install`, maintainer hooks, systemd, production access и root не используются.
Для повторного запуска существующего scratch нужен явный `--resume`; исходные
файлы сверяются с подписанными архивами. Bundle и evidence не перезаписываются.

`--download-only` проверяет и наполняет cache. `--offline` запрещает загрузки
при сборке, требует полный cache и немедленно отвергает отсутствующий/изменённый
файл. Это **не** тест установки в clean VM с запрещённым external egress.

Nginx/module и runtime libraries собираются для Ubuntu 24.04 ABI. Harness
запускает комплектный Ubuntu24 loader с замкнутым набором ELF dependencies;
фактические host OS/kernel записываются отдельно. PRoot разделяет host kernel
и не предоставляет изоляцию VM. Production qualification для другого kernel,
OS или tuple из этих результатов не выводится.

`--renderer` (или `AGP_TEST_WAF_RENDERER`) запускает настоящий `agpctl waf-render`
для каждого policy и отрицательных cases. Явный `--reference-renderer` доступен
для диагностики engine с Python reference template и **не** квалифицирует Go
renderer. Evidence указывает использованный renderer и SHA256 его файла.

В response phase connector 1.0.4 может блокировать ответ закрытием соединения
до HTTP status line. Стенд принимает такой результат только при EOF до первого
байта status line, actual CRS outbound blocking rule и отсутствии утечки body;
он записывает `status: 0`/`eof_before_status_line`, не выдаёт это за HTTP 403.
Частичные заголовки/body или HTTP 200 в blocking case вызывают FAIL.

`licenses.json` связывает каждый runtime и notice файл с реальными upstream
или Ubuntu package bytes и copyright notices. `LicenseRef` обозначает источник
notices, а не выдуманное SPDX заключение. Три пустых upstream plugin placeholders,
которые fixed renderer не подключает, не входят в release runtime; их список
сохранён в provenance. Исполняемые CRS rules не изменяются.

`checksums.json`, `build.json` и native evidence сами по себе не являются
доверенным разрешением публикации. Проверка TUF, независимая подпись release
manifest, SBOM/license coverage и связывание corpus/harness с exact artifact
closure выполняются отдельно repository verifier. Подписывать test fixture
разрешено только отдельными ephemeral test roots.

Harness выполняет все mandatory cases, пропуски не предусмотрены. Для
диагностики failed run оставляет private scratch; при PASS временные процессы
и автоматически созданный scratch удаляются. Корпус содержит только
синтетические запросы; evidence включает rule IDs, status и upstream byte/count
дельты, без request body, cookies или credentials.
