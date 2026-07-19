# DoubleG Scanner v1.3.0 — Download Detection Upgrade

Windows 10/11 x64 дээр ажиллах, хэрэглэгчийн зөвшөөрөлтэй **local-only / read-only** CS2 integrity болон forensic scanner.

## v1.3.0-д зассан гол асуудал

Өмнөх хувилбар recent downloaded cheat файлыг ажиллуулаагүй үед зөвхөн filename keyword эсвэл exact hash таарвал барьдаг байсан. `knownCheats`, `knownHashes`, `knownDomains` хоосон бөгөөд файлын нэр ерөнхий байвал буруу `NOT DETECTED` гарч болох байв.

v1.3.0 дараах давхаргуудыг нэмсэн:

- Quick mode хүртэл Downloads/Desktop дахь recent executable/archive файлыг шалгана.
- Full mode default сонголт болсон.
- ZIP/JAR archive-ийг задлалгүйгээр entry болон executable payload-ийг шалгана.
- Executable болон ZIP доторх executable дээр CS2 reference, cheat-related string, process/memory manipulation API-ийн static correlation хийнэ.
- Recent unsigned executable, executable payload-тай archive, эсвэл бүрэн шалгаж чадаагүй recent archive дээр `REVIEW` гаргана — шууд clean гэж дүгнэхгүй.
- Browser download history болон local file artifact нэг нэрээр таарвал файл ажиллаагүй байсан ч independent correlation үүсгэнэ.
- Full/Forensic mode Microsoft Defender `MpCmdRun.exe`-г `-DisableRemediation` тохиргоотой ажиллуулж Downloads/Desktop (Forensic-д Temp) scan хийнэ.
- Defender threat name илэрвэл UI болон PDF дээр нэр, зам, detection method-ийг гаргана.

## Result-ийн утга

- **DETECTED** — exact known SHA-256/domain, Microsoft Defender detection, unsigned CS2-loaded module, эсвэл critical correlation.
- **REVIEW** — recent unsigned executable/archive, strong static indicator, browser + local file correlation зэрэг manual review шаардсан evidence.
- **NOT DETECTED** — completed module-уудаас high-confidence эсвэл review-level indicator гараагүй.
- **INCOMPLETE** — хангалттай module ажиллаагүй.
- **CANCELLED** — scan дуусахаас өмнө зогсоосон.

`REVIEW` нь cheat батлагдсан гэсэн үг биш. `NOT DETECTED` нь 100% clean гэсэн баталгаа биш.

## Аюулгүй байдлын зарчим

- Server, webhook, telemetry, upload байхгүй.
- Password, cookie, browser session, Discord token, autofill, card data уншихгүй.
- Хувийн зураг, видео, document-ийн агуулгыг шалгахгүй.
- DoubleG Scanner өөрөө файл delete, quarantine, restore, modify хийхгүй.
- Microsoft Defender scan нь `-DisableRemediation` ашиглана: actions хэрэгжүүлэхгүй, detection нь command output-оор уншигдана.
- Kernel driver, Windows service, startup persistence суулгахгүй.
- Browser database-ийн scanner-owned temporary copy-г scan дуусмагц цэвэрлэнэ.

## Scan mode

- **Quick** — process/module/network + recent Downloads/Desktop executable/archive inspection.
- **Full (recommended/default)** — Quick дээр browser downloads, execution artifacts, deleted-file metadata, drivers/startup, Microsoft Defender no-remediation scan нэмэгдэнэ.
- **Forensic** — урт хугацаа, өндөр item limit, Temp directory Defender scan нэмэгдэнэ.

## Detection database

`DoubleGScanner\Data\rules.json`

- `knownCheats`: нэртэй exact SHA-256 entries
- `knownHashes`: legacy exact SHA-256
- `knownDomains`: баталгаатай distribution domains
- `highRiskKeywords`, `mediumRiskKeywords`: supporting rules
- `trustedPublishers`: false positive багасгах allowlist

Exact hash эсвэл Defender threat name байвал PDF дээр нэртэй гарна. Heuristic static evidence нь exact product name зохиохгүй, `REVIEW` гэж гарна.

## GitHub Actions-аар үнэгүй setup build хийх

1. Repository root дээр `.github`, `DoubleGScanner`, `Installer`, `Scripts`, `DoubleGScanner.sln` байрлуулна.
2. `Actions` → `Build DoubleG Scanner` → `Run workflow`.
3. `DoubleGScanner-installer` artifact татна.
4. ZIP дотор `DoubleGScannerSetup.exe` байна.

## Local report

```text
Documents\DoubleG Scanner\Reports\<SCAN-ID>\
```

- PDF report
- JSON evidence package
- PDF SHA-256 sidecar

## Чухал хязгаар

- Private/packed/new cheat бүрийг 100% танихгүй.
- Microsoft Defender detection нь тухайн компьютерийн Defender engine, definitions, cloud protection state-аас хамаарна.
- Encrypted/password-protected RAR/7z-ийг built-in parser бүрэн задлахгүй; ийм recent download дээр `REVIEW` гаргаж Defender module-ийн coverage-г харуулна.
- Kernel/DMA cheat-д user-mode scanner 100% баталгаа өгөхгүй.
- Production public release-ээс өмнө clean Windows 10/11 VM болон өөрийн test computer дээр QA хийнэ.
