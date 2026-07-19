# DoubleG Scanner v1.0.0 — Full source release

Windows 10/11 x64 дээр ажиллах, хэрэглэгчийн тодорхой зөвшөөрөлтэй **local-only / read-only** CS2 integrity ба forensic scanner.

## Аюулгүй байдлын үндсэн зарчим

- Сервер, webhook, telemetry, upload код байхгүй.
- Password, cookie, browser session, Discord token, autofill, card data уншихгүй.
- Хувийн зураг, бичлэг, document-ийн агуулгыг нээхгүй.
- Файл delete, quarantine, restore, modify хийхгүй. Зөвхөн scanner-ийн өөрийн түр copy-г дуусахад цэвэрлэнэ.
- Kernel driver, Windows service, startup persistence суулгахгүй.
- Screenshot, keylogger, clipboard collector, нууц background monitoring байхгүй.
- Installer нь per-user бөгөөд суулгахад admin permission шаардахгүй.
- Scan эхлэхийн өмнө хэрэглэгч consent checkbox-оор зөвшөөрнө.

## Scan mode

- **Quick** — system profile, running process, CS2 live module, live TCP connection.
- **Full** — Quick дээр browser metadata, execution history, Recycle Bin metadata, drivers/startup, recent executable/archive scan нэмэгдэнэ.
- **Forensic** — Full-ийн илүү өргөн хугацаа ба өндөр item limit ашиглана.

## Бодит collector модулиуд

1. Windows security profile, elevation state, scanner binary SHA-256
2. Running process path, start time, SHA-256, Authenticode trust
3. CS2 ажиллаж байвал loaded module path/hash/signature inspection
4. Chrome, Edge, Brave, Opera, Opera GX, Firefox-ийн зөвхөн relevant visit/download metadata
5. Prefetch, UserAssist, BAM, Recent Items execution traces
6. Recycle Bin `$I` deleted-file metadata; файл сэргээхгүй, агуулга нээхгүй
7. Registered kernel/file-system driver metadata ба Run/RunOnce/Startup entries
8. Live TCP connections ба system network counters
9. Downloads/Desktop/Temp дахь recent executable/archive metadata; ZIP-ийн entry нэр л уншина
10. Exact hash/domain, signature, path, independent-source correlation дээр суурилсан risk scoring
11. Professional PDF, JSON evidence, PDF SHA-256 sidecar report bundle

## Result

- `DETECTED` — exact known hash/domain, unsigned user-writable CS2 module, эсвэл хүчтэй independent correlation
- `REVIEW` — сэжигтэй боловч дангаараа нотолгоо биш
- `NOT DETECTED` — completed module-уудаас known high-confidence indicator олдоогүй
- `INCOMPLETE` — шаардлагатай module хангалттай бүрэн ажиллаагүй
- `CANCELLED` — хэрэглэгч scan-ийг зогсоосон

`NOT DETECTED` нь 100% cheat ашиглаагүй гэсэн баталгаа биш. Ялангуяа private kernel/DMA cheat, цэвэрлэгдсэн artifact, шинэ үл мэдэгдэх build-ийг ямар ч user-mode scanner бүрэн баталгаатай барихгүй.

## Detection database

`DoubleGScanner\Data\rules.json`

- `knownHashes`: зөвхөн баталгаатай SHA-256
- `knownDomains`: зөвхөн баталгаатай distribution domain
- `highRiskKeywords`, `mediumRiskKeywords`: supporting evidence
- `trustedPublishers`: false positive багасгах allowlist

Keyword эсвэл filename ганцаараа `DETECTED` гаргахгүй. Сайн илрүүлэлт хийхэд rules database-ийг баталгаатай sample-аар тогтмол шинэчилнэ.

## Windows дээр build хийх

Шаардлага:

- Visual Studio Community 2026 + `Desktop development with .NET`, эсвэл .NET 10 SDK
- Setup EXE хийх бол Inno Setup 6

Visual Studio-д `DoubleGScanner\DoubleGScanner.csproj` нээгээд `Release | x64` сонгон build хийнэ.

Portable/self-contained release:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Scripts\Build-Release.ps1
```

Setup EXE:

```powershell
.\Scripts\Build-Installer.ps1
```

Output:

```text
Release\win-x64\DoubleGScanner.exe
Release\Installer\DoubleGScannerSetup_v1.0.0.exe
```

## GitHub Actions-аар үнэгүй build хийх

1. Энэ folder-ийн бүх файлыг GitHub repository руу upload/push хийнэ.
2. `Actions` → `Build DoubleG Scanner` → `Run workflow`.
3. Дууссаны дараа Artifacts-аас installer болон portable build татна.

Дэлгэрэнгүй: `BUILD_WITH_GITHUB_MN.md`.

## Report

```text
Documents\DoubleG Scanner\Reports\<SCAN-ID>\
```

Үүсэх файл:

- `DoubleG-Scanner_Report_<SCAN-ID>.pdf`
- `DoubleG-Scanner_Evidence_<SCAN-ID>.json`
- `DoubleG-Scanner_Report_<SCAN-ID>.pdf.sha256.txt`

## SmartScreen ба баталгаа

Source read-only байсан ч unsigned шинэ installer дээр Windows `Unknown publisher`/SmartScreen анхааруулга харуулж болно. Үүнийг хуурамч аргаар арилгах ёсгүй. Public тараахдаа code-signing certificate эсвэл Microsoft Store distribution ашиглана.

## Бодит хязгаар

- Kernel driver суулгахгүй тул бүх kernel cheat-ийг 100% барихгүй.
- DMA-г ердийн user-mode app 100% тогтоохгүй.
- SSD TRIM болсон arbitrary deleted content сэргээхгүй; Windows-д үлдсэн metadata trace шалгана.
- CS2 ажиллаагүй бол live module inspection partial гарна.
- Historical per-process byte usage бүх Windows системд найдвартай байдаггүй; одоогийн build live TCP ба cumulative interface counters гаргана.
- Production release хийхээс өмнө Windows 10/11 test machine, clean VM, standard user/admin нөхцөлд QA хийнэ.
