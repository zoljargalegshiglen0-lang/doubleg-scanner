# DoubleG Scanner v1.3.0 — GitHub setup

## 1. Шинэ source-оо repository-д тавих

1. `DoubleGScanner_v1.3.0_DetectionUpgrade_FullSource.zip`-ийг Extract All хийнэ.
2. GitHub Desktop → repository `doubleg-scanner` → Repository → Show in Explorer.
3. Clone folder-ийн харагдаж байгаа хуучин source-ийг устгана. Hidden `.git` folder-ийг устгахгүй.
4. Задалсан v1.3.0 folder-ийн **доторх** бүх file/folder-ийг repository root руу хуулна.
5. Root дээр `.github`, `DoubleGScanner`, `Installer`, `Scripts`, `DoubleGScanner.sln` шууд харагдах ёстой.
6. GitHub Desktop Summary: `Update DoubleG Scanner to v1.3.0 detection upgrade`.
7. Commit to main → Push origin.

## 2. Setup build хийх

1. GitHub website → Actions.
2. `Build DoubleG Scanner`.
3. `Run workflow` → branch `main` → `Run workflow`.
4. Ногоон болсон run-ийн `Artifacts` хэсгээс `DoubleGScanner-installer` татна.
5. ZIP дотор `DoubleGScannerSetup.exe` байна.

## 3. Test хийх

1. Setup install/upgrade хийнэ.
2. DoubleG Scanner нээхэд UAC гарвал зөвшөөрнө.
3. Default `Full scan` → consent → Start scan.
4. Coverage дээр `Downloaded and local file scan` болон `Microsoft Defender no-remediation scan` completed эсэхийг шалгана.
5. Downloaded executable/archive байгаа бол PDF Findings хэсгийг шалгана.

## 4. Public release

1. Releases → Draft a new release.
2. Tag: `v1.3.0`.
3. Title: `DoubleG Scanner v1.3.0`.
4. Publish release.
5. Tag workflow дуусмагц installer assets release дээр автоматаар нэмэгдэнэ.

Public latest link:

```text
https://github.com/zoljargalegshiglen0-lang/doubleg-scanner/releases/latest
```

Direct setup link:

```text
https://github.com/zoljargalegshiglen0-lang/doubleg-scanner/releases/latest/download/DoubleGScannerSetup.exe
```
