# DoubleG Scanner v1.3.0 — Public release хийх

1. v1.3.0 source-ийн доторх бүх file/folder-ийг GitHub repository root руу хуулна. Hidden `.git` folder-ийг устгахгүй.
2. GitHub Desktop: Summary `Update DoubleG Scanner to v1.3.0 detection upgrade` → Commit to main → Push origin.
3. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
4. Ногоон run-ийн Artifacts хэсгээс `DoubleGScanner-installer` татаж test хийнэ.
5. Full scan-ийг administrator/UAC зөвшөөрөлтэй ажиллуулж `Downloaded and local file scan` болон `Microsoft Defender no-remediation scan` coverage-г шалгана.
6. Test амжилттай бол Releases → Draft a new release → tag `v1.3.0` → Publish release.
7. Tag workflow дуусмагц `DoubleGScannerSetup.exe` болон SHA-256 assets автоматаар release дээр нэмэгдэнэ.

Latest release:

```text
https://github.com/zoljargalegshiglen0-lang/doubleg-scanner/releases/latest
```

Direct setup:

```text
https://github.com/zoljargalegshiglen0-lang/doubleg-scanner/releases/latest/download/DoubleGScannerSetup.exe
```

Unsigned installer дээр SmartScreen warning гарч болно. GitHub-д public байршуулсан нь code-signing биш.
