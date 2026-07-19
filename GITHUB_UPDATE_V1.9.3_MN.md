# DoubleG Scanner v1.9.3 — Defender hang fix

## Зассан асуудал

Scanner `Microsoft Defender no-remediation scan` дээр 85–88%-д зогсож,
цааш үргэлжлэхгүй байсан алдааг зассан.

Шинэ ажиллагаа:

- UI хоёр секунд тутам target болон elapsed time харуулна.
- Downloads: 90 секундийн safety timeout
- Desktop: 60 секундийн safety timeout
- Temp: 60 секундийн safety timeout
- Timeout бол Defender process-ийг зогсооно.
- Тухайн module `Partial` болж, бусад scan үргэлжилнэ.
- Cancel хийхэд Defender process tree хамт зогсоно.

## GitHub-д оруулах

1. `DoubleGScanner_v1.9.3_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файлыг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary:
   `Fix v1.9.3 Microsoft Defender scan hang`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Хуучин run дээр Re-run хийхгүй.

## Test

Forensic Scan эхлүүлэхэд Defender хэсэг дээр:

`Scanning Downloads • target 1/3 • 00:18 elapsed • safety limit 01:30`

гэж хөдөлж харагдана.

Target safety timeout хүрвэл:

`Downloads reached the safety timeout; continuing to the next module.`

гэж гараад scan цааш үргэлжилнэ.
