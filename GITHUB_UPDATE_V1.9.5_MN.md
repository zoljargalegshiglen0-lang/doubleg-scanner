# DoubleG Scanner v1.9.5 — Quick deleted-download update

## Өөрчлөлт

Quick Scan одоо:

- Chrome, Edge, Brave, Opera GX, Firefox recent download record шалгана.
- Татсан `.exe/.dll/.sys/.zip/.rar/.7z/.msi` файл одоо байхгүй бол Findings-д гаргана.
- Recycle Bin-ийн recent executable/archive metadata шалгана.
- Administrator эрхтэй бол recent USN delete events шалгана.
- Browser download болон deletion trace-ийн ижил filename-ийг хооронд нь тулгана.

Known cheat name/domain таарвал хүчтэй finding гарна.

Ерөнхий нэртэй устсан executable/archive-ийг шууд cheat гэж худал батлахгүй:
`Downloaded executable/archive was later deleted — REVIEW`

Raw unallocated disk scan зөвхөн Forensic Scan-д хэвээр.

## GitHub-д оруулах

1. `DoubleGScanner_v1.9.5_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файлыг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary: `Add v1.9.5 Quick deleted download detection`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Хуучин run-ийг Re-run хийхгүй.

## Test

1. Known cheat нэртэй test `.zip` эсвэл `.exe`-г browser-оор татна.
2. Файлыг устгана.
3. Quick Scan ажиллуулна.
4. Findings дээр browser missing-file trace гарна.
5. Recycle Bin эсвэл USN trace байвал correlated deleted-download finding гарна.

Жинхэнэ malware/cheat ажиллуулах шаардлагагүй. Аюулгүй dummy test filename ашиглана.
