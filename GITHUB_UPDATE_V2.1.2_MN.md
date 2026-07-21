# DoubleG Scanner v2.1.2 — Build Fix

## Зассан алдаа

GitHub Actions дээр:

`Build DoubleG Scanner → Process completed with exit code 1`

гарч байсан installer build алдааг зассан.

Regular scanner installer одоо unsigned/missing kernel driver-г package хийхгүй.
Kernel driver нь тусдаа `Build DoubleG Kernel Driver` workflow дээр хэвээр.

## GitHub update

1. `DoubleGScanner_v2.1.2_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Fix scanner installer build v2.1.2`

5. `Commit to main` → `Push origin`.
6. GitHub → Actions → `Build DoubleG Scanner` → `Run workflow`.
7. Failed #15 run дээр Re-run хийхгүй. Шинэ run үүсгэнэ.
