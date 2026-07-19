# DoubleG Scanner v1.9.4 UI hotfix

## Өөрчлөлт

Live Analysis card дээр байсан `READ ONLY` badge-ийг бүрэн арилгасан.

Scanner-ийн:
- scan logic
- read-only collection
- privacy
- detection
- PDF/JSON report
- NTFS forensic scan
- Defender timeout fix

өөрчлөгдөөгүй.

## GitHub-д оруулах

1. `DoubleGScanner_v1.9.4_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файлыг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary: `Remove v1.9.4 read only badge`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
