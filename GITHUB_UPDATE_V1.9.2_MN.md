# DoubleG Scanner v1.9.2 UI hotfix

## Зассан асуудал

`Forensic scan` сонголт consent checkbox болон button хэсгийн доогуур орж
давхцаж байсан layout алдааг зассан.

- Scan mode мөрүүд Auto height болсон.
- Radio card padding/spacing багассан.
- Forensic тайлбар нэг мөрөнд багтана.
- Consent хэсгийн дээр тогтмол зай нэмэгдсэн.
- Quick, Full, Forensic гурвуулаа бүрэн харагдана.

## GitHub-д оруулах

1. `DoubleGScanner_v1.9.2_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файлыг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary: `Fix v1.9.2 forensic scan layout overlap`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Хуучин failed run-ийг Re-run хийхгүй.

## Шалгах

Scan Profile дээр:

- Quick scan
- Full scan
- Forensic scan
- Consent checkbox
- Cancel / Start Scan buttons

хоорондоо давхцахгүй, бүрэн харагдана.
