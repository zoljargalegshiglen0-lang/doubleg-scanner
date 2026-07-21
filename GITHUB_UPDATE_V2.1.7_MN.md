# DoubleG Scanner v2.1.7 — Faster All-Disk Scan

## Яагаад удаж байсан бэ?

v2.1.6 Forensic Scan бүх disk дээрх `.exe`, `.dll`, `.sys`, archive бүрт:

- signature
- SHA-256
- static analysis
- archive content analysis

хийж байсан. Тиймээс Windows болон Program Files дотор хэдэн мянган энгийн
файл дээр хэт удаж байсан.

## Шинэ ажиллагаа

### Stage 1 — Fast metadata sweep

Бүх ready Fixed/Removable disk дээр:

- filename
- folder/path
- extension
- date
- size
- family alias

хурдан шалгана.

### Stage 2 — Deep inspection

Зөвхөн:

- known family name
- suspicious keyword
- Downloads
- user-writable folder
- recent candidate
- suspicious archive

дээр hash/signature/static/archive analysis хийнэ.

## Хугацааны хязгаар

- Quick disk stage: ойролцоогоор 75 секунд
- Full disk stage: ойролцоогоор 3 минут
- Forensic disk stage: ойролцоогоор 5 минут
- Нэг файл: Quick 4 сек / Full 8 сек / Forensic 12 сек

Хязгаарт хүрвэл module `PARTIAL` болж, scanner цааш үргэлжилнэ.

## Progress

Одоо:

`Fast disk sweep: 25,000 candidates, 420 deep checks — Fixed disk C:\`

гэж байнга шинэчлэгдэнэ.

## GitHub update

1. `DoubleGScanner_v2.1.7_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Speed up all disk scan v2.1.7`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner` → шинэ run.
7. Хуучин failed/success run дээр Re-run хийхгүй.
