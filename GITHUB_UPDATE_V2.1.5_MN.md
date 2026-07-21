# DoubleG Scanner v2.1.5

## Нэмэгдсэн family

- Sysware
- Astral
- Ech0
- Predator
- Weebware
- Omniaim
- Precision Cheats
- Abyss
- Redeye Cheats
- 420Cheats
- 5DollarCheats
- Neverloose
- HVHGod
- Phantom

`Neverloose` нь `Neverlose`-оос тусдаа.

`Predator` болон `Predator Systems`, `Phantom` болон `Phantom Overlay`
тусдаа family хэвээр.

## Browser history

Known family нэр browser title, URL, download history-д таарвал PDF дээр
улаан detection card болж гарна.

## Устгасан browser history

Scanner дараах SQLite residual хэсгүүдийг read-only sample хийнэ:

- WAL
- Rollback journal
- Freelist pages

Нэр/domain fragment үлдсэн бол `Recovered browser trace` гэж гарна.

Энэ recovery нь баталгаатай биш. Browser VACUUM хийсэн, SSD TRIM ажилласан,
эсвэл data overwrite болсон бол олдохгүй байж болно. Recovered fragment-ийн
visit time найдвартай биш.

## Бүх disk

Quick, Full, Forensic бүгд:

- бүх ready Fixed disk
- бүх ready Removable disk

дээр `.exe`, `.dll`, `.sys`, archive, `.lnk`, `.url` болон family нэртэй
artifact хайна.

Scan хэт удахгүй байлгахын тулд mode бүр item/time cap-тай.

## GitHub update

1. `DoubleGScanner_v2.1.5_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Add browser recovery and all disk scan v2.1.5`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner` → шинэ run.
