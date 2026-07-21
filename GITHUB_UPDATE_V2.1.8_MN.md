# DoubleG Scanner v2.1.8 — Not Responding Fix

## Яагаад Not Responding болсон бэ?

Disk metadata sweep олон file дээр дараалж ажиллах үед deep-inspection `await`
хүртэл synchronous loop нь WPF UI dispatcher thread дээр ажиллаж байсан.

Scanner data шалгаж байсан ч Windows UI message боловсруулах боломжгүй болж:

`DoubleG Scanner (Not Responding)`

гэж харагдсан.

## Засвар

v2.1.8 дээр:

- ScanCoordinator бүхэлдээ background thread дээр ажиллана
- PDF/JSON report background thread дээр үүснэ
- Progress UI thread рүү safe байдлаар очно
- Progress update burst-ийг coalesce хийнэ
- Cancel дарахад шууд `Cancelling scan` гэж харагдана
- Window move/minimize хийх боломжтой хэвээр байна

Scan coverage болон detection хасагдаагүй.

## GitHub update

1. `DoubleGScanner_v2.1.8_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Fix Not Responding UI v2.1.8`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner` → шинэ run ажиллуулна.
7. Шинэ build-ээ суулгаад scan дахин хийнэ.
