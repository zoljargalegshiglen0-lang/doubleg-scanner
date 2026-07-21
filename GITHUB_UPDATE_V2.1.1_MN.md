# DoubleG Scanner v2.1.1 — Duplicate Finding Fix

## Зассан зүйл

Нэг cheat олон эх сурвалжаас илэрсэн үед одоо нэг л удаа гарна.

Жишээ:

- `ExLoader_Installer.exe`
- `ExLoader_Installer.zip`
- USN deleted trace
- Browser download
- MFT metadata

дээр тус тусдаа 5 finding биш:

`ExLoader — 1 combined finding`

гэж гарна.

Kernel finding мөн адил:

`DGS-KERNEL-CORR-013`

driver бүр дээр тусдаа card үүсгэхгүй. Нэг summary card дотор:

- хэдэн record нэгтгэгдсэн
- ямар source-ууд байсан
- sample artifact path-ууд

харагдана.

## GitHub update

1. `DoubleGScanner_v2.1.1_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Fix duplicate cheat and kernel findings v2.1.1`

5. `Commit to main` → `Push origin`.
6. GitHub Actions дээр шинэ build ажиллуулна.

## Анхаарах зүйл

Өмнө нь үүссэн PDF автоматаар өөрчлөгдөхгүй.

v2.1.1-ээр шинэ scan хийж, шинэ PDF report гаргана.
