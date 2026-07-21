# DoubleG Scanner v2.1.3 — Shortcut & Cheat Alias Detection

## Зассан зүйл

`undetek-v10.4.0.lnk` шиг Recent Items shortcut-ийг одоо:

- Shortcut filename
- Target path
- Arguments
- Working directory
- Internet Shortcut URL

гээд бүгдээр нь шалгана.

Shortcut target-ийг ажиллуулахгүй, зөвхөн metadata уншина.

## Cheat family database

`Undetek` нэмэгдсэн.

Мөн одоогийн жагсаалтыг илүү өргөн public CS2 family/alias-уудаар
нэмэгдүүлсэн. Нэг cheat олон trace-тэй байсан ч v2.1.1-ийн дагуу нэг combined
finding болж гарна.

Private болон байнга rebrand хийдэг cheat-үүд байдаг тул database нь
`rules.json`-аар цааш шинэчлэгдэх боломжтой curated list хэвээр.

## GitHub update

1. `DoubleGScanner_v2.1.3_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх file/folder-ийг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Add shortcut and Undetek alias detection v2.1.3`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner` → шинэ run ажиллуулна.

## Test

1. `%APPDATA%\Microsoft\Windows\Recent` дотор
   `undetek-v10.4.0.lnk` байгаа компьютерт scan хийнэ.
2. Findings дээр `Undetek` named execution trace гарна.
3. Олон Undetek trace байвал нэг combined finding болж гарна.
