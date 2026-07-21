# DoubleG Scanner v2.1.10 — NTFS Scope Build Fix

## Алдаа

GitHub Actions дээр:

```text
The name 'MaxBytesPerVolume' does not exist in the current context
The name 'MaxCandidates' does not exist in the current context
The name 'maxBytesPerVolume' does not exist in the current context
The name 'maxCandidates' does not exist in the current context
```

гэж гарсан.

## Шалтгаан

`maxBytesPerVolume`, `maxCandidates` declaration-ууд
`NtfsMftCollector` дотор буруу орсон байсан.

Гэтэл эдгээрийг ашиглаж байгаа газар нь:

`UnallocatedSpaceCollector`

юм.

## Засвар

Declaration-уудыг зөв collector method руу шилжүүлсэн.

v2.1.9-ийн:

- rotating wheel
- elapsed timer
- Forensic completion mode
- browser recovery
- all-disk scan
- PDF report
- cheat family database

бүгд хэвээр.

## GitHub update

1. `DoubleGScanner_v2.1.10_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Fix NTFS variable scope build error v2.1.10`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner` → шинэ run ажиллуулна.
7. Хуучин failed run дээр Re-run хийхгүй.
