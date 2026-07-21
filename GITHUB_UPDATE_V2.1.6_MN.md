# DoubleG Scanner v2.1.6 — Build Fix

## Алдаа

GitHub Actions дээр:

- `Too many characters in character literal`
- `Newline in constant`
- `Syntax error, ',' expected`
- `) expected`

гэсэн алдаа гарсан.

Шалтгаан нь `ForensicCollectors.cs` дотор Windows path-ийн backslash char
буруу escape хийгдсэн байсан.

## Засвар

Буруу:

```csharp
TrimEnd('\')
```

Зөв C# source:

```csharp
TrimEnd('\\')
```

Хоёр мөрийг зассан. v2.1.5-ийн:

- browser residual recovery
- бүх disk scan
- cheat family database
- PDF report
- duplicate finding fix

бүгд хэвээр.

## GitHub update

1. `DoubleGScanner_v2.1.6_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Fix backslash build error v2.1.6`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner`.
7. Failed хуучин run дээр Re-run хийхгүй; шинэ run ажиллуулна.
