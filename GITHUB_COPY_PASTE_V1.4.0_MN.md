# DoubleG Scanner v1.4.0 — GitHub руу шууд солих

## 1. ZIP задлах

`DoubleGScanner_v1.4.0_CompactNamedDetection_FullSource.zip` → Right click → Extract All.

## 2. GitHub Desktop

1. GitHub Desktop нээнэ.
2. `doubleg-scanner` repository сонгоно.
3. `Repository → Show in Explorer` дарна.
4. Repository доторх харагдаж байгаа хуучин source file/folder-уудыг устгана.
5. Hidden `.git` folder-ийг огт устгахгүй.
6. Шинэ v1.4.0 folder-ийн **доторх бүх зүйл**-ийг repository root руу copy/paste хийнэ.

Зөв бүтэц:

```text
doubleg-scanner/
├── .github/
├── Docs/
├── DoubleGScanner/
├── Installer/
├── Scripts/
└── DoubleGScanner.sln
```

## 3. Commit / Push

Summary:

```text
Update DoubleG Scanner to v1.4.0 compact named detection
```

`Commit to main` → `Push origin`.

## 4. Setup build

GitHub website → Actions → Build DoubleG Scanner → Run workflow → main → Run workflow.

Шинэ run ногоон бол доод талын Artifacts-аас `DoubleGScanner-installer` татна.

## 5. Public release

Test амжилттай бол Releases → Draft a new release:

- Tag: `v1.4.0`
- Title: `DoubleG Scanner v1.4.0`

Publish release хийхэд installer asset автоматаар нэмэгдэнэ.
