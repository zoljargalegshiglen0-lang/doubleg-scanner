# DoubleG Scanner v1.9.1 build fix

## Зассан зүйл

- `ReadOnlySpan<byte> cannot be preserved across a yield boundary`
- `SystemProfileCollector does not exist in the current context`
- GitHub Actions Node.js 20 deprecation warning

## GitHub-д оруулах

1. `DoubleGScanner_v1.9.1_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файл болон `.github` folder-ийг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary: `Fix v1.9.1 forensic build errors`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Failed болсон хуучин run-ийг Re-run хийхгүй. Шинэ run үүсгэнэ.

Workflow:
- actions/checkout@v6
- actions/setup-dotnet@v5
- actions/upload-artifact@v6
