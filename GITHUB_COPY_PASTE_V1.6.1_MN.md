# DoubleG Scanner v1.6.1 PDF English-only update

Энэ update зөвхөн PDF тайлангийн Монгол болон bilingual текстийг авсан.
Scanner UI, detection engine, collectors болон rules өөрчлөгдөөгүй.

## GitHub update
1. Replace package ZIP-ийг задлана.
2. Доторх файлуудыг cloned `doubleg-scanner` repository root руу copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. GitHub Desktop дээр commit message: `Update PDF report to English-only v1.6.1`
5. `Commit to main` дараад `Push origin` дарна.
6. GitHub -> Actions -> Build DoubleG Scanner -> Run workflow.
7. Шинэ workflow run-ийн Artifacts хэсгээс installer татна.

## Updated files
- DoubleGScanner/Services/ReportService.cs
- DoubleGScanner/DoubleGScanner.csproj
- Installer/DoubleGScanner.iss
- CHANGELOG.md
