# DoubleG Scanner v1.9.0 — GitHub update

1. `DoubleGScanner_v1.9.0_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → `doubleg-scanner` → Repository → Show in Explorer.
3. Patch доторх бүх файл/folder-ийг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary:
   `Add v1.9.0 NTFS forensic scan`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Хуучин run дээр Re-run хийхгүй.
9. Build ногоон бол Artifacts → DoubleGScanner-installer татна.

## Test

1. Шинэ setup-ийг install хийнэ.
2. Scan Profile дээр Quick, Full, Forensic гэсэн 3 сонголт харагдана.
3. Forensic Scan сонгоод START SCAN дарна.
4. Standard user бол Windows UAC-аар administrator restart санал болгоно.
5. Coverage дээр дараах module-ууд харагдана:
   - NTFS MFT metadata
   - USN change journal
   - Unallocated-space signature scan
6. Administrator permission өгөөгүй бол verdict нь INCOMPLETE байна.

Raw scan нь файл сэргээж хадгалахгүй. Зөвхөн free cluster доторх PE/ZIP/RAR/7z/MSI signature болон cheat-related strings/static indicators-ийг memory дотор шалгана.
