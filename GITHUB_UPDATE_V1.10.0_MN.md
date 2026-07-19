# DoubleG Scanner v1.10.0 — Kernel & Driver Integrity

## Нэмэгдсэн module

`Kernel & driver integrity`

Quick, Full, Forensic Scan бүгд дээр loaded kernel driver болон Windows kernel
security posture шалгана.

Full / Forensic дээр нэмээд:

- Code Integrity Operational event
- Driver-service installation event
- Driver path / signature / publisher / SHA-256
- VBS and Memory Integrity status
- Kernel DMA Protection capability
- Vulnerable Driver Blocklist configuration
- Loaded `.sys` + browser/file/deleted/USN correlation

Энэ нь custom kernel driver биш. `.sys` суулгахгүй, kernel memory өөрчлөхгүй.

## GitHub-д оруулах

1. `DoubleGScanner_v1.10.0_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файл/folder-ийг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary:
   `Add v1.10.0 kernel and driver integrity scan`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Хуучин failed run дээр Re-run хийхгүй.

## Test

1. Scanner-ийг Administrator эрхтэй нээнэ.
2. Quick Scan ажиллуулна.
3. Coverage дээр `Kernel & driver integrity` харагдана.
4. PDF дээр:
   - KERNEL SECURITY POSTURE
   - LOADED KERNEL DRIVERS
   - CODE INTEGRITY / DRIVER EVENTS
   хэсгүүд гарна.
5. Full Scan ажиллуулж Code Integrity event collection шалгана.

Filename heuristic match нь шууд cheat detection биш бөгөөд Review хэлбэрээр гарна.
Exact vulnerable-driver SHA-256 match эсвэл user-writable path-аас loaded driver бол
илүү хүчтэй finding гарна.
