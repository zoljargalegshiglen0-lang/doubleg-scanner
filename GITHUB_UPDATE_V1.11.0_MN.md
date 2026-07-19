# DoubleG Scanner v1.11.0 — Scan tier rebalance

## Шинэ бүтэц

### Quick Scan
Одоогийн хуучин Full Scan-ийн бүх шалгалт:

- Browser history/downloads
- Process, CS2 modules, network
- Prefetch, UserAssist, BAM, Recent Items
- Recycle Bin deleted traces
- Drivers and startup persistence
- Downloads/Desktop/Temp recursive file scan
- 120 хоног / 7,000 хүртэл файл
- Microsoft Defender Downloads + Desktop

### Full Scan
Одоогийн хуучин Forensic Scan-ийн бүх шалгалт:

- Quick-ийн бүх module
- NTFS MFT
- USN Journal
- Unallocated executable/archive signatures
- 365 хоног / 18,000 хүртэл файл
- Defender Temp scan

### Forensic Scan
Full Scan-ийн бүх шалгалт дээр:

- Loaded kernel drivers
- Driver signature, publisher, SHA-256
- VBS / Memory Integrity / DMA posture
- Code Integrity events
- Driver service installation events
- Kernel driver correlation

## Administrator

Full болон Forensic Scan дээр START SCAN дарахад UAC permission автоматаар хүснэ.

## GitHub update

1. `DoubleGScanner_v1.11.0_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → doubleg-scanner → Repository → Show in Explorer.
3. Patch доторх бүх файлыг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Summary:
   `Rebalance scan tiers in v1.11.0`
6. `Commit to main` → `Push origin`.
7. GitHub → Actions → Build DoubleG Scanner → Run workflow → main.
8. Хуучин run дээр Re-run хийхгүй.

## Test

- Quick Coverage дээр Kernel & driver integrity нь Skipped байна.
- Quick дээр Execution history, Drivers and startup persistence, Defender ажиллана.
- Full эхлэхэд UAC хүснэ.
- Full Coverage дээр MFT, USN, Unallocated ажиллана; Kernel skipped байна.
- Forensic Coverage дээр MFT, USN, Unallocated болон Kernel & driver integrity бүгд ажиллана.
