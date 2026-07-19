# DoubleG Scanner v1.9.4

## New Forensic Scan

The third scan mode is now always visible in the Scan Profile card.

Forensic Scan adds three read-only NTFS modules:

- NTFS MFT metadata enumeration
- USN change/deletion journal inspection
- Unallocated-space executable/archive signature sampling

The scanner does not restore recovered content to disk. It does not recover
photos, documents, browser databases, or private messages. Raw-volume analysis
is limited to executable/archive signatures and cheat-related static evidence.

Administrator access is required. When Forensic Scan is started as a standard
user, DoubleG Scanner offers to restart through Windows UAC.

## Important limits

- MFT metadata does not prove that a file was executed.
- USN records can be cleared or overwritten.
- Free-cluster sampling is capped for performance and privacy.
- SSD TRIM or overwritten clusters can permanently remove deleted content.
- A completed scan cannot guarantee detection of every private, kernel, or DMA cheat.


## v1.9.1 build fix

- Fixed raw-signature ReadOnlySpan iterator compilation.
- Fixed the collector namespace used by the administrator prompt.
- Updated GitHub Actions to Node.js 24-compatible majors.


## v1.9.2 layout fix

- Fixed Forensic Scan overlapping the consent/actions area.
- Compact scan-mode cards now fit cleanly at supported display scales.


## v1.9.3 Defender reliability fix

- Defender target scans have visible heartbeat updates.
- Every target has a strict safety timeout.
- Timed-out targets are stopped and reported as Partial instead of freezing the application.


## v1.9.4 UI hotfix

- Removed the READ ONLY badge from the Live Analysis header.
