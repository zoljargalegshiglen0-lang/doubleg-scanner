# DoubleG Scanner v2.1.6

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


## v1.9.5 Quick deleted-download detection

- Quick Scan includes recent browser downloads and missing-file status.
- Recent Recycle Bin executable/archive traces are included.
- Elevated Quick Scan includes a capped USN deletion check.
- Generic deleted executables remain review evidence rather than confirmed cheat detections.


## v1.10.0 Kernel & Driver Integrity

- Loaded kernel driver enumeration, path resolution, signature, publisher and SHA-256.
- VBS, Memory Integrity, Code Integrity policy, DMA capability and driver-blocklist posture.
- Full/Forensic Code Integrity and driver-service event collection.
- Exact vulnerable-driver hash support and non-conclusive filename heuristics.
- No custom `.sys` driver and no kernel memory modification.


## v1.11.0 scan tier mapping

- Quick = previous Full Scan.
- Full = previous Forensic Scan.
- Forensic = Full disk forensics + Kernel & Driver Integrity.
- Kernel integrity now runs only in Forensic mode.


## v2.0.0 real kernel-mode scanner

- Added `DoubleGKernel.sys`, a read-only KMDF control driver.
- Kernel-mode loaded-module enumeration uses `AuxKlibQueryModuleInformation`.
- Forensic Scan is Incomplete when the signed driver is unavailable.
- Kernel addresses and arbitrary memory operations are not exposed.
- CI driver artifacts are unsigned development builds and are not silently shipped.


## v2.1.0 report polish

- PDF report now separates **Cheat Detection Summary** from neutral supporting review items.
- Only the main detected cheat cards are highlighted in red.
- Browser history, last activity, network/data usage, local files, kernel & drivers, deleted traces, and Defender results each get their own article section.
- Added DoubleG logo and stronger brand color styling to the PDF.
- Non-primary review items use neutral wording so generic installers and technical traces are easier to interpret.


## v2.1.1 finding deduplication

- One named cheat is displayed once, regardless of how many collectors found it.
- Repeated kernel-driver correlation results are summarized by rule.
- Combined cards preserve evidence count, sources, and sample artifact paths.


## v2.1.2 build fix

- Standard scanner installer no longer tries to package a missing unsigned kernel driver.
- Kernel driver remains a separate workflow/artifact.
- Report nullable and certificate API warnings were cleaned up.


## v2.1.3 shortcut and alias detection

- Detects named cheat-family traces from Recent Items `.lnk` and `.url` shortcuts.
- Reads shortcut target/arguments without executing the referenced file.
- Adds Undetek and a broader curated CS2 family/alias database.
- Ambiguous names use exact or controlled version-prefix matching to reduce false positives.


## v2.1.4 expanded cheat-family database

- Added every name in the supplied CS2 cheat/family/source list.
- Uses longest/best alias resolution for similarly named products.
- Community release forums are classified as review sources, not automatically as a confirmed cheat.
- The list remains updateable through `Data/rules.json`; private/rebranded names can still require future updates.


## v2.1.5 browser recovery and all-disk search

- Added the latest supplied cheat-family names, including separate Neverloose, Predator, and Phantom entries.
- Named browser history/download matches are highlighted red in the PDF.
- Samples SQLite WAL, rollback-journal, and freelist pages for possible deleted named browser traces.
- Quick, Full, and Forensic scan all ready fixed/removable volumes with bounded read-only sweeps.


## v2.1.6 build fix

- Fixed invalid escaped backslash character literals in the all-disk root-path check.
- No scan behavior was removed.
