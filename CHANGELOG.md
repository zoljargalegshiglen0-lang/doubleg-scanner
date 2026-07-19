# Changelog

## 1.9.2
- Fixed the Forensic Scan card overlapping the consent checkbox.
- Changed the Scan Profile content rows to Auto sizing.
- Reduced scan-mode padding and vertical spacing.
- Added guaranteed spacing above consent and action buttons.
- Increased the top dashboard row slightly for display-scaling compatibility.
- Preserved all v1.9.1 scan, NTFS forensic, detection and report behavior.

## 1.9.1
- Fixed all ReadOnlySpan/yield compiler errors in the raw signature scanner.
- Fixed the missing SystemProfileCollector namespace in MainWindow.
- Updated official GitHub Actions to Node.js 24-compatible majors.
- Preserved the v1.9.0 MFT, USN Journal and free-cluster forensic behavior.

## 1.9.0
- Fixed the hidden/clipped Forensic Scan selection.
- Added automatic UAC restart prompt for Forensic Scan.
- Added read-only NTFS MFT metadata enumeration.
- Added recent USN change/deletion journal inspection.
- Added capped unallocated-cluster executable/archive signature sampling.
- Added forensic evidence to PDF and JSON reports.
- Forensic verdict becomes Incomplete when required disk-level modules are unavailable.
- No recovered content is restored or written to disk.

## 1.8.0
- Reworked the interface using DoubleG website black and deep-red colors.
- Added template-style rounded gradient buttons.
- Replaced navigation buttons with checked-state radio navigation.
- Fixed Overview, Findings and Coverage active backgrounds.
- Fixed unreadable black text in cards and tables.
- Preserved all scan, detection and report behavior.

## 1.7.0
- Rebuilt UI to match a clean dashboard template more closely.
- Added compact sidebar navigation and separate Dashboard, Findings and Module pages.
- Removed all hardcoded version badges from the UI.
- Version now reads automatically from AssemblyInformationalVersion.
- Updated csproj, installer, manifest, rules and security manifest to 1.7.0.
- Preserved detection, collectors, JSON evidence and English PDF reporting.

## 1.6.1
- Removed all Mongolian text and bilingual labels from the generated PDF report.
- PDF report is now English-only with cleaner professional terminology.
- Scanner UI, detection logic, collectors, JSON evidence, and dashboard design are unchanged.

## 1.4.0
- Added compact rounded custom-window UI and dark title bar.
- Reduced default window size and removed unnecessary visual clutter.
- Added curated named-cheat alias rules and independent named-evidence correlation.
- Reduced false positives for ordinary unsigned installers and generic archives.
- Added bilingual English/Mongolian PDF verdicts, labels, explanations, and limitations.
- Updated version, installer, manifest, and release documentation.

## 1.3.0
- Fixed false `NOT DETECTED` results for many downloaded-but-not-executed executable/archive files.
- Full scan is now the default profile.
- Quick scan now inspects recent Downloads/Desktop executable and archive artifacts.
- Added static CS2/cheat/injection indicator correlation for binaries.
- Added read-only ZIP/JAR embedded payload inspection without extraction.
- Added conservative `REVIEW` findings for recent unsigned executables, executable archives, and unreadable/encrypted recent archives.
- Added browser-download + local-file correlation without requiring execution.
- Added Microsoft Defender custom scan integration using `-DisableRemediation`.
- Defender threat names and artifact paths now appear in PDF/JSON findings.
- Added Microsoft Defender coverage to the report.
- Updated UI descriptions, rules, privacy documentation, manifest and version to 1.3.0.

## 1.2.0
- Complete DoubleG black/red visual redesign.
- Added DoubleG logo and premium scan UI.

## 1.1.1
- Fixed System.IO imports, MigraDoc color parsing and Inno Setup detection.

## 1.1.0
- Added named exact SHA-256 cheat signatures and public GitHub release workflow.
