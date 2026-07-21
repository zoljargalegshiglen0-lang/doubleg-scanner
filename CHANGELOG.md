# Changelog

## 2.1.6
- Fixed GitHub Actions C# syntax errors in `ForensicCollectors.cs`.
- Corrected two Windows path trimming character literals from invalid `TrimEnd('\')` source syntax to valid escaped backslash literals.
- Preserved v2.1.5 browser residual recovery, all-disk scanning, family database, PDF report, and kernel integration behavior.

## 2.1.5
- Added Sysware, Astral, Ech0, Predator, Weebware, Omniaim, Precision Cheats, Abyss, Redeye Cheats, 420Cheats, 5DollarCheats, Neverloose, HVHGod, and Phantom.
- Neverloose is a separate canonical family from Neverlose.
- Predator remains separate from Predator Systems; Phantom remains separate from Phantom Overlay.
- Named browser visits and downloads now create red-highlighted report cards.
- Added read-only recovery of named browser fragments from SQLite WAL, rollback-journal, and freelist pages.
- Recovered browser fragments are explicitly marked as possible deleted/stale history with no reliable timestamp.
- Added all-ready-fixed/removable-volume artifact sweep to Quick, Full, and Forensic scans.
- Named-family paths are checked regardless of age; generic candidates use mode-specific date, item, and time limits.
- Added `.url` files to the all-disk artifact sweep.
- Preserved one-family/one-combined-finding consolidation.

## 2.1.4
- Added every cheat/family/source name supplied in the current user list.
- Expanded the curated database from 45 entries to a larger family set.
- Added Hexui, Melatonin, Valthrun, VisionCloud, Asphyxia, En1gma, ArtificialAiming, InvisionCheats, PerfectAim, EngineOwning, VRedux, Nightfall, SharkHack, DragonBurn, Voidware, Externity, Koryo, Fecurity, Novoline, Aurora, Ev0lve, DMA families, and other supplied names.
- Added Midnight Lite, Airflow Reloaded, and Moonlight DMA as separate canonical families.
- Added Elitepvpers Releases and UnknownCheats Releases as community release sources rather than confirmed single cheat products.
- Replaced first-match alias resolution with best-match resolution.
- Exact matches outrank version-prefix matches, and version-prefix matches outrank broad distinctive aliases.
- Prevented `Midnight Lite` from being reduced to `Midnight`, `Airflow Reloaded` to `Airflow`, and `Moonlight DMA` to `Moonlight`.
- Canonical family names no longer automatically perform unsafe broad substring matching.
- Preserved Recent Items shortcut metadata scanning and one-cheat/one-finding consolidation.

## 2.1.3
- Added Undetek as a named CS2 cheat family, including versioned shortcut aliases such as `undetek-v10.4.0`.
- Recent Items now reads `.lnk` shortcut name, target path, arguments, and working directory without opening the target.
- Recent Items now reads `.url` Internet Shortcut URLs without opening them.
- Expanded the curated CS2 family database with additional public families and safer aliases.
- Added exact-alias and controlled version-prefix matching for ambiguous product names.
- Version-prefix matching accepts loader/setup/version patterns while avoiding broad substring matching.
- Added selected known distribution domains for browser correlation.
- Preserved one-cheat/one-combined-finding deduplication from v2.1.1.

## 2.1.2
- Fixed the GitHub Actions `Build DoubleG Scanner` installer failure.
- Restored the standard scanner installer to the previously proven Inno Setup structure.
- Removed unsigned/missing kernel-driver packaging from the regular scanner installer.
- Kernel driver source and build remain available through the separate `Build DoubleG Kernel Driver` workflow.
- Cleared nullable warnings in `ReportService.cs`.
- Replaced the obsolete certificate-loading API with `X509CertificateLoader`.
- Preserved v2.1.1 cheat/kernel finding deduplication and v2.1.0 PDF layout.

## 2.1.1
- Consolidated repeated detections for the same named cheat into one finding.
- ExLoader `.exe`, `.zip`, USN, MFT, browser, and local-file traces now appear as one ExLoader result.
- Consolidated repeated kernel findings into one summary per kernel rule.
- `DGS-KERNEL-CORR-013` no longer creates one PDF card for every normal Windows driver.
- Combined findings retain evidence count, sources, and up to eight artifact paths.
- Applied deduplication in the detection engine, PDF report, JSON result, and UI finding count.
- Old PDF files are unchanged; a new scan/report is required.

## 2.1.0
- Redesigned the PDF report layout for cleaner, easier manual review.
- Added a dedicated **Cheat Detection Summary** section that highlights only primary detections in red.
- Supporting browser, kernel, installer, and trace findings are now shown separately as neutral review items.
- Added article-style sections for Browser History, Last Activity, Network/Data Usage, Local Files & Downloads, Kernel & Drivers, Deleted Traces, and Microsoft Defender.
- Added DoubleG logo support and improved brand styling in the PDF.
- Copied `Assets\DoubleGLogo.png` to output/publish so it can be rendered inside generated reports.

## 2.0.0
- Added the real `DoubleGKernel.sys` KMDF kernel-mode scanner component.
- Kernel driver enumerates loaded operating-system image modules through `AuxKlibQueryModuleInformation`.
- Added a versioned, bounded IOCTL protocol and C# kernel-driver client.
- Kernel output deliberately excludes kernel base addresses.
- No arbitrary kernel/physical/process memory read or write operations exist.
- Control device access is restricted to SYSTEM and built-in Administrators.
- Forensic Scan is now marked Incomplete when the signed kernel driver is unavailable.
- Added WDK NuGet-based unsigned development build workflow.
- Added signed-driver import, install, and uninstall scripts.
- Public installer includes a kernel driver only when a valid signed binary is supplied.
- Installer now uses administrator privileges and Program Files when packaging the signed driver.

## 1.11.0
- Rebalanced the three scan tiers.
- Quick Scan now uses the previous Full Scan scope.
- Quick includes browser history/downloads, execution traces, Recycle Bin, driver/startup persistence, recursive Temp/local file scanning, and Microsoft Defender.
- Full Scan now uses the previous Forensic Scan scope.
- Full includes NTFS MFT, USN Journal, unallocated executable/archive signatures, 365-day file depth, and Defender Temp scanning.
- Kernel & Driver Integrity was removed from Quick and Full.
- Forensic Scan now equals Full disk forensics plus Kernel & Driver Integrity.
- Full and Forensic automatically request administrator elevation.
- Fixed the elevation prompt leaving the UI in a false scanning state when elevation was declined.
- Updated verdict coverage requirements for the new tier mapping.

## 1.10.0
- Added a user-mode Kernel & Driver Integrity collector.
- Enumerates currently loaded kernel drivers with Windows PSAPI.
- Resolves driver paths and records signature, publisher, SHA-256, size, and timestamp.
- Attempts to enable SeDebugPrivilege for complete driver enumeration on supported systems.
- Reads VBS, Memory Integrity, Code Integrity policy, DMA capability, Secure Boot, and vulnerable-driver blocklist configuration.
- Reads recent Windows Code Integrity Operational events in Full and Forensic scans.
- Reads recent driver-service installation events from the System log.
- Supports exact vulnerable-driver SHA-256 entries and lower-confidence filename heuristics.
- Correlates loaded .sys drivers with browser, file, deletion, USN, and execution evidence.
- Adds kernel security, loaded-driver, and Code Integrity sections to PDF/JSON reports.
- Does not install a custom kernel driver, read arbitrary kernel memory, or modify system security settings.

## 1.9.5
- Quick Scan now checks recent browser executable/archive downloads.
- Quick Scan reports downloaded files that are no longer present.
- Quick Scan now checks recent relevant Recycle Bin metadata.
- When elevated, Quick Scan checks a capped recent USN deletion window.
- Added browser-download + Recycle Bin/USN deletion correlation.
- Known cheat names/domains can produce strong findings after the file is deleted.
- Generic deleted executables/archives are shown as Review evidence, not falsely classified as confirmed cheats.
- Raw unallocated-space recovery remains exclusive to Forensic Scan.
- Preserved Defender timeout, NTFS forensic, PDF, JSON and UI behavior.

## 1.9.4
- Removed the READ ONLY badge from the Live Analysis header.
- Preserved all scanner privacy, read-only collection, detection, NTFS forensic, Defender timeout, PDF and JSON behavior.

## 1.9.3
- Fixed the Microsoft Defender stage permanently freezing at 85–88%.
- Removed the unbounded redirected-output wait after a Defender timeout.
- Added a visible heartbeat every two seconds with target and elapsed time.
- Added per-target safety limits: Downloads 90s, Desktop 60s, Temp 60s.
- Timed-out Defender targets are stopped and reported as Partial.
- The scan now continues to detection and report generation after a Defender timeout.
- Cancel now terminates the spawned Defender process tree.
- Preserved all NTFS forensic, detection, PDF and UI behavior.

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
