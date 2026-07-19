# Changelog

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
