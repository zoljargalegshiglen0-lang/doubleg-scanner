# v2.2.4 expected result against DGS-20260722-123449-45DD6933037

## Suppressed from the cheat finding ledger

These remain available as raw evidence when relevant, but are no longer labelled as cheats:

- GitHub Desktop embedded `git-lfs.exe`
- Microsoft Visual Studio/.NET targeting packs
- Microsoft Defender platform DLL/EXE files (`MpSvc.dll`, `MpRtp.dll`, `MpDlp.dll`, `mpengine.dll`, etc.)
- Microsoft OneDrive updater/client files
- Windows Xbox Game Bar / `GameBarFTServer.exe`
- Windows Sense / WinSxS system files
- Windows Package Cache MSI files
- DoubleG Scanner's own executable
- Opera/Qt binaries that matched only weak strings such as `bhop`, `OpenProcess`, or `SetWindowsHookEx`
- `ticket-bot.zip` and `@sapphire/*` Node dependencies
- Deleted DoubleG/Novacs installers
- Deleted POS Service and OnisShop installers
- Google search result pages and ChatGPT conversation titles containing cheat words

## Still shown as confirmed red detections when evidence remains credible

- Exact known cheat SHA-256 matches
- `DragonBurn-usermode.exe` with aimbot/triggerbot/CS2 indicators
- `DragonBurn-kernel.exe` with kdmapper/iqvw64e/external-cheat indicators
- Credible `ExLoader` binary markers or direct ExLoader executable evidence
- Credible `Valthrun` local/execution correlation
- Named cheat module loaded by `cs2.exe`
- Named cheat process currently running
- Named cheat execution records
- High-confidence injection/private executable-memory correlations
- DMA device + independent DMA software/activity correlation

## Browser-only presentation

Direct visits to Neverlose, Memesense, Sysware, Undetek and similar known cheat sites may still appear, but only as:

`CHEAT WEBSITE TRACE - NOT PROOF OF USE`

They do not count as confirmed cheat detections and no longer receive critical risk weight.
