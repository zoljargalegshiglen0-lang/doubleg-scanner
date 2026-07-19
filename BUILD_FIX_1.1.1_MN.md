# v1.1.1 build fix

- Added global System.IO imports for File, Path, Directory, FileStream, FileInfo, DriveInfo and related types.
- Replaced unsupported MigraDoc Color.FromHex calls with Color.Parse.
- Fixed the PowerShell Program Files (x86) environment variable syntax.
- Added fallback discovery for ISCC.exe.
- Build scripts now stop immediately when dotnet restore/publish or Inno Setup fails.
