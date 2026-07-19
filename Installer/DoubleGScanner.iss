#define MyAppName "DoubleG Scanner"
#define MyAppVersion "1.1.1"
#define MyAppPublisher "DoubleG"
#define MyAppExeName "DoubleGScanner.exe"
[Setup]
AppId={{2A1A3D1C-024E-49AF-996D-A8B0D2A63D91}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\DoubleG Scanner
DefaultGroupName=DoubleG Scanner
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\Release\Installer
OutputBaseFilename=DoubleGScannerSetup
SetupIconFile=..\DoubleGScanner\Assets\DoubleGScanner.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no
ChangesEnvironment=no
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
[Files]
Source: "..\Release\win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{autoprograms}\DoubleG Scanner"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\DoubleG Scanner"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch DoubleG Scanner"; Flags: nowait postinstall skipifsilent
