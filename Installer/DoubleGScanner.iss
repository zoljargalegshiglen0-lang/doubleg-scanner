#define MyAppName "DoubleG Scanner"
#define MyAppVersion "2.1.1"
#define MyAppPublisher "DoubleG"
#define MyAppExeName "DoubleGScanner.exe"
[Setup]
AppId={{2A1A3D1C-024E-49AF-996D-A8B0D2A63D91}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\DoubleG Scanner
DefaultGroupName=DoubleG Scanner
DisableProgramGroupPage=yes
PrivilegesRequired=admin
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
Source: "..\Release\win-x64\Drivers\DoubleGKernel.sys"; DestDir: "{sys}\drivers"; DestName: "DoubleGKernel.sys"; Flags: ignoreversion restartreplace skipifsourcedoesntexist
[Icons]
Name: "{autoprograms}\DoubleG Scanner"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\DoubleG Scanner"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
[Run]
Filename: "{sys}\sc.exe"; Parameters: "create DoubleGKernel type= kernel start= demand binPath= ""{sys}\drivers\DoubleGKernel.sys"" DisplayName= ""DoubleG Kernel Scanner"""; Flags: runhidden waituntilterminated ignoreerrors; Check: FileExists(ExpandConstant('{sys}\drivers\DoubleGKernel.sys'))
Filename: "{sys}\sc.exe"; Parameters: "config DoubleGKernel start= demand binPath= ""{sys}\drivers\DoubleGKernel.sys"""; Flags: runhidden waituntilterminated ignoreerrors; Check: FileExists(ExpandConstant('{sys}\drivers\DoubleGKernel.sys'))
Filename: "{app}\{#MyAppExeName}"; Description: "Launch DoubleG Scanner"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop DoubleGKernel"; Flags: runhidden waituntilterminated ignoreerrors
Filename: "{sys}\sc.exe"; Parameters: "delete DoubleGKernel"; Flags: runhidden waituntilterminated ignoreerrors
