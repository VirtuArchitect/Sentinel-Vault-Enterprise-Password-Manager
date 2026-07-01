#define AppName "Sentinel Vault"
#define AppVersion "1.0.0"
#define AppPublisher "VirtuArchitect"
#define AppExeName "run-sentinel.ps1"

[Setup]
AppId={{B8F15207-CE96-47E8-A8BF-8E7DB7A34A1D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Sentinel Vault
DefaultGroupName=Sentinel Vault
DisableProgramGroupPage=yes
OutputBaseFilename=SentinelVault-Windows-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\assets\sentinel-vault-app-icon.svg

[Files]
Source: "{#SourceRoot}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\Sentinel Vault"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\run-sentinel.ps1"""; WorkingDir: "{app}"
Name: "{autoprograms}\Sentinel Vault"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\run-sentinel.ps1"""; WorkingDir: "{app}"

[Run]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\install.ps1"" -InstallDir ""{app}"" -SkipStartMenuShortcut"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\uninstall.ps1"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated
