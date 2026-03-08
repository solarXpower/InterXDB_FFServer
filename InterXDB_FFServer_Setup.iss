; InterXDB_FFServer Inno Setup Script
; Builds: InterXDB_FFServer_Setup.exe
; Compiler: Inno Setup 6  (C:\Program Files (x86)\Inno Setup 6\ISCC.exe)

#define AppName      "InterXDB FFServer"
#define AppVersion   "1.0"
#define AppPublisher "OnSolar / The Next Software"
#define AppExeName   "InterXDB_FFServer.exe"
#define SourceDir    "C:\AI Software\anviz\dist\InterXDB_FFServer"
#define OutputDir    "C:\AI Software\anviz\installer"

[Setup]
AppId={{B7E2A3F1-4C9D-4E8A-B2F5-1D6C3A9E7B04}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=
DefaultDirName={autopf}\InterXDB FFServer
DefaultGroupName={#AppName}
OutputDir={#OutputDir}
OutputBaseFilename=InterXDB_FFServer_Setup_v{#AppVersion}
SetupIconFile=C:\AI Software\anviz\InterXICO.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}
MinVersion=6.1

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Create a &Desktop shortcut";    GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Files]
; Copy entire dist folder (EXE + _internal)
Source: "{#SourceDir}\{#AppExeName}";    DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\_internal\*";      DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu shortcut
Name: "{group}\{#AppName}";              Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\_internal\InterXICO.ico"
Name: "{group}\Uninstall {#AppName}";    Filename: "{uninstallexe}"

; Desktop shortcut (optional)
Name: "{autodesktop}\{#AppName}";        Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\_internal\InterXICO.ico"; Tasks: desktopicon

[Run]
; Offer to launch the app after install
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove config and database created at runtime
Type: files; Name: "{app}\interxdb_config.json"
Type: files; Name: "{app}\interxdb.db"
Type: filesandordirs; Name: "{app}"
