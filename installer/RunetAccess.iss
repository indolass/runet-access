; Runet Access - Windows installer (Inno Setup 6). Built by scripts\make-installer.ps1, never by hand:
; the script verifies the components, stages an explicit file list and passes the /D defines below.
;
; Properties of this installer:
;  - per-user install, no administrator rights, no UAC prompt
;  - no autostart, no services, no scheduled tasks, no system proxy/network/browser-association changes
;  - the user's key and browser profile live in %LOCALAPPDATA%\RunetAccess, OUTSIDE the install folder:
;    updates never touch them, uninstall keeps them unless the user explicitly asks to delete them

#ifndef AppVersion
  #error AppVersion is not defined (use scripts\make-installer.ps1)
#endif
#ifndef StagingDir
  #error StagingDir is not defined (use scripts\make-installer.ps1)
#endif
#ifndef OutDir
  #error OutDir is not defined (use scripts\make-installer.ps1)
#endif
#ifndef OutName
  #define OutName "RunetAccess-Setup-" + AppVersion
#endif
; User data folder. Fixed in the product; tests of the "delete my data" choice compile a variant
; that points it at a throw-away folder (it must still be named RunetAccess).
#ifndef DataDir
  #define DataDir "{localappdata}\RunetAccess"
#endif

[Setup]
AppId={{B7E2C1A4-5D3F-4E8B-9A16-0C4D7F2E6A31}
AppName=Runet Access
AppVersion={#AppVersion}
AppVerName=Runet Access {#AppVersion}
AppPublisher=Runet Access (проект с открытым кодом)
AppPublisherURL=https://github.com/indolass/runet-access
AppSupportURL=https://github.com/indolass/runet-access
AppUpdatesURL=https://github.com/indolass/runet-access
VersionInfoVersion={#AppVersion}.0
VersionInfoDescription=Установщик Runet Access
DefaultDirName={localappdata}\Programs\RunetAccess
DefaultGroupName=Runet Access
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutDir}
OutputBaseFilename={#OutName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
InfoBeforeFile={#SourcePath}\info-before.txt
; Setup/uninstall refuse to replace files under a running program (the program holds this mutex)
; and ask the user to close it. Nothing is ever killed: no Restart Manager, no force-close.
AppMutex=RunetAccess.SingleInstance.6f0c7e1a
CloseApplications=no
RestartApplications=no
UninstallDisplayIcon={app}\RunetAccess.exe
UninstallDisplayName=Runet Access
UsePreviousAppDir=yes
SetupLogging=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; Flags: unchecked

[Files]
Source: "{#StagingDir}\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Runet Access"; Filename: "{app}\RunetAccess.exe"; WorkingDir: "{app}"; Comment: "Российские сайты в отдельном окне"
Name: "{autoprograms}\Runet Access — инструкция"; Filename: "{app}\Инструкция.txt"
Name: "{autodesktop}\Runet Access"; Filename: "{app}\RunetAccess.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\RunetAccess.exe"; Description: "Запустить Runet Access"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[Code]
// ---------- uninstall: optional removal of the user's data ----------

function HasParam(const Name: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Name) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function UserDataDir(): String;
begin
  Result := RemoveBackslashUnlessRoot(ExpandConstant('{#DataDir}'));
end;

// Only these named items of OUR folder are ever removed. The folder itself goes only when it is
// empty afterwards (RemoveDir never deletes a non-empty folder). Nothing outside it, and never
// the ordinary Chrome profile.
procedure RemoveUserData();
var
  D: String;
begin
  D := UserDataDir();
  if CompareText(ExtractFileName(D), 'RunetAccess') <> 0 then
    Exit;                                   // refuse an unexpected path
  DeleteFile(D + '\key.dpapi');
  DeleteFile(D + '\key.dpapi.tmp');
  DeleteFile(D + '\run.lock');
  if DirExists(D + '\profile') then
    DelTree(D + '\profile', True, True, True);
  RemoveDir(D);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Ask: Boolean;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  if not DirExists(UserDataDir()) then
    Exit;
  if UninstallSilent then
    Ask := HasParam('/DELETEDATA')          // silent: only on explicit request
  else
    Ask := MsgBox('Удалить также сохранённый ключ и профиль специального браузера?' + #13#10 + #13#10 +
                  'Папка: ' + UserDataDir() + #13#10 + #13#10 +
                  'Обычный профиль Chrome и другие ваши данные не затрагиваются. ' +
                  'Если нажать «Нет», при повторной установке ключ и вход на сайтах сохранятся.',
                  mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  if Ask then
    RemoveUserData();
end;
