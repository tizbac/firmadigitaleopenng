; NSIS installer for the 64-bit Windows build of FirmaDigitaleOpen.
;
; Built on Linux with native makensis (Debian package "nsis"), or on Windows
; with the NSIS distribution:
;
;   makensis -DAPP_VERSION=1.0.0 -DSOURCE_DIR=build-win/app \
;            -DOUT_FILE=firmadigitaleopen-1.0.0-win64-setup.exe \
;            packaging/windows/installer.nsi
;
; SOURCE_DIR must contain firmadigitaleopen.exe plus every DLL/plugin that
; packaging/windows/deploy.sh collected.

Unicode true

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!ifndef APP_VERSION
  !define APP_VERSION "1.0.0"
!endif
!ifndef SOURCE_DIR
  !error "SOURCE_DIR is required (directory with firmadigitaleopen.exe)"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "firmadigitaleopen-${APP_VERSION}-win64-setup.exe"
!endif
!ifndef ICON_FILE
  !define ICON_FILE "${__FILEDIR__}/../../resources/firmadigitaleopen.ico"
!endif

!define APP_NAME       "FirmaDigitaleOpen"
!define APP_EXE        "firmadigitaleopen.exe"
!define APP_PUBLISHER  "FirmaDigitaleOpen"
!define APP_VERSION_4  "${APP_VERSION}.0"

!define REG_APP        "Software\FirmaDigitaleOpen"
!define REG_UNINSTALL  "Software\Microsoft\Windows\CurrentVersion\Uninstall\FirmaDigitaleOpen"
!define PROGID_P7M     "FirmaDigitaleOpen.p7m"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 64
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${APP_VERSION_4}"
VIAddVersionKey /LANG=1033 "ProductName"     "${APP_NAME}"
VIAddVersionKey /LANG=1033 "ProductVersion"  "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "FileVersion"     "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "FileDescription" "FirmaDigitaleOpen installer"
VIAddVersionKey /LANG=1033 "CompanyName"     "${APP_PUBLISHER}"
VIAddVersionKey /LANG=1033 "LegalCopyright"  "GPL-3.0-only"

!define MUI_ICON        "${ICON_FILE}"
!define MUI_UNICON      "${ICON_FILE}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "$(RUN_APP)"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Italian"
!insertmacro MUI_LANGUAGE "English"

LangString RUN_APP          ${LANG_ITALIAN} "Avvia ${APP_NAME}"
LangString RUN_APP          ${LANG_ENGLISH} "Launch ${APP_NAME}"
LangString SEC_APP          ${LANG_ITALIAN} "File dell'applicazione (obbligatorio)"
LangString SEC_APP          ${LANG_ENGLISH} "Application files (required)"
LangString SEC_STARTMENU    ${LANG_ITALIAN} "Voce nel menu Start"
LangString SEC_STARTMENU    ${LANG_ENGLISH} "Start Menu shortcut"
LangString SEC_DESKTOP      ${LANG_ITALIAN} "Icona sul desktop"
LangString SEC_DESKTOP      ${LANG_ENGLISH} "Desktop shortcut"
LangString SEC_ASSOC        ${LANG_ITALIAN} "Associazione .p7m e menu contestuale"
LangString SEC_ASSOC        ${LANG_ENGLISH} ".p7m association and context menu"
LangString SEC_UNINSTALL    ${LANG_ITALIAN} "Disinstallazione"
LangString SEC_UNINSTALL    ${LANG_ENGLISH} "Uninstall"
LangString MSG_X64          ${LANG_ITALIAN} "${APP_NAME} richiede Windows a 64 bit."
LangString MSG_X64          ${LANG_ENGLISH} "${APP_NAME} requires 64-bit Windows."
LangString DESC_P7M         ${LANG_ITALIAN} "Documento firmato P7M (CMS)"
LangString DESC_P7M         ${LANG_ENGLISH} "P7M signed document (CMS)"
LangString CTX_SIGN_PDF     ${LANG_ITALIAN} "Firma PDF"
LangString CTX_SIGN_PDF     ${LANG_ENGLISH} "Sign PDF"
LangString CTX_SIGN_PADES   ${LANG_ITALIAN} "Firma PAdES"
LangString CTX_SIGN_PADES   ${LANG_ENGLISH} "Sign PAdES"
LangString CTX_SIGN_P7M     ${LANG_ITALIAN} "Firma P7M"
LangString CTX_SIGN_P7M     ${LANG_ENGLISH} "Sign P7M"

!macro REGISTER_ASSOC EXT PROGID DESCRIPTION
    ; ProgID + "Open with" entry. Only .p7m is associated; .pdf is left to the
    ; user's preferred reader and gets a context-menu action instead.
    WriteRegStr HKLM "Software\Classes\${PROGID}" "" "${DESCRIPTION}"
    WriteRegStr HKLM "Software\Classes\${PROGID}\DefaultIcon" "" "$INSTDIR\${APP_EXE},0"
    WriteRegStr HKLM "Software\Classes\${PROGID}\shell\open\command" "" '"$INSTDIR\${APP_EXE}" "%1"'
    WriteRegStr HKLM "Software\Classes\${EXT}\OpenWithProgids" "${PROGID}" ""
!macroend

!macro REGISTER_CONTEXT_MENU KEY LABEL ARGS
    WriteRegStr HKLM "${KEY}" "" "${LABEL}"
    WriteRegStr HKLM "${KEY}" "Icon" "$INSTDIR\${APP_EXE},0"
    WriteRegStr HKLM "${KEY}" "MultiSelectModel" "Single"
    WriteRegStr HKLM "${KEY}\command" "" '"$INSTDIR\${APP_EXE}" ${ARGS} "%1"'
!macroend

Function .onInit
    SetRegView 64
    ${IfNot} ${RunningX64}
        MessageBox MB_ICONSTOP "$(MSG_X64)"
        Abort
    ${EndIf}
    ReadRegStr $0 HKLM "${REG_APP}" "InstallDir"
    ${If} $0 != ""
        StrCpy $INSTDIR $0
    ${EndIf}
FunctionEnd

Function un.onInit
    SetRegView 64
FunctionEnd

Section "$(SEC_APP)" SEC_APP
    SectionIn RO
    SetOutPath "$INSTDIR"
    File /r "${SOURCE_DIR}/*"
    WriteUninstaller "$INSTDIR\uninstall.exe"

    WriteRegStr HKLM "${REG_APP}" "InstallDir" "$INSTDIR"

    WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayName"     "${APP_NAME}"
    WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr HKLM "${REG_UNINSTALL}" "Publisher"       "${APP_PUBLISHER}"
    WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayIcon"     "$INSTDIR\${APP_EXE},0"
    WriteRegStr HKLM "${REG_UNINSTALL}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "${REG_UNINSTALL}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoModify" 1
    WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoRepair" 1
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "${REG_UNINSTALL}" "EstimatedSize" "$0"

    ; Allow "firmadigitaleopen.exe" from Win+R / ShellExecute.
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${APP_EXE}" "" "$INSTDIR\${APP_EXE}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${APP_EXE}" "Path" "$INSTDIR"
SectionEnd

Section "$(SEC_STARTMENU)" SEC_STARTMENU
    SetShellVarContext all
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
    CreateShortCut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "$(SEC_DESKTOP)" SEC_DESKTOP
    SetShellVarContext all
    CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
SectionEnd

Section "$(SEC_ASSOC)" SEC_ASSOC
    SetRegView 64
    ; Upgrade cleanup: older installers registered a .pdf OpenWith entry.
    ; .pdf must now keep the user's default reader.
    DeleteRegValue HKLM "Software\Classes\.pdf\OpenWithProgids" "FirmaDigitaleOpen.pdf"
    DeleteRegKey HKLM "Software\Classes\FirmaDigitaleOpen.pdf"

    ; File association: .p7m only (never steal the .pdf default handler).
    !insertmacro REGISTER_ASSOC ".p7m" "${PROGID_P7M}" "$(DESC_P7M)"

    ReadRegStr $0 HKLM "Software\Classes\.p7m" ""
    ${If} $0 == ""
        WriteRegStr HKLM "Software\Classes\.p7m" "" "${PROGID_P7M}"
    ${EndIf}

    ; Explorer context menus. "Firma PDF" is .pdf-specific; PAdES/P7M signing
    ; is offered for every file type (PAdES validates that the input is a PDF).
    !insertmacro REGISTER_CONTEXT_MENU "Software\Classes\SystemFileAssociations\.pdf\shell\FirmaDigitaleOpenSignPdf" "$(CTX_SIGN_PDF)" "--sign-pades"
    !insertmacro REGISTER_CONTEXT_MENU "Software\Classes\*\shell\FirmaDigitaleOpenSignPades" "$(CTX_SIGN_PADES)" "--sign-pades"
    !insertmacro REGISTER_CONTEXT_MENU "Software\Classes\*\shell\FirmaDigitaleOpenSignP7m" "$(CTX_SIGN_P7M)" "--sign-p7m"
SectionEnd

LangString DESC_SEC_APP       ${LANG_ITALIAN} "Eseguibile, DLL Qt/OpenSSL/poppler/MinGW e modulo PKCS#11 Bit4id."
LangString DESC_SEC_APP       ${LANG_ENGLISH} "Executable, Qt/OpenSSL/poppler/MinGW DLLs and the Bit4id PKCS#11 module."
LangString DESC_SEC_STARTMENU ${LANG_ITALIAN} "Aggiunge ${APP_NAME} al menu Start."
LangString DESC_SEC_STARTMENU ${LANG_ENGLISH} "Adds ${APP_NAME} to the Start Menu."
LangString DESC_SEC_DESKTOP   ${LANG_ITALIAN} "Crea un collegamento sul desktop."
LangString DESC_SEC_DESKTOP   ${LANG_ENGLISH} "Creates a desktop shortcut."
LangString DESC_SEC_ASSOC     ${LANG_ITALIAN} "Associa i .p7m e aggiunge Firma PDF / PAdES / P7M al menu contestuale di Esplora file."
LangString DESC_SEC_ASSOC     ${LANG_ENGLISH} "Associates .p7m and adds Sign PDF / PAdES / P7M to the Explorer context menu."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_APP}       "$(DESC_SEC_APP)"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_STARTMENU} "$(DESC_SEC_STARTMENU)"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP}   "$(DESC_SEC_DESKTOP)"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_ASSOC}     "$(DESC_SEC_ASSOC)"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
    SetShellVarContext all
    SetRegView 64

    ReadRegStr $0 HKLM "Software\Classes\.p7m" ""
    ${If} $0 == "${PROGID_P7M}"
        DeleteRegValue HKLM "Software\Classes\.p7m" ""
    ${EndIf}
    ; Remove old .pdf association from previous versions (upgrade cleanup).
    DeleteRegValue HKLM "Software\Classes\.pdf\OpenWithProgids" "FirmaDigitaleOpen.pdf"
    DeleteRegKey HKLM "Software\Classes\FirmaDigitaleOpen.pdf"
    DeleteRegValue HKLM "Software\Classes\.p7m\OpenWithProgids" "${PROGID_P7M}"
    DeleteRegKey HKLM "Software\Classes\${PROGID_P7M}"

    ; Explorer context-menu actions.
    DeleteRegKey HKLM "Software\Classes\SystemFileAssociations\.pdf\shell\FirmaDigitaleOpenSignPdf"
    DeleteRegKey HKLM "Software\Classes\*\shell\FirmaDigitaleOpenSignPades"
    DeleteRegKey HKLM "Software\Classes\*\shell\FirmaDigitaleOpenSignP7m"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\${APP_EXE}"
    DeleteRegKey HKLM "${REG_APP}"
    DeleteRegKey HKLM "${REG_UNINSTALL}"

    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
    RMDir  "$SMPROGRAMS\${APP_NAME}"
    Delete "$DESKTOP\${APP_NAME}.lnk"

    Delete "$INSTDIR\uninstall.exe"
    RMDir /r "$INSTDIR"
SectionEnd
