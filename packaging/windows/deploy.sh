#!/usr/bin/env bash
# Collect every DLL the Windows build needs next to the executable and copy
# the Qt plugins it loads at run time.
#
# This is the equivalent of windeployqt for the Fedora mingw64 cross build:
# Fedora's mingw64 Qt does not ship windeployqt.exe, and running the Windows
# tool would need Wine. The dependency closure is computed from the PE import
# tables with objdump, so it is architecture-agnostic and complete.
#
# Usage: deploy.sh <app-dir> [sysroot]
#   app-dir   directory holding firmadigitaleopen.exe (cmake --install target)
#   sysroot   mingw sysroot (default /usr/x86_64-w64-mingw32/sys-root/mingw)

set -euo pipefail

APP_DIR=${1:?usage: deploy.sh <app-dir> [sysroot]}
SYSROOT=${2:-${SYSROOT:-/usr/x86_64-w64-mingw32/sys-root/mingw}}
BIN_DIR="$SYSROOT/bin"
QT_PLUGINS=${QT_PLUGINS:-"$SYSROOT/lib/qt6/plugins"}
EXE="$APP_DIR/firmadigitaleopen.exe"

if [[ ! -d "$QT_PLUGINS" ]]; then
    for candidate in "$SYSROOT/lib/qt6/plugins" "$SYSROOT/share/qt6/plugins" \
                     "$SYSROOT/lib64/qt6/plugins"; do
        if [[ -d "$candidate" ]]; then
            QT_PLUGINS="$candidate"
            break
        fi
    done
fi

if [[ ! -f "$EXE" ]]; then
    echo "deploy.sh: $EXE not found" >&2
    exit 1
fi
if [[ ! -d "$BIN_DIR" ]]; then
    echo "deploy.sh: mingw sysroot bin directory not found: $BIN_DIR" >&2
    exit 1
fi

echo "==> deploying Windows runtime into $APP_DIR"
echo "    sysroot: $SYSROOT"

# ------------------------------------------------------------------ plugins --
# Only the plugins the GUI actually needs: the platform plugin is mandatory,
# the Windows style keeps the native look, tls is needed for the TSL download
# (Schannel backend on Windows), sqlite for the (future) SQL use and
# networkinformation for interface-change notifications.
for sub in platforms styles tls sqldrivers networkinformation; do
    src="$QT_PLUGINS/$sub"
    [[ -d "$src" ]] || continue
    mkdir -p "$APP_DIR/$sub"
    for f in "$src"/*.dll; do
        [[ -f "$f" ]] || continue
        base=$(basename "$f")
        case "$sub:$base" in
            platforms:qwindows.dll) ;;
            styles:qmodernwindowsstyle.dll) ;;
            sqldrivers:qsqlite.dll) ;;
            tls:*) ;;
            networkinformation:*) ;;
            *) continue ;;
        esac
        cp -f "$f" "$APP_DIR/$sub/$base"
        echo "    plugin $sub/$base"
    done
done

# ------------------------------------------------------- dependency closure --
# Index the sysroot DLLs case-insensitively (Windows file names are
# case-insensitive, the PE import table spelling is not authoritative).
declare -A SYS_DLLS=()
while IFS= read -r -d '' f; do
    key=$(basename "$f" | tr '[:upper:]' '[:lower:]')
    SYS_DLLS["$key"]="$f"
done < <(find "$BIN_DIR" -maxdepth 1 -type f -iname '*.dll' -print0)

# DLLs provided by Windows itself (or the UCRT) must never be copied.
is_system_dll() {
    case "${1,,}" in
        api-ms-win-*|ext-ms-*) return 0 ;;
        advapi32.dll|authz.dll|bcrypt.dll|cfgmgr32.dll|comctl32.dll|comdlg32.dll|\
        credui.dll|crypt32.dll|cryptbase.dll|d3d9.dll|d3d11.dll|d3d12.dll|dbghelp.dll|\
        dhcpcsvc.dll|dnsapi.dll|dwmapi.dll|dwrite.dll|dxgi.dll|gdi32.dll|gdiplus.dll|\
        imm32.dll|iphlpapi.dll|kernel32.dll|kernelbase.dll|mpr.dll|msimg32.dll|\
        msvcp*.dll|msvcr*.dll|ncrypt.dll|netapi32.dll|ntdll.dll|ole32.dll|\
        oleacc.dll|oleaut32.dll|opengl32.dll|powrprof.dll|psapi.dll|rpcrt4.dll|\
        secur32.dll|setupapi.dll|shell32.dll|shlwapi.dll|ucrtbase.dll|\
        user32.dll|userenv.dll|uxtheme.dll|vcruntime*.dll|version.dll|\
        shcore.dll|winhttp.dll|wininet.dll|winmm.dll|winscard.dll|wldap32.dll|ws2_32.dll|wsock32.dll|\
        wtsapi32.dll) return 0 ;;
    esac
    return 1
}

declare -A PROVIDED=()   # lower-case basename -> path in APP_DIR
while IFS= read -r -d '' f; do
    PROVIDED["$(basename "$f" | tr '[:upper:]' '[:lower:]')"]="$f"
done < <(find "$APP_DIR" -type f -iname '*.dll' -print0)

# Always ship the TLS DLLs (Qt's OpenSSL backend loads them dynamically, so
# they do not show up in any import table) and, when present, the MinGW
# runtime (the compiler may link them statically, in which case copying them
# is harmless).
for name in libssl-3-x64.dll libcrypto-3-x64.dll libgcc_s_seh-1.dll \
            libstdc++-6.dll libwinpthread-1.dll; do
    src="${SYS_DLLS[${name,,}]:-}"
    [[ -n "$src" ]] || continue
    if [[ -z "${PROVIDED[${name,,}]:-}" ]]; then
        cp -f "$src" "$APP_DIR/$name"
        PROVIDED["${name,,}"]="$APP_DIR/$name"
        echo "    dll    $name"
    fi
done

queue=("$EXE")
while IFS= read -r -d '' f; do queue+=("$f"); done \
    < <(find "$APP_DIR" -type f -iname '*.dll' -print0)

declare -A SCANNED=()
missing=0
while ((${#queue[@]})); do
    file="${queue[0]}"
    queue=("${queue[@]:1}")

    key=$(basename "$file" | tr '[:upper:]' '[:lower:]')
    [[ -n "${SCANNED[$key]:-}" ]] && continue
    SCANNED["$key"]=1

    while IFS= read -r dll; do
        [[ -n "$dll" ]] || continue
        low=${dll,,}
        is_system_dll "$low" && continue

        if [[ -n "${PROVIDED[$low]:-}" ]]; then
            continue
        fi
        src="${SYS_DLLS[$low]:-}"
        if [[ -z "$src" ]]; then
            echo "deploy.sh: MISSING $dll (imported by $(basename "$file"))" >&2
            missing=1
            continue
        fi
        cp -f "$src" "$APP_DIR/$(basename "$src")"
        PROVIDED["$low"]="$APP_DIR/$(basename "$src")"
        echo "    dll    $(basename "$src")"
        queue+=("$APP_DIR/$(basename "$src")")
    done < <(objdump -p "$file" 2>/dev/null \
                | sed -n 's/^[[:space:]]*DLL Name:[[:space:]]*//p' | tr -d '\r')
done

if ((missing)); then
    echo "deploy.sh: cannot complete the DLL set (see MISSING above)" >&2
    exit 1
fi

if [[ ! -f "$APP_DIR/platforms/qwindows.dll" ]]; then
    echo "deploy.sh: platforms/qwindows.dll was not copied (check QT_PLUGINS=$QT_PLUGINS)" >&2
    exit 1
fi
if ! compgen -G "$APP_DIR/tls/*.dll" > /dev/null; then
    echo "deploy.sh: no Qt TLS backend copied; HTTPS/TSL download would fail" >&2
    exit 1
fi

# The Bit4id module is optional (the app can use a machine-wide install), but
# when it is bundled it must carry its config and card licences.
if [[ -f "$APP_DIR/bit4xpki.dll" ]]; then
    [[ -f "$APP_DIR/bit4xpki.dll.conf" ]] || \
        echo "deploy.sh: WARNING bit4xpki.dll has no bit4xpki.dll.conf" >&2
    [[ -d "$APP_DIR/bit4xpki.dll.rc" ]] || \
        echo "deploy.sh: WARNING bit4xpki.dll has no bit4xpki.dll.rc licences" >&2
fi

echo "==> Windows deployment complete: $(find "$APP_DIR" -type f | wc -l) files, $(du -sh "$APP_DIR" | cut -f1)"
