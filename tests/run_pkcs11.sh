#!/usr/bin/env bash
#
# Drives the PKCS#11 smoke/full test (tst_pkcs11). Resolution order:
#
#   1. FDO_PKCS11_LIB (and optional FDO_PKCS11_PIN) -> use that module
#      directly (e.g. a physical Bit4id token via libbit4xpki.so).
#   2. SoftHSM2 emulator -> initialise a throwaway token with a generated
#      RSA key + self-signed cert and run the full login+sign+verify path.
#   3. Fallback -> the Bit4id library in the source tree, enumeration only
#      (no token needed); this still exercises module load + slot discovery.
#
# The test is written so that a missing token is never a hard failure; only
# a library/ABI load problem or a signing/verification mismatch is.
set -u

bin="${1:?usage: run_pkcs11.sh <path-to-tst_pkcs11>}"
root="$(cd "$(dirname "$0")/.." && pwd)"

# --- 1) Explicit module from the environment --------------------------------
if [ -n "${FDO_PKCS11_LIB:-}" ] && [ -e "$FDO_PKCS11_LIB" ]; then
    echo "[pkcs11] using module from FDO_PKCS11_LIB: $FDO_PKCS11_LIB"
    if [ -n "${FDO_PKCS11_PIN:-}" ]; then
        exec "$bin" "$FDO_PKCS11_LIB" "$FDO_PKCS11_PIN"
    fi
    exec "$bin" "$FDO_PKCS11_LIB"
fi

# --- 2) SoftHSM2 emulator ---------------------------------------------------
find_softhsm_lib() {
    local c
    for c in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        [ -e "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

if softhsm_lib="$(find_softhsm_lib)" && command -v softhsm2-util >/dev/null 2>&1 \
        && command -v pkcs11-tool >/dev/null 2>&1; then
    echo "[pkcs11] using SoftHSM emulator: $softhsm_lib"
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    mkdir -p "$work/tokens"
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' \
        "$work" > "$work/softhsm2.conf"
    export SOFTHSM2_CONF="$work/softhsm2.conf"

    pin="12345678"
    # Initialise a token with both SO and user PINs.
    if ! softhsm2-util --init-token --free --label "FDO Test Token" \
            --so-pin "$pin" --pin "$pin" >/dev/null 2>&1; then
        echo "[pkcs11] SoftHSM token init failed" >&2
        exit 1
    fi
    # Generate an RSA key + self-signed cert.
    if ! openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" \
            -out "$work/cert.pem" -days 3650 -nodes \
            -subj "/CN=FDO SoftHSM Test User" >/dev/null 2>&1; then
        echo "[pkcs11] openssl key/cert generation failed" >&2
        exit 1
    fi
    # Import cert + private key, both with CKA_ID "DS3" (0x445333), the id the
    # Bit4id flow looks for first.
    pkcs11-tool --module "$softhsm_lib" --write-object "$work/cert.pem" \
        --type cert --id 44:53:33 --label "DS3 cert" --pin "$pin" >/dev/null 2>&1
    pkcs11-tool --module "$softhsm_lib" --write-object "$work/key.pem" \
        --type privkey --id 44:53:33 --label "DS3 key" --pin "$pin" >/dev/null 2>&1

    "$bin" "$softhsm_lib" "$pin"
    exit $?
fi

# --- 3) Fallback: Bit4id library, enumeration only --------------------------
if [ -e "$root/../libbit4xpki.so" ]; then
    echo "[pkcs11] no SoftHSM available; using Bit4id lib (enumeration only)"
    "$bin" "$root/../libbit4xpki.so"
    exit $?
fi

echo "[pkcs11] no PKCS#11 module available; skipping (PASS)"
exit 0
