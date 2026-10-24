# About

Let me be clear with that, this project is mostly vibe-coded, from original python version i made, if you are not ok with that, feel free to use the crashy ones that barely run on linux or require ubuntu 8.04 :)
Resulting signatures have been verified against Infocert verification tool, and they fully pass.
Beware for some smart card readers you may need not just opensc but also cccid drivers.

<img width="1140" height="827" alt="Schermata_20260830_020227" src="https://github.com/user-attachments/assets/ed0c6c44-d61b-42e8-9677-43b511934207" />


# FirmaDigitaleOpen C++

C++/Qt6 rewrite of the Python `FirmaDigitaleOpen` tool. It signs PDFs with
**PAdES-BES** and produces/verifies **P7M** (CMS detached) signatures, using a
PKCS#11 security token (Bit4id) for the private key. It also verifies
**TSL** (Trusted Lists) status lists.

The cryptographic core (`fdo_core`) has no Qt dependency and is fully unit
tested; the Qt GUI sits on top of it.

## Windows version

A self-contained **Windows x64** version is available from the
[Releases](https://github.com/tizbac/firmadigitaleopenng/releases) page as
`firmadigitaleopen-<version>-win64-setup.exe`. It bundles Qt 6, Poppler,
OpenSSL, libxml2 and the Bit4id PKCS#11 module, so no separate runtime or Qt
installation is required.

- `.p7m` file association (`.pdf` keeps the user's default reader)
- Explorer right-click actions: **Firma PDF** on PDFs, **Firma PAdES** and
  **Firma P7M** on any file type
- Renewed-token identities `DS3`, `DS4`, `DS5`… with certificate expiry shown
  and warnings for non-DSx or expired certificates

## Linux desktop integration (KDE / Dolphin)

The Debian/RPM packages install Dolphin service menus:

- **Firma PDF** on `.pdf` files
- **Firma PAdES** and **Firma P7M** on any file type

Only `.p7m` is associated with the application; `.pdf` keeps the desktop's
default reader. GNOME/Nautilus integration is not included yet.

## Features

- **PAdES-BES** PDF signing (ByteRange + CMS signed-data, RFC 3161-style
  signed attributes, re-tagged to the PDF spec layout).
- **P7M** detached CMS signing and verification.
- **TSL** parser + verifier (Italian/EU Trusted Lists).
- **Windows x64 build** (MinGW cross-compile in Docker) with a self-contained
  NSIS installer that bundles Qt, poppler, OpenSSL and the Bit4id PKCS#11
  module.

## Trust model

Signature verification is TSL-only and fails closed. Trust anchors are the CA
certificates of services that are currently `granted`,
`recognisedatnationallevel` or `accredited` in the selected/cached TSL. The
TSL's own XML-signature certificate (`ds:KeyInfo`), withdrawn/ceased services
and non-CA services (TSA, eSeal, identity) are never used as anchors. Without an
up-to-date TSL — explicit file, fresh cache, or successful auto-download — no
signed PDF/P7M is reported valid. The core verifier additionally rejects an
empty anchor set before validating the chain, so there is no self-anchored
fallback.
- **PKCS#11** token layer: thin `dlopen`/`LoadLibraryW` wrapper (no system PKCS#11
  headers required) that enumerates slots, logs in, finds the signer key/cert by
  `CKA_ID` `DS3`/`DS4`/`DS5`... (renewed tokens), and signs. The GUI shows the
  certificate `CKA_ID` and expiry and warns before signing with a non-DSx or
  expired certificate.
- Canonical XML (C14N) helpers.

## Dependencies

- CMake >= 3.16, a C++17 compiler (g++/clang)
- Qt 6.5+ (Widgets, Network, Sql)
- OpenSSL 3.x
- libxml2
- For the PKCS#11 *emulator* test (optional): SoftHSM2 (`softhsm2-util`),
  OpenSC (`pkcs11-tool`), and `openssl`

Debian/Ubuntu:
```
sudo apt install qt6-base-dev libssl-dev libxml2-dev cmake g++ \
     softhsm2 opensc openssl
```

## Build

```
cmake -S . -B build
cmake --build build -j
```

Outputs:
- `build/firmadigitaleopen` — the Qt GUI
- `build/fdo_core` — the static crypto/PKCS#11 library
- `build/tst_*` — test executables

## Windows build (64-bit)

The Windows GUI is cross-compiled with MinGW-w64 in Docker and packaged with a
native NSIS installer. The result is a self-contained x64 application: Qt,
poppler, OpenSSL, libxml2 and the MinGW runtime are all bundled, so nothing
needs to be installed on the target machine.

```bash
docker build --target win-package -t fdo-win .
docker run --rm -v "$PWD:/out" fdo-win
# -> firmadigitaleopen-<version>-win64-setup.exe
```

What the Docker stages do:

- Fedora 44 `mingw64-*` packages provide the cross toolchain, Qt 6.11,
  poppler-qt6, OpenSSL 3 and libxml2; `cmake/toolchain-mingw64.cmake` points
  CMake at that sysroot.
- `packaging/windows/deploy.sh` walks the PE import tables of the executable
  and of every plugin, copies each non-system DLL from the sysroot and the
  required Qt plugins (`platforms`, `styles`, `tls`, `sqldrivers`,
  `networkinformation`) next to the executable — the same result as
  `windeployqt`, which Fedora's cross Qt does not ship.
- A Debian stage runs `makensis` (native Linux NSIS, no Wine) on
  `packaging/windows/installer.nsi`.

The installer installs under `%ProgramFiles%\FirmaDigitaleOpen`, creates Start
Menu and desktop shortcuts, and ships an uninstaller. It associates **only
`.p7m`** (claimed when it has no owner) and adds Explorer context-menu actions:
**Firma PDF** on `.pdf` files plus **Firma PAdES** and **Firma P7M** on every
file type. `.pdf` keeps the user's default reader. The executable is built as a
GUI app (`-mwindows`) with icon and VERSIONINFO resource.

The Bit4id PKCS#11 module is bundled: `bit4xpki.dll` is Bit4id's official
**x86-64** module taken from the Bit4id Universal Middleware kit (module
version 1.4.11.1228, installer 11.861), together with `bit4xpki.dll.conf` and
`bit4xpki.dll.rc/*.lic`. Those files must always sit in the same directory as
the executable (the module reads them from there). If the module is absent the
build still succeeds and, at run time, the app falls back to a machine-wide
Bit4id install (`%SystemRoot%\System32\bit4xpki.dll`) or OpenSC.

Windows tests are not run for now: the ctest suites are POSIX-only and are
driven by `tests/run_pkcs11.sh`; the Windows build is compile-checked by the
`windows` GitHub Actions workflow.

The installer and executable are not code-signed, so Windows SmartScreen may
show a warning on first run.

## Run the tests

```
ctest --test-dir build --output-on-failure
```

Suites: `c14n`, `tslverifier`, `p7mverify`, `pades`, `pkcs11`, `guisign`.
The first four are pure and need no hardware. `guisign` builds the Qt `MainWindow`
offscreen, renders a PDF page through Poppler (`PdfPreview`), and — when a token
is reachable — runs the exact token→cert→PAdES/P7M signing path the GUI wires up
(headless, no display needed). The `pkcs11` and `guisign` suites are driven by
[`tests/run_pkcs11.sh`](tests/run_pkcs11.sh), which auto-selects a module:

1. **Physical token** — if `FDO_PKCS11_LIB` (and optionally `FDO_PKCS11_PIN`)
   are set, that module is used. Example (Bit4id):
   ```
   FDO_PKCS11_LIB=../libbit4xpki.so FDO_PKCS11_PIN=1234 \
       ctest --test-dir build -R pkcs11 --output-on-failure
   ```
2. **SoftHSM emulator** — otherwise, if SoftHSM2 is installed, a throwaway
   token is initialised in a temp dir, a fresh RSA key + self-signed cert are
   imported (with `CKA_ID "DS3"`), and the full **login → findSigner → sign →
   verify** path is exercised. The signature is verified against the token
   certificate with independent OpenSSL EVP code, so a broken signing path
   fails the test.
3. **Fallback** — if neither is available, the Bit4id library in the source
   tree is loaded for an enumeration-only smoke test. A missing token is never
   a hard failure; a library/ABI load error or a signature-verification
   mismatch is.

You can also run the PKCS#11 test binary directly against the emulator:
```
SOFTHSM2_CONF=/path/to/softhsm2.conf \
    ./build/tst_pkcs11 /usr/lib/softhsm/libsofthsm2.so <user-pin>
```

## PKCS#11 emulator (SoftHSM2)

A physical token is not required to develop or test. SoftHSM2 provides a
software PKCS#11 token. The `pkcs11` ctest sets one up automatically in a temp
directory and tears it down afterwards. To set one up **by hand** (e.g. to
inspect it with `pkcs11-tool` or to point the GUI at it):

```bash
# 1) Working area + config
export FDO_SHSM=/tmp/fdo-softhsm
mkdir -p "$FDO_SHSM/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' \
    "$FDO_SHSM" > "$FDO_SHSM/softhsm2.conf"
export SOFTHSM2_CONF="$FDO_SHSM/softhsm2.conf"          # every PKCS#11 client needs this

LIB=/usr/lib/softhsm/libsofthsm2.so        # adjust to your install path
PIN=12345678

# 2) Initialise a token (sets both SO and user PINs)
softhsm2-util --init-token --free --label "FDO Test Token" \
    --so-pin "$PIN" --pin "$PIN"

# 3) Generate an RSA key + self-signed cert
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$FDO_SHSM/key.pem" -out "$FDO_SHSM/cert.pem" \
    -subj "/CN=FDO SoftHSM Test User"

# 4) Import cert + private key, both with CKA_ID "DS3" (0x445333) —
#    the id the Bit4id signing flow looks for first.
pkcs11-tool --module "$LIB" --write-object "$FDO_SHSM/cert.pem" \
    --type cert    --id 44:53:33 --label "DS3 cert" --pin "$PIN"
pkcs11-tool --module "$LIB" --write-object "$FDO_SHSM/key.pem" \
    --type privkey --id 44:53:33 --label "DS3 key"  --pin "$PIN"

# 5) Sanity check
pkcs11-tool --module "$LIB" --list-objects --pin "$PIN"
```

Then run the test against it:
```
SOFTHSM2_CONF="$FDO_SHSM/softhsm2.conf" \
    ./build/tst_pkcs11 "$LIB" "$PIN"
```
Expected output ends with:
```
  sign OK: 256 bytes
  verify OK: signature matches certificate
```

### Emulator notes / gotchas

- **`SOFTHSM2_CONF` must be exported** for every process that loads the
  SoftHSM module, otherwise it uses the system default token directory.
- **Private-key import needs a user login** (`--pin`), not an SO login
  (`--so-pin`).
- SoftHSM reports all of its virtual slots as `tokenPresent`, so the layer
  distinguishes real tokens by looking for a certificate on the slot.
- SoftHSM's `C_FindObjects` requires a **non-NULL** `pObjectCount`.
- SoftHSM does **not** expose `CKA_ID` for reading (the length probe returns
  `CK_UNAVAILABLE_INFORMATION`). The layer's `CKA_ID "DS3"` search therefore
  finds no match and transparently falls back to a class-only search. That is
  correct for a single-key token; on a real token that does expose `CKA_ID`
  (e.g. Bit4id), the ID-based selection is used to pick the right key.
- **Mechanism ID mismatch:** this system's `p11-kit` header and its SoftHSM
  build encode `CKM_SHA256_RSA_PKCS` as `0x40`, whereas the OASIS spec (and
  most tokens, e.g. Bit4id) use `0x1051`. The PKCS#11 layer in
  `src/pkcs11.cpp` therefore tries both values in `sign()` so it works against
  either encoding.

## Project layout

```
src/
  pkcs11_abi.h    Minimal PKCS#11 ABI (types, constants, fn pointers)
  pkcs11.{h,cpp}  dlopen PKCS#11 wrapper (slots, login, signer, sign)
  cmssigner.{h,cpp} CMS (signed-data) build + verify
  pades.{h,cpp}   PAdES-BES PDF signing (ByteRange layout)
  p7m.{h,cpp}     P7M detached CMS sign/verify
  der.{h,cpp}     DER encode/parse helpers
  c14n.{h,cpp}    Canonical XML
  tslparser / tslverifier  TSL parsing + verification
  x509util.{h,cpp} X.509 helpers
  base64.{h,cpp}
   main.cpp / mainwindow.*  Qt GUI (PAdES + P7M tabs)
   pdfpreview.*             Poppler PDF page view + click-drag signature box
tests/
   tst_c14n.cpp / tst_tslverifier.cpp / tst_p7mverify.cpp / tst_pades.cpp
   tst_pkcs11.cpp + run_pkcs11.sh   PKCS#11 test + module auto-selection
   tst_guisign.cpp                  headless GUI + signing-path test
   data/                            fixtures (TSL, sample PDF, etc.)
cmake/toolchain-mingw64.cmake        Windows x64 cross toolchain (Fedora mingw64)
packaging/windows/                   NSIS installer + runtime DLL deployment
```

## Status

- Crypto/PKCS#11 core: **complete** and covered by the test suites.
- GUI: **complete** — PAdES / P7M tabs with slot detection and PDF preview
  (click-drag signature box), wired to the `Pkcs11` + `Pades`/`P7M` core.
  Covered headlessly by the `guisign` suite (offscreen construction, Poppler
  render, full token→sign→verify path). Visual layout not yet reviewed.
