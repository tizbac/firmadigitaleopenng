# AGENTS.md

C++17/Qt6 digital-signature tool: PAdES-BES PDF signing, P7M (CMS detached) sign/verify, TSL verification, PKCS#11 (Bit4id) token access. `fdo_core` is a Qt-free static crypto library; the Qt GUI (`main.cpp`, `mainwindow.*`, `pdfpreview.*`) sits on top. Everything lives in namespace `fdo`. README.md has full details.

## Build & test

```
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure          # all suites
ctest --test-dir build -R pades --output-on-failure  # single suite
```

- Requires Qt6 >= 6.5 (Widgets/Network/Sql), OpenSSL 3, libxml2, and `libpoppler-qt6-dev`. Poppler ships no CMake config; CMakeLists.txt builds an imported target from the raw header/library and fails hard without it.
- **Docker (Debian trixie, hermetic and reproducible):** `docker build --target test -t fdo-test .` runs configure + full build + all 6 ctest suites (Qt 6.8, OpenSSL 3.5, poppler-qt6, SoftHSM2 + OpenSC so the `pkcs11`/`guisign` suites run the real emulated-token path). `docker build -t fdo-pkg .` additionally runs cpack; the `.deb` bundles `libbit4xpki.so` when it is present next to the repo (it is part of the build context, just like on the host) and skips the token module with a WARNING otherwise. `docker run --rm -v "$PWD:/out" fdo-pkg` drops `firmadigitaleopen_<version>_<arch>.deb` into `$PWD`. Container sets `QT_QPA_PLATFORM=offscreen` (tests are headless).
- **Docker (Fedora 44, RPM):** the same Dockerfile also defines `rpm-test` (`docker build --target rpm-test -t fdo-rpm-test .` → build + 6 ctest on Fedora, Qt 6.11 + poppler-qt6 + SoftHSM at `/usr/lib64/pkcs11/libsofthsm2.so`) and `rpm-pkg` (`docker build --target rpm-pkg -t fdo-rpm .` + `docker run --rm -v "$PWD:/out" fdo-rpm` → `firmadigitaleopen-<version>-1.<arch>.rpm`). The Dockerfile default target is still the Debian `package` stage.
- **Docker (AppImage):** `docker build --target appimage -t fdo-appimage .` (builds on the Debian `test` stage) runs linuxdeploy + the Qt plugin (`ENV APPIMAGE_EXTRACT_AND_RUN=1` so linuxdeploy can spawn the plugin AppImage without FUSE; a `qmake6` symlink is added so the plugin finds Qt; the Debian build is configured with `-DCMAKE_INSTALL_PREFIX=/usr` so the DESTDIR install lands under `$APPDIR/usr/...`). Output `FirmaDigitaleOpen-x86_64.AppImage` carries the binary, Qt6/poppler/ssl/xml2 libs, the platforms plugin and the Bit4id bundle at `usr/lib/<multiarch>/firmadigitaleopen/`; `defaultP11Lib()` probes `$APPDIR/usr/lib/x86_64-linux-gnu/firmadigitaleopen/libbit4xpki.so` then `$APPDIR/usr/lib/...` before the system paths.
- The checked-in `build/` and `build-plain/` directories are stale: they were configured from a previous checkout path (`/home/tiziano/FirmaDigitaleOpen/firmadigitaleopencpp`), so their ctest entries point at old binaries. Configure a fresh build dir instead of trusting them.
- No lint/format/typecheck tooling is configured in this repo.

## Test suites and gotchas

- Suites: `c14n`, `tslverifier`, `p7mverify`, `pades` (pure, fast); `pkcs11`, `guisign` (need a PKCS#11 module, resolved automatically — see below).
- **`tests/data/test.pdf` is missing from the repo**, but `pades` and `guisign` hard-fail without it (`tst_pades` exits 2). Any small valid PDF works; place it at `tests/data/test.pdf`. The PAdES parser only supports classic xref tables, not xref streams. Test binaries take the data dir as `argv[1]`, so they can also be pointed at any dir containing a `test.pdf` (e.g. `./build/tst_pades /path/to/dir`).
- `pkcs11` and `guisign` run via `tests/run_pkcs11.sh`, which resolves a module in order: (1) `FDO_PKCS11_LIB` + optional `FDO_PKCS11_PIN` env vars (physical token), (2) SoftHSM2 emulator — auto-initialises a throwaway token in a temp dir and exercises full login→sign→verify, (3) Bit4id lib next to the repo for enumeration-only, (4) skip with PASS. A missing token is never a failure; a module-load/ABI error or a signature-verification mismatch is.
- To run the GUI test headless with a physical token: `FDO_PKCS11_LIB=../libbit4xpki.so FDO_PKCS11_PIN=1234 ctest --test-dir build -R guisign --output-on-failure`.
- Optional real-world P7M check: configure with `-DTESTP7M=/path/to/file.p7m` (adds the AgID TSL verification part to `p7mverify` and a real-world smoke run to the `guisign` verify-tab part). **Never commit `.p7m` files** — they contain signed content (`.gitignore` already excludes `*.p7m`).
- The GUI verify tab (accepts signed `.pdf` — embedded PAdES — and `.p7m`) **requires an up-to-date TSL**: no explicit TSL file, no fresh cached one, and (unless disabled) a failed auto-download → the signature is reported NON VALIDA (no self-anchored fallback anymore). TSL resolution order: explicit path in the TSL field → cached copy → auto-download of `https://eidas.agid.gov.it/TL/TSL-IT.xml` into the cache (a "Aggiorna TSL" button forces this). Cache lives under `QStandardPaths::AppLocalDataLocation/TSL-IT.xml`, overridable with `FDO_TSL_CACHE_DIR`; `FDO_DISABLE_TSL_DOWNLOAD=1` turns the auto-download into a no-op (tests rely on it). The `guisign` Part C verify-tab test builds its own CA/leaf, signs a fixture P7M AND a real PDF, asserts no-TSL refusal, then caches a fixture TSL containing the CA and asserts positive TSL-anchored verify for both — all hermetic.
- Run a test binary directly: `./build/tst_pkcs11 <module.so> [pin]`.

## Packaging (CPack .deb)

Build the Debian package from a fresh build dir (do `cmake -S . -B build-deb` then):

```
cmake --build build-deb -j && cpack --config build-deb/CPackConfig.cmake
# -> firmadigitaleopen_<version>_<arch>.deb in the repo root
```

- Content: `/usr/bin/firmadigitaleopen`, the Bit4id bundle under `${libdir}/firmadigitaleopen/` (`libbit4xpki.so` dwm install `install(PROGRAMS ...)` → 755, `.conf` + `.rc/*.lic` 644), plus `firmadigitaleopen.desktop` and `firmadigitaleopen.svg` (hicolor scalable apps). `defaultP11Lib()` in `src/mainwindow.cpp` already probes `/usr/lib/x86_64-linux-gnu/firmadigitaleopen/libbit4xpki.so`, `/usr/lib/...`, `/usr/lib64/...` before the dev-tree variants.
- The `.so`/`.conf`/`.rc` are **in git** (committed deliberately; `.gitignore` re-includes `libbit4xpki.so` over the global `*.so`, and `.conf`/`.rc` are plain tracked files). The module **must** always be installed together with its `.conf` and `.rc/*.lic` in the *same* directory: `libbit4xpki.so` reads `libbit4xpki.so.conf` from its own directory at `C_Initialize` time (strace-verified), so a lone `.so` fails with `CKR_GENERAL_ERROR` (`C_Initialize` rv=5). CMakeLists enforces this: if the `.so` is present but the `.conf` is not, configure fails with `FATAL_ERROR`; if the `.so` is absent the whole bundle is skipped with a WARNING (no orphan config either). Keep the files next to the repo when packaging.
- Debian runtime Depends are set manually (no `dpkg-shlibdeps`): `libqt6widgets6, libqt6network6, libqt6sql6, libpoppler-qt6-6, libssl3, libxml2`. Overridable at configure time via `-DCPACK_DEBIAN_PACKAGE_DEPENDS=...`, and `-DCPACK_DEBIAN_PACKAGE_MAINTAINER=...` for the placeholder maintainer/contact (`firmadigitaleopen@example.invalid`).
- Architecture defaults from `CMAKE_SYSTEM_PROCESSOR` (amd64/arm64); override with `-DCPACK_DEBIAN_PACKAGE_ARCHITECTURE=...`. CMake 4.x derives the output name from `CPACK_PACKAGE_FILE_NAME` (no separate deb-specific name var).
- Inspecting without dpkg: `cd /tmp/i && ar x <file>.deb && tar xzf control.tar.gz && tar tzf data.tar.gz`.
- A `postinst` (from `packaging/postinst`, wired via `CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA`) refreshes `update-desktop-database` + `update-mime-database` on install/upgrade so the file association takes effect immediately.
- File association: `.desktop` MimeType claims `.pdf` + `.p7m` (`application/pdf`, `application/pkcs7-mime` — the non-`x-` variant is what Debian's shared-mime-info globs `.p7m` to — plus `application/x-pkcs7-mime`, `application/pkcs7-signature`, `application/x-pkcs7-signature`). `Exec=firmadigitaleopen %f` → a path arg makes `main.cpp` call `openFileForVerify()` (verify tab + immediate verification) for both formats.

## Packaging — Arch Linux (PKGBUILD)

- Repo-root `PKGBUILD` (1.0.0) + `firmadigitaleopen.install` script sharing `resources/firmadigitaleopen.desktop`/`.svg` and the same CMake install rules. Arch runtime deps: `qt6-base poppler-qt6 openssl libxml2` (Qt6 is monolithic there — no separate network/sql packages).
- `makepkg` sources straight from the git remote configured in `.git/config` (`git+ssh://git@git.tizbac.ovh/tiziano/firmadigitaleopencpp.git`). The proprietary Bit4id `.so` is committed, so the clone ships it and CMake bundles it; without it CMake's bundle guard still builds and packages, minus the token module. **`makepkg` must not strip the module** (default `strip` option would truncate `libbit4xpki.so` and break it — `C_Initialize` fails with CKR_GENERAL_ERROR), hence `options=('!strip')` in the PKGBUILD. Tests are NOT run by makepkg (`check()` absent): the ctest suites need untracked fixture data (e.g. `tests/data/test.pdf`) that git doesn't ship — use the Dockerfile for a full build+test. `firmadigitaleopen.install` refreshes desktop+mime DBs in `post_install`/`post_upgrade`/`post_remove`.

## GitHub Actions release workflow

- `.github/workflows/release.yml` builds on push of a `v*` tag or `workflow_dispatch`, producing the `.deb`, the `.rpm` and the AppImage via the Docker stages (`package`, `rpm-pkg`, `appimage`) and attaching them to the GitHub Release (`softprops/action-gh-release`). Jobs are allowed to upload artifacts even when the release branch/tag checks differ; the context includes the committed `libbit4xpki.so` so all three bundles carry the token module.

## PKCS#11 quirks (do not "fix")

- Signer key/cert are located by `CKA_ID "DS3"`; SoftHSM doesn't expose `CKA_ID` for reading, so the layer transparently falls back to a class-only search (correct for single-key tokens).
- `sign()` in `src/pkcs11.cpp` tries both `CKM_SHA256_RSA_PKCS` (0x1051) and 0x40: this system's p11-kit/SoftHSM build encodes the mechanism as 0x40.
- SoftHSM's `C_FindObjects` requires a non-NULL `pObjectCount`; SoftHSM reports every virtual slot as `tokenPresent`, so real tokens are distinguished by having a certificate.
- For manual SoftHSM work, `SOFTHSM2_CONF` must be exported for every PKCS#11 client process (setup steps in README.md).

## Conventions

- Core error strings are in Italian (e.g. `"xref non trovata (xref stream non supportato)"` in `pades.cpp`); tests and README rely on them — keep them.
- Tests are plain executables with a `CHECK` macro, no framework; they print `OK`/`FAIL` lines and return non-zero on failure.
