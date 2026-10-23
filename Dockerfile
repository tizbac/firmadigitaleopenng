# Multi-stage build/test/package image for FirmaDigitaleOpenCpp.
#
# Two independent Linux toolchains plus a Windows cross toolchain, pick the
# target explicitly:
#   Debian (trixie) — default target:
#     docker build --target test -t fdo-test .     # configure + build + full ctest
#     docker build -t fdo-pkg .                    # ...plus build the .deb with cpack
#     docker run --rm -v "$PWD:/out" fdo-pkg      # drop firmadigitaleopen_*.deb into CWD
#   Fedora (44) — RPM:
#     docker build --target rpm-test -t fdo-rpm-test .  # configure + build + full ctest
#     docker build --target rpm-pkg -t fdo-rpm .        # ...plus build the .rpm
#     docker run --rm -v "$PWD:/out" fdo-rpm            # drop firmadigitaleopen-*.rpm into CWD
#   Fedora (44) — Windows x64 installer (MinGW cross build + NSIS):
#     docker build --target win-package -t fdo-win .
#     docker run --rm -v "$PWD:/out" fdo-win            # drop the *-win64-setup.exe into CWD
#
# The Linux packages reproduce genuine distributions (Debian: Qt 6.8, OpenSSL
# 3.5, poppler-qt6; Fedora: Qt 6.x, OpenSSL 3.x) with SoftHSM2 + OpenSC so the
# PKCS#11 suite runs the real emulated-token path. The proprietary
# libbit4xpki.so is bundled when present next to the repo (it is part of the
# build context, like on the host); when absent the package is produced
# without the token module (CPack warns).

# ------------------------------------------------------------- rpm: build ----
FROM fedora:44 AS rpm-base

# Headless: all Qt tests use the offscreen platform plugin.
ENV QT_QPA_PLATFORM=offscreen

RUN dnf install -y --setopt=install_weak_deps=False \
        gcc-c++ \
        cmake \
        ninja-build \
        rpm-build \
        openssl \
        openssl-devel \
        qt6-qtbase-devel \
        poppler-qt6-devel \
        libxml2-devel \
        softhsm \
        opensc \
    && dnf clean all

# ------------------------------------------------------------ rpm: test ----
FROM rpm-base AS rpm-test

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build \
 && ctest --test-dir /build --output-on-failure

# --------------------------------------------------------- rpm: package ----
FROM rpm-test AS rpm-pkg

# cpack drops the .rpm into the working directory.
RUN cpack -G RPM --config /build/CPackConfig.cmake

VOLUME /out
WORKDIR /out
ENTRYPOINT ["sh", "-c", "cp /src/firmadigitaleopen-*.rpm /out/ && ls -l /out/"]

# ---------------------------------------------------------- deb: build ----
FROM debian:trixie-slim AS base

ENV DEBIAN_FRONTEND=noninteractive
# Headless: all Qt tests use the offscreen platform plugin.
ENV QT_QPA_PLATFORM=offscreen

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        build-essential \
        cmake \
        ninja-build \
        openssl \
        qt6-base-dev \
        libqt6sql6-sqlite \
        libpoppler-qt6-dev \
        libssl-dev \
        libxml2-dev \
        softhsm2 \
        opensc \
        file \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------ test ----
FROM base AS test

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
 && cmake --build /build \
 && ctest --test-dir /build --output-on-failure

# --------------------------------------------------------- appimage ----
FROM test AS appimage

# Packages the same Debian (trixie) build into a portable AppImage with
# linuxdeploy + the Qt plugin. The Bit4id module bundle ends up in
# $APPDIR/usr/lib/firmadigitaleopen/ (the AppImage probe in mainwindow.cpp).
# APPIMAGE_EXTRACT_AND_RUN lets linuxdeploy launch the plugin AppImage
# without FUSE.
ENV APPIMAGE_EXTRACT_AND_RUN=1
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends wget file \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q \
        https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage \
        -O /tmp/linuxdeploy.AppImage \
    && wget -q \
        https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage \
        -O /tmp/linuxdeploy-plugin-qt.AppImage \
    && chmod +x /tmp/linuxdeploy.AppImage /tmp/linuxdeploy-plugin-qt.AppImage \
    && mkdir -p /AppDir \
    && DESTDIR=/AppDir cmake --install /build \
    && ln -sf /usr/lib/qt6/bin/qmake6 /usr/local/bin/qmake \
    && QT_QPA_PLATFORM=offscreen /tmp/linuxdeploy.AppImage --appimage-extract-and-run \
        --appdir /AppDir \
        --plugin qt \
        --output appimage \
    && ls -la /src/*.AppImage

VOLUME /out
WORKDIR /out
ENTRYPOINT ["sh", "-c", "cp /src/*.AppImage /out/ && ls -l /out/"]

# --------------------------------------------------------- windows: build ----
# Cross-compiles the 64-bit Windows GUI with Fedora's mingw64 toolchain.
# Qt6, poppler-qt6, OpenSSL and libxml2 come from the mingw64 sysroot.
# packaging/windows/deploy.sh then copies the complete non-system DLL closure
# and the required Qt plugins next to the executable (the equivalent of
# windeployqt, which Fedora's cross Qt does not ship).
FROM fedora:44 AS win-base

RUN dnf install -y --setopt=install_weak_deps=False \
        cmake \
        ninja-build \
        binutils \
        mingw64-gcc-c++ \
        mingw64-qt6-qtbase \
        mingw64-poppler-qt6 \
        mingw64-openssl \
        mingw64-libxml2 \
    && dnf clean all

FROM win-base AS win-build

WORKDIR /src
COPY . /src

RUN set -eux; \
    sed -n 's/^project(FirmaDigitaleOpenCpp VERSION \([0-9][0-9.]*\).*/\1/p' \
        /src/CMakeLists.txt > /version; \
    test -s /version; \
    cmake -S /src -B /build -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE=/src/cmake/toolchain-mingw64.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/app; \
    cmake --build /build; \
    cmake --install /build; \
    bash /src/packaging/windows/deploy.sh /app

# ------------------------------------------------------- windows: package ----
# Native NSIS on Debian builds the Windows installer (no Wine needed); the
# staged application directory is copied from the Fedora cross-build stage.
FROM debian:trixie-slim AS win-package

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        nsis \
    && rm -rf /var/lib/apt/lists/*

COPY --from=win-build /app /app
COPY --from=win-build /version /version
COPY resources/firmadigitaleopen.ico /packaging/firmadigitaleopen.ico
COPY packaging/windows/installer.nsi /packaging/installer.nsi

RUN set -eux; \
    mkdir -p /dist; \
    VERSION="$(cat /version)"; \
    makensis -V2 \
        -DAPP_VERSION="$VERSION" \
        -DSOURCE_DIR=/app \
        -DICON_FILE=/packaging/firmadigitaleopen.ico \
        -DOUT_FILE="/dist/firmadigitaleopen-${VERSION}-win64-setup.exe" \
        /packaging/installer.nsi

VOLUME /out
WORKDIR /out
ENTRYPOINT ["sh", "-c", "cp /dist/*.exe /out/ && ls -l /out/"]

# -------------------------------------------------------------- package ----
FROM test AS package

# cpack drops the .deb into the working directory.
RUN cpack --config /build/CPackConfig.cmake

VOLUME /out
WORKDIR /out
ENTRYPOINT ["sh", "-c", "cp /src/firmadigitaleopen_*.deb /out/ && ls -l /out/"]
