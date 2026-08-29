# Multi-stage Debian (trixie) build/test/package image for FirmaDigitaleOpenCpp.
#
#   docker build --target test -t fdo-test .     # configure + build + full ctest
#   docker build -t fdo-pkg .                    # ...plus build the .deb with cpack
#   docker run --rm -v "$PWD:/out" fdo-pkg      # drop firmadigitaleopen_*.deb into CWD
#
# The .deb reproduces a genuine Debian build (Qt 6.8, OpenSSL 3.5, poppler-qt6,
# SoftHSM2 + OpenSC for the PKCS#11 suite). The proprietary libbit4xpki.so is
# bundled when present next to the repo (it is part of the build context, like
# on the host); when absent the .deb is produced without the token module (CPack
# warns) and the pkcs11/guisign tests use the SoftHSM emulator.

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
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------ test ----
FROM base AS test

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build \
 && ctest --test-dir /build --output-on-failure

# -------------------------------------------------------------- package ----
FROM test AS package

# cpack drops the .deb into the working directory.
RUN cpack --config /build/CPackConfig.cmake

VOLUME /out
WORKDIR /out
ENTRYPOINT ["sh", "-c", "cp /src/firmadigitaleopen_*.deb /out/ && ls -l /out/"]