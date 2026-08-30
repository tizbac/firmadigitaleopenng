#!/bin/sh
# Refresh desktop + mime databases after install/upgrade so the .pdf/.p7m
# file association (MimeType in the .desktop file) takes effect immediately.
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database /usr/share/applications || true
command -v update-mime-database >/dev/null 2>&1 \
    && update-mime-database /usr/share/mime || true
exit 0