cmake_minimum_required(VERSION 3.16)
project(FirmaDigitaleOpenCpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Network Sql)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(fdo_core STATIC
    src/base64.cpp
    src/c14n.cpp
    src/cmssigner.cpp
    src/der.cpp
    src/p7m.cpp
    src/pades.cpp
    src/pkcs11.cpp
    src/tslparser.cpp
    src/tslverifier.cpp
    src/x509util.cpp
)
target_include_directories(fdo_core PUBLIC src)
target_link_libraries(fdo_core PUBLIC LibXml2::LibXml2 OpenSSL::Crypto)
if (NOT APPLE)
    target_link_libraries(fdo_core PUBLIC ${CMAKE_DL_LIBS})
endif()

# Poppler-Qt6 for PDF preview. This system ships no CMake config, so build an
# imported target from the found header + shared library.
find_path(POPPLER_QT6_INCLUDE_DIR NAMES poppler/qt6/poppler-qt6.h)
find_library(POPPLER_QT6_LIBRARY NAMES poppler-qt6)
if (NOT POPPLER_QT6_INCLUDE_DIR OR NOT POPPLER_QT6_LIBRARY)
    message(FATAL_ERROR "Poppler-Qt6 not found (install libpoppler-qt6-dev)")
endif()
add_library(PopplerQt6 SHARED IMPORTED)
set_target_properties(PopplerQt6 PROPERTIES
    IMPORTED_LOCATION "${POPPLER_QT6_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${POPPLER_QT6_INCLUDE_DIR}")

qt_add_executable(firmadigitaleopen
    src/main.cpp
    src/mainwindow.cpp
    src/pdfpreview.cpp
    src/p11worker.cpp
    resources/resources.qrc
)

target_link_libraries(firmadigitaleopen PRIVATE Qt6::Widgets Qt6::Network PopplerQt6 fdo_core)

enable_testing()

add_executable(tst_c14n tests/tst_c14n.cpp)
target_link_libraries(tst_c14n PRIVATE fdo_core)
add_test(NAME c14n COMMAND tst_c14n ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)

add_executable(tst_tslverifier tests/tst_tslverifier.cpp)
target_link_libraries(tst_tslverifier PRIVATE fdo_core)
add_test(NAME tslverifier COMMAND tst_tslverifier ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/TSL-IT.xml)

add_executable(tst_p7mverify tests/tst_p7mverify.cpp)
target_link_libraries(tst_p7mverify PRIVATE fdo_core)
# Optional: path to a real-world .p7m verified against the AgID TSL (part 5).
# .p7m files contain sensitive data (content + signature): NEVER commit them;
# pass one via -DTESTP7M=/path/to/file.p7m when you have one to hand.
set(TESTP7M "" CACHE STRING "Optional .p7m file for the p7mverify + GUI verify-tab tests")
if(TESTP7M)
    add_test(NAME p7mverify COMMAND tst_p7mverify ${CMAKE_CURRENT_SOURCE_DIR}/tests/data
             ${TESTP7M})
else()
    add_test(NAME p7mverify COMMAND tst_p7mverify ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)
endif()

add_executable(tst_pades tests/tst_pades.cpp)
target_link_libraries(tst_pades PRIVATE fdo_core)
add_test(NAME pades COMMAND tst_pades ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)

# PKCS#11 test: run via a wrapper that auto-selects a module. It prefers a
# physical token (FDO_PKCS11_LIB/FDO_PKCS11_PIN), else the SoftHSM2 emulator
# (full login+sign+verify), else falls back to the Bit4id lib (enumeration
# only). A missing token is not a failure; a load/ABI error or a signature
# verification mismatch is.
add_executable(tst_pkcs11 tests/tst_pkcs11.cpp)
target_link_libraries(tst_pkcs11 PRIVATE fdo_core)
add_test(NAME pkcs11
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_pkcs11.sh
                 $<TARGET_FILE:tst_pkcs11>)

# Headless GUI test: constructs MainWindow offscreen, renders a PDF page via
# Poppler (PdfPreview), then -- through the same run_pkcs11.sh resolution --
# runs the exact token->cert->PAdES/P7M signing path the GUI wires up.
qt_add_executable(tst_guisign
    tests/tst_guisign.cpp
    src/mainwindow.cpp
    src/pdfpreview.cpp
    src/p11worker.cpp
)
target_link_libraries(tst_guisign PRIVATE Qt6::Widgets Qt6::Network PopplerQt6 fdo_core)
target_compile_definitions(tst_guisign PRIVATE
    FDO_SAMPLE_PDF="${CMAKE_CURRENT_SOURCE_DIR}/tests/data/test.pdf")
# When TESTP7M is set, the GUI test also exercises the verify tab (part C).
if(TESTP7M)
    target_compile_definitions(tst_guisign PRIVATE FDO_SAMPLE_P7M="${TESTP7M}")
endif()
add_test(NAME guisign
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_pkcs11.sh
                 $<TARGET_FILE:tst_guisign>)

# ---------------------------------------------------------------- packaging --#
include(GNUInstallDirs)

install(TARGETS firmadigitaleopen RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Bit4id PKCS#11 module + its run-time config, shipped inside the app's own
# (libdir)/firmadigitaleopen so defaultP11Lib() finds it. The .so reads
# libbit4xpki.so.conf from its own directory at load time, so the config (and
# the .rc licences) must always ride along with the .so: a module without its
# config does not work. Therefore, if the .so is present but the .conf is not,
# refuse to configure instead of packaging a broken half-bundle.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libbit4xpki.so")
    if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libbit4xpki.so.conf")
        message(FATAL_ERROR "libbit4xpki.so.conf manca accanto a libbit4xpki.so: il modulo token non funzionerebbe senza la sua configurazione")
    endif()
    install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/libbit4xpki.so
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/firmadigitaleopen)
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libbit4xpki.so.conf
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/firmadigitaleopen)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libbit4xpki.so.rc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/firmadigitaleopen
            FILES_MATCHING PATTERN "*.lic")
else()
    message(WARNING "libbit4xpki.so non trovato: il pacchetto non includera il modulo token Bit4id")
endif()

install(FILES resources/firmadigitaleopen.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES resources/firmadigitaleopen.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)

# ------------------------------------------------------------------- CPack --#
set(CPACK_PACKAGE_NAME "firmadigitaleopen")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VENDOR "FirmaDigitaleOpen")
set(CPACK_PACKAGE_CONTACT "firmadigitaleopen@example.invalid")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Firma digitale PAdES/P7M con token PKCS#11")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "FirmaDigitaleOpen <firmadigitaleopen@example.invalid>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libqt6widgets6, libqt6network6, libqt6sql6, libpoppler-qt6-6, libssl3, libxml2")
if (NOT CPACK_DEBIAN_PACKAGE_ARCHITECTURE)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
    else()
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
    endif()
endif()
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
# Refresh desktop+mime databases after install so the .pdf/.p7m file
# association (MimeType in the .desktop file) takes effect immediately.
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/postinst")
# --- RPM (Fedora) ------------------------------------------------------------#
# Used when packaging with `cpack -G RPM` (see the Dockerfile fedora stage);
# harmless when building the .deb.
set(CPACK_RPM_PACKAGE_NAME "firmadigitaleopen")
set(CPACK_RPM_PACKAGE_SUMMARY "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-only")
set(CPACK_RPM_PACKAGE_VENDOR "${CPACK_PACKAGE_VENDOR}")
set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_REQUIRES "qt6-qtbase, poppler-qt6, openssl-libs, libxml2")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/post-rpm.sh")
if (NOT CPACK_RPM_PACKAGE_ARCHITECTURE)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
    else()
        set(CPACK_RPM_PACKAGE_ARCHITECTURE "aarch64")
    endif()
endif()
set(CPACK_RPM_FILE_NAME
    "${CPACK_RPM_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}.${CPACK_RPM_PACKAGE_ARCHITECTURE}.rpm")
include(CPack)
