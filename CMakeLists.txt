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
    resources/resources.qrc
)

target_link_libraries(firmadigitaleopen PRIVATE Qt6::Widgets PopplerQt6 fdo_core)

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
)
target_link_libraries(tst_guisign PRIVATE Qt6::Widgets PopplerQt6 fdo_core)
target_compile_definitions(tst_guisign PRIVATE
    FDO_SAMPLE_PDF="${CMAKE_CURRENT_SOURCE_DIR}/tests/data/test.pdf")
# When TESTP7M is set, the GUI test also exercises the verify tab (part C).
if(TESTP7M)
    target_compile_definitions(tst_guisign PRIVATE FDO_SAMPLE_P7M="${TESTP7M}")
endif()
add_test(NAME guisign
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_pkcs11.sh
                 $<TARGET_FILE:tst_guisign>)
