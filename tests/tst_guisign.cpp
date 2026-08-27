// tst_guisign: headless test of the Qt GUI wiring.
//   Part A (always): construct MainWindow offscreen and render a PDF page with
//                    Poppler via PdfPreview (catches GUI/Poppler init bugs).
//   Part B (when a usable token is reachable): run the exact signing path the
//                    GUI uses -- token cert -> X509Cert -> Pades/P7M sign ->
//                    self-anchored verify -- to prove the wiring end to end.
//   Part C (when FDO_SAMPLE_P7M is set): exercise the file-association path --
//                    openFileForVerify() on a real-world .p7m, which verifies
//                    it self-anchored through the GUI's verify tab.
//
// Usage: tst_guisign <p11lib> [pin]
// (same interface as tst_pkcs11, so tests/run_pkcs11.sh drives it.)
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <QApplication>
#include <QFile>
#include <QFileInfo>

#include "mainwindow.h"
#include "pdfpreview.h"
#include "pkcs11.h"
#include "pades.h"
#include "p7m.h"
#include "x509util.h"

#ifndef FDO_SAMPLE_PDF
#define FDO_SAMPLE_PDF "tests/data/test.pdf"
#endif

#ifndef FDO_SAMPLE_P7M
#define FDO_SAMPLE_P7M ""
#endif

using namespace fdo;

namespace {

std::vector<unsigned char> readAll(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>() };
}

bool writeAll(const std::string &path, const std::vector<unsigned char> &b)
{
    std::ofstream f(path, std::ios::binary);
    if (!static_cast<bool>(f))
        return false;
    f.write(reinterpret_cast<const char *>(b.data()),
            static_cast<std::streamsize>(b.size()));
    return static_cast<bool>(f);
}

} // namespace

int main(int argc, char **argv)
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    // ---- Part A: GUI construction + Poppler render (always) ----
    MainWindow w;
    w.show();
    app.processEvents();

    PdfPreview pv;
    QString perr;
    if (!pv.loadPdf(QString::fromUtf8(FDO_SAMPLE_PDF), 0, &perr) ||
        pv.pageCount() <= 0) {
        std::fprintf(stderr, "FAIL: PDF preview load (%s)\n",
                     perr.toUtf8().constData());
        return 1;
    }
    std::printf("OK: GUI constructed; preview rendered %d page(s)\n",
                pv.pageCount());

    // ---- Part C: verify tab via the file-association path (always, if sample) ----
    {
        const QString sample = QString::fromUtf8(FDO_SAMPLE_P7M);
        if (!sample.isEmpty() && QFileInfo::exists(sample)) {
            w.openFileForVerify(sample); // no TSL: self-anchored verify
            const QString report = w.verifyReportText();
            if (!report.contains("FIRMA VALIDA")) {
                std::fprintf(stderr, "FAIL: verify tab report for %s:\n%s\n",
                            sample.toUtf8().constData(),
                            report.toUtf8().constData());
                return 1;
            }
            std::printf("OK: verify tab opened %s -> %s\n",
                        sample.toUtf8().constData(),
                        report.contains("ancora propria")
                            ? "valid (self-anchored)"
                            : "valid (TSL)");
        } else if (!sample.isEmpty()) {
            std::printf("sample %s missing; verify-tab test skipped\n",
                        sample.toUtf8().constData());
        }
    }

    // ---- Part B: token sign path (only when a module is supplied) ----
    if (argc < 2) {
        std::printf("no PKCS#11 module supplied; GUI-only test passed\n");
        return 0;
    }
    const std::string lib = argv[1];
    const std::string pin = argc > 2 ? argv[2] : "";

    std::string err;
    const auto found = Pkcs11::enumerateSlots(lib, &err);
    const Pkcs11Slot *use = nullptr;
    for (const auto &s : found)
        if (s.hasCert) {
            use = &s;
            break;
        }
    if (!use && !found.empty())
        use = &found.front();
    if (!use) {
        std::printf("no usable slot (smoke pass): %s\n", err.c_str());
        return 0;
    }

    Pkcs11 p11;
    if (!p11.loadLibrary(lib, &err) || !p11.login(use->index, pin, &err) ||
        !p11.findSigner(&err)) {
        std::printf("token not ready (smoke pass): %s\n", err.c_str());
        return 0;
    }
    const auto *signer = p11.signer();
    if (!signer || signer->certDer.empty()) {
        std::printf("no signer cert (smoke pass)\n");
        return 0;
    }
    auto cert = X509Cert::fromDer(signer->certDer);
    if (!cert) {
        std::fprintf(stderr, "FAIL: token certificate invalid\n");
        return 1;
    }

    const auto signFn = [&p11](const std::vector<unsigned char> &data,
                               std::vector<unsigned char> &sig, std::string &e) {
        return p11.sign(data, sig, &e);
    };

    const std::vector<unsigned char> pdf = readAll(FDO_SAMPLE_PDF);
    if (pdf.empty()) {
        std::fprintf(stderr, "FAIL: cannot read %s\n", FDO_SAMPLE_PDF);
        return 1;
    }

    // Self-signed token cert doubles as the trust anchor.
    X509Cert anchor;
    anchor.der = cert->der;
    anchor.selfSigned = true;
    auto anchorPtr = std::unique_ptr<X509Cert>(new X509Cert(anchor));
    const std::vector<const X509Cert *> anchors{ anchorPtr.get() };

    // PAdES (visible stamp, as the GUI would produce).
    PadesConfig cfg;
    cfg.pdfBytes = pdf;
    cfg.onPage = 0;
    cfg.visible = true;
    cfg.visibleText = "Firmato digitalmente da ";
    cfg.boxX1 = 50;
    cfg.boxY1 = 50;
    cfg.boxX2 = 250;
    cfg.boxY2 = 120;
    cfg.signerCert = *cert;
    PadesResult pr = Pades::sign(cfg, signFn);
    if (!pr.ok) {
        std::fprintf(stderr, "FAIL: PAdES sign: %s\n", pr.error.c_str());
        return 1;
    }
    P7MResult pvres = Pades::verify(pr.pdfBytes, anchors);
    if (!pvres.ok) {
        std::fprintf(stderr, "FAIL: PAdES verify: %s\n", pvres.error.c_str());
        return 1;
    }
    std::printf("OK: PAdES sign + self-anchored verify (signer: %s)\n",
                pvres.signerSubject.c_str());

    // P7M detached/CAdES over a small content.
    const std::vector<unsigned char> content = { 'h', 'e', 'l', 'l', 'o',
                                                 ' ', 'g', 'u', 'i' };
    const std::string inPath = "/tmp/tst_guisign_content.bin";
    const std::string outPath = "/tmp/tst_guisign_out.p7m";
    writeAll(inPath, content);
    std::string serr;
    if (!P7M::signFile(inPath, outPath, signer->certDer, signFn, &serr)) {
        std::fprintf(stderr, "FAIL: P7M sign: %s\n", serr.c_str());
        return 1;
    }
    const std::vector<unsigned char> p7m = readAll(outPath);
    P7MResult r7 = P7M::decodeAndVerify(p7m, anchors);
    if (!r7.ok) {
        std::fprintf(stderr, "FAIL: P7M verify: %s\n", r7.error.c_str());
        return 1;
    }
    std::printf("OK: P7M sign + self-anchored verify\n");

    std::printf("GUI sign test passed\n");
    return 0;
}
