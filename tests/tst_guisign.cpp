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
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "base64.h"
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

using UpKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UpX509 = std::unique_ptr<X509, decltype(&X509_free)>;

UpKey genKey()
{
    return { EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048), EVP_PKEY_free };
}

void addCaBasicConstraints(X509 *x, int critical)
{
    BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
    if (!bc)
        return;
    bc->ca = 1;
    bc->pathlen = nullptr;
    X509_EXTENSION *ex = X509V3_EXT_i2d(NID_basic_constraints, critical, bc);
    if (ex) {
        X509_add_ext(x, ex, -1);
        X509_EXTENSION_free(ex);
    }
    BASIC_CONSTRAINTS_free(bc);
}

UpX509 mkCa(const EVP_PKEY *caKey, const char *cn)
{
    X509 *ca = X509_new();
    X509_set_version(ca, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
    X509_gmtime_adj(X509_getm_notBefore(ca), 0);
    X509_gmtime_adj(X509_getm_notAfter(ca), 3600LL * 24 * 3650);
    X509_NAME *name = X509_get_subject_name(ca);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(cn), -1, -1, 0);
    X509_set_issuer_name(ca, name);
    X509_set_pubkey(ca, const_cast<EVP_PKEY *>(caKey));
    addCaBasicConstraints(ca, 1);
    X509_sign(ca, const_cast<EVP_PKEY *>(caKey), EVP_sha256());
    return { ca, X509_free };
}

UpX509 mkLeaf(const EVP_PKEY *leafKey, const X509 *ca, const EVP_PKEY *caKey,
              const char *cn)
{
    X509 *leaf = X509_new();
    X509_set_version(leaf, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf), 2);
    X509_gmtime_adj(X509_getm_notBefore(leaf), -60);
    X509_gmtime_adj(X509_getm_notAfter(leaf), 3600LL * 24 * 3650);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(leaf), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(cn), -1, -1, 0);
    X509_set_issuer_name(leaf, X509_get_subject_name(ca));
    X509_set_pubkey(leaf, const_cast<EVP_PKEY *>(leafKey));
    X509_sign(leaf, const_cast<EVP_PKEY *>(caKey), EVP_sha256());
    return { leaf, X509_free };
}

std::vector<unsigned char> x509Der(const X509 *x)
{
    unsigned char *der = nullptr;
    const int len = i2d_X509(x, &der);
    std::vector<unsigned char> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

bool signWithKey(const EVP_PKEY *key, const std::vector<unsigned char> &data,
                 std::vector<unsigned char> &sig, std::string &err)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr,
                                   const_cast<EVP_PKEY *>(key)) != 1) {
        err = "EVP_DigestSignInit";
        EVP_MD_CTX_free(ctx);
        return false;
    }
    size_t len = 0;
    bool ok = EVP_DigestSign(ctx, nullptr, &len, data.data(), data.size()) == 1;
    sig.resize(len);
    ok = ok && EVP_DigestSign(ctx, sig.data(), &len, data.data(), data.size()) == 1;
    sig.resize(len);
    EVP_MD_CTX_free(ctx);
    if (!ok)
        err = "EVP_DigestSign";
    return ok;
}

} // namespace

int main(int argc, char **argv)
{
    qputenv("QT_QPA_PLATFORM", "offscreen");

    // Hermetic TSL handling for the verify tab: local cache dir + no network.
    // FDO_DISABLE_TSL_DOWNLOAD makes the download-on-verify step a no-op so
    // the test never touches the network.
    const QByteArray cacheDir =
        QFileInfo(QString::fromLocal8Bit(argv[0])).absolutePath().toUtf8() +
        "/.tsl-test-cache";
    QDir().mkpath(QString::fromLocal8Bit(cacheDir));
    qputenv("FDO_TSL_CACHE_DIR", cacheDir);
    qputenv("FDO_DISABLE_TSL_DOWNLOAD", "1");

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

    // ---- Part C: verify tab (always, hermetic) ------------------------------
    // Build a CA + leaf on the fly, sign a small content and push it through
    // the GUI verify tab:
    //   1) without any TSL -> must FAIL (no trust chain without an up-to-date TSL);
    //   2) with a fixture TSL (the CA as trust anchor, far-future NextUpdate)
    //      in the local cache -> must PASS (TSL-anchored verification).
    {
        const std::string work = cacheDir.constData();
        auto caKey = genKey();
        auto leafKey = genKey();
        auto ca = mkCa(caKey.get(), "FDO Test CA");
        auto leaf = mkLeaf(leafKey.get(), ca.get(), caKey.get(), "FDO Test User");
        const std::vector<unsigned char> caDer = x509Der(ca.get());
        const std::vector<unsigned char> leafDer = x509Der(leaf.get());
        const auto signFn = [&leafKey](const std::vector<unsigned char> &d,
                                       std::vector<unsigned char> &s, std::string &e) {
            return signWithKey(leafKey.get(), d, s, e);
        };

        const std::string content = work + "/content.bin";
        const std::string p7m = work + "/signed.p7m";
        writeAll(content, { 'a', 'b', 'c', 1, 2, 3 });
        std::string err;
        if (!P7M::signFile(content, p7m, leafDer, signFn, &err)) {
            std::fprintf(stderr, "FAIL: fixture P7M sign: %s\n", err.c_str());
            return 1;
        }
        const QString sample = QString::fromStdString(p7m);

        w.openFileForVerify(sample);
        QString report = w.verifyReportText();
        if (!report.contains("FIRMA NON VALIDA") || !report.contains("TSL")) {
            std::fprintf(stderr, "FAIL: verify without TSL must be rejected, report:\n%s\n",
                         report.toUtf8().constData());
            return 1;
        }
        std::printf("OK: verify without TSL refused (no trust chain)\n");

        const std::string b64 = fdo::base64Encode(caDer.data(), caDer.size());
        const std::string tslXml =
            "<TrustServiceStatusList xmlns=\"http://uri.etsi.org/02231/v2#\">"
            "<SchemeInformation>"
            "<TSLVersionIdentifier>1</TSLVersionIdentifier>"
            "<TSLSequenceNumber>1</TSLSequenceNumber>"
            "<ListIssueDateTime>2026-08-01T00:00:00Z</ListIssueDateTime>"
            "<NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>"
            "</SchemeInformation>"
            "<TrustServiceProviderList><TrustServiceProvider><TSPInformation>"
            "<TSPName>FDO</TSPName>"
            "</TSPInformation><TSPServices><TSPService><ServiceInformation>"
            "<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/SvceType/CA/QC"
            "</ServiceTypeIdentifier>"
            "<ServiceName><Name xml:lang=\"it\">FDO</Name></ServiceName>"
            "<ServiceStatus>http://uri.etsi.org/TrstSvc/SvceStatus/"
            "recognisedatnationallevel</ServiceStatus>"
            "<ServiceDigitalIdentity><DigitalId><X509Certificate>" + b64 +
            "</X509Certificate></DigitalId></ServiceDigitalIdentity>"
            "</ServiceInformation></TSPService></TSPServices>"
            "</TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>";
        writeAll(work + "/TSL-IT.xml",
                 { tslXml.begin(), tslXml.end() });

        w.openFileForVerify(sample);
        report = w.verifyReportText();
        if (!report.contains("FIRMA VALIDA") || !report.contains("TSL")) {
            std::fprintf(stderr, "FAIL: TSL-anchored verify, report:\n%s\n",
                         report.toUtf8().constData());
            return 1;
        }
        std::printf("OK: verify via cached fixture TSL -> valid\n");

        // PAdES: sign a real PDF with the same leaf, then verify it through
        // the GUI's verify tab (detached CMS embedded in the PDF).
        const std::vector<unsigned char> pdf = readAll(FDO_SAMPLE_PDF);
        if (pdf.empty()) {
            std::fprintf(stderr, "FAIL: cannot read %s\n", FDO_SAMPLE_PDF);
            return 1;
        }
        auto leafCert = fdo::X509Cert::fromDer(leafDer);
        if (!leafCert) {
            std::fprintf(stderr, "FAIL: leaf cert decode\n");
            return 1;
        }
        PadesConfig cfg;
        cfg.pdfBytes = pdf;
        cfg.onPage = 0;
        cfg.visible = true;
        cfg.visibleText = "Firmato digitalmente da ";
        cfg.boxX1 = 50;
        cfg.boxY1 = 50;
        cfg.boxX2 = 250;
        cfg.boxY2 = 120;
        cfg.signerCert = *leafCert;
        PadesResult pr = Pades::sign(cfg, signFn);
        if (!pr.ok) {
            std::fprintf(stderr, "FAIL: PAdES sign: %s\n", pr.error.c_str());
            return 1;
        }
        const std::string pdfOut = work + "/signed.pdf";
        writeAll(pdfOut, pr.pdfBytes);
        w.openFileForVerify(QString::fromStdString(pdfOut));
        report = w.verifyReportText();
        if (!report.contains("FIRMA VALIDA") || !report.contains("PAdES")) {
            std::fprintf(stderr, "FAIL: PAdES verify via GUI, report:\n%s\n",
                         report.toUtf8().constData());
            return 1;
        }
        std::printf("OK: verify signed PDF via fixture TSL -> valid\n");
    }

    // ---- Part C2: real-world sample (.p7m exercised via the verify tab) ----
    // Only a smoke check: with the fixture TSL cached, a real-world signature
    // is not anchored to it, so the outcome (valid or not) depends on the
    // sample; what matters is that the decode+verify pipeline runs.
    {
        const QString sample = QString::fromUtf8(FDO_SAMPLE_P7M);
        if (!sample.isEmpty() && QFileInfo::exists(sample)) {
            w.openFileForVerify(sample);
            const QString report = w.verifyReportText();
            if (!report.contains("FIRMA")) {
                std::fprintf(stderr, "FAIL: verify tab report for %s:\n%s\n",
                             sample.toUtf8().constData(),
                             report.toUtf8().constData());
                return 1;
            }
            std::printf("OK: verify tab opened %s -> %s\n",
                        sample.toUtf8().constData(),
                        report.contains("FIRMA VALIDA") ? "valid (TSL)"
                                                          : "not valid (no TSL trust)");
        } else if (!sample.isEmpty()) {
            std::printf("sample %s missing; verify-tab sample test skipped\n",
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
