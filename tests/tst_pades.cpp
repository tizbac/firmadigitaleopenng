// tst_pades: PAdES-BES PDF sign/verify tests.
// Usage: tst_pades <dataDir>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "p7m.h"
#include "pades.h"
#include "x509util.h"

using namespace fdo;

static int g_failures = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        const std::string msg_ = (msg);                                        \
        if (cond) {                                                            \
            std::printf("  OK   %s\n", msg_.c_str());                          \
        } else {                                                               \
            std::printf("  FAIL %s\n", msg_.c_str());                          \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

namespace {

using UpKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UpX509 = std::unique_ptr<X509, decltype(&X509_free)>;

std::vector<unsigned char> readFile(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>() };
}

bool writeFile(const std::string &path, const std::vector<unsigned char> &data)
{
    std::ofstream f(path, std::ios::binary);
    if (!static_cast<bool>(f))
        return false;
    f.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(f);
}

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

UpX509 mkCa(const EVP_PKEY *caKey)
{
    X509 *ca = X509_new();
    X509_set_version(ca, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
    X509_gmtime_adj(X509_getm_notBefore(ca), 0);
    X509_gmtime_adj(X509_getm_notAfter(ca), 3600LL * 24 * 3650);
    X509_NAME *name = X509_get_subject_name(ca);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("FDO Test CA"),
                               -1, -1, 0);
    X509_set_issuer_name(ca, name);
    X509_set_pubkey(ca, const_cast<EVP_PKEY *>(caKey));
    addCaBasicConstraints(ca, 1);
    X509_sign(ca, const_cast<EVP_PKEY *>(caKey), EVP_sha256());
    return { ca, X509_free };
}

UpX509 mkLeaf(const EVP_PKEY *leafKey, const X509 *ca, const EVP_PKEY *caKey)
{
    X509 *leaf = X509_new();
    X509_set_version(leaf, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf), 2);
    X509_gmtime_adj(X509_getm_notBefore(leaf), -60);
    X509_gmtime_adj(X509_getm_notAfter(leaf), 3600LL * 24 * 3650);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(leaf), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("FDO Test User"),
                               -1, -1, 0);
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
    if (ok) {
        sig.resize(len);
        ok = EVP_DigestSign(ctx, sig.data(), &len, data.data(), data.size()) == 1;
    }
    EVP_MD_CTX_free(ctx);
    if (!ok)
        err = "EVP_DigestSign";
    return ok;
}

// offset of the first hex digit of the signature value in the Sig dictionary
std::size_t findSigHex(const std::vector<unsigned char> &pdf)
{
    const std::string s(reinterpret_cast<const char *>(pdf.data()), pdf.size());
    const auto br = s.rfind("/ByteRange [");
    if (br == std::string::npos)
        return std::string::npos;
    const auto lt = s.find('<', br + 56);
    if (lt == std::string::npos)
        return std::string::npos;
    return lt + 1;
}

} // namespace

int main(int argc, char **argv)
{
    const std::string dataDir = argc > 1 ? argv[1] : "tests/data";

    const std::vector<unsigned char> pdf = readFile(dataDir + "/test.pdf");
    if (pdf.empty() || pdf.size() < 100 ||
        std::memcmp(pdf.data(), "%PDF-", 5) != 0) {
        std::printf("cannot load %s/test.pdf\n", dataDir.c_str());
        return 2;
    }

    UpKey caKey = genKey();
    UpKey leafKey = genKey();
    UpX509 ca = mkCa(caKey.get());
    UpX509 leaf = mkLeaf(leafKey.get(), ca.get(), caKey.get());
    X509Cert anchor;
    anchor.der = x509Der(ca.get());
    anchor.selfSigned = true;
    auto anchorPtr = std::unique_ptr<X509Cert>(new X509Cert(anchor));
    const std::vector<const X509Cert *> anchors{ anchorPtr.get() };

    X509Cert signerCert;
    signerCert.der = x509Der(leaf.get());

    SignFunction signer = [&leafKey](const std::vector<unsigned char> &data,
                                     std::vector<unsigned char> &sig,
                                     std::string &err) {
        return signWithKey(leafKey.get(), data, sig, err);
    };

    X509Cert caCert;
    caCert.der = x509Der(ca.get());

    // ---- 1) invisible signature ----
    std::printf("== 1) invisible PAdES-BES sign + verify ==\n");
    PadesConfig cfg;
    cfg.pdfBytes = pdf;
    cfg.signerCert = signerCert;
    cfg.extraCerts.push_back(caCert);
    PadesResult pr = Pades::sign(cfg, signer);
    CHECK(pr.ok, "sign invisible (err: " + pr.error + ")");
    if (!pr.ok)
        return 1;
    CHECK(writeFile("/tmp/fdo_test_invisible.pdf", pr.pdfBytes), "wrote /tmp/fdo_test_invisible.pdf");
    P7MResult vr = Pades::verify(pr.pdfBytes, anchors);
    CHECK(vr.ok, "verify invisible (err: " + vr.error + ")");
    CHECK(vr.signerSubject.find("FDO Test User") != std::string::npos,
          "signer subject: " + vr.signerSubject);
    CHECK(vr.anchorSubject.find("FDO Test CA") != std::string::npos,
          "anchor: " + vr.anchorSubject);
    CHECK(!vr.signingTime.empty(), "signingTime: " + vr.signingTime);

    // ---- 2) visible signature ----
    std::printf("== 2) visible PAdES-BES (stamp) sign + verify ==\n");
    PadesConfig vcfg = cfg;
    vcfg.visible = true;
    vcfg.onPage = 0;
    vcfg.boxX1 = 50;
    vcfg.boxY1 = 50;
    vcfg.boxX2 = 250;
    vcfg.boxY2 = 100;
    PadesResult vpr = Pades::sign(vcfg, signer);
    CHECK(vpr.ok, "sign visible (err: " + vpr.error + ")");
    if (vpr.ok) {
        CHECK(writeFile("/tmp/fdo_test_visible.pdf", vpr.pdfBytes),
              "wrote /tmp/fdo_test_visible.pdf");
        P7MResult vvr = Pades::verify(vpr.pdfBytes, anchors);
        CHECK(vvr.ok, "verify visible (err: " + vvr.error + ")");
    }

    // ---- 3) tampered content must fail ----
    std::printf("== 3) tampered content must fail ==\n");
    std::vector<unsigned char> tampered = pr.pdfBytes;
    if (!tampered.empty() && tampered.size() > 1001)
        tampered[1000] ^= 0x01;
    P7MResult tvr = Pades::verify(tampered, anchors);
    CHECK(!tvr.ok, "tampered content rejected (err: " + tvr.error + ")");

    // ---- 4) tampered signature must fail ----
    std::printf("== 4) tampered signature value must fail ==\n");
    std::vector<unsigned char> badSig = pr.pdfBytes;
    const std::size_t hx = findSigHex(badSig);
    if (hx != std::string::npos && hx + 1 < badSig.size())
        badSig[hx + 1] = (badSig[hx + 1] == 'a') ? 'b' : 'a';
    P7MResult svr = Pades::verify(badSig, anchors);
    CHECK(!svr.ok, "tampered signature rejected (err: " + svr.error + ")");

    // ---- 5) wrong anchor must fail ----
    std::printf("== 5) wrong trust anchor must fail ==\n");
    UpKey otherCaKey = genKey();
    UpX509 otherCa = mkCa(otherCaKey.get());
    X509Cert otherAnchor;
    otherAnchor.der = x509Der(otherCa.get());
    otherAnchor.selfSigned = true;
    auto otherPtr = std::unique_ptr<X509Cert>(new X509Cert(otherAnchor));
    const std::vector<const X509Cert *> wrongAnchors{ otherPtr.get() };
    P7MResult wr = Pades::verify(pr.pdfBytes, wrongAnchors);
    CHECK(!wr.ok, "wrong anchor rejected (err: " + wr.error + ")");

    std::printf(g_failures ? "SOME PADES TESTS FAILED\n" : "All pades tests passed.\n");
    return g_failures ? 1 : 0;
}
