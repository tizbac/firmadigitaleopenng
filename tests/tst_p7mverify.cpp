// tst_p7mverify: CMS p7m sign/decode/verify tests.
// Usage: tst_p7mverify <dataDir> [sampleP7m]
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "p7m.h"
#include "tslparser.h"
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
    if (argc < 2) {
        std::printf("usage: %s <dataDir> [sampleP7m]\n", argv[0]);
        return 2;
    }
    const std::string dataDir = argv[1];

    // ---- setup: CA + leaf, in-memory signing --------------------------------
    auto caKey = genKey();
    auto leafKey = genKey();
    auto ca = mkCa(caKey.get());
    auto leaf = mkLeaf(leafKey.get(), ca.get(), caKey.get());
    const std::vector<unsigned char> caDer = x509Der(ca.get());
    const std::vector<unsigned char> leafDer = x509Der(leaf.get());
    auto caCert = X509Cert::fromDer(caDer);
    auto leafCert = X509Cert::fromDer(leafDer);

    const std::string contentPath = dataDir + "/p7m_test_content.bin";
    const std::string p7mPath = dataDir + "/p7m_test_content.bin.p7m";
    const std::vector<unsigned char> content = { 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3,
                                                 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    writeFile(contentPath, content);

    std::printf("== 1) round-trip: sign + verify (in-memory key) ==\n");
    std::string err;
    const bool signed_ = P7M::signFile(
        contentPath, p7mPath, leafDer,
        [&](const std::vector<unsigned char> &d, std::vector<unsigned char> &s,
            std::string &e) { return signWithKey(leafKey.get(), d, s, e); },
        &err);
    CHECK(signed_, std::string("signFile (err: ") + err + ")");

    const std::vector<unsigned char> p7mBytes = readFile(p7mPath);
    std::vector<const X509Cert *> anchors{ caCert.get() };
    P7MResult r = P7M::decodeAndVerify(p7mBytes, anchors);
    CHECK(r.ok, std::string("verify ok (err: ") + r.error + ")");
    CHECK(r.content == content, "embedded content matches");
    CHECK(r.signerSubject.find("FDO Test User") != std::string::npos, "signer subject");
    CHECK(!r.signingTime.empty(), std::string("signingTime: ") + r.signingTime);
    CHECK(r.anchorSubject.find("FDO Test CA") != std::string::npos,
          std::string("anchor: ") + r.anchorSubject);
    CHECK(r.embeddedCerts == 1, "1 embedded cert");

    std::printf("== 2) tampered signature must fail ==\n");
    {
        auto tampered = p7mBytes;
        // flip a byte in the last 256 bytes (signature area)
        for (int i = static_cast<int>(tampered.size()) - 1; i > 0; --i) {
            tampered[i] ^= 0x01;
            break;
        }
        P7MResult r2 = P7M::decodeAndVerify(tampered, anchors);
        CHECK(!r2.ok, std::string("tampered sig rejected (") + r2.error + ")");
    }

    std::printf("== 3) tampered content must fail (messageDigest) ==\n");
    {
        auto tampered = p7mBytes;
        // the embedded content is the eContent OCTET STRING; flip one of its bytes.
        bool found = false;
        for (std::size_t i = 0; i + content.size() <= tampered.size(); ++i) {
            if (std::memcmp(tampered.data() + i, content.data(), content.size()) == 0) {
                tampered[i] ^= 0x01;
                found = true;
                break;
            }
        }
        CHECK(found, "content located inside p7m");
        P7MResult r3 = P7M::decodeAndVerify(tampered, anchors);
        CHECK(!r3.ok, std::string("tampered content rejected (") + r3.error + ")");
    }

    std::printf("== 4) wrong anchor must fail (chain) ==\n");
    {
        auto otherKey = genKey();
        auto otherCa = mkCa(otherKey.get());
        auto otherCaCert = X509Cert::fromDer(x509Der(otherCa.get()));
        std::vector<const X509Cert *> wrongAnchors{ otherCaCert.get() };
        P7MResult r4 = P7M::decodeAndVerify(p7mBytes, wrongAnchors);
        CHECK(!r4.ok, std::string("wrong anchor rejected (") + r4.error + ")");
    }

    std::printf("== 5) no TSL anchors must fail (no self-anchoring) ==\n");
    {
        std::vector<const X509Cert *> noAnchors;
        P7MResult r5 = P7M::decodeAndVerify(p7mBytes, noAnchors);
        CHECK(!r5.ok, std::string("verify without TSL anchors rejected (") +
                          r5.error + ")");
    }

    int rc = g_failures == 0 ? 0 : 1;

    if (argc >= 3) {
        std::printf("== 6) sample p7m against the AgID TSL ==\n");
        auto tsl = TslParser::parseFile(dataDir + "/TSL-IT.xml");
        if (!tsl) {
            std::printf("  FAIL cannot parse TSL\n");
            return 1;
        }
        std::vector<const X509Cert *> tslAnchors;
        std::vector<std::unique_ptr<X509Cert>> tslCerts;
        for (const auto &c : tsl->trustAnchors()) {
            auto x = X509Cert::fromDer(c);
            if (x) {
                tslCerts.push_back(std::move(x));
                tslAnchors.push_back(tslCerts.back().get());
            }
        }
        std::printf("        TSL trust anchors loaded: %zu\n", tslAnchors.size());
        const std::vector<unsigned char> sample = readFile(argv[2]);
        P7MResult rs = P7M::decodeAndVerify(sample, tslAnchors);
        CHECK(rs.ok, std::string("sample p7m verified (err: ") + rs.error + ")");
        if (rs.ok) {
            std::printf("        signer: %s\n", rs.signerSubject.c_str());
            std::printf("        anchor: %s\n", rs.anchorSubject.c_str());
            std::printf("        time:   %s%s\n", rs.signingTime.c_str(),
                        rs.validAtSigningTimeOnly ? "  (valid at signing time only)" : "");
        }
        if (!rs.ok)
            rc = 1;
    }

    std::printf("\n%s\n", g_failures == 0 ? "All p7m tests passed."
                                          : "SOME p7m TESTS FAILED");
    return rc;
}
