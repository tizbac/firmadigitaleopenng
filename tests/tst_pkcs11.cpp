// tst_pkcs11: smoke test the PKCS#11 layer against a real module.
// Usage: tst_pkcs11 <libPath> [pin]
// Enumerates slots/tokens and prints signer info if a token is present.
// Exits 0 when the module loads and enumerates (even with no token),
// non-zero only on a hard library/ABI failure.
#include <cstdio>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "pkcs11.h"

using namespace fdo;

// Verifies an RSA PKCS#1 v1.5 + SHA-256 signature (what CKM_SHA256_RSA_PKCS
// produces) over `data` using the public key in the X.509 certificate `certDer`.
static bool verifyRsaSha256(const std::vector<unsigned char> &certDer,
                            const std::vector<unsigned char> &data,
                            const std::vector<unsigned char> &sig, std::string *err)
{
    const unsigned char *p = certDer.data();
    X509 *x = d2i_X509(nullptr, &p, static_cast<long>(certDer.size()));
    if (!x) {
        if (err)
            *err = "cannot parse certificate";
        return false;
    }
    EVP_PKEY *key = X509_get_pubkey(x);
    X509_free(x);
    if (!key) {
        if (err)
            *err = "cannot extract public key";
        return false;
    }
    bool ok = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestVerify(ctx, sig.data(), sig.size(), data.data(), data.size()) == 1)
        ok = true;
    if (ctx)
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::printf("usage: tst_pkcs11 <libPath> [pin]\n");
        return 2;
    }
    const std::string lib = argv[1];
    const std::string pin = argc > 2 ? argv[2] : "";

    std::string err;
    const std::vector<Pkcs11Slot> slots = Pkcs11::enumerateSlots(lib, &err);
    if (slots.empty() && !err.empty()) {
        std::printf("enumerate failed: %s\n", err.c_str());
        // A missing token is not a hard failure for a smoke test, but a
        // load/ABI error is. Distinguish by re-loading explicitly.
        Pkcs11 p11;
        if (!p11.loadLibrary(lib, &err)) {
            std::printf("  loadLibrary failed: %s\n", err.c_str());
            return 1;
        }
        std::printf("module loads OK, but no slots reported\n");
        return 0;
    }

    std::printf("found %zu slot(s) with token present\n", slots.size());
    for (const Pkcs11Slot &s : slots) {
        std::printf("  slot 0x%lx: label='%s' desc='%s' loginRequired=%d\n", s.index,
                    s.tokenLabel.c_str(), s.slotDescription.c_str(),
                    s.loginRequired ? 1 : 0);
        if (s.hasCert)
            std::printf("    cert: %s %s (serial %s)\n", s.certGivenName.c_str(),
                        s.certSurname.c_str(), s.certSerialHex.c_str());
    }

    if (pin.empty()) {
        std::printf("no PIN supplied; skipping login/sign\n");
        return 0;
    }

    // Try to login + sign on the first slot that has a cert.
    for (const Pkcs11Slot &s : slots) {
        if (!s.hasCert)
            continue;
        Pkcs11 p11;
        if (!p11.loadLibrary(lib, &err)) {
            std::printf("  loadLibrary failed: %s\n", err.c_str());
            return 1;
        }
        if (!p11.login(s.index, pin, &err)) {
            std::printf("  login(slot 0x%lx) failed: %s\n", s.index, err.c_str());
            continue;
        }
        if (!p11.findSigner(&err)) {
            std::printf("  findSigner failed: %s\n", err.c_str());
            continue;
        }
        const Pkcs11::Signer *sig = p11.signer();
        std::printf("  signer: keyId='%s' label='%s' certDER=%zu bytes\n",
                    sig->keyId.c_str(), sig->keyLabel.c_str(), sig->certDer.size());
        const std::string msg = "hello world";
        const std::vector<unsigned char> data(msg.begin(), msg.end());
        std::vector<unsigned char> out;
        if (!p11.sign(data, out, &err)) {
            std::printf("  sign failed: %s\n", err.c_str());
            continue;
        }
        std::printf("  sign OK: %zu bytes\n", out.size());
        const bool verified = verifyRsaSha256(sig->certDer, data, out, &err);
        std::printf(verified ? "  verify OK: signature matches certificate\n"
                             : "  verify FAILED: %s\n",
                    verified ? "" : err.c_str());
        return verified ? 0 : 1;
    }
    std::printf("no slot with a certificate to test signing on\n");
    return 0;
}
