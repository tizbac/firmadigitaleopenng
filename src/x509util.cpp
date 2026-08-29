#include "x509util.h"
#include "base64.h"

#include <cstdio>
#include <cstring>

#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace fdo {
namespace {

std::string toHex(const unsigned char *data, size_t len)
{
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xF];
    }
    return out;
}

std::string nameOneline(X509_NAME *name)
{
    char *s = X509_NAME_oneline(name, nullptr, 0);
    std::string out = s ? s : "";
    if (s)
        OPENSSL_free(s);
    return out;
}

std::string serialHexOf(X509 *x)
{
    const ASN1_INTEGER *ser = X509_get_serialNumber(x);
    BIGNUM *bn = ASN1_INTEGER_to_BN(ser, nullptr);
    if (!bn)
        return {};
    char *h = BN_bn2hex(bn);
    std::string out = h ? h : "";
    if (h)
        OPENSSL_free(h);
    BN_free(bn);
    return out;
}

std::string timePrint(const ASN1_TIME *t)
{
    BIO *bio = BIO_new(BIO_s_mem());
    std::string out;
    if (bio && ASN1_TIME_print(bio, const_cast<ASN1_TIME *>(t))) {
        char buf[128];
        const int n = BIO_gets(bio, buf, sizeof(buf));
        if (n > 0) {
            out.assign(buf, static_cast<size_t>(n));
            while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
                out.pop_back();
        }
    }
    if (bio)
        BIO_free(bio);
    return out;
}

} // namespace

std::string X509Util::sha256Hex(const void *data, size_t len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    EVP_Digest(static_cast<const unsigned char *>(data), len, md, &mdLen, EVP_sha256(), nullptr);
    return toHex(md, mdLen);
}

std::string X509Util::sha256Hex(const std::vector<unsigned char> &data)
{
    return sha256Hex(data.data(), data.size());
}

std::unique_ptr<X509Cert> X509Cert::fromDer(const std::vector<unsigned char> &derIn)
{
    if (derIn.empty())
        return nullptr;
    const unsigned char *p = derIn.data();
    X509 *x = d2i_X509(nullptr, &p, static_cast<long>(derIn.size()));
    if (!x)
        return nullptr;

    auto cert = std::make_unique<X509Cert>();
    cert->der = derIn;
    cert->derSha256Hex = X509Util::sha256Hex(derIn);
    cert->subject = nameOneline(X509_get_subject_name(x));
    char nmBuf[1024];
    int nLen = X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_givenName,
                                         nmBuf, sizeof(nmBuf));
    if (nLen > 0)
        cert->givenName.assign(nmBuf, static_cast<size_t>(nLen));
    nLen = X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_surname,
                                     nmBuf, sizeof(nmBuf));
    if (nLen > 0)
        cert->surname.assign(nmBuf, static_cast<size_t>(nLen));
    cert->issuer = nameOneline(X509_get_issuer_name(x));
    cert->serialHex = serialHexOf(x);
    cert->notBefore = timePrint(X509_get0_notBefore(x));
    cert->notAfter = timePrint(X509_get0_notAfter(x));

    // SPKI DER
    EVP_PKEY *pkey = X509_get_pubkey(x);
    if (pkey) {
        unsigned char *spki = nullptr;
        const int len = i2d_PUBKEY(pkey, &spki);
        if (len > 0 && spki) {
            cert->spkiDer.assign(spki, spki + len);
            OPENSSL_free(spki);
        }
        EVP_PKEY_free(pkey);
    }

    // issuer Name DER + raw serial (big-endian, sign padding stripped)
    unsigned char *issDer = nullptr, *subDer = nullptr;
    const int issLen = i2d_X509_NAME(X509_get_issuer_name(x), &issDer);
    const int subLen = i2d_X509_NAME(X509_get_subject_name(x), &subDer);
    if (issLen > 0 && issDer)
        cert->issuerNameDer.assign(issDer, issDer + issLen);
    {
        const ASN1_INTEGER *ser = X509_get_serialNumber(x);
        const unsigned char *sd = ASN1_STRING_get0_data(ser);
        int sl = ASN1_STRING_length(ser);
        while (sl > 1 && sd[0] == 0) {
            ++sd;
            --sl;
        }
        if (sl > 0)
            cert->serialRaw.assign(sd, sd + sl);
    }
    bool sameName = issLen > 0 && subLen > 0 && issLen == subLen &&
                    std::memcmp(issDer, subDer, static_cast<size_t>(issLen)) == 0;
    if (issDer)
        OPENSSL_free(issDer);
    if (subDer)
        OPENSSL_free(subDer);
    if (sameName) {
        EVP_PKEY *pk = X509_get_pubkey(x);
        if (pk) {
            cert->selfSigned = X509_verify(x, pk) == 1;
            EVP_PKEY_free(pk);
        }
    }

    // AIA
    const int nidAia = OBJ_txt2nid("authorityInfoAccess");
    if (void *ext = X509_get_ext_d2i(x, nidAia, nullptr, nullptr)) {
        auto *seq = static_cast<STACK_OF(ACCESS_DESCRIPTION) *>(ext);
        for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(seq); ++i) {
            const ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(seq, i);
            if (!ad || !ad->method || !ad->location)
                continue;
            char oidBuf[128];
            const int oidLen = OBJ_obj2txt(oidBuf, sizeof(oidBuf), ad->method, 0);
            if (oidLen < 0)
                continue;
            const std::string oidStr(oidBuf, static_cast<size_t>(oidLen));
            if (ad->location->type == V_ASN1_IA5STRING && ad->location->d.ia5) {
                const char *uri =
                    reinterpret_cast<const char *>(ASN1_STRING_get0_data(ad->location->d.ia5));
                if (oidStr == "1.3.6.1.5.5.7.48.5") // id-ad-caIssuers
                    cert->aiaCaIssuers.emplace_back(uri);
                else if (oidStr == "1.3.6.1.5.5.7.48.1") // id-ad-ocsp
                    cert->aiaOcsp.emplace_back(uri);
            }
        }
        sk_ACCESS_DESCRIPTION_pop_free(seq, ACCESS_DESCRIPTION_free);
    }

    X509_free(x);
    return cert;
}

std::unique_ptr<X509Cert> X509Cert::fromPemFile(const std::string &path)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f)
        return nullptr;
    X509 *x = PEM_read_X509(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    if (!x)
        return nullptr;
    unsigned char *der = nullptr;
    const int len = i2d_X509(x, &der);
    X509_free(x);
    if (len <= 0 || !der)
        return nullptr;
    std::vector<unsigned char> bytes(der, der + len);
    OPENSSL_free(der);
    return fromDer(bytes);
}

std::unique_ptr<X509Cert> X509Cert::fromDerFile(const std::string &path)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f)
        return nullptr;
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    const size_t got = std::fread(bytes.data(), 1, bytes.size(), f);
    std::fclose(f);
    bytes.resize(got);
    return fromDer(bytes);
}

EssCertIdV2 X509Util::essCertIdV2(const X509Cert &certIn)
{
    EssCertIdV2 out;
    const unsigned char *p = certIn.der.data();
    X509 *x = d2i_X509(nullptr, &p, static_cast<long>(certIn.der.size()));
    if (!x)
        return out;

    unsigned char *issDer = nullptr;
    const int issLen = i2d_X509_NAME(X509_get_issuer_name(x), &issDer);
    if (issLen > 0 && issDer) {
        out.issuerSha256Hex = sha256Hex(issDer, static_cast<size_t>(issLen));
        OPENSSL_free(issDer);
    }
    out.serialHex = certIn.serialHex;
    out.certSha256Hex = certIn.derSha256Hex;
    X509_free(x);
    return out;
}

ChainResult X509Util::validateChain(const X509Cert &leaf,
                                    const std::vector<const X509Cert *> &untrusted,
                                    const std::vector<const X509Cert *> &anchors,
                                    std::time_t now)
{
    ChainResult r;
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        r.error = "X509_STORE_new failed";
        return r;
    }
    // TSL entries are mostly intermediate (qualified) CAs, not self-signed
    // roots: allow a trusted non-self-signed cert to terminate the chain.
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    for (const X509Cert *a : anchors) {
        const unsigned char *p = a->der.data();
        X509 *x = d2i_X509(nullptr, &p, static_cast<long>(a->der.size()));
        if (!x)
            continue;
        X509_STORE_add_cert(store, x);
        X509_free(x);
    }

    const unsigned char *lp = leaf.der.data();
    X509 *lx = d2i_X509(nullptr, &lp, static_cast<long>(leaf.der.size()));
    if (!lx) {
        X509_STORE_free(store);
        r.error = "cannot parse leaf certificate";
        return r;
    }

    STACK_OF(X509) *chain = sk_X509_new_null();
    sk_X509_push(chain, lx); // ownership transfers to the stack
    for (const X509Cert *u : untrusted) {
        const unsigned char *p = u->der.data();
        X509 *x = d2i_X509(nullptr, &p, static_cast<long>(u->der.size()));
        if (x)
            sk_X509_push(chain, x);
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ok = 0;
    if (ctx && X509_STORE_CTX_init(ctx, store, lx, chain) == 1) {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_time(param, now);
        ok = X509_verify_cert(ctx);
        if (ok == 1) {
            r.ok = true;
            STACK_OF(X509) *built = X509_STORE_CTX_get0_chain(ctx);
            if (built) {
                const X509 *top = sk_X509_value(built, sk_X509_num(built) - 1);
                if (top)
                    r.anchorSubject = nameOneline(X509_get_subject_name(top));
            }
        } else {
            const int err = X509_STORE_CTX_get_error(ctx);
            const int depth = X509_STORE_CTX_get_error_depth(ctx);
            r.error = X509_verify_cert_error_string(err);
            const X509 *bad = X509_STORE_CTX_get_current_cert(ctx);
            if (bad) {
                r.error += " at depth " + std::to_string(depth) + ": " +
                           nameOneline(X509_get_subject_name(bad));
            }
        }
    } else {
        r.error = "X509_STORE_CTX_init failed";
    }
    if (ctx)
        X509_STORE_CTX_free(ctx); // also frees the chain (incl. lx)
    X509_STORE_free(store);
    return r;
}

} // namespace fdo
