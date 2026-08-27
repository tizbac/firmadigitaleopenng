#include "tslverifier.h"
#include "c14n.h"

#include <algorithm>
#include <cstring>

#include <libxml/tree.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace fdo {
namespace {

using XmlNode = struct _xmlNode;

const char *kExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const char *kEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

const EVP_MD *digestMd(const std::string &method)
{
    if (method == "http://www.w3.org/2001/04/xmlenc#sha256")
        return EVP_sha256();
    if (method == "http://www.w3.org/2001/04/xmlenc#sha512")
        return EVP_sha512();
    return nullptr;
}

std::vector<unsigned char> digestOf(const EVP_MD *md, const std::vector<unsigned char> &data)
{
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    EVP_Digest(data.data(), data.size(), out.data(), &outLen, md, nullptr);
    out.resize(outLen);
    return out;
}

bool constantTimeEqual(const std::vector<unsigned char> &a, const std::vector<unsigned char> &b)
{
    if (a.size() != b.size())
        return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

const XmlNode *findElementById(const XmlNode *n, const std::string &id)
{
    std::vector<const XmlNode *> stack{ n };
    while (!stack.empty()) {
        const XmlNode *start = stack.back();
        stack.pop_back();
        for (const XmlNode *c = start; c; c = c->next) {
            if (c->type != XML_ELEMENT_NODE)
                continue;
            const xmlChar *idAttr = xmlGetProp(c, BAD_CAST "Id");
            if (idAttr) {
                const bool match = std::string(reinterpret_cast<const char *>(idAttr)) == id;
                xmlFree(const_cast<xmlChar *>(idAttr));
                if (match)
                    return c;
            }
            if (c->children)
                stack.push_back(c->children);
        }
    }
    return nullptr;
}

const XmlNode *firstChildByName(const XmlNode *n, const char *name)
{
    for (const XmlNode *c = n ? n->children : nullptr; c; c = c->next)
        if (c->type == XML_ELEMENT_NODE && std::strcmp(reinterpret_cast<const char *>(c->name), name) == 0)
            return c;
    return nullptr;
}

} // namespace

TslVerification TslVerifier::verify(const Tsl &tsl)
{
    TslVerification r;
    if (!tsl.hasSignature) {
        r.error = "no XML-DSig signature found";
        return r;
    }
    XmlNode *root = static_cast<XmlNode *>(tsl.root);
    const XmlNode *sig = nullptr;
    for (const XmlNode *c = root->children; c; c = c->next)
        if (c->type == XML_ELEMENT_NODE &&
            std::strcmp(reinterpret_cast<const char *>(c->name), "Signature") == 0 &&
            c->ns && std::strcmp(reinterpret_cast<const char *>(c->ns->href),
                                  "http://www.w3.org/2000/09/xmldsig#") == 0)
            sig = c;
    if (!sig) {
        r.error = "ds:Signature element not found";
        return r;
    }

    const XmlNode *signedInfo = firstChildByName(sig, "SignedInfo");
    if (!signedInfo) {
        r.error = "ds:SignedInfo not found";
        return r;
    }

    // --- references -------------------------------------------------
    for (const TslReference &ref : tsl.references) {
        const EVP_MD *md = digestMd(ref.digestMethod);
        if (!md) {
            r.error = "unsupported DigestMethod: " + ref.digestMethod;
            return r;
        }
        if (ref.uri.empty()) {
            const bool enveloped =
                std::any_of(ref.transforms.begin(), ref.transforms.end(),
                            [](const std::string &t) { return t == kEnveloped; });
            const std::vector<unsigned char> c14n = enveloped
                ? C14N::canonicalize(root, [sig](const XmlNode *n) { return n != sig; })
                : C14N::canonicalize(root);
            if (!constantTimeEqual(digestOf(md, c14n), ref.digestValue)) {
                r.error = "whole-document reference digest mismatch";
                return r;
            }
            r.refWholeDoc = true;
        } else if (!ref.uri.empty() && ref.uri.front() == '#') {
            const XmlNode *frag = findElementById(root, ref.uri.substr(1));
            if (!frag) {
                r.error = "fragment not found: " + ref.uri;
                return r;
            }
            const std::vector<unsigned char> c14n = C14N::canonicalize(frag);
            if (!constantTimeEqual(digestOf(md, c14n), ref.digestValue)) {
                r.error = "fragment reference digest mismatch: " + ref.uri;
                return r;
            }
            r.refFragment = true;
        } else {
            r.error = "unsupported reference URI: " + ref.uri;
            return r;
        }
    }
    if (tsl.references.empty()) {
        r.error = "no ds:Reference elements";
        return r;
    }

    // --- RSA over exclusive c14n of SignedInfo ----------------------
    const std::vector<unsigned char> c14n = C14N::canonicalize(signedInfo);

    if (tsl.keyInfoCerts.empty()) {
        r.error = "no certificate in ds:KeyInfo";
        return r;
    }
    const std::vector<unsigned char> &der = tsl.keyInfoCerts.front();
    const unsigned char *p = der.data();
    X509 *x509 = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (!x509) {
        r.error = "cannot parse ds:KeyInfo certificate";
        return r;
    }
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    bool ok = false;
    if (pkey) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
            EVP_DigestVerifyUpdate(ctx, c14n.data(), c14n.size()) == 1)
            ok = EVP_DigestVerifyFinal(ctx, tsl.signatureValue.data(),
                                       tsl.signatureValue.size()) == 1;
        EVP_MD_CTX_free(ctx);
    }
    EVP_PKEY_free(pkey);
    X509_free(x509);

    r.signature = ok;
    if (!ok)
        r.error = "RSA signature verification failed";
    return r;
}

} // namespace fdo
