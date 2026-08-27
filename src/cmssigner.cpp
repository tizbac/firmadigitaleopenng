#include "cmssigner.h"
#include "der.h"
#include "x509util.h"

#include <openssl/evp.h>

namespace fdo {
namespace {

using der::Bytes;
using der::operator+;
using der::operator+=;

const char *OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const char *OID_SHA256_RSA = "1.2.840.113549.1.1.11";
const char *OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const char *OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const char *OID_ATTR_MSG_DIGEST = "1.2.840.113549.1.9.4";
const char *OID_ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5";
const char *OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";

Bytes digestAlgorithmSha256() { return der::seq(der::oid(OID_SHA256)); }

Bytes issuerSerial(const X509Cert &c)
{
    return der::seq(c.issuerNameDer + der::integerBigEndian(c.serialRaw.data(),
                                                            c.serialRaw.size()));
}

Bytes essCertIdV2(const X509Cert &c)
{
    // RFC 5652: ESSCertIDv2 ::= SEQUENCE { certHash CertificateHash, issuerSerial, ... }
    // CertificateHash ::= SEQUENCE { hashAlgorithm, certificateHash OCTET STRING }
    unsigned char md[32];
    unsigned int mdLen = 0;
    EVP_Digest(c.der.data(), c.der.size(), md, &mdLen, EVP_sha256(), nullptr);
    const Bytes certHash = der::seq(der::seq(der::oid(OID_SHA256)) +
                                    der::octetString(md, mdLen));
    return der::seq(certHash + issuerSerial(c));
}

Bytes attrContentType(const CmsConfig &cfg)
{
    return der::seq(der::oid(OID_ATTR_CONTENT_TYPE) +
                    der::setOf(der::oid(cfg.contentTypeOid)));
}

Bytes attrMessageDigest(const std::vector<unsigned char> &content)
{
    unsigned char md[32];
    unsigned int mdLen = 0;
    EVP_Digest(content.data(), content.size(), md, &mdLen, EVP_sha256(), nullptr);
    return der::seq(der::oid(OID_ATTR_MSG_DIGEST) + der::setOf(der::octetString(md, mdLen)));
}

Bytes attrSigningTime(std::time_t t)
{
    return der::seq(der::oid(OID_ATTR_SIGNING_TIME) + der::setOf(der::utcTime(t)));
}

Bytes attrSigningCertV2(const X509Cert &c)
{
    // AttributeValue: SET OF { ESSCertIDv2 } (no extra wrapping)
    return der::seq(der::oid(OID_ATTR_SIGNING_CERT_V2) + der::setOf(essCertIdV2(c)));
}

} // namespace

std::vector<unsigned char> CmsSigner::buildSignedAttrs(const CmsConfig &cfg,
                                                       std::string *error)
{
    auto cert = X509Cert::fromDer(cfg.signerCertDer);
    if (!cert) {
        if (error)
            *error = "certificato firmatario non valido (DER)";
        return {};
    }
    const Bytes attrs =
        attrContentType(cfg) + attrMessageDigest(cfg.content) +
        attrSigningTime(cfg.signingTime ? cfg.signingTime : std::time(nullptr)) +
        attrSigningCertV2(*cert);
    // Canonical signed form: SET OF Attribute (0x31). RFC 5652 5.3: the
    // signature is computed over this form; assemble() stores the
    // [0] IMPLICIT (0xA0) form in the document.
    return der::setOf(attrs);
}

std::vector<unsigned char> CmsSigner::assemble(const CmsConfig &cfg,
                                               const std::vector<unsigned char> &signedAttrsDer,
                                               const std::vector<unsigned char> &signature,
                                               std::string *error)
{
    auto cert = X509Cert::fromDer(cfg.signerCertDer);
    if (!cert) {
        if (error)
            *error = "certificato firmatario non valido (DER)";
        return {};
    }

    // store signedAttrs as [0] IMPLICIT SET OF Attribute (RFC 5652); the
    // signed form is the plain SET OF with identical length
    Bytes storedAttrs = der::Bytes(signedAttrsDer);
    if (!storedAttrs.empty() && storedAttrs.front() == 0x31)
        storedAttrs.front() = 0xA0;

    // NOTE: the signature is stored as OCTET STRING (not the RFC 5652
    // BIT STRING): both OpenSSL's CMS parser and asn1crypto expect it.
    // signatureAlgorithm: parameters MUST be NULL for rsaPss/PKCS#1
    // digest algorithms (RFC 8017)
    const Bytes sigAlg = der::seq(der::oid(OID_SHA256_RSA) + der::nullValue());

    const Bytes signerInfo =
        der::seq(der::integer(1) + issuerSerial(*cert) + digestAlgorithmSha256() +
                  storedAttrs + sigAlg + der::octetString(signature));

    Bytes encapContent = der::oid(cfg.contentTypeOid);
    if (!cfg.detached)
        encapContent += der::explicitTag(0, der::octetString(cfg.content));

    Bytes certSet;
    certSet += cfg.signerCertDer;
    for (const auto &c : cfg.extraCerts)
        certSet += c;

    const Bytes signedData =
        der::seq(der::integer(1) + der::setOf(digestAlgorithmSha256()) +
                 der::seq(encapContent) + der::implicitTag(0, der::seq(certSet)) +
                 der::setOf(signerInfo));

    // ContentInfo: SEQUENCE { OID signedData, [0] EXPLICIT SignedData }
    return der::seq(der::oid(OID_SIGNED_DATA) + der::explicitTag(0, signedData));
}

} // namespace fdo
