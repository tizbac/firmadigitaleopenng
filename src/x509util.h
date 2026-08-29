#pragma once

#include <cstddef>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace fdo {

struct X509Cert
{
    std::vector<unsigned char> der;
    std::string subject;   // "C=IT, O=..., CN=..."
    std::string givenName; // GN (2.5.4.42), may be empty
    std::string surname;   // SN (2.5.4.4), may be empty
    std::string issuer;
    std::string serialHex;
    std::string notBefore; // "YYYY-MM-DD HH:MM:SS" UTC
    std::string notAfter;
    std::string derSha256Hex;
    bool selfSigned = false;

    std::vector<unsigned char> spkiDer; // SubjectPublicKeyInfo DER
    std::vector<unsigned char> issuerNameDer; // DER of the issuer Name
    std::vector<unsigned char> serialRaw; // serial, big-endian, no sign padding

    std::vector<std::string> aiaCaIssuers; // @caIssuers URIs
    std::vector<std::string> aiaOcsp;      // @OCSP URIs

    static std::unique_ptr<X509Cert> fromDer(const std::vector<unsigned char> &der);
    static std::unique_ptr<X509Cert> fromPemFile(const std::string &path);
    static std::unique_ptr<X509Cert> fromDerFile(const std::string &path);
};

struct EssCertIdV2
{
    std::string issuerSha256Hex; // SHA-256 of the DER-encoded issuer Name
    std::string serialHex;
    std::string certSha256Hex;   // SHA-256 of the whole certificate DER
};

struct ChainResult
{
    bool ok = false;
    std::string error;
    std::string anchorSubject; // TSL certificate the chain terminated at
};

class X509Util
{
public:
    static std::string sha256Hex(const void *data, size_t len);
    static std::string sha256Hex(const std::vector<unsigned char> &data);

    // RFC 5035 / 5280 ESSCertIDv2 of the certificate.
    static EssCertIdV2 essCertIdV2(const X509Cert &cert);

    // Validates `leaf` (optionally with `untrusted` intermediates) against the
    // given trust anchors at time `now`. Anchors that are not self-signed are
    // accepted as chain terminators (X509_V_FLAG_PARTIAL_CHAIN), which matches
    // how the AgID TSL lists qualified CAs.
    static ChainResult validateChain(const X509Cert &leaf,
                                     const std::vector<const X509Cert *> &untrusted,
                                     const std::vector<const X509Cert *> &anchors,
                                     std::time_t now);
};

} // namespace fdo
