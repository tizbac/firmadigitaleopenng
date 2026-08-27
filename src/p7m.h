#pragma once

#include <cstddef>
#include <ctime>
#include <functional>
#include <string>
#include <vector>

#include "x509util.h"

namespace fdo {

// sign(data) -> signature, or false with *error set. The implementation
// performs the hashing internally (e.g. CKM_SHA256_RSA_PKCS on a token).
using SignFunction = std::function<bool(const std::vector<unsigned char> &data,
                                        std::vector<unsigned char> &signature,
                                        std::string &error)>;

// Parsed CMS SignedData (internal representation used by the verifier)
struct ParsedCms
{
    bool ok = false;
    std::string error;
    std::vector<unsigned char> content;
    bool detached = false;
    std::vector<std::vector<unsigned char>> embeddedCerts;
    std::vector<unsigned char> sidIssuerDer;
    std::vector<unsigned char> sidSerial;
    std::vector<unsigned char> signedAttrsTlv; // full [1] IMPLICIT TLV
    std::vector<unsigned char> signature;      // BIT STRING payload
    std::time_t signingTime = 0;
    bool hasSigningTime = false;
    std::vector<unsigned char> msgDigestAttr;
    std::vector<unsigned char> essCertHash;
    std::vector<unsigned char> essIssuerDer;
    std::vector<unsigned char> essSerial;
    std::string contentTypeOid; // content_type signed attribute (dot notation)
};

struct P7MResult
{
    bool ok = false;
    std::string error;
    std::vector<unsigned char> content; // extracted (embedded) content
    std::string signerSubject;
    std::string signerIssuer;
    std::string signerSerial;
    std::string signingTime; // "YYYY-MM-DD HH:MM:SS"
    std::string anchorSubject; // TSL certificate the chain terminated at
    std::vector<unsigned char> signerCertDer;
    int embeddedCerts = 0;
    bool validAtSigningTimeOnly = false; // chain OK at signing time, not now
};

class P7M
{
public:
    // Sign `input` into a CAdES-BES .p7m (embedded content, "data" type).
    static bool signFile(const std::string &inputPath, const std::string &outputPath,
                         const std::vector<unsigned char> &signerCertDer,
                         const SignFunction &sign, std::string *error);

    // Decode a .p7m and verify: embedded content, RSA signature over the
    // signed attributes, message digest, and certificate chain against the
    // given trust anchors (TSL certificates).
    static P7MResult decodeAndVerify(const std::vector<unsigned char> &p7m,
                                     const std::vector<const X509Cert *> &anchors,
                                     std::time_t now = 0);

    // Verify a detached CMS (PAdES-style): cmsDer is the raw SignedData and
    // content are the signed bytes (e.g. the PDF byte range).
    static P7MResult verifyDetached(const std::vector<unsigned char> &cmsDer,
                                    const std::vector<unsigned char> &content,
                                    const std::vector<const X509Cert *> &anchors,
                                    std::time_t now = 0);

    // Shared verification core (signer lookup + attribute/chain checks)
    static P7MResult verifyParsed(const ParsedCms &cms,
                                  const std::vector<const X509Cert *> &anchors,
                                  std::time_t now = 0);
};

} // namespace fdo
