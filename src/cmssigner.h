#pragma once

#include <ctime>
#include <string>
#include <vector>

namespace fdo {

struct CmsConfig
{
    std::vector<unsigned char> signerCertDer; // full X509Certificate TLV
    std::vector<std::vector<unsigned char>> extraCerts; // optional chain certs
    std::string contentTypeOid = "1.2.840.113549.1.7.1"; // "data"
    std::vector<unsigned char> content;
    bool detached = false; // no eContent in encapContentInfo
    std::time_t signingTime = 0; // 0 = now
};

class CmsSigner
{
public:
    // DER of the [1] IMPLICIT SignedAttributes block (what gets signed).
    static std::vector<unsigned char> buildSignedAttrs(const CmsConfig &cfg,
                                                       std::string *error);
    // Full CMS ContentInfo DER (signedData) from the produced signature.
    static std::vector<unsigned char> assemble(const CmsConfig &cfg,
                                               const std::vector<unsigned char> &signedAttrsDer,
                                               const std::vector<unsigned char> &signature,
                                               std::string *error);
};

} // namespace fdo
