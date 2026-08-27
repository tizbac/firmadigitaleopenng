#pragma once

#include <cstddef>
#include <ctime>
#include <string>
#include <vector>

#include "p7m.h"
#include "x509util.h"

namespace fdo {

struct PadesConfig
{
    std::vector<unsigned char> pdfBytes;
    std::string fieldName = "Signature1";
    std::string signerName; // Sig dict /Name (empty = signer CN)
    int onPage = 0;         // 0-based page for the visible stamp
    double boxX1 = 50, boxY1 = 50, boxX2 = 250, boxY2 = 100;
    bool visible = false;
    std::string visibleText = "Firmato digitalmente da ";
    X509Cert signerCert;
    std::vector<X509Cert> extraCerts; // issuer chain, appended to the CMS
};

struct PadesResult
{
    bool ok = false;
    std::string error;
    std::vector<unsigned char> pdfBytes; // signed PDF
};

class Pades
{
public:
    // PAdES-BES: append a detached CMS signature (adbe.pkcs7.detached) as a
    // PDF incremental update. sign() performs the SHA256-RSA operation
    // internally (e.g. CKM_SHA256_RSA_PKCS on a token).
    static PadesResult sign(const PadesConfig &cfg, const SignFunction &sign);

    // Verify the latest PAdES signature in the PDF against the trust anchors.
    static P7MResult verify(const std::vector<unsigned char> &pdfBytes,
                            const std::vector<const X509Cert *> &anchors,
                            std::time_t now = 0);
};

} // namespace fdo
