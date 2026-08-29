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
    double maxFont = 12.0; // stamp font cap (points), 0 = library default
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

// Shared metrics for the visible PAdES stamp: the GUI preview renders exactly
// what Pades::sign draws, using the same font/baseline math (WYSIWYG). Units
// are PDF points with a bottom-left origin; the font is a built-in Helvetica
// substitution.
struct StampLayout
{
    double left = 4.0; // text x offset inside the box
    double y1 = 0;     // first-line baseline from the box bottom
    double y2 = 0;     // second-line baseline from the box bottom
    double fs = 12.0;  // resolved font size (points)
};

struct StampBox
{
    double w = 0;
    double h = 0;
};

// Font size that fits the two stamp lines in a box of width boxW (capped at
// maxFont). Helvetica's average glyph width is ~0.5 em.
double stampFontSize(const std::string &line1, const std::string &line2,
                     double boxW, double maxFont = 36.0);

// Box that holds the two stamp lines at maxFont before page clamping.
StampBox stampFitBox(const std::string &line1, const std::string &line2,
                     double maxFont = 36.0);

// Baselines/font inside a given box.
StampLayout stampLayout(const std::string &line1, const std::string &line2,
                        double boxW, double boxH, double maxFont = 36.0);

// "YYYY-MM-DD HH:MM:SS" UTC shown on the "Time:" stamp line.
std::string stampTimeString(std::time_t t);

class Pades
{
public:
    // PAdES-BES: append a detached CMS signature (ETSI.CAdES.detached) as a
    // PDF incremental update. sign() performs the SHA256-RSA operation
    // internally (e.g. CKM_SHA256_RSA_PKCS on a token).
    static PadesResult sign(const PadesConfig &cfg, const SignFunction &sign);

    // Verify the latest PAdES signature in the PDF against the trust anchors.
    static P7MResult verify(const std::vector<unsigned char> &pdfBytes,
                            const std::vector<const X509Cert *> &anchors,
                            std::time_t now = 0);
};

} // namespace fdo
