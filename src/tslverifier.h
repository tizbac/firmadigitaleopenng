#pragma once

#include "tslparser.h"

namespace fdo {

struct TslVerification
{
    bool refWholeDoc = false; // URI="" reference: digest over c14n of the whole document
    bool refFragment = false; // URI="#..." reference: digest over c14n of the fragment
    bool signature = false;   // RSA over c14n(ds:SignedInfo)
    std::string error;

    bool ok() const { return refWholeDoc && refFragment && signature; }
};

// Verifies the XML-DSig signature of an AgID TSL:
//  - digest of every ds:Reference (enveloped-signature + exclusive c14n)
//  - RSA signature over the exclusive c14n of ds:SignedInfo, with the
//    certificate embedded in ds:KeyInfo.
class TslVerifier
{
public:
    static TslVerification verify(const Tsl &tsl);
};

} // namespace fdo
