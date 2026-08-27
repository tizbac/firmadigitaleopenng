#include "tslparser.h"
#include "tslverifier.h"

#include <iostream>
#include <string>

int main(int argc, char **argv)
{
    const std::string path = argc > 1 ? argv[1] : "tests/data/TSL-IT.xml";

    auto tsl = fdo::TslParser::parseFile(path);
    if (!tsl) {
        std::cerr << "FAIL: cannot parse " << path << "\n";
        return 2;
    }

    int failures = 0;
    auto expect = [&](bool cond, const char *what) {
        std::cout << (cond ? "OK   " : "FAIL ") << what << "\n";
        if (!cond)
            ++failures;
    };

    expect(tsl->versionIdentifier == "6", "TSLVersionIdentifier == 6");
    expect(tsl->sequenceNumber == "223", "TSLSequenceNumber == 223");
    expect(tsl->allCerts.size() == 548, "548 X509Certificate entries (547 services + KeyInfo)");
    expect(tsl->services.size() == 560, "560 TSPService entries");
    expect(tsl->hasSignature, "has XML-DSig signature");
    expect(tsl->keyInfoCerts.size() == 1, "one KeyInfo certificate");
    expect(tsl->references.size() == 2, "two ds:Reference entries");

    const fdo::TslVerification v = fdo::TslVerifier::verify(*tsl);
    expect(v.refWholeDoc, "ref1 digest (whole doc excl. ds:Signature)");
    expect(v.refFragment, "ref2 digest (xades:SignedProperties)");
    expect(v.signature, "RSA over c14n(ds:SignedInfo)");
    if (!v.ok())
        std::cerr << "  error: " << v.error << "\n";

    if (failures) {
        std::cerr << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "all TSL tests passed\n";
    return 0;
}
