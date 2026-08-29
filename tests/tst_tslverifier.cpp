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
    expect(!tsl->issueDateTime.empty(), "ListIssueDateTime parsed");
    expect(!tsl->nextUpdate.empty(), "NextUpdate parsed");
    expect(tsl->upToDate(std::time(nullptr)), "TSL is up to date (NextUpdate in the future)");
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

    const char *kMinTsl = "<TrustServiceStatusList "
                          "xmlns=\"http://uri.etsi.org/02231/v2#\"><SchemeInformation>"
                          "<ListIssueDateTime>%1</ListIssueDateTime>"
                          "<NextUpdate><dateTime>%2</dateTime></NextUpdate>"
                          "</SchemeInformation></TrustServiceStatusList>";

    auto build = [&](const char *issue, const char *next) {
        std::string xml = kMinTsl;
        auto replaceAll = [&](const char *tk, const char *val) {
            const std::string key = std::string("%") + tk;
            size_t at = xml.find(key);
            while (at != std::string::npos) {
                xml.replace(at, key.size(), val);
                at = xml.find(key);
            }
        };
        replaceAll("1", issue);
        replaceAll("2", next);
        return fdo::TslParser::parseXml(xml);
    };

    {
        auto fresh = build("2026-08-30T10:00:00Z", "2099-12-31T23:59:59Z");
        expect(fresh && fresh->issueDateTime == "2026-08-30T10:00:00Z",
               "minimal TSL: ListIssueDateTime parsed");
        expect(fresh && fresh->upToDate(std::time(nullptr)),
               "minimal TSL with future NextUpdate is up to date");
    }
    {
        auto offset = build("2026-08-30T12:00:00+02:00", "2099-01-01T00:00:00+01:00");
        expect(offset && offset->upToDate(std::time(nullptr)),
               "offset-form NextUpdate (+HH:MM) handled");
        auto offsetTz = build("2026-08-30T10:00:00Z", "2099-01-01T00:00:00+0200");
        expect(offsetTz && offsetTz->upToDate(std::time(nullptr)),
               "offset-form NextUpdate (+HHMM) handled");
    }
    {
        auto stale = build("2020-01-01T00:00:00Z", "2020-06-01T00:00:00Z");
        expect(stale && !stale->upToDate(std::time(nullptr)),
               "stale TSL (NextUpdate in the past) is not up to date");
        auto undated = build("2026-08-30T10:00:00Z", "not-a-date");
        expect(undated && !undated->upToDate(std::time(nullptr)),
               "unparseable NextUpdate is not up to date");
    }

    if (failures) {
        std::cerr << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "all TSL tests passed\n";
    return 0;
}
