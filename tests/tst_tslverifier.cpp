#include "tslparser.h"
#include "tslverifier.h"

#include <algorithm>
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
    expect(!tsl->trustAnchors().empty(),
           "real TSL yields CA trust anchors (granted/recognised/accredited)");
    {
        const auto anchors = tsl->trustAnchors();
        expect(tsl->keyInfoCerts.size() != 1 ||
                   std::find(anchors.begin(), anchors.end(),
                             tsl->keyInfoCerts.front()) == anchors.end(),
               "TSL XML-signature certificate is not a trust anchor");
    }

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

    // Trust anchors: only certificates of currently valid CA services count.
    // The TSL signature certificate, withdrawn services and non-CA services
    // must never be used to validate a document signature.
    {
        auto service = [](const char *status, const char *type, const char *cert) {
            return std::string("<TSPService><ServiceInformation>"
                               "<ServiceTypeIdentifier>") + type +
                   "</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">x</Name>"
                   "</ServiceName><ServiceStatus>" + status +
                   "</ServiceStatus><ServiceDigitalIdentity><DigitalId>"
                   "<X509Certificate>" + cert + "</X509Certificate>"
                   "</DigitalId></ServiceDigitalIdentity></ServiceInformation></TSPService>";
        };
        const std::string base =
            "<TrustServiceStatusList xmlns=\"http://uri.etsi.org/02231/v2#\" "
            "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
            "<SchemeInformation><ListIssueDateTime>2026-08-01T00:00:00Z"
            "</ListIssueDateTime><NextUpdate><dateTime>2099-01-01T00:00:00Z"
            "</dateTime></NextUpdate></SchemeInformation>"
            "<TrustServiceProviderList><TrustServiceProvider><TSPServices>";
        const std::string end =
            "</TSPServices></TrustServiceProvider></TrustServiceProviderList>"
            "<ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
            "R0hJ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"
            "</TrustServiceStatusList>";
        const std::string xml =
            base +
            service("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
                    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC", "QUJD") +
            service("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
                    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC", "REVG") +
            service("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
                    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC", "SktM") +
            end;
        auto t = fdo::TslParser::parseXml(xml);
        expect(t != nullptr, "synthetic TSL parsed");
        expect(t && t->allCerts.size() == 4, "synthetic TSL has 4 certificates");
        expect(t && t->trustAnchors().size() == 1,
               "only the granted CA service is a trust anchor");
        expect(t && t->trustAnchors().size() == 1 &&
                   t->trustAnchors().front() ==
                       std::vector<unsigned char>{'A', 'B', 'C'},
               "trust anchor is the granted CA certificate (not KeyInfo/withdrawn/TSA)");
        auto anchorsEmpty = fdo::TslParser::parseXml(
            "<TrustServiceStatusList xmlns=\"http://uri.etsi.org/02231/v2#\">"
            "<SchemeInformation><ListIssueDateTime>2026-08-01T00:00:00Z"
            "</ListIssueDateTime><NextUpdate><dateTime>2099-01-01T00:00:00Z"
            "</dateTime></NextUpdate></SchemeInformation>"
            "<TrustServiceProviderList><TrustServiceProvider><TSPServices>"
            "</TSPServices></TrustServiceProvider></TrustServiceProviderList>"
            "</TrustServiceStatusList>");
        expect(anchorsEmpty && anchorsEmpty->trustAnchors().empty(),
               "TSL without services yields no trust anchors");
    }

    if (failures) {
        std::cerr << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "all TSL tests passed\n";
    return 0;
}
