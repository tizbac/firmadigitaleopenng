#pragma once

#include <ctime>
#include <memory>
#include <string>
#include <vector>

struct _xmlDoc;
struct _xmlNode;

namespace fdo {

struct TslService
{
    std::string serviceTypeIdentifier; // full URI, e.g. http://uri.etsi.org/TrstSvc/Svctype/CA/QC
    std::string serviceName;           // DN or free text
    std::string serviceStatus;         // full URI, e.g. .../Svcstatus/granted
    std::vector<unsigned char> certDer;
};

struct TslReference
{
    std::string uri; // "" for the whole document, "#id" for a fragment
    std::vector<std::string> transforms;
    std::string digestMethod;
    std::vector<unsigned char> digestValue;
};

struct Tsl
{
    ~Tsl();

    std::string versionIdentifier;
    std::string sequenceNumber;
    std::string issueDateTime; // SchemeInformation > ListIssueDateTime > dateTime
    std::string nextUpdate;    // SchemeInformation > NextUpdate > dateTime

    std::vector<std::vector<unsigned char>> allCerts; // every X509Certificate, document order
    std::vector<TslService> services;

    bool hasSignature = false;
    std::string signatureMethod; // e.g. http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    std::vector<unsigned char> signatureValue;
    std::vector<std::vector<unsigned char>> keyInfoCerts; // DER
    std::vector<TslReference> references;

    _xmlDoc *xmlDoc = nullptr; // owned: the parsed document
    _xmlNode *root = nullptr;  // root element (borrowed from xmlDoc)

    // True when NextUpdate is present and in the future: the list may still
    // be trusted as up to date. A missing/unparseable NextUpdate is stale.
    bool upToDate(std::time_t now = std::time(nullptr)) const;
};

class TslParser
{
public:
    static std::unique_ptr<Tsl> parseFile(const std::string &path);
    static std::unique_ptr<Tsl> parseXml(const std::string &xml);
};

} // namespace fdo
