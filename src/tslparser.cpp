#include "tslparser.h"
#include "base64.h"

#include <cctype>
#include <cstring>

#include <libxml/parser.h>
#include <libxml/tree.h>

namespace fdo {

Tsl::~Tsl()
{
    if (xmlDoc)
        xmlFreeDoc(reinterpret_cast<xmlDocPtr>(xmlDoc));
}

namespace {

const char *kNsTsl = "http://uri.etsi.org/02231/v2#";
const char *kNsDs = "http://www.w3.org/2000/09/xmldsig#";

std::string textOf(const xmlNode *n)
{
    std::string out;
    for (const xmlNode *c = n ? n->children : nullptr; c; c = c->next)
        if (c->type == XML_TEXT_NODE && c->content)
            out += reinterpret_cast<const char *>(c->content);
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.front())))
        out.erase(out.begin());
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back())))
        out.pop_back();
    return out;
}

// All descendant text, concatenated (for elements like ServiceName>Name).
std::string descendantText(const xmlNode *n)
{
    if (!n)
        return {};
    std::string out = textOf(n);
    for (const xmlNode *c = n->children; c; c = c->next)
        if (c->type == XML_ELEMENT_NODE)
            out += descendantText(c);
    return out;
}

const xmlNode *childByName(const xmlNode *n, const char *name, const char *ns = nullptr)
{
    for (const xmlNode *c = n ? n->children : nullptr; c; c = c->next) {
        if (c->type != XML_ELEMENT_NODE)
            continue;
        if (std::strcmp(reinterpret_cast<const char *>(c->name), name) != 0)
            continue;
        if (ns && (!c->ns || std::strcmp(reinterpret_cast<const char *>(c->ns->href), ns) != 0))
            continue;
        return c;
    }
    return nullptr;
}

bool isElement(const xmlNode *n, const char *name, const char *ns)
{
    return n && n->type == XML_ELEMENT_NODE &&
           std::strcmp(reinterpret_cast<const char *>(n->name), name) == 0 &&
           n->ns && std::strcmp(reinterpret_cast<const char *>(n->ns->href), ns) == 0;
}

void collectCerts(const xmlNode *n, std::vector<std::vector<unsigned char>> &out)
{
    for (const xmlNode *c = n; c; c = c->next) {
        if (c->type != XML_ELEMENT_NODE)
            continue;
        if (std::strcmp(reinterpret_cast<const char *>(c->name), "X509Certificate") == 0) {
            auto der = base64Decode(textOf(c));
            if (!der.empty())
                out.push_back(std::move(der));
        }
        if (c->children)
            collectCerts(c->children, out);
    }
}

void parseServices(const xmlNode *root, Tsl &tsl)
{
    std::vector<const xmlNode *> stack{ root };
    while (!stack.empty()) {
        const xmlNode *n = stack.back();
        stack.pop_back();
        for (const xmlNode *c = n->children; c; c = c->next) {
            if (c->type != XML_ELEMENT_NODE)
                continue;
            if (isElement(c, "TSPServices", kNsTsl)) {
                for (const xmlNode *svc = c->children; svc; svc = svc->next) {
                    if (!isElement(svc, "TSPService", kNsTsl))
                        continue;
                    TslService s;
                    const xmlNode *info = childByName(svc, "ServiceInformation", kNsTsl);
                    if (info) {
                        if (const xmlNode *t = childByName(info, "ServiceTypeIdentifier", kNsTsl))
                            s.serviceTypeIdentifier = textOf(t);
                        if (const xmlNode *n2 = childByName(info, "ServiceName", kNsTsl))
                            s.serviceName = descendantText(n2);
                        if (const xmlNode *st = childByName(info, "ServiceStatus", kNsTsl))
                            s.serviceStatus = textOf(st);
                        if (const xmlNode *di = childByName(info, "ServiceDigitalIdentity", kNsTsl))
                            if (const xmlNode *id = childByName(di, "DigitalId", kNsTsl))
                                if (const xmlNode *cert = childByName(id, "X509Certificate"))
                                    s.certDer = base64Decode(textOf(cert));
                    }
                    tsl.services.push_back(std::move(s));
                }
            }
            stack.push_back(c);
        }
    }
}

void parseSignature(const xmlNode *root, Tsl &tsl)
{
    for (const xmlNode *c = root->children; c; c = c->next) {
        if (!isElement(c, "Signature", kNsDs))
            continue;
        tsl.hasSignature = true;
        if (const xmlNode *si = childByName(c, "SignedInfo")) {
            // the algorithm is an attribute
            if (const xmlNode *sm = childByName(si, "SignatureMethod", kNsDs))
                for (const xmlAttr *a = sm->properties; a; a = a->next)
                    if (std::strcmp(reinterpret_cast<const char *>(a->name), "Algorithm") == 0 &&
                        a->children && a->children->content)
                        tsl.signatureMethod = reinterpret_cast<const char *>(a->children->content);
            for (const xmlNode *ref = si->children; ref; ref = ref->next) {
                if (!isElement(ref, "Reference", kNsDs))
                    continue;
                TslReference r;
                for (const xmlAttr *a = ref->properties; a; a = a->next)
                    if (std::strcmp(reinterpret_cast<const char *>(a->name), "URI") == 0 &&
                        a->children && a->children->content)
                        r.uri = reinterpret_cast<const char *>(a->children->content);
                if (const xmlNode *tr = childByName(ref, "Transforms", kNsDs))
                    for (const xmlNode *t = tr->children; t; t = t->next)
                        if (isElement(t, "Transform", kNsDs))
                            for (const xmlAttr *a = t->properties; a; a = a->next)
                                if (std::strcmp(reinterpret_cast<const char *>(a->name), "Algorithm") == 0 &&
                                    a->children && a->children->content)
                                    r.transforms.emplace_back(
                                        reinterpret_cast<const char *>(a->children->content));
                if (const xmlNode *dm = childByName(ref, "DigestMethod", kNsDs))
                    for (const xmlAttr *a = dm->properties; a; a = a->next)
                        if (std::strcmp(reinterpret_cast<const char *>(a->name), "Algorithm") == 0 &&
                            a->children && a->children->content)
                            r.digestMethod = reinterpret_cast<const char *>(a->children->content);
                if (const xmlNode *dv = childByName(ref, "DigestValue", kNsDs))
                    r.digestValue = base64Decode(textOf(dv));
                tsl.references.push_back(std::move(r));
            }
        }
        if (const xmlNode *sv = childByName(c, "SignatureValue"))
            tsl.signatureValue = base64Decode(textOf(sv));
        if (const xmlNode *ki = childByName(c, "KeyInfo"))
            if (const xmlNode *xd = childByName(ki, "X509Data", kNsDs))
                for (const xmlNode *x = xd->children; x; x = x->next)
                    if (isElement(x, "X509Certificate", kNsDs) ||
                        std::strcmp(reinterpret_cast<const char *>(x->name), "X509Certificate") == 0) {
                        auto der = base64Decode(textOf(x));
                        if (!der.empty())
                            tsl.keyInfoCerts.push_back(std::move(der));
                    }
        break;
    }
}

} // namespace

std::unique_ptr<Tsl> TslParser::parseXml(const std::string &xml)
{
    xmlKeepBlanksDefault(1);
    xmlDocPtr doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), nullptr, nullptr, 0);
    if (!doc)
        return nullptr;
    auto tsl = std::make_unique<Tsl>();
    tsl->xmlDoc = reinterpret_cast<_xmlDoc *>(doc);
    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root) {
        tsl.reset();
        xmlFreeDoc(doc);
        return nullptr;
    }
    tsl->root = root;
    if (const xmlNode *si = childByName(root, "SchemeInformation", kNsTsl)) {
        if (const xmlNode *v = childByName(si, "TSLVersionIdentifier", kNsTsl))
            tsl->versionIdentifier = textOf(v);
        if (const xmlNode *s = childByName(si, "TSLSequenceNumber", kNsTsl))
            tsl->sequenceNumber = textOf(s);
    }
    collectCerts(root, tsl->allCerts);
    parseServices(root, *tsl);
    parseSignature(root, *tsl);
    return tsl;
}

std::unique_ptr<Tsl> TslParser::parseFile(const std::string &path)
{
    xmlKeepBlanksDefault(1);
    xmlDocPtr doc = xmlReadFile(path.c_str(), nullptr, 0);
    if (!doc)
        return nullptr;
    auto tsl = std::make_unique<Tsl>();
    tsl->xmlDoc = reinterpret_cast<_xmlDoc *>(doc);
    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root) {
        tsl.reset();
        xmlFreeDoc(doc);
        return nullptr;
    }
    tsl->root = root;
    if (const xmlNode *si = childByName(root, "SchemeInformation", kNsTsl)) {
        if (const xmlNode *v = childByName(si, "TSLVersionIdentifier", kNsTsl))
            tsl->versionIdentifier = textOf(v);
        if (const xmlNode *s = childByName(si, "TSLSequenceNumber", kNsTsl))
            tsl->sequenceNumber = textOf(s);
    }
    collectCerts(root, tsl->allCerts);
    parseServices(root, *tsl);
    parseSignature(root, *tsl);
    return tsl;
}

} // namespace fdo
