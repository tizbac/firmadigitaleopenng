#include "c14n.h"

#include <libxml/parser.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static bool readFile(const std::string &path, std::vector<unsigned char> &out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

static bool check(const char *label, const std::vector<unsigned char> &got, const std::string &path)
{
    std::vector<unsigned char> want;
    if (!readFile(path, want)) {
        std::cerr << label << ": cannot read " << path << "\n";
        return false;
    }
    if (got != want) {
        std::cerr << label << ": MISMATCH (got " << got.size() << ", want " << want.size() << " bytes)\n";
        const size_t n = std::min(got.size(), want.size());
        for (size_t i = 0; i < n; ++i) {
            if (got[i] != want[i]) {
                std::cerr << "  first diff at byte " << i << "\n";
                const size_t a = i > 60 ? i - 60 : 0;
                auto show = [&a](const char *what, const std::vector<unsigned char> &v, size_t from, size_t to) {
                    std::string s(reinterpret_cast<const char *>(v.data()) + from, to - from);
                    for (char &ch : s)
                        if (ch < 32 || ch > 126)
                            ch = '?';
                    std::cerr << "  " << what << " [" << a << ".." << to << "]: " << s << "\n";
                };
                show("want", want, a, std::min(n, i + 60));
                show("got ", got, a, std::min(n, i + 60));
                break;
            }
        }
        return false;
    }
    std::cout << label << ": OK (" << got.size() << " bytes)\n";
    return true;
}

int main(int argc, char **argv)
{
    const std::string dataDir = argc > 1 ? argv[1] : "tests/data";

    xmlKeepBlanksDefault(1);
    xmlDocPtr doc = xmlReadFile((dataDir + "/TSL-IT.xml").c_str(), nullptr, 0);
    if (!doc) {
        std::cerr << "cannot parse " << dataDir << "/TSL-IT.xml\n";
        return 2;
    }
    xmlNode *root = xmlDocGetRootElement(doc);

    int failures = 0;

    // 1) whole document minus ds:Signature (enveloped-signature + exc-c14n)
    {
        std::vector<unsigned char> got = fdo::C14N::canonicalize(root, [](const xmlNode *n) {
            return !(n->type == XML_ELEMENT_NODE &&
                     std::strcmp(reinterpret_cast<const char *>(n->name), "Signature") == 0 &&
                     n->ns && std::strcmp(reinterpret_cast<const char *>(n->ns->href),
                                          "http://www.w3.org/2000/09/xmldsig#") == 0);
        });
        if (!check("ref1 (whole doc excl Signature)", got, dataDir + "/ref1_c14n.bin"))
            ++failures;
    }

    // 2) the xades:SignedProperties fragment (URI="#xades-id-...")
    {
        const char *wantName = "SignedProperties";
        const char *wantNs = "http://uri.etsi.org/01903/v1.3.2#";
        const char *wantId = "xades-id-a0e2d2dab0d1c7545376c2e7f49a141e";
        std::function<xmlNode *(const xmlNode *)> find =
            [&find, wantName, wantNs, wantId](const xmlNode *n) -> xmlNode * {
            for (const xmlNode *c = n; c; c = c->next) {
                if (c->type != XML_ELEMENT_NODE)
                    continue;
                const xmlChar *id = xmlGetProp(c, BAD_CAST "Id");
                const bool match =
                    std::strcmp(reinterpret_cast<const char *>(c->name), wantName) == 0 &&
                    c->ns && std::strcmp(reinterpret_cast<const char *>(c->ns->href), wantNs) == 0 &&
                    id && std::strcmp(reinterpret_cast<const char *>(id), wantId) == 0;
                if (id)
                    xmlFree(const_cast<xmlChar *>(id));
                if (match)
                    return const_cast<xmlNode *>(c);
                if (c->children) {
                    xmlNode *r = find(c->children);
                    if (r)
                        return r;
                }
            }
            return nullptr;
        };
        xmlNode *frag = find(root);
        if (!frag) {
            std::cerr << "cannot locate xades:SignedProperties\n";
            return 2;
        }
        std::vector<unsigned char> got = fdo::C14N::canonicalize(frag);
        if (!check("ref2 (SignedProperties fragment)", got, dataDir + "/c14n_ref2_gt.bin"))
            ++failures;
    }

    // 3) ds:SignedInfo (preimage of the RSA signature)
    {
        xmlNode *sig = nullptr;
        for (xmlNode *c = root->children; c; c = c->next)
            if (c->type == XML_ELEMENT_NODE &&
                std::strcmp(reinterpret_cast<const char *>(c->name), "Signature") == 0)
                sig = c;
        xmlNode *si = nullptr;
        for (xmlNode *c = sig ? sig->children : nullptr; c; c = c->next)
            if (c->type == XML_ELEMENT_NODE &&
                std::strcmp(reinterpret_cast<const char *>(c->name), "SignedInfo") == 0)
                si = c;
        if (!si) {
            std::cerr << "cannot locate ds:SignedInfo\n";
            return 2;
        }
        std::vector<unsigned char> got = fdo::C14N::canonicalize(si);
        if (!check("SignedInfo (RSA preimage)", got, dataDir + "/c14n_signedinfo_gt.bin"))
            ++failures;
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    if (failures) {
        std::cerr << failures << " c14n test(s) FAILED\n";
        return 1;
    }
    std::cout << "all c14n tests passed\n";
    return 0;
}
