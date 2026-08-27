#include "c14n.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <string>

#include <libxml/tree.h>

namespace fdo {
namespace {

std::string escapeText(const char *s)
{
    std::string out;
    for (; s && *s; ++s) {
        switch (*s) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;";  break;
        case '>': out += "&gt;";  break;
        default:  out += *s;
        }
    }
    return out;
}

std::string escapeAttr(const char *s)
{
    std::string out;
    for (; s && *s; ++s) {
        switch (*s) {
        case '&': out += "&amp;";  break;
        case '<': out += "&lt;";   break;
        case '>': out += "&gt;";   break;
        case '"': out += "&quot;"; break;
        default:  out += *s;
        }
    }
    return out;
}

// Namespace declarations already emitted by output ancestors, along the
// current output path. Key: prefix ("" for the default namespace).
// Value: the URI that was emitted; a missing key means "not emitted".
struct Emitted
{
    std::map<std::string, std::string> ns;
};

struct Renderer
{
    std::string out;

    void element(const xmlNode *e, const Emitted &inherited, const C14N::Visibility &visible)
    {
        const xmlChar *prefix = (e->ns && e->ns->prefix) ? e->ns->prefix : nullptr;
        const xmlChar *uri = (e->ns && e->ns->href) ? e->ns->href : nullptr;

        // Namespaces used by this element, in document order of first use:
        // the element name first, then the attributes.
        std::vector<std::pair<std::string, std::string>> used;
        used.emplace_back(prefix ? reinterpret_cast<const char *>(prefix) : "",
                          uri ? reinterpret_cast<const char *>(uri) : "");
        for (const xmlAttr *a = e->properties; a; a = a->next) {
            if (a->type != XML_ATTRIBUTE_NODE)
                continue;
            if (!a->ns)
                continue; // no-namespace attribute: never the default namespace
            const xmlChar *ap = (a->ns && a->ns->prefix) ? a->ns->prefix : nullptr;
            const xmlChar *au = (a->ns && a->ns->href) ? a->ns->href : nullptr;
            used.emplace_back(ap ? reinterpret_cast<const char *>(ap) : "",
                              au ? reinterpret_cast<const char *>(au) : "");
        }

        // Namespace declarations to emit on this element: those used here
        // whose (prefix, uri) pair was not already emitted by an output
        // ancestor.
        Emitted emitted = inherited;
        std::vector<std::string> decls;
        for (const auto &[p, u] : used) {
            if (p == "xml" && u == "http://www.w3.org/XML/1998/namespace")
                continue; // pre-defined prefix: never re-declared
            auto it = emitted.ns.find(p);
            if (it != emitted.ns.end() && it->second == u)
                continue;
            if (p.empty()) {
                if (u.empty()) {
                    // This element is out of a default namespace that an
                    // output ancestor emitted: emit xmlns="".
                    if (it == emitted.ns.end())
                        continue;
                    decls.emplace_back("xmlns=\"\"");
                } else {
                    decls.push_back("xmlns=\"" + escapeAttr(u.c_str()) + "\"");
                }
            } else {
                decls.push_back("xmlns:" + p + "=\"" + escapeAttr(u.c_str()) + "\"");
            }
            emitted.ns[p] = u;
        }

        // Attributes in C14N order: (namespace URI, local name).
        std::vector<const xmlAttr *> attrs;
        for (const xmlAttr *a = e->properties; a; a = a->next)
            if (a->type == XML_ATTRIBUTE_NODE)
                attrs.push_back(a);
        std::stable_sort(attrs.begin(), attrs.end(), [](const xmlAttr *a, const xmlAttr *b) {
            const char *au = (a->ns && a->ns->href) ? reinterpret_cast<const char *>(a->ns->href) : "";
            const char *bu = (b->ns && b->ns->href) ? reinterpret_cast<const char *>(b->ns->href) : "";
            const int c = std::strcmp(au, bu);
            if (c != 0)
                return c < 0;
            return std::strcmp(reinterpret_cast<const char *>(a->name),
                               reinterpret_cast<const char *>(b->name)) < 0;
        });

        const auto qname = [&](std::string &s) {
            if (prefix) {
                s += reinterpret_cast<const char *>(prefix);
                s += ':';
            }
            s += reinterpret_cast<const char *>(e->name);
        };

        out += '<';
        qname(out);
        for (const auto &d : decls)
            out += ' ' + d;
        for (const xmlAttr *a : attrs) {
            out += ' ';
            if (a->ns && a->ns->prefix) {
                out += reinterpret_cast<const char *>(a->ns->prefix);
                out += ':';
            }
            out += reinterpret_cast<const char *>(a->name);
            out += "=\"";
            out += escapeAttr(a->children ? reinterpret_cast<const char *>(a->children->content) : "");
            out += '"';
        }
        out += '>';

        for (const xmlNode *c = e->children; c; c = c->next) {
            switch (c->type) {
            case XML_ELEMENT_NODE:
                if (visible && !visible(c))
                    continue;
                element(c, emitted, visible);
                break;
            case XML_TEXT_NODE:
                if (c->content)
                    out += escapeText(reinterpret_cast<const char *>(c->content));
                break;
            default:
                // comments, PIs, DTD nodes: not serialized
                break;
            }
        }

        out += "</";
        qname(out);
        out += '>';
    }
};

} // namespace

std::vector<unsigned char> C14N::canonicalize(const xmlNode *root, const Visibility &visible)
{
    Renderer r;
    r.element(root, Emitted{}, visible);
    return {r.out.begin(), r.out.end()};
}

} // namespace fdo
