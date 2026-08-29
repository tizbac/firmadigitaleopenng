#include "pades.h"

#include <cctype>
#include <cstring>
#include <map>

#include "cmssigner.h"

namespace fdo {
namespace {

// ---------------------------------------------------------------------------
// Minimal PDF reader (classic xref tables, uncompressed objects)
// ---------------------------------------------------------------------------

struct PdfDoc
{
    std::vector<unsigned char> pdf;
    std::map<int, std::size_t> objOffset; // obj number -> offset of "N G obj"
    int maxObj = 0;
    int rootRef = 0;
    std::size_t xrefOffset = 0;
    std::string trailerDict;
    std::string rootDict; // raw catalog dictionary <<...>>
    bool hasAcroForm = false;
    std::string acroFormDict;
    std::vector<int> pages; // page object numbers, in document order
};

void appendStr(std::vector<unsigned char> &v, const std::string &s)
{
    v.insert(v.end(), s.begin(), s.end());
}

std::string hexOf(const std::vector<unsigned char> &v)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (unsigned char c : v) {
        s += d[c >> 4];
        s += d[c & 0xF];
    }
    return s;
}

bool hexToBytes(const std::string &s, std::vector<unsigned char> &out)
{
    if (s.size() % 2 != 0)
        return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        const int hi = val(s[i]);
        const int lo = val(s[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

// offset of the xref table referenced by the LAST startxref
bool findStartxref(const std::vector<unsigned char> &pdf, std::size_t &xrefOff)
{
    if (pdf.size() < 16)
        return false;
    const std::string s(reinterpret_cast<const char *>(pdf.data()), pdf.size());
    const auto pos = s.rfind("startxref");
    if (pos == std::string::npos)
        return false;
    std::size_t i = pos + 9;
    while (i < s.size() && (s[i] == '\r' || s[i] == '\n' || s[i] == ' ' || s[i] == '\t'))
        ++i;
    std::size_t j = i;
    while (j < s.size() && s[j] >= '0' && s[j] <= '9')
        ++j;
    if (j == i || j > s.size() || std::stoull(s.substr(i, j - i)) >= s.size())
        return false;
    xrefOff = std::stoull(s.substr(i, j - i));
    return true;
}

// "N G obj" at off -> body between "obj" and "endobj"
bool readObjBody(const std::vector<unsigned char> &pdf, std::size_t off,
                 std::string &body)
{
    if (off + 16 > pdf.size())
        return false;
    const std::string head(
        reinterpret_cast<const char *>(pdf.data() + off),
        std::min<std::size_t>(64, pdf.size() - off));
    const auto k = head.find("obj");
    if (k == std::string::npos)
        return false;
    const std::size_t start = off + k + 3;
    const std::string rest(
        reinterpret_cast<const char *>(pdf.data() + start), pdf.size() - start);
    const auto e = rest.find("endobj");
    if (e == std::string::npos)
        return false;
    body = rest.substr(0, e);
    while (!body.empty() && std::isspace(static_cast<unsigned char>(body.back())))
        body.pop_back();
    return true;
}

// find a key inside raw dictionary text; valOff = start of the value.
// PDF names are self-delimiting: no space is required before a key
// (e.g. "R/Root"), but the character after must not extend the name.
bool findKey(const std::string &text, const std::string &key, std::size_t &valOff)
{
    auto isNameChar = [](unsigned char c) {
        return std::isalnum(c) || c == '+' || c == '-' || c == '_';
    };
    std::size_t pos = 0;
    while ((pos = text.find(key, pos)) != std::string::npos) {
        const std::size_t after = pos + key.size();
        if (after >= text.size() || !isNameChar(static_cast<unsigned char>(text[after]))) {
            std::size_t v = after;
            while (v < text.size() && std::isspace(static_cast<unsigned char>(text[v])))
                ++v;
            valOff = v;
            return true;
        }
        pos += key.size();
    }
    return false;
}

// parse "N G R" at off
bool parseRef(const std::string &text, std::size_t off, int &refNum)
{
    std::size_t i = off;
    auto skipWs = [&]() {
        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i])))
            ++i;
    };
    auto digits = [&](long long &v) {
        std::size_t j = i;
        while (j < text.size() && text[j] >= '0' && text[j] <= '9')
            ++j;
        if (j == i)
            return false;
        v = std::stoll(text.substr(i, j - i));
        i = j;
        return true;
    };
    long long n = 0, g = 0;
    if (!digits(n))
        return false;
    skipWs();
    if (!digits(g))
        return false;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i])))
        ++i;
    if (i >= text.size() || text[i] != 'R')
        return false;
    refNum = static_cast<int>(n);
    return true;
}

// parse "[N G R, N G R, ...]" at off (text[off] == '[')
bool parseRefs(const std::string &text, std::size_t off, std::vector<int> &refs)
{
    if (off >= text.size() || text[off] != '[')
        return false;
    refs.clear();
    std::size_t i = off + 1;
    while (i < text.size() && text[i] != ']') {
        while (i < text.size() &&
               (std::isspace(static_cast<unsigned char>(text[i])) || text[i] == ','))
            ++i;
        if (i < text.size() && text[i] == ']')
            break;
        int r = 0;
        if (!parseRef(text, i, r))
            return false;
        refs.push_back(r);
        while (i < text.size() && text[i] != ',' && text[i] != ']')
            ++i;
    }
    return true;
}

// parse four integers "[a b c d]" at off
bool parseInts4(const std::string &text, std::size_t off, unsigned long long out[4])
{
    if (off >= text.size() || text[off] != '[')
        return false;
    std::size_t i = off + 1;
    for (int k = 0; k < 4; ++k) {
        while (i < text.size() &&
               (std::isspace(static_cast<unsigned char>(text[i])) || text[i] == ','))
            ++i;
        std::size_t j = i;
        while (j < text.size() && text[j] >= '0' && text[j] <= '9')
            ++j;
        if (j == i)
            return false;
        out[k] = std::stoull(text.substr(i, j - i));
        i = j;
    }
    return true;
}

void collectPages(const PdfDoc &doc, int ref, std::vector<int> &pages)
{
    auto it = doc.objOffset.find(ref);
    if (it == doc.objOffset.end())
        return;
    std::string body;
    if (!readObjBody(doc.pdf, it->second, body))
        return;
    std::size_t off = 0;
    if (findKey(body, "/Kids", off)) {
        std::vector<int> kids;
        if (parseRefs(body, off, kids))
            for (int k : kids)
                collectPages(doc, k, pages);
    } else {
        pages.push_back(ref);
    }
}

// parse a classic xref table; returns the raw trailer dictionary
bool parseXref(const std::vector<unsigned char> &pdf, std::size_t xrefOff,
               std::map<int, std::size_t> &objs, int &maxObj,
               std::string &trailerDict, std::string &err)
{
    const std::string s(reinterpret_cast<const char *>(pdf.data() + xrefOff),
                        pdf.size() - xrefOff);
    if (s.size() < 8 || s.compare(0, 4, "xref") != 0) {
        err = "xref non trovata (xref stream non supportato)";
        return false;
    }
    auto skipWs = [&](std::size_t &i) {
        while (i < s.size() && (s[i] == '\r' || s[i] == '\n' || s[i] == ' ' ||
                                s[i] == '\t'))
            ++i;
    };
    std::size_t p = 4;
    while (true) {
        skipWs(p);
        std::size_t q = p;
        while (q < s.size() && s[q] >= '0' && s[q] <= '9')
            ++q;
        if (q == p)
            break; // reached "trailer"
        const long long start = std::stoll(s.substr(p, q - p));
        p = q;
        skipWs(p);
        q = p;
        while (q < s.size() && s[q] >= '0' && s[q] <= '9')
            ++q;
        if (q == p) {
            err = "xref malformata";
            return false;
        }
        const long long count = std::stoll(s.substr(p, q - p));
        p = q;
        for (long long i = 0; i < count; ++i) {
            while (p < s.size() && (s[p] == '\r' || s[p] == '\n'))
                ++p;
            if (p + 20 > s.size()) {
                err = "xref tronca";
                return false;
            }
            const long long offset = std::stoll(s.substr(p, 10));
            const int gen = std::stoi(s.substr(p + 11, 5));
            const char kw = s[p + 17];
            if (kw == 'n' && gen == 0 && offset > 0) {
                const int num = static_cast<int>(start + i);
                objs[num] = static_cast<std::size_t>(offset);
                maxObj = std::max(maxObj, num);
            }
            p += 20;
        }
        skipWs(p);
        if (p + 7 <= s.size() && s.compare(p, 7, "trailer") == 0)
            break;
    }
    p += 7;
    skipWs(p);
    if (p + 2 > s.size() || s.compare(p, 2, "<<") != 0) {
        err = "trailer non trovato";
        return false;
    }
    // scan to the matching ">>"
    std::size_t depth = 0;
    for (std::size_t i = p; i + 1 < s.size(); ++i) {
        if (s[i] == '<' && s[i + 1] == '<') {
            ++depth;
            ++i;
        } else if (s[i] == '>' && s[i + 1] == '>') {
            --depth;
            ++i;
            if (depth == 0) {
                trailerDict = s.substr(p, i - p + 1);
                return true;
            }
        }
    }
    err = "trailer non chiuso";
    return false;
}

bool loadDoc(const std::vector<unsigned char> &pdf, PdfDoc &doc, std::string &err)
{
    doc.pdf = pdf;
    std::size_t xrefOff = 0;
    if (!findStartxref(pdf, xrefOff)) {
        err = "startxref non trovato";
        return false;
    }
    doc.xrefOffset = xrefOff;
    if (!parseXref(pdf, xrefOff, doc.objOffset, doc.maxObj, doc.trailerDict, err))
        return false;
    std::size_t off = 0;
    if (!findKey(doc.trailerDict, "/Root", off) || !parseRef(doc.trailerDict, off,
                                                             doc.rootRef)) {
        err = "trailer: /Root mancante";
        return false;
    }
    auto it = doc.objOffset.find(doc.rootRef);
    if (it == doc.objOffset.end() ||
        !readObjBody(pdf, it->second, doc.rootDict)) {
        err = "oggetto catalogo non trovato";
        return false;
    }
    if (findKey(doc.rootDict, "/AcroForm", off)) {
        doc.hasAcroForm = true;
        int afRef = 0;
        if (parseRef(doc.rootDict, off, afRef)) {
            auto a = doc.objOffset.find(afRef);
            if (a != doc.objOffset.end())
                readObjBody(pdf, a->second, doc.acroFormDict);
        }
    }
    int pagesRef = 0;
    if (findKey(doc.rootDict, "/Pages", off) && parseRef(doc.rootDict, off, pagesRef))
        collectPages(doc, pagesRef, doc.pages);
    return true;
}

std::string pdfName(const X509Cert &c)
{
    if (!c.givenName.empty() || !c.surname.empty()) {
        std::string n = c.givenName;
        if (!n.empty() && !c.surname.empty())
            n += " ";
        n += c.surname;
        return n;
    }
    // fallback: extract the CN component from the subject string
    const std::string &s = c.subject;
    auto pos = s.find("CN=");
    if (pos == std::string::npos)
        return s;
    pos += 3;
    auto end = s.find(',', pos);
    if (end == std::string::npos)
        return s.substr(pos);
    return s.substr(pos, end - pos);
}

std::string escapePdfText(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\' || c == '(' || c == ')')
            out += '\\';
        out += c;
    }
    return out;
}

std::string pdfDateTime(std::time_t t)
{
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[40];
    std::strftime(buf, sizeof(buf), "D:%Y%m%d%H%M%S", &tm);
    int offMin = static_cast<int>((mktime(&tm) - timegm(&tm)) / 60);
    char sign = offMin < 0 ? '-' : '+';
    int a = offMin < 0 ? -offMin : offMin;
    char tz[16];
    std::snprintf(tz, sizeof(tz), "%c%02d'%02d'", sign, a / 60, a % 60);
    return std::string(buf) + tz;
}

// PDF requires a '.' decimal point regardless of the process locale
std::string locNum(double v, int prec)
{
    char b[64];
    std::snprintf(b, sizeof(b), "%.*f", prec, v);
    std::string s(b);
    for (char &c : s)
        if (c == ',')
            c = '.';
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
// Visible-stamp layout (shared with the GUI preview)
// ---------------------------------------------------------------------------

double stampFontSize(const std::string &line1, const std::string &line2,
                     double boxW, double maxFont)
{
    constexpr double kMinFont = 6.0;
    const double maxLen = std::max<double>(line1.size(), line2.size());
    if (maxLen <= 0 || boxW <= 8.0)
        return kMinFont;
    return std::max(kMinFont, std::min(maxFont, (boxW - 8.0) / (0.5 * maxLen)));
}

StampBox stampFitBox(const std::string &line1, const std::string &line2,
                     double maxFont)
{
    const double maxLen = std::max<double>(line1.size(), line2.size());
    StampBox b;
    b.w = 12.0 + (0.5 * maxLen) * maxFont;
    b.h = 6.0 + 2.2 * maxFont + 8.0;
    return b;
}

StampLayout stampLayout(const std::string &line1, const std::string &line2,
                        double boxW, double boxH, double maxFont)
{
    StampLayout l;
    l.fs = stampFontSize(line1, line2, boxW, maxFont);
    l.y1 = boxH - 6.0 - l.fs;
    l.y2 = boxH - 6.0 - 2.2 * l.fs;
    l.left = 4.0;
    return l;
}

std::string stampTimeString(std::time_t t)
{
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// ---------------------------------------------------------------------------
// Pades::sign
// ---------------------------------------------------------------------------

PadesResult Pades::sign(const PadesConfig &cfg, const SignFunction &sign)
{
    PadesResult res;
    std::string err;
    PdfDoc doc;
    if (!loadDoc(cfg.pdfBytes, doc, err)) {
        res.error = err;
        return res;
    }
    if (cfg.visible &&
        (cfg.onPage < 0 || cfg.onPage >= static_cast<int>(doc.pages.size()))) {
        res.error = "pagina non valida per il timbro visibile";
        return res;
    }

    const int sigObj = doc.maxObj + 1;
    const int fieldObj = doc.maxObj + 2;
    const int acroObj = doc.maxObj + 3;
    const bool newCat = !doc.hasAcroForm;
    const int catObj = doc.maxObj + 4;
    const int apObj = doc.maxObj + 5;
    const int visObj = doc.maxObj + 6;

    const std::string name =
        cfg.signerName.empty() ? pdfName(cfg.signerCert) : cfg.signerName;

    int pageRef = 0;
    if (cfg.visible) {
        if (cfg.onPage < 0 || cfg.onPage >= static_cast<int>(doc.pages.size())) {
            res.error = "pagina non valida";
            return res;
        }
        pageRef = doc.pages[cfg.onPage];
    }

    std::string appearanceStream_;
    std::string appearanceBBox_;
    // build the incremental update for a signature hex string of sigHexLen
    auto buildLayout = [&](int sigHexLen, std::vector<unsigned char> &out,
                           std::size_t &hexStart, std::string &lerr) -> bool {
        // --- signature dictionary ---
        std::string sigDict =
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached\n"
            "   /ByteRange [0000000000 0000000000 0000000000 0000000000]\n"
            "   /Contents <" + std::string(sigHexLen, '0') + ">";
        sigDict += " /Length " + std::to_string(sigHexLen / 2) +
                   " /Name (" + escapePdfText(name) +
                   ") /M (" + pdfDateTime(std::time(nullptr)) +
                   ") /Location () /Reason () /ContactInfo () >>";

        // --- field / widget ---
        std::string fieldDict;
        if (cfg.visible) {
            const double w = cfg.boxX2 - cfg.boxX1;
            const double h = cfg.boxY2 - cfg.boxY1;
            const std::string line1 = cfg.visibleText + " : " + name;
            const std::string line2 =
                "Time: " + stampTimeString(std::time(nullptr));
            const StampLayout sl = stampLayout(line1, line2, w, h, cfg.maxFont);
            const std::string fsStr = locNum(sl.fs, 6).substr(0, 6);
            const std::string y1 = locNum(sl.y1, 1);
            const std::string y2 = locNum(sl.y2, 1);
            const std::string wStr = locNum(w, 1);
            const std::string hStr = locNum(h, 1);
            appearanceStream_ =
                "BT\n/F1 " + fsStr + " Tf\n1 0 0 1 4 " + y1 + " Tm\n(" +
                escapePdfText(line1) +
                ") Tj\n1 0 0 1 4 " + y2 + " Tm\n(" + escapePdfText(line2) +
                ") Tj\nET";
            appearanceBBox_ = std::string("[0 0 ") + wStr + " " + hStr + "]";
            fieldDict = "<< /Type /Annot /Subtype /Widget /FT /Sig /T (" +
                        escapePdfText(cfg.fieldName) + ") /V " +
                        std::to_string(sigObj) + " 0 R /P " +
                        std::to_string(pageRef) + " 0 R\n   /Rect [" +
                        locNum(cfg.boxX1, 6) + " " + locNum(cfg.boxY1, 6) +
                        " " + locNum(cfg.boxX2, 6) + " " +
                        locNum(cfg.boxY2, 6) +
                        "] /F 4 /AP << /N " + std::to_string(apObj) +
                        " 0 R >> >>";
        } else {
            fieldDict = "<< /FT /Sig /T (" + escapePdfText(cfg.fieldName) +
                        ") /V " + std::to_string(sigObj) +
                        " 0 R /Ff 3 >>";
            appearanceStream_.clear();
            appearanceBBox_.clear();
        }

        // --- AcroForm (always re-emitted with the new field) ---
        std::string oldFields;
        std::size_t off = 0;
        if (doc.hasAcroForm && findKey(doc.acroFormDict, "/Fields", off)) {
            std::vector<int> fields;
            if (parseRefs(doc.acroFormDict, off, fields))
                for (int f : fields)
                    oldFields += (std::to_string(f) + " 0 R ");
        }
        std::string acroDict = "<< /Fields [" +
                               std::to_string(fieldObj) + " 0 R " + oldFields +
                               "] /SigFlags 3 >>";

        // --- catalog (only when /AcroForm is added) ---
        std::string catDict;
        if (newCat) {
            catDict = doc.rootDict;
            if (catDict.size() >= 2 && catDict.compare(catDict.size() - 2, 2, ">>") == 0)
                catDict.replace(catDict.size() - 2, 2,
                                " /AcroForm " + std::to_string(acroObj) + " 0 R >>");
        }

        // --- page (visible only: add the annotation) ---
        std::string pageDict;
        if (cfg.visible) {
            auto it = doc.objOffset.find(pageRef);
            if (it == doc.objOffset.end()) {
                lerr = "oggetto pagina non trovato";
                return false;
            }
            if (!readObjBody(doc.pdf, it->second, pageDict)) {
                lerr = "lettura pagina non riuscita";
                return false;
            }
            if (pageDict.size() < 2 || pageDict.compare(pageDict.size() - 2, 2, ">>") != 0) {
                lerr = "dizionario pagina non supportato";
                return false;
            }
            if (findKey(pageDict, "/Annots", off)) {
                // append to the existing array
                auto close = pageDict.find(']', off);
                if (close == std::string::npos) {
                    lerr = "/Annots non supportato";
                    return false;
                }
                pageDict.insert(close, (" " + std::to_string(fieldObj) + " 0 R").c_str());
            } else {
                pageDict.replace(pageDict.size() - 2, 2,
                                 (" /Annots [" + std::to_string(fieldObj) +
                                  " 0 R] >>").c_str());
            }
        }

        // --- visible signature: stamp the appearance directly in the page
        //     content stream too, so every renderer shows it even when
        //     annotations are hidden ---
        std::string visStream;
        bool overlayActive = false;
        if (cfg.visible) {
            std::size_t rOff = 0;
            const bool hasRes = findKey(pageDict, "/Resources", rOff);
            const bool inlineRes = hasRes && rOff + 1 < pageDict.size() &&
                                   pageDict[rOff] == '<' && pageDict[rOff + 1] == '<';
            if (inlineRes) {
                // scan the resources value (starts with "<<" at rOff); depth 1
                // means the resources closing ">>" is reached
                std::size_t i = rOff + 2, depth = 1;
                for (; i + 1 < pageDict.size() && depth; ++i) {
                    if (pageDict[i] == '<' && pageDict[i + 1] == '<') { ++depth; ++i; }
                    else if (pageDict[i] == '>' && pageDict[i + 1] == '>') { --depth; ++i; }
                }
                if (!depth) {
                    // endRes = index of the first '>' of the resources closing '>>'
                    const std::size_t endRes = i - 2;
                    const std::size_t xop = pageDict.find("/XObject", rOff);
                    if (xop != std::string::npos && xop < endRes) {
                        std::size_t so = xop + 8;
                        while (so < endRes &&
                               std::isspace(static_cast<unsigned char>(pageDict[so])))
                            ++so;
                        if (so + 1 < endRes && pageDict[so] == '<' && pageDict[so + 1] == '<') {
                            std::size_t j = so + 2, d2 = 1;
                            for (; j + 1 <= endRes && d2; ++j) {
                                if (pageDict[j] == '<' && pageDict[j + 1] == '<') { ++d2; ++j; }
                                else if (pageDict[j] == '>' && pageDict[j + 1] == '>') { --d2; ++j; }
                            }
                            if (!d2)
                                pageDict.insert(j - 2, ("/VisSig " + std::to_string(apObj) + " 0 R ").c_str());
                        }
                    } else {
                        pageDict.insert(endRes, (" /XObject << /VisSig " + std::to_string(apObj) + " 0 R >>").c_str());
                    }
                    // prepend the form onto the page content stream
                    std::size_t cOff = 0;
                    if (!findKey(pageDict, "/Contents", cOff) && pageDict.size() >= 2)
                        cOff = std::string::npos;
                    if (cOff != std::string::npos && cOff < pageDict.size() && pageDict[cOff] == '[') {
                        const std::size_t cc = pageDict.find(']', cOff);
                        if (cc != std::string::npos)
                            pageDict.insert(cc, (" " + std::to_string(visObj) + " 0 R").c_str());
                    } else if (cOff != std::string::npos && cOff < pageDict.size()) {
                        int cnum = 0;
                        if (parseRef(pageDict, cOff, cnum)) {
                            const std::size_t rr = pageDict.find(" 0 R", cOff);
                            if (rr != std::string::npos && rr + 4 < pageDict.size()) {
                                const std::string origRef = pageDict.substr(cOff, rr + 4 - cOff);
                                pageDict.replace(cOff, rr + 4 - cOff,
                                                 "[" + origRef + " " + std::to_string(visObj) + " 0 R]");
                            }
                        }
                    } else if (pageDict.size() >= 2 && pageDict.compare(pageDict.size() - 2, 2, ">>") == 0) {
                        pageDict.replace(pageDict.size() - 2, 2,
                                         (" /Contents [" + std::to_string(visObj) + " 0 R] >>").c_str());
                    }
                    char vsl[96];
                    std::snprintf(vsl, sizeof(vsl), "q 1 0 0 1 %s %s cm /VisSig Do Q",
                                  locNum(cfg.boxX1, 1).c_str(),
                                  locNum(cfg.boxY1, 1).c_str());
                    visStream = vsl;
                    overlayActive = true;
                }
            }
        }

        // --- assemble ---
        out = doc.pdf;
        auto appendObj = [&](int num, const std::string &body) {
            appendStr(out, "\n" + std::to_string(num) + " 0 obj\n" + body + "\nendobj");
        };
        // remember where the placeholder hex begins (after the "<" that opens
        // the hex string — not the "<<" of the dictionary)
        hexStart = out.size() +
                   ("\n" + std::to_string(sigObj) + " 0 obj\n").size() +
                   sigDict.find("<" + std::string(sigHexLen, '0')) + 1;
        appendObj(sigObj, sigDict);
        appendObj(fieldObj, fieldDict);
        appendObj(acroObj, acroDict);
        if (newCat)
            appendObj(catObj, catDict);
        if (cfg.visible)
            appendObj(pageRef, pageDict);
        if (cfg.visible) {
            const std::string apStream = appearanceStream_ + "\n";
            const std::string apDict =
                "<< /Type /XObject /Subtype /Form /BBox " + appearanceBBox_ +
                " /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Length " +
                std::to_string(apStream.size()) + " >>\nstream\n" + apStream +
                "endstream";
            appendObj(apObj, apDict);
            if (overlayActive) {
                const std::string vs = visStream + "\n";
                const std::string visDict =
                    "<< /Length " + std::to_string(vs.size()) + " >>\nstream\n" + vs +
                    "endstream";
                appendObj(visObj, visDict);
            }
        }

        // --- xref + trailer ---
        std::string xref = "xref\n";
        auto appendEntry = [&](int num, std::size_t objOff) {
            xref += std::to_string(num) + " 1\n";
            char line[24];
            std::snprintf(line, sizeof(line), "%010zu 00000 n \n", objOff);
            xref += line;
        };
        // object offsets (search only the appended region: a number like
        // "101 0 obj" could substring-match inside old binary streams)
        const std::size_t tailStart = doc.pdf.size();
        auto objAt = [&](int num) -> std::size_t {
            const std::string s(reinterpret_cast<const char *>(out.data()), out.size());
            const std::string needle = "\n" + std::to_string(num) + " 0 obj";
            return s.find(needle, tailStart) + 1;
        };
        appendEntry(sigObj, objAt(sigObj));
        appendEntry(fieldObj, objAt(fieldObj));
        appendEntry(acroObj, objAt(acroObj));
        if (newCat)
            appendEntry(catObj, objAt(catObj));
        if (cfg.visible)
            appendEntry(pageRef, objAt(pageRef));
        if (cfg.visible)
            appendEntry(apObj, objAt(apObj));
        if (overlayActive)
            appendEntry(visObj, objAt(visObj));

        appendStr(out, "\n"); // keyword delimiter before xref
        const std::size_t xrefPos = out.size();
        appendStr(out, xref);
        std::string trailer = "<< /Size " +
                              std::to_string(doc.maxObj + (cfg.visible
                                            ? (overlayActive ? 7 : 6)
                                            : newCat ? 5 : 4)) +
                              " /Root " +
                              std::to_string(newCat ? catObj : doc.rootRef) + " 0 R" +
                              " /Prev " + std::to_string(doc.xrefOffset) + " >>";
        appendStr(out, "\ntrailer\n" + trailer + "\nstartxref\n" +
                          std::to_string(xrefPos) + "\n%%EOF");
        return true;
    };

    // two-pass: the placeholder hex length must match the real signature length
    std::vector<unsigned char> out;
    std::size_t hexStart = 0;
    int sigHexLen = 512; // RSA-2048 assumption for the first pass
    for (int pass = 0; pass < 3; ++pass) {
        if (!buildLayout(sigHexLen, out, hexStart, err)) {
            res.error = err;
            return res;
        }
        const std::size_t X = hexStart;
        const std::size_t Y = hexStart + sigHexLen;
        // canonical PAdES layout: the gap between the two ranges must contain
        // the whole /Contents hex-string value INCLUDING its < and >
        // delimiters, so the first signed range ends before "<" and the second
        // starts right after ">"
        const std::size_t xBeg = hexStart - 1;
        const std::size_t yEnd = hexStart + sigHexLen + 1;
        if (Y >= out.size() || yEnd >= out.size()) {
            res.error = "layout PDF non valido";
            return res;
        }
        // fill the ByteRange numbers BEFORE signing: they live in the first
        // (signed) range, so the signed content must already contain them
        {
            auto putRange = [&](std::size_t where, unsigned long long v) {
                char br[12];
                std::snprintf(br, sizeof(br), "%010llu", v);
                std::memcpy(out.data() + where, br, 10);
            };
            const std::string s(reinterpret_cast<const char *>(out.data()), out.size());
            const auto brPos = s.find("/ByteRange [");
            if (brPos == std::string::npos) {
                res.error = "ByteRange non trovato";
                return res;
            }
            // /ByteRange [low1 len1 low2 len2]: first range = [0, X),
            // second range = [Y, end-of-file) so the signature hex string
            // (between X and Y) is excluded from the signed content.
            putRange(brPos + 23, xBeg);
            putRange(brPos + 34, yEnd);
            putRange(brPos + 45, out.size() - yEnd);
        }
        const std::vector<unsigned char> content(out.begin(), out.begin() + xBeg);
        const std::vector<unsigned char> content2(out.begin() + yEnd, out.end());

        CmsConfig ccfg;
        ccfg.signerCertDer = cfg.signerCert.der;
        for (const auto &c : cfg.extraCerts)
            ccfg.extraCerts.push_back(c.der);
        ccfg.contentTypeOid = "1.2.840.113549.1.7.1"; // id-data (PAdES)
        ccfg.detached = true;
        ccfg.signingTime = std::time(nullptr);
        ccfg.content = content;
        ccfg.content.insert(ccfg.content.end(), content2.begin(), content2.end());

        std::string cerr;
        const auto signedAttrs = CmsSigner::buildSignedAttrs(ccfg, &cerr);
        if (signedAttrs.empty()) {
            res.error = cerr;
            return res;
        }
        std::vector<unsigned char> signature;
        if (!sign(signedAttrs, signature, err)) {
            res.error = err;
            return res;
        }
        std::string aerr;
        const std::vector<unsigned char> cms =
            CmsSigner::assemble(ccfg, signedAttrs, signature, &aerr);
        if (cms.empty()) {
            res.error = aerr;
            return res;
        }
        if (static_cast<int>(cms.size() * 2) == sigHexLen) {
            // paste the CMS signature value into the reserved hex slot
            const std::string hex = hexOf(cms);
            for (std::size_t i = 0; i < hex.size(); ++i)
                out[X + i] = hex[i];
            res.pdfBytes = out;
            res.ok = true;
            return res;
        }
        sigHexLen = static_cast<int>(cms.size() * 2); // retry with real length
    }
    res.error = "impossibile dimensionare la firma";
    return res;
}

// ---------------------------------------------------------------------------
// Pades::verify
// ---------------------------------------------------------------------------

P7MResult Pades::verify(const std::vector<unsigned char> &pdfBytes,
                        const std::vector<const X509Cert *> &anchors, std::time_t now)
{
    P7MResult r;
    std::string err;
    PdfDoc doc;
    if (!loadDoc(pdfBytes, doc, err)) {
        r.error = err;
        return r;
    }
    if (!doc.hasAcroForm) {
        r.error = "nessun campo firma presente nel PDF";
        return r;
    }
    std::size_t off = 0;
    if (!findKey(doc.acroFormDict, "/Fields", off)) {
        r.error = "AcroForm: /Fields mancante";
        return r;
    }
    std::vector<int> fields;
    if (!parseRefs(doc.acroFormDict, off, fields) || fields.empty()) {
        r.error = "AcroForm: /Fields non valido";
        return r;
    }
    // latest signature field = last entry
    int fieldRef = fields.back();
    std::string fieldDict;
    {
        auto it = doc.objOffset.find(fieldRef);
        if (it == doc.objOffset.end() ||
            !readObjBody(doc.pdf, it->second, fieldDict)) {
            r.error = "campo firma non letto";
            return r;
        }
    }
    int sigRef = 0;
    if (!findKey(fieldDict, "/V", off) || !parseRef(fieldDict, off, sigRef)) {
        r.error = "campo firma: /V mancante";
        return r;
    }
    std::string sigDict;
    {
        auto it = doc.objOffset.find(sigRef);
        if (it == doc.objOffset.end() ||
            !readObjBody(doc.pdf, it->second, sigDict)) {
            r.error = "dizionario firma non letto";
            return r;
        }
    }
    if (sigDict.find("/adbe.pkcs7.detached") == std::string::npos &&
        sigDict.find("/ETSI.CAdES.detached") == std::string::npos) {
        r.error = "SubFilter non supportato (atteso adbe.pkcs7.detached o ETSI.CAdES.detached)";
        return r;
    }
    if (!findKey(sigDict, "/ByteRange", off)) {
        r.error = "firma: /ByteRange mancante";
        return r;
    }
    unsigned long long br[4] = {0};
    if (!parseInts4(sigDict, off, br)) {
        r.error = "firma: /ByteRange non valido";
        return r;
    }
    // hex string value (under /Contents): first "<" after the ByteRange array
    std::size_t hp = off;
    while (hp < sigDict.size() && sigDict[hp] != ']')
        ++hp;
    if (hp >= sigDict.size()) {
        r.error = "firma: /ByteRange non chiuso";
        return r;
    }
    hp = sigDict.find('<', hp);
    if (hp == std::string::npos) {
        r.error = "firma: valore non trovato";
        return r;
    }
    const auto h1 = hp;
    const auto h2 = sigDict.find('>', h1 + 1);
    if (h1 == std::string::npos || h2 == std::string::npos) {
        r.error = "firma: valore non trovato";
        return r;
    }
    std::vector<unsigned char> cms;
    if (!hexToBytes(sigDict.substr(h1 + 1, h2 - h1 - 1), cms)) {
        r.error = "firma: valore hex non valido";
        return r;
    }
    // PAdES ByteRange: [low1 len1 low2 len2] with absolute offsets + lengths;
    // signed content = [low1, low1+len1) + [low2, low2+len2)
    if (br[0] + br[1] > doc.pdf.size() || br[2] + br[3] > doc.pdf.size() ||
        br[0] + br[1] > br[2]) {
        r.error = "ByteRange fuori dai limiti del file";
        return r;
    }
    std::vector<unsigned char> content(doc.pdf.begin() + br[0],
                                       doc.pdf.begin() + br[0] + br[1]);
    content.insert(content.end(), doc.pdf.begin() + br[2],
                   doc.pdf.begin() + br[2] + br[3]);

    r = P7M::verifyDetached(cms, content, anchors, now);
    if (r.ok)
        r.content.clear(); // not interesting for a PDF signature
    return r;
}

} // namespace fdo
