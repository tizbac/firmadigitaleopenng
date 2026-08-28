#include "p7m.h"

#include <cstdio>
#include <cstring>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "cmssigner.h"
#include "der.h"

namespace fdo {
namespace {

using der::Bytes;

const char *OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const char *OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const char *OID_ATTR_MSG_DIGEST = "1.2.840.113549.1.9.4";
const char *OID_ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5";
const char *OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";

std::string oidToDots(const unsigned char *p, std::size_t n)
{
    if (n == 0)
        return {};
    std::string out = std::to_string(static_cast<int>(p[0]) / 40) + "." +
                      std::to_string(static_cast<int>(p[0]) % 40);
    unsigned long v = 0;
    for (std::size_t i = 1; i < n; ++i) {
        v = (v << 7) | (p[i] & 0x7F);
        if (!(p[i] & 0x80)) {
            out += "." + std::to_string(v);
            v = 0;
        }
    }
    return out;
}

struct Tlv
{
    std::uint8_t tag = 0;
    const unsigned char *data = nullptr;
    std::size_t len = 0;
    std::size_t next = 0;
    bool indefinite = false;
    std::vector<unsigned char> chunked; // concatenated content of a chunked primitive
};

// Offset just past the TLV starting at `off` (0 on error). Handles definite
// and indefinite (BER) lengths, skipping nested structures so that the
// matching end-of-contents (00 00) is found at the right depth.
std::size_t tlvEnd(const unsigned char *buf, std::size_t bufLen, std::size_t off)
{
    if (off + 2 > bufLen)
        return 0;
    std::size_t p = off + 1;
    const unsigned char l0 = buf[p++];
    if (!(l0 & 0x80)) {
        const std::size_t end = p + l0;
        return end <= bufLen ? end : 0;
    }
    if (l0 & 0x7F) {
        const int n = l0 & 0x7F;
        if (n > 4 || p + n > bufLen)
            return 0;
        std::size_t len = 0;
        for (int i = 0; i < n; ++i)
            len = (len << 8) | buf[p++];
        const std::size_t end = p + len;
        return end <= bufLen ? end : 0;
    }
    // Indefinite length: consume whole TLVs until the matching 00 00.
    int depth = 1;
    while (p + 1 <= bufLen) {
        if (buf[p] == 0x00 && buf[p + 1] == 0x00) {
            if (--depth == 0)
                return p + 2;
            p += 2;
            continue;
        }
        const std::size_t e = tlvEnd(buf, bufLen, p);
        if (!e)
            return 0;
        p = e;
    }
    return 0;
}

bool readTlv(const unsigned char *buf, std::size_t bufLen, std::size_t off, Tlv &t)
{
    if (off + 2 > bufLen)
        return false;
    t.tag = buf[off];
    const std::size_t end = tlvEnd(buf, bufLen, off);
    if (!end)
        return false;
    std::size_t p = off + 1;
    const unsigned char l0 = buf[p++];
    t.indefinite = (l0 == 0x80);
    if (t.indefinite && !(t.tag & 0x20)) {
        // Chunked primitive (e.g. OCTET STRING): join the chunks.
        std::size_t q = p;
        while (q + 1 < end) {
            if (buf[q] == 0x00 && buf[q + 1] == 0x00) {
                q = end;
                continue;
            }
            Tlv c;
            if (!readTlv(buf, bufLen, q, c) || c.tag != 0x04)
                return false;
            t.chunked.insert(t.chunked.end(), c.data, c.data + c.len);
            q = c.next;
        }
        t.data = t.chunked.data();
        t.len = t.chunked.size();
    } else if (t.indefinite) {
        t.data = buf + p;
        t.len = end - p;
    } else if (l0 & 0x80) {
        const int n = l0 & 0x7F;
        if (n > 4 || p + n > bufLen)
            return false;
        std::size_t len = 0;
        for (int i = 0; i < n; ++i)
            len = (len << 8) | buf[p++];
        t.data = buf + p;
        t.len = len;
    } else {
        t.data = buf + p;
        t.len = l0;
    }
    t.next = end;
    return true;
}

// Reads an OCTET STRING at `off` and returns its content bytes. Accepts both
// primitive (0x04) and constructed (0x24) forms, definite or
// indefinite/chunked, which real-world CAdES producers (e.g. InfoCert) emit.
bool readOctetContent(const unsigned char *buf, std::size_t bufLen, std::size_t off,
                      std::vector<unsigned char> &out)
{
    Tlv t;
    if (!readTlv(buf, bufLen, off, t) || (t.tag != 0x04 && t.tag != 0x24))
        return false;
    if (t.tag == 0x04 && !t.indefinite) { // primitive, definite: direct content
        out.assign(t.data, t.data + t.len);
        return true;
    }
    if (t.tag == 0x04 && t.indefinite) { // readTlv already joined the chunks
        out = std::move(t.chunked);
        return true;
    }
    // Constructed (0x24): content is a run of 0x04 chunks (terminated by
    // 00 00 when indefinite). Concatenate their payloads.
    out.clear();
    const std::size_t end = t.next;
    std::size_t q = t.data - buf;
    while (q + 1 < end) {
        if (buf[q] == 0x00 && buf[q + 1] == 0x00) {
            q = end;
            continue;
        }
        Tlv c;
        if (!readTlv(buf, bufLen, q, c) || c.tag != 0x04)
            return false;
        out.insert(out.end(), c.data, c.data + c.len);
        q = c.next;
    }
    return true;
}

std::time_t parseAsn1Time(std::uint8_t tag, const unsigned char *d, std::size_t n)
{
    auto dig = [&](std::size_t i) -> int {
        return (i < n && d[i] >= '0' && d[i] <= '9') ? d[i] - '0' : -1;
    };
    std::tm tm{};
    if (tag == 0x18) { // GeneralizedTime YYYYMMDDHHMMSSZ
        if (n < 12)
            return 0;
        tm.tm_year = dig(0) * 1000 + dig(1) * 100 + dig(2) * 10 + dig(3) - 1900;
        tm.tm_mon = dig(4) * 10 + dig(5) - 1;
        tm.tm_mday = dig(6) * 10 + dig(7);
        tm.tm_hour = dig(8) * 10 + dig(9);
        tm.tm_min = dig(10) * 10 + dig(11);
        tm.tm_sec = (n >= 14) ? dig(12) * 10 + dig(13) : 0;
    } else { // UTCTime YYMMDDHHMMSSZ
        if (n < 12)
            return 0;
        const int yy = dig(0) * 10 + dig(1);
        tm.tm_year = yy + (yy < 50 ? 2000 : 1900) - 1900;
        tm.tm_mon = dig(2) * 10 + dig(3) - 1;
        tm.tm_mday = dig(4) * 10 + dig(5);
        tm.tm_hour = dig(6) * 10 + dig(7);
        tm.tm_min = dig(8) * 10 + dig(9);
        tm.tm_sec = (n >= 14) ? dig(10) * 10 + dig(11) : 0;
    }
    if (tm.tm_year < 0 || tm.tm_mon < 0 || tm.tm_mon > 11 || tm.tm_mday < 1)
        return 0;
    return timegm(&tm);
}

std::string formatTime(std::time_t t)
{
    if (t == 0)
        return {};
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// Find attribute with the given OID among the signed attributes (a SET OF at
// absolute offset setOff..setOff+setLen); returns the values SET content.
bool findSignedAttr(const unsigned char *buf, std::size_t n, std::size_t setOff,
                    std::size_t setLen, const std::vector<unsigned char> &oidDer,
                    const unsigned char *&outData, std::size_t &outLen)
{
    std::size_t off = setOff;
    while (off < setOff + setLen) {
        Tlv attr;
        if (!readTlv(buf, n, off, attr) || attr.tag != 0x30)
            return false;
        Tlv type;
        if (!readTlv(buf, n, attr.data - buf, type) || type.tag != 0x06)
            return false;
        if (type.len == oidDer.size() &&
            std::memcmp(type.data, oidDer.data(), type.len) == 0) {
            Tlv values;
            if (!readTlv(buf, n, type.next, values) || values.tag != 0x31)
                return false;
            outData = values.data;
            outLen = values.len;
            return true;
        }
        off = attr.next;
    }
    return false;
}

bool parseCms(const std::vector<unsigned char> &in, ParsedCms &out, std::string *error)
{
    const unsigned char *buf = in.data();
    const std::size_t n = in.size();
    auto fail = [&](const std::string &msg) {
        out.error = msg;
        return false;
    };
    // returns true when `cond` holds (i.e. on failure)
    auto failIf = [&](bool cond, const std::string &msg) {
        if (cond) {
            out.error = msg;
            return true;
        }
        return false;
    };

    // der::oid() returns the full TLV; keep only the OID body for comparisons
    auto oidBody = [](const char *dot) {
        const Bytes t = der::oid(dot);
        return std::vector<unsigned char>(t.begin() + 2, t.end());
    };

    Tlv ci, ciContent;
    if (failIf(!readTlv(buf, n, 0, ci) || ci.tag != 0x30, "structura CMS non valida"))
        return false;
    // ContentInfo: OID, [0] EXPLICIT content
    Tlv ciOid;
    if (failIf(!readTlv(buf, n, 0 + (ci.data - buf), ciOid) || ciOid.tag != 0x06,
               "ContentInfo: OID mancante"))
        return false;
    const std::vector<unsigned char> oidSignedData = oidBody(OID_SIGNED_DATA);
    if (ciOid.len != oidSignedData.size() ||
        std::memcmp(ciOid.data, oidSignedData.data(), ciOid.len) != 0)
        return fail("non e' un SignedData (CMS)");
    if (failIf(!readTlv(buf, n, ciOid.next, ciContent) || ciContent.tag != 0xA0,
               "ContentInfo: [0] mancante"))
        return false;
    // SignedData: version, digestAlgorithms, encapContentInfo, certificates[0], signerInfos
    Tlv sdVersion, sdDigestAlgs, sdEncap, sdCerts, sdSignerInfos;
    {
        Tlv sd;
        if (failIf(!readTlv(buf, n, ciContent.data - buf, sd) || sd.tag != 0x30,
                   "SignedData mancante"))
            return false;
        std::size_t off = sd.data - buf;
        auto base = buf;
        auto rd = [&](std::size_t o, Tlv &t) { return readTlv(base, n, o, t); };
        if (failIf(!rd(off, sdVersion) || sdVersion.tag != 0x02,
                   "SignedData: version mancante"))
            return false;
        off = sdVersion.next;
        if (failIf(!rd(off, sdDigestAlgs) || sdDigestAlgs.tag != 0x31,
                   "SignedData: digestAlgorithms mancante"))
            return false;
        off = sdDigestAlgs.next;
        if (failIf(!rd(off, sdEncap) || sdEncap.tag != 0x30,
                   "SignedData: encapContentInfo mancante"))
            return false;
        off = sdEncap.next;
        // certificates ([0] IMPLICIT) is OPTIONAL; when absent the
        // signerInfos SET OF follows encapContentInfo directly.
        Tlv nxt;
        if (failIf(!rd(off, nxt), "SignedData: campi mancanti"))
            return false;
        if (nxt.tag == 0x31) {
            sdSignerInfos = nxt;
        } else if (nxt.tag == 0xA0) {
            sdCerts = nxt;
            off = sdCerts.next;
            if (failIf(!rd(off, sdSignerInfos) || sdSignerInfos.tag != 0x31,
                       "SignedData: signerInfos mancante"))
                return false;
        } else {
            return fail("SignedData: certificates mancante");
        }
    }

    // encapContentInfo: OID eContentType, optional [0] eContent
    Tlv encOid, encContent;
    {
        if (failIf(!readTlv(buf, n, sdEncap.data - buf, encOid) || encOid.tag != 0x06,
                   "encapContentInfo: OID mancante"))
            return false;
        if (encOid.next >= sdEncap.next ||
            !readTlv(buf, n, encOid.next, encContent) || encContent.tag != 0xA0) {
            out.detached = true;
        } else {
            if (failIf(!readOctetContent(buf, n, encContent.data - buf, out.content),
                       "encapContentInfo: eContent non valido"))
                return false;
        }
    }

    // embedded certificates (full raw TLVs); absent when the field was omitted
    if (sdCerts.data) {
        std::size_t off = sdCerts.data - buf;
        while (off < sdCerts.next) {
            Tlv c;
            if (!readTlv(buf, n, off, c) || c.tag != 0x30)
                break;
            out.embeddedCerts.emplace_back(buf + off, buf + c.next);
            off = c.next;
        }
    }

    // signerInfos SET -> first SignerInfo SEQUENCE
    Tlv si;
    if (failIf(!readTlv(buf, n, sdSignerInfos.data - buf, si) || si.tag != 0x30,
               "SignerInfo mancante"))
        return false;
    // SignerInfo: version, sid, digestAlgorithm, signedAttrs[1], signatureAlgorithm, signature
    Tlv siVersion, siSid, siDigAlg, siSignedAttrs, siSigAlg, siSignature;
    std::size_t signedAttrsStart = 0;
    {
        std::size_t off = si.data - buf;
        if (failIf(!readTlv(buf, n, off, siVersion) || siVersion.tag != 0x02,
                   "SignerInfo: version mancante"))
            return false;
        off = siVersion.next;
        if (failIf(!readTlv(buf, n, off, siSid) || siSid.tag != 0x30,
                   "SignerInfo: sid mancante"))
            return false;
        off = siSid.next;
        if (failIf(!readTlv(buf, n, off, siDigAlg) || siDigAlg.tag != 0x30,
                   "SignerInfo: digestAlgorithm mancante"))
            return false;
        off = siDigAlg.next;
        signedAttrsStart = off;
        // RFC 5652 says [1] IMPLICIT; asn1crypto (the original Python tool)
        // writes [0] IMPLICIT — accept both
        if (failIf(!readTlv(buf, n, off, siSignedAttrs) ||
                   (siSignedAttrs.tag != 0xA1 && siSignedAttrs.tag != 0xA0),
                   "SignerInfo: signedAttrs mancante"))
            return false;
        off = siSignedAttrs.next;
        if (failIf(!readTlv(buf, n, off, siSigAlg) || siSigAlg.tag != 0x30,
                   "SignerInfo: signatureAlgorithm mancante"))
            return false;
        off = siSigAlg.next;
        // RFC 5652 says BIT STRING; asn1crypto writes OCTET STRING — accept both
        if (failIf(!readTlv(buf, n, off, siSignature) ||
                   (siSignature.tag != 0x03 && siSignature.tag != 0x04),
                   "SignerInfo: signature mancante"))
            return false;
    }

    // sid: issuer Name DER + serial INTEGER
    Tlv sidName, sidSerial;
    if (failIf(!readTlv(buf, n, siSid.data - buf, sidName) || sidName.tag != 0x30,
               "sid: issuer mancante"))
        return false;
    if (failIf(!readTlv(buf, n, sidName.next, sidSerial) || sidSerial.tag != 0x02,
               "sid: serial mancante"))
        return false;
    // full Name TLV (tag+length+content), matching X509Cert::issuerNameDer
    out.sidIssuerDer.assign(buf + (siSid.data - buf), sidName.data + sidName.len);
    {
        const unsigned char *s = sidSerial.data;
        std::size_t sl = sidSerial.len;
        while (sl > 1 && s[0] == 0) {
            ++s;
            --sl;
        }
        out.sidSerial.assign(s, s + sl);
    }

    // signedAttrs: keep the full TLV (these are the exact signed bytes)
    out.signedAttrsTlv.assign(buf + signedAttrsStart, buf + siSignedAttrs.next);

    if (siSignature.tag == 0x03) { // BIT STRING: first byte = unused bits
        if (siSignature.len < 2 || siSignature.data[0] != 0)
            return fail("signature BIT STRING non valida");
        out.signature.assign(siSignature.data + 1, siSignature.data + siSignature.len);
    } else { // OCTET STRING
        if (siSignature.len == 0)
            return fail("signature vuota");
        out.signature.assign(siSignature.data, siSignature.data + siSignature.len);
    }

    // walk the signed attributes
    const std::size_t attrsSetOff = siSignedAttrs.data - buf;
    const std::size_t attrsSetLen = siSignedAttrs.len;
    {
        const std::vector<unsigned char> oidTime = oidBody(OID_ATTR_SIGNING_TIME);
        const std::vector<unsigned char> oidMd = oidBody(OID_ATTR_MSG_DIGEST);
        const std::vector<unsigned char> oidEss = oidBody(OID_ATTR_SIGNING_CERT_V2);
        const std::vector<unsigned char> oidCt = oidBody(OID_ATTR_CONTENT_TYPE);
        const unsigned char *v = nullptr;
        std::size_t vl = 0;
        if (findSignedAttr(buf, n, attrsSetOff, attrsSetLen, oidCt, v, vl)) {
            Tlv t;
            if (readTlv(buf, n, v - buf, t) && t.tag == 0x06)
                out.contentTypeOid = oidToDots(t.data, t.len);
        }
        if (findSignedAttr(buf, n, attrsSetOff, attrsSetLen, oidTime, v, vl)) {
            Tlv t;
            if (readTlv(buf, n, v - buf, t)) {
                out.signingTime = parseAsn1Time(t.tag, t.data, t.len);
                out.hasSigningTime = out.signingTime > 0;
            }
        }
        if (findSignedAttr(buf, n, attrsSetOff, attrsSetLen, oidMd, v, vl)) {
            Tlv t;
            if (readTlv(buf, n, v - buf, t) && t.tag == 0x04)
                out.msgDigestAttr.assign(t.data, t.data + t.len);
        }
        if (findSignedAttr(buf, n, attrsSetOff, attrsSetLen, oidEss, v, vl)) {
            // The first element of the values SET carries the ESSCertID.
            // Accepted shapes (first TLV of the values SET):
            //  - RFC 5652: SEQUENCE (ESSCertIDv2)
            //  - some older tools: OCTET STRING { SEQUENCE { SEQUENCE { ESSCertIDv2 } } }
            //  - InfoCert-style: extra SEQUENCE wrappers around a v1 ESSCertID
            auto assignSerial = [&out](const Tlv &sn) {
                const unsigned char *s = sn.data;
                std::size_t sl = sn.len;
                while (sl > 1 && s[0] == 0) {
                    ++s;
                    --sl;
                }
                out.essSerial.assign(s, s + sl);
            };
            // Parses an ESSCertID at (p, len): either the RFC 5652 v2 form
            // SEQUENCE { CertificateHash, [1] IssuerSerial } (certificateHash a
            // BIT STRING, or an OCTET STRING in legacy non-compliant output) or
            // the v1 form SEQUENCE { OCTET STRING hash, SEQUENCE { GeneralNames,
            // INTEGER } } with the issuer name in a [4] field (explicit or
            // implicit).
            auto parseEss = [&out, &assignSerial](const unsigned char *p,
                                                  std::size_t len) -> bool {
                Tlv certHash;
                if (!readTlv(p, len, 0, certHash))
                    return false;
                if (certHash.tag == 0x30) {
                    // RFC 5652: CertificateHash ::= SEQUENCE { algId, certificateHash }
                    Tlv algId, h, issWrap, issSer, name, sn;
                    if (!readTlv(certHash.data, certHash.len, 0, algId) ||
                        algId.tag != 0x30 ||
                        !readTlv(certHash.data, certHash.len, algId.next, h) ||
                        (h.tag != 0x03 && h.tag != 0x04) ||
                        (h.tag == 0x03 && h.len < 1))
                        return false;
                    if (h.tag == 0x03) // BIT STRING: skip the unused-bits byte
                        out.essCertHash.assign(h.data + 1, h.data + h.len);
                    else
                        out.essCertHash.assign(h.data, h.data + h.len);
                    // IssuerSerial: [1] EXPLICIT (RFC 5652) or bare SEQUENCE
                    if (!readTlv(p, len, certHash.next, issSer) || issSer.tag != 0x30) {
                        if (!readTlv(p, len, certHash.next, issWrap) ||
                            issWrap.tag != 0xA1 ||
                            !readTlv(issWrap.data, issWrap.len, 0, issSer) ||
                            issSer.tag != 0x30)
                            return false;
                    }
                    // IssuerSerial ::= SEQUENCE { name Name, serialNumber INTEGER }
                    if (!readTlv(issSer.data, issSer.len, 0, name) || name.tag != 0x30 ||
                        !readTlv(issSer.data, issSer.len, name.next, sn) || sn.tag != 0x02)
                        return false;
                    // full Name TLV; name is the first field of issSer
                    out.essIssuerDer.assign(issSer.data, name.data + name.len);
                    assignSerial(sn);
                    return true;
                }
                if (certHash.tag != 0x04)
                    return false;
                // v1 ESSCertID (asn1crypto / InfoCert):
                // SEQUENCE { OCTET STRING hash, SEQUENCE { GeneralNames, INTEGER } }
                out.essCertHash.assign(certHash.data, certHash.data + certHash.len);
                Tlv issSer, gn, a4, sn;
                if (!readTlv(p, len, certHash.next, issSer) || issSer.tag != 0x30 ||
                    !readTlv(issSer.data, issSer.len, 0, gn) ||
                    (gn.tag != 0x30 && gn.tag != 0x31) ||
                    !readTlv(gn.data, gn.len, 0, a4) || a4.tag != 0xA4 ||
                    !readTlv(issSer.data, issSer.len, gn.next, sn) || sn.tag != 0x02)
                    return false;
                // [4] carries the issuer Name: usually its raw content (implicit
                // tagging), but InfoCert writes the full Name TLV (explicit)
                Bytes nameTlv(a4.data, a4.data + a4.len);
                if (nameTlv.empty() || nameTlv.front() != 0x30)
                    nameTlv = der::tlv(0x30, nameTlv);
                out.essIssuerDer = nameTlv;
                assignSerial(sn);
                return true;
            };

            Tlv t, scv2, certsSeq;
            if (readTlv(buf, n, v - buf, t)) {
                if (t.tag == 0x30) {
                    if (!parseEss(t.data, t.len)) {
                        // InfoCert-style extra wrappers: SEQUENCE { SEQUENCE { ... } }
                        Tlv w1, w2;
                        if (readTlv(t.data, t.len, 0, w1) && w1.tag == 0x30 &&
                            readTlv(w1.data, w1.len, 0, w2) && w2.tag == 0x30)
                            parseEss(w2.data, w2.len);
                    }
                } else if (t.tag == 0x04 && readTlv(t.data, t.len, 0, scv2) &&
                           scv2.tag == 0x30 &&
                           readTlv(scv2.data, scv2.len, 0, certsSeq) &&
                           certsSeq.tag == 0x30 &&
                           readTlv(certsSeq.data, certsSeq.len, 0, t) && t.tag == 0x30) {
                    parseEss(t.data, t.len);
                }
            }
        }
    }

    out.ok = true;
    return true;
}

} // namespace

bool P7M::signFile(const std::string &inputPath, const std::string &outputPath,
                   const std::vector<unsigned char> &signerCertDer,
                   const SignFunction &sign, std::string *error)
{
    FILE *f = std::fopen(inputPath.c_str(), "rb");
    if (!f) {
        if (error)
            *error = "impossibile leggere il file di input";
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> content(static_cast<std::size_t>(size));
    if (size > 0 && std::fread(content.data(), 1, content.size(), f) != content.size()) {
        std::fclose(f);
        if (error)
            *error = "errore di lettura del file di input";
        return false;
    }
    std::fclose(f);

    CmsConfig cfg;
    cfg.signerCertDer = signerCertDer;
    cfg.content = content;
    cfg.detached = false;
    cfg.contentTypeOid = "1.2.840.113549.1.7.1"; // data

    std::string err;
    const Bytes signedAttrs = CmsSigner::buildSignedAttrs(cfg, &err);
    if (signedAttrs.empty()) {
        if (error)
            *error = err;
        return false;
    }
    std::vector<unsigned char> signature;
    if (!sign(signedAttrs, signature, err)) {
        if (error)
            *error = err;
        return false;
    }
    const Bytes derOut = CmsSigner::assemble(cfg, signedAttrs, signature, &err);
    if (derOut.empty()) {
        if (error)
            *error = err;
        return false;
    }
    FILE *out = std::fopen(outputPath.c_str(), "wb");
    if (!out) {
        if (error)
            *error = "impossibile scrivere il file di output";
        return false;
    }
    const bool ok =
        derOut.empty() ||
        std::fwrite(derOut.data(), 1, derOut.size(), out) == derOut.size();
    std::fclose(out);
    if (!ok && error)
        *error = "errore di scrittura del file di output";
    return ok;
}

P7MResult P7M::verifyParsed(const ParsedCms &cms,
                            const std::vector<const X509Cert *> &anchors,
                            std::time_t now)
{
    P7MResult r;

    // locate the signer certificate in the embedded set by sid (issuer+serial)
    const X509Cert *signer = nullptr;
    std::vector<const X509Cert *> untrusted;
    std::vector<std::unique_ptr<X509Cert>> parsed;
    parsed.reserve(cms.embeddedCerts.size());
    for (const auto &c : cms.embeddedCerts) {
        auto x = X509Cert::fromDer(c);
        if (!x)
            continue;
        if (!signer && x->issuerNameDer == cms.sidIssuerDer &&
            x->serialRaw == cms.sidSerial)
            signer = x.get();
        parsed.push_back(std::move(x));
    }
    r.embeddedCerts = static_cast<int>(parsed.size());
    if (!signer) {
        r.error = "certificato del firmatario non trovato nei certificati incorporati";
        return r;
    }
    r.signerSubject = signer->subject;
    r.signerIssuer = signer->issuer;
    r.signerSerial = signer->serialHex;
    r.signerCertDer = signer->der;
    r.signingTime = cms.hasSigningTime ? formatTime(cms.signingTime) : "";
    for (const auto &x : parsed)
        if (x.get() != signer)
            untrusted.push_back(x.get());

    auto sha256raw = [](const void *data, size_t len, unsigned char out[32]) {
        unsigned int l = 0;
        return EVP_Digest(static_cast<const unsigned char *>(data), len, out, &l,
                          EVP_sha256(), nullptr) == 1 &&
               l == 32;
    };

    // 1) RSA signature over the signedAttrs
    {
        const unsigned char *sp = signer->der.data();
        X509 *sx = d2i_X509(nullptr, &sp, static_cast<long>(signer->der.size()));
        bool sigOk = false;
        if (sx) {
            EVP_PKEY *pkey = X509_get_pubkey(sx);
            if (pkey) {
                auto verify = [&](const std::vector<unsigned char> &bytes) {
                    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                    if (!mdctx ||
                        EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr,
                                             pkey) != 1)
                        return false;
                    const bool ok = EVP_DigestVerify(mdctx, cms.signature.data(),
                                                     cms.signature.size(), bytes.data(),
                                                     bytes.size()) == 1;
                    EVP_MD_CTX_free(mdctx);
                    return ok;
                };
                // RFC 5652 5.3: the signature is computed over the plain
                // SET OF (0x31) form, while the document stores the
                // [0] IMPLICIT (0xA0) form (same length)
                std::vector<unsigned char> canonical = cms.signedAttrsTlv;
                if (!canonical.empty() && canonical.front() == 0xA0)
                    canonical.front() = 0x31;
                sigOk = verify(canonical);
                if (!sigOk)
                    sigOk = verify(cms.signedAttrsTlv); // tolerate nonstandard
                EVP_PKEY_free(pkey);
            }
            X509_free(sx);
        }
        if (!sigOk) {
            r.error = "firma RSA non valida sugli attributi firmati";
            return r;
        }
    }

    // 2) message digest of the content
    if (!cms.msgDigestAttr.empty() && !cms.content.empty()) {
        unsigned char md[32];
        if (cms.msgDigestAttr.size() != 32 ||
            !sha256raw(cms.content.data(), cms.content.size(), md) ||
            std::memcmp(md, cms.msgDigestAttr.data(), 32) != 0) {
            r.error = "digest del contenuto non corrispondente (messageDigest)";
            return r;
        }
    }

    // 3) ESSCertIDv2 (signing_certificate_v2) consistency
    if (!cms.essCertHash.empty()) {
        unsigned char md[32];
        if (cms.essCertHash.size() != 32 ||
            !sha256raw(signer->der.data(), signer->der.size(), md) ||
            std::memcmp(md, cms.essCertHash.data(), 32) != 0 ||
            signer->issuerNameDer != cms.essIssuerDer ||
            signer->serialRaw != cms.essSerial) {
            r.error = "attributo signing_certificate_v2 non coerente con il certificato";
            return r;
        }
    }

    // 4) chain against the TSL anchors
    ChainResult chain = X509Util::validateChain(*signer, untrusted, anchors,
                                                now ? now : std::time(nullptr));
    if (!chain.ok && cms.hasSigningTime) {
        // retry at signing time: the signature may still be "valid when made"
        ChainResult atSigning =
            X509Util::validateChain(*signer, untrusted, anchors, cms.signingTime);
        if (atSigning.ok) {
            r.validAtSigningTimeOnly = true;
            chain = atSigning;
        }
    }
    if (!chain.ok) {
        r.error = "catena certificati non valida: " + chain.error;
        return r;
    }
    r.anchorSubject = chain.anchorSubject;
    r.content = cms.content;
    r.ok = true;
    return r;
}

P7MResult P7M::decodeAndVerify(const std::vector<unsigned char> &p7m,
                               const std::vector<const X509Cert *> &anchors,
                               std::time_t now)
{
    ParsedCms cms;
    if (!parseCms(p7m, cms, nullptr)) {
        P7MResult r;
        r.error = cms.error;
        return r;
    }
    return verifyParsed(cms, anchors, now);
}

P7MResult P7M::verifyDetached(const std::vector<unsigned char> &cmsDer,
                              const std::vector<unsigned char> &content,
                              const std::vector<const X509Cert *> &anchors,
                              std::time_t now)
{
    ParsedCms cms;
    if (!parseCms(cmsDer, cms, nullptr)) {
        P7MResult r;
        r.error = cms.error;
        return r;
    }
    if (!cms.detached) {
        P7MResult r;
        r.error = "il contenuto non e' detached (atteso per PAdES)";
        return r;
    }
    cms.content = content;
    return verifyParsed(cms, anchors, now);
}

} // namespace fdo
