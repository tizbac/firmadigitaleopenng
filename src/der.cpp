#include "der.h"

#include <cstdio>
#include <cstring>

namespace fdo {
namespace der {

Bytes operator+(Bytes a, const Bytes &b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

Bytes &operator+=(Bytes &a, const Bytes &b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

void writeLen(Bytes &out, std::uint64_t len)
{
    if (len < 0x80) {
        out.push_back(static_cast<unsigned char>(len));
        return;
    }
    Bytes body;
    while (len > 0) {
        body.insert(body.begin(), static_cast<unsigned char>(len & 0xFF));
        len >>= 8;
    }
    out.push_back(static_cast<unsigned char>(0x80 | body.size()));
    out.insert(out.end(), body.begin(), body.end());
}

Bytes tlv(std::uint8_t tag, const Bytes &content)
{
    Bytes out(1, tag);
    writeLen(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

Bytes seq(const Bytes &content) { return tlv(0x30, content); }
Bytes setOf(const Bytes &content) { return tlv(0x31, content); }

Bytes oid(const std::string &dot)
{
    std::vector<std::uint64_t> comps;
    std::string cur;
    auto push = [&] {
        if (cur.empty())
            return;
        std::uint64_t v = 0;
        for (char c : cur)
            v = v * 10 + static_cast<unsigned>(c - '0');
        comps.push_back(v);
        cur.clear();
    };
    for (char c : dot) {
        if (c == '.')
            push();
        else
            cur += c;
    }
    push();
    if (comps.size() < 2)
        return {};

    Bytes body;
    body.push_back(static_cast<unsigned char>(comps[0] * 40 + comps[1]));
    for (std::size_t i = 2; i < comps.size(); ++i) {
        std::uint64_t v = comps[i];
        Bytes parts;
        parts.push_back(static_cast<unsigned char>(v & 0x7F));
        v >>= 7;
        while (v > 0) {
            parts.insert(parts.begin(), static_cast<unsigned char>((v & 0x7F) | 0x80));
            v >>= 7;
        }
        body.insert(body.end(), parts.begin(), parts.end());
    }
    return tlv(0x06, body);
}

Bytes octetString(const void *data, std::size_t len)
{
    return tlv(0x04, Bytes(static_cast<const unsigned char *>(data),
                           static_cast<const unsigned char *>(data) + len));
}

Bytes octetString(const Bytes &b) { return tlv(0x04, b); }

Bytes integer(std::uint64_t v)
{
    Bytes body;
    if (v == 0) {
        body.push_back(0);
        return tlv(0x02, body);
    }
    while (v > 0) {
        body.insert(body.begin(), static_cast<unsigned char>(v & 0xFF));
        v >>= 8;
    }
    if (body.front() & 0x80)
        body.insert(body.begin(), 0);
    return tlv(0x02, body);
}

Bytes integerBigEndian(const unsigned char *data, std::size_t len)
{
    if (len == 0)
        len = 1; // zero
    Bytes body(data, data + len);
    if (body.front() & 0x80)
        body.insert(body.begin(), 0);
    return tlv(0x02, body);
}

Bytes bitString(const Bytes &bits)
{
    Bytes body;
    body.push_back(0); // no unused bits
    body.insert(body.end(), bits.begin(), bits.end());
    return tlv(0x03, body);
}

Bytes nullValue() { return tlv(0x05, {}); }

Bytes utcTime(std::time_t t)
{
    std::tm tmUtc{};
#if defined(_WIN32)
    gmtime_s(&tmUtc, &t);
#else
    gmtime_r(&t, &tmUtc);
#endif
    char buf[32];
    if (tmUtc.tm_year + 1900 >= 2050) {
        std::snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ", tmUtc.tm_year + 1900,
                      tmUtc.tm_mon + 1, tmUtc.tm_mday, tmUtc.tm_hour, tmUtc.tm_min,
                      tmUtc.tm_sec);
        return tlv(0x18, Bytes(buf, buf + std::strlen(buf))); // GeneralizedTime
    }
    std::snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ", tmUtc.tm_year % 100,
                  tmUtc.tm_mon + 1, tmUtc.tm_mday, tmUtc.tm_hour, tmUtc.tm_min,
                  tmUtc.tm_sec);
    return tlv(0x17, Bytes(buf, buf + std::strlen(buf))); // UTCTime
}

Bytes explicitTag(std::uint8_t n, const Bytes &innerTlv)
{
    return tlv(static_cast<unsigned char>(0xA0 | (n & 0x1F)), innerTlv);
}

Bytes implicitTag(std::uint8_t n, const Bytes &innerTlv)
{
    // Re-tag the whole TLV: [n] IMPLICIT
    Bytes body(innerTlv);
    // strip the existing tag+length, keep content
    std::size_t i = 1;
    if (body[i] & 0x80) {
        const std::size_t nBytes = body[i] & 0x7F;
        i = 2 + nBytes;
    } else {
        i = 2;
    }
    const Bytes content(body.begin() + i, body.end());
    return tlv(static_cast<unsigned char>(0xA0 | (n & 0x1F)), content);
}

Bytes ia5String(const std::string &s) { return tlv(0x16, Bytes(s.begin(), s.end())); }

} // namespace der
} // namespace fdo
