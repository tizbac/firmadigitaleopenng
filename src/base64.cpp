#include "base64.h"

#include <array>

namespace fdo {
namespace {

constexpr char kEnc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const std::array<int, 256> &decTable()
{
    static const std::array<int, 256> t = [] {
        std::array<int, 256> t{};
        t.fill(-1);
        for (int i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(kEnc[i])] = i;
        return t;
    }();
    return t;
}

} // namespace

std::string base64Encode(const unsigned char *data, size_t len)
{
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        const unsigned v = (static_cast<unsigned>(data[i]) << 16) |
                           (static_cast<unsigned>(data[i + 1]) << 8) |
                           static_cast<unsigned>(data[i + 2]);
        out += kEnc[(v >> 18) & 63];
        out += kEnc[(v >> 12) & 63];
        out += kEnc[(v >> 6) & 63];
        out += kEnc[v & 63];
        i += 3;
    }
    if (len - i == 1) {
        const unsigned v = static_cast<unsigned>(data[i]) << 16;
        out += kEnc[(v >> 18) & 63];
        out += kEnc[(v >> 12) & 63];
        out += "==";
    } else if (len - i == 2) {
        const unsigned v = (static_cast<unsigned>(data[i]) << 16) |
                           (static_cast<unsigned>(data[i + 1]) << 8);
        out += kEnc[(v >> 18) & 63];
        out += kEnc[(v >> 12) & 63];
        out += kEnc[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

std::vector<unsigned char> base64Decode(const std::string &in)
{
    const auto &t = decTable();
    std::vector<unsigned char> out;
    int val = 0;
    int bits = -8;
    for (const char ch : in) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == '=')
            break;
        const int d = t[c];
        if (d < 0)
            continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<unsigned char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

} // namespace fdo
