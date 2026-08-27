#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace fdo {
namespace der {

using Bytes = std::vector<unsigned char>;

Bytes operator+(Bytes a, const Bytes &b);
Bytes &operator+=(Bytes &a, const Bytes &b);

void writeLen(Bytes &out, std::uint64_t len);
Bytes tlv(std::uint8_t tag, const Bytes &content);
Bytes seq(const Bytes &content);
Bytes setOf(const Bytes &content);
Bytes oid(const std::string &dotNotation);
Bytes octetString(const void *data, std::size_t len);
Bytes octetString(const Bytes &b);
Bytes integer(std::uint64_t v);
Bytes integerBigEndian(const unsigned char *data, std::size_t len);
Bytes bitString(const Bytes &bits);
Bytes nullValue();
Bytes utcTime(std::time_t t); // UTCTime, or GeneralizedTime for >= 2050
Bytes explicitTag(std::uint8_t n, const Bytes &innerTlv);
Bytes implicitTag(std::uint8_t n, const Bytes &innerTlv);
Bytes ia5String(const std::string &s);

} // namespace der
} // namespace fdo
