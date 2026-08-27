#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace fdo {

std::string base64Encode(const unsigned char *data, size_t len);
inline std::string base64Encode(const std::string &data)
{
    return base64Encode(reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

// Lenient: ignores whitespace and any non-base64 character.
std::vector<unsigned char> base64Decode(const std::string &in);

} // namespace fdo
