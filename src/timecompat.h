#pragma once

#include <ctime>

namespace fdo {

// Thread-safe gmtime/localtime and UTC-to-time_t conversion.
// The ISO C functions are POSIX-only, so map them to the MSVC equivalents
// when building for Windows (MinGW).
inline std::tm *gmtimeSafe(const std::time_t &t, std::tm &out)
{
#if defined(_WIN32)
    return gmtime_s(&out, &t) == 0 ? &out : nullptr;
#else
    return gmtime_r(&t, &out);
#endif
}

inline std::tm *localtimeSafe(const std::time_t &t, std::tm &out)
{
#if defined(_WIN32)
    return localtime_s(&out, &t) == 0 ? &out : nullptr;
#else
    return localtime_r(&t, &out);
#endif
}

// time_t from a UTC struct tm (POSIX timegm / Windows _mkgmtime).
inline std::time_t timegmSafe(std::tm &tm)
{
#if defined(_WIN32)
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

} // namespace fdo
