#include "pkcs11.h"
#include "x509util.h"
#include "timecompat.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <fstream>

#include <openssl/x509.h>

namespace fdo {

using namespace p11;

namespace {

// Thin portable dynamic-library loader: dlopen/dlsym on POSIX, LoadLibraryW/
// GetProcAddress on Windows. Paths are UTF-8 on both platforms.
#ifdef _WIN32
std::wstring utf8ToWide(const std::string &s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                      nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

void *openLibrary(const std::string &path, std::string *error)
{
    const std::wstring wide = utf8ToWide(path);
    HMODULE handle = LoadLibraryW(wide.c_str());
    if (!handle && error) {
        const DWORD code = GetLastError();
        char *msg = nullptr;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, code, 0, reinterpret_cast<char *>(&msg), 0, nullptr);
        std::string text = msg ? msg : "unknown error";
        LocalFree(msg);
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
            text.pop_back();
        *error = "LoadLibrary: " + text;
    }
    return handle;
}

void *librarySymbol(void *handle, const char *name)
{
    return reinterpret_cast<void *>(
        GetProcAddress(static_cast<HMODULE>(handle), name));
}

void closeLibrary(void *handle)
{
    if (handle)
        FreeLibrary(static_cast<HMODULE>(handle));
}
#else
void *openLibrary(const std::string &path, std::string *error)
{
    void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle && error)
        *error = std::string("dlopen: ") + dlerror();
    return handle;
}

void *librarySymbol(void *handle, const char *name)
{
    return dlsym(handle, name);
}

void closeLibrary(void *handle)
{
#ifdef _WIN32
    // Bit4id's module starts a certificate-store notification thread when a
    // card is present. Unloading it (DLL_PROCESS_DETACH) while that thread is
    // alive crashes inside the module. Keep the DLL mapped for the process
    // lifetime; Windows releases it at exit. C_Finalize is still called.
    (void)handle;
#else
    if (handle)
        dlclose(handle);
#endif
}
#endif

// PKCS#11 string fields are blank-padded, not necessarily NUL-terminated.
std::string fixedString(const char *p, std::size_t n)
{
    std::size_t len = 0;
    while (len < n && p[len] != '\0')
        ++len;
    while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t' || p[len - 1] == '\r' ||
                       p[len - 1] == '\n'))
        --len;
    return std::string(p, len);
}

// Optional call trace for diagnosing crashes inside a vendor PKCS#11 module.
// Enable with FDO_PKCS11_TRACE=1; the log goes to %TEMP%\fdo-pkcs11.log
// (Windows) or $TMPDIR/fdo-pkcs11.log (POSIX). Each line is flushed.
void tracePkcs11(const char *fmt, ...)
{
    if (!std::getenv("FDO_PKCS11_TRACE"))
        return;
#ifdef _WIN32
    const char *dir = std::getenv("TEMP");
    const char *sep = "\\";
#else
    const char *dir = std::getenv("TMPDIR");
    const char *sep = "/";
#endif
    std::string path = (dir && *dir) ? dir : ".";
    path += sep;
    path += "fdo-pkcs11.log";
    FILE *f = std::fopen(path.c_str(), "a");
    if (!f)
        return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(f, fmt, ap);
    va_end(ap);
    std::fputc('\n', f);
    std::fclose(f);
}

// Renewed Bit4id tokens move the signing certificate/key from DS3 to DS4,
// DS5, ... Accept any "DS<digit>" CKA_ID instead of only DS3.
bool isDsId(const std::vector<unsigned char> &id)
{
    return id.size() == 3 && id[0] == 'D' && id[1] == 'S' && id[2] >= '0' &&
           id[2] <= '9';
}

std::string idDisplay(const std::vector<unsigned char> &id)
{
    if (id.empty())
        return {};
    bool printable = true;
    for (unsigned char c : id) {
        if (c < 0x20 || c > 0x7e) {
            printable = false;
            break;
        }
    }
    if (printable)
        return std::string(id.begin(), id.end());
    std::string out;
    char buf[4];
    for (unsigned char c : id) {
        std::snprintf(buf, sizeof(buf), "%02X", c);
        out += buf;
    }
    return out;
}

struct CertMetadata
{
    bool ok = false;
    std::string subject;
    std::string givenName;
    std::string surname;
    std::string serialHex;
    std::string keyId;
    bool keyIdIsDs = false;
    std::string notAfter;
    std::time_t notAfterEpoch = 0;
    bool expired = false;
};

CertMetadata certMetadata(const std::vector<unsigned char> &der,
                          const std::vector<unsigned char> &id)
{
    CertMetadata m;
    m.keyId = idDisplay(id);
    m.keyIdIsDs = isDsId(id);
    if (der.empty())
        return m;
    const unsigned char *p = der.data();
    X509 *x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (!x)
        return m;

    char *sub = X509_NAME_oneline(X509_get_subject_name(x), nullptr, 0);
    if (sub) {
        m.subject = sub;
        OPENSSL_free(sub);
    }
    char buf[1024];
    int n = X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_givenName, buf,
                                      sizeof(buf));
    if (n > 0)
        m.givenName.assign(buf, static_cast<size_t>(n));
    n = X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_surname, buf,
                                  sizeof(buf));
    if (n > 0)
        m.surname.assign(buf, static_cast<size_t>(n));
    BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), nullptr);
    if (bn) {
        char *h = BN_bn2hex(bn);
        if (h) {
            m.serialHex = h;
            OPENSSL_free(h);
        }
        BN_free(bn);
    }

    const ASN1_TIME *na = X509_get0_notAfter(x);
    if (na) {
        m.expired = X509_cmp_current_time(na) < 0;
        std::tm tm{};
        if (ASN1_TIME_to_tm(na, &tm) == 1) {
            m.notAfterEpoch = timegmSafe(tm);
            char tbuf[40];
            std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S UTC", &tm);
            m.notAfter = tbuf;
        }
    }
    X509_free(x);
    m.ok = true;
    return m;
}

// Higher score wins: a DSx certificate is preferred, then a currently valid
// one, then the latest expiry.
int certScore(const CertMetadata &m)
{
    return (m.keyIdIsDs ? 4 : 0) + (!m.expired ? 2 : 0);
}

bool certBetter(const CertMetadata &a, const CertMetadata &b)
{
    const int sa = certScore(a);
    const int sb = certScore(b);
    if (sa != sb)
        return sa > sb;
    return a.notAfterEpoch > b.notAfterEpoch;
}

} // namespace

bool loadFnTable(FnTable &t, const std::string &path, std::string *error)
{
    t.handle = openLibrary(path, error);
    if (!t.handle) {
        return false;
    }
#ifdef _WIN32
    // Bit4id's Windows x64 build packs PKCS#11 structs to 4 bytes: its Lua
    // bridge walks CK_ATTRIBUTE arrays with a 16-byte stride and reads pValue
    // at +4 / ulValueLen at +12. Native 24-byte structs make it dereference
    // padding as a pointer, which crashes deeper in the module.
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    t.packedAbi = lower.find("bit4") != std::string::npos;
    if (const char *packed = std::getenv("FDO_PKCS11_PACKED_ABI"))
        t.packedAbi = std::strcmp(packed, "0") != 0;
    tracePkcs11("loadFnTable: %s packedAbi=%d", path.c_str(), t.packedAbi ? 1 : 0);
#endif
    auto sym = [&](const char *name) { return librarySymbol(t.handle, name); };
    t.C_Initialize = reinterpret_cast<C_Initialize_t>(sym("C_Initialize"));
    t.C_Finalize = reinterpret_cast<C_Finalize_t>(sym("C_Finalize"));
    t.C_GetSlotList = reinterpret_cast<C_GetSlotList_t>(sym("C_GetSlotList"));
    t.C_GetSlotInfo = reinterpret_cast<C_GetSlotInfo_t>(sym("C_GetSlotInfo"));
    t.C_GetTokenInfo = reinterpret_cast<C_GetTokenInfo_t>(sym("C_GetTokenInfo"));
    t.C_OpenSession = reinterpret_cast<C_OpenSession_t>(sym("C_OpenSession"));
    t.C_CloseSession = reinterpret_cast<C_CloseSession_t>(sym("C_CloseSession"));
    t.C_Login = reinterpret_cast<C_Login_t>(sym("C_Login"));
    t.C_FindObjectsInit = reinterpret_cast<C_FindObjectsInit_t>(sym("C_FindObjectsInit"));
    t.C_FindObjects = reinterpret_cast<C_FindObjects_t>(sym("C_FindObjects"));
    t.C_FindObjectsFinal = reinterpret_cast<C_FindObjectsFinal_t>(sym("C_FindObjectsFinal"));
    t.C_GetAttributeValue =
        reinterpret_cast<C_GetAttributeValue_t>(sym("C_GetAttributeValue"));
    t.C_SignInit = reinterpret_cast<C_SignInit_t>(sym("C_SignInit"));
    t.C_Sign = reinterpret_cast<C_Sign_t>(sym("C_Sign"));
    if (!t.C_Initialize || !t.C_GetSlotList || !t.C_OpenSession || !t.C_Login ||
        !t.C_FindObjectsInit || !t.C_FindObjects || !t.C_GetAttributeValue ||
        !t.C_SignInit || !t.C_Sign) {
        if (error)
            *error = "PKCS#11 library is missing required C_* functions";
        closeLibrary(t.handle);
        t.handle = nullptr;
        return false;
    }
    return true;
}


Pkcs11::~Pkcs11()
{
    close();
}

void Pkcs11::close()
{
    if (m_sessionOpen && m_fn) {
        m_fn->C_CloseSession(m_session);
        m_sessionOpen = false;
    }
    if (m_fn) {
#ifndef _WIN32
        m_fn->C_Finalize(nullptr);
#endif
        if (m_fn->handle)
            closeLibrary(m_fn->handle);
        m_fn.reset();
    }
    m_signer.reset();
    m_keyHandle = 0;
}

bool Pkcs11::loadLibrary(const std::string &libPath, std::string *error)
{
    close();
    m_fn = std::make_unique<FnTable>();
    if (!loadFnTable(*m_fn, libPath, error)) {
        m_fn.reset();
        return false;
    }
    tracePkcs11("Pkcs11::C_Initialize");
    const CK_RV rv = m_fn->C_Initialize(nullptr);
    tracePkcs11("Pkcs11::C_Initialize -> 0x%lx", static_cast<unsigned long>(rv));
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        if (error)
            *error = std::string("C_Initialize failed: ") + rvName(rv);
        if (m_fn->handle)
            closeLibrary(m_fn->handle);
        m_fn.reset();
        return false;
    }
    return true;
}

bool Pkcs11::login(unsigned long slotIndex, const std::string &pin, std::string *error)
{
    if (!m_fn) {
        if (error)
            *error = "library not loaded";
        return false;
    }
    CK_SESSION_HANDLE session = 0;
    CK_RV rv = m_fn->C_OpenSession(slotIndex,
                                   CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                   &session);
    if (rv != CKR_OK) {
        if (error)
            *error = std::string("C_OpenSession failed: ") + rvName(rv);
        return false;
    }
    rv = m_fn->C_Login(session, CKU_USER,
                       const_cast<CK_UTF8CHAR_PTR>(pin.data()),
                       static_cast<CK_ULONG>(pin.size()));
    if (rv != CKR_OK) {
        if (error) {
            *error = rv == CKR_PIN_INCORRECT
                         ? "PIN errata"
                         : std::string("C_Login failed: ") + rvName(rv);
        }
        m_fn->C_CloseSession(session);
        return false;
    }
    m_slotIndex = slotIndex;
    m_session = session;
    m_sessionOpen = true;
    return true;
}

bool Pkcs11::findSigner(std::string *error)
{
    if (!m_sessionOpen || !m_fn) {
        if (error)
            *error = "not logged in";
        return false;
    }

    struct KeyObj
    {
        CK_OBJECT_HANDLE handle = 0;
        std::vector<unsigned char> id;
        std::string label;
    };
    struct CertObj
    {
        CK_OBJECT_HANDLE handle = 0;
        std::vector<unsigned char> id;
        std::vector<unsigned char> der;
        CertMetadata meta;
    };
    std::vector<KeyObj> keys;
    std::vector<CertObj> certs;

    // Enumerate every object on the token (a NULL template matches all
    // objects) and match class + CKA_ID on the host side, instead of relying
    // on the module's template filtering.
    if (m_fn->C_FindObjectsInit(m_session, nullptr, 0) != CKR_OK) {
        if (error)
            *error = "C_FindObjectsInit failed";
        return false;
    }
    for (;;) {
        CK_OBJECT_HANDLE batch[64];
        CK_ULONG found = 0;
        const CK_RV rv = m_fn->C_FindObjects(m_session, batch, 64, &found);
        if (rv != CKR_OK) {
            if (m_fn->C_FindObjectsFinal)
                m_fn->C_FindObjectsFinal(m_session);
            if (error)
                *error = std::string("C_FindObjects failed: ") + rvName(rv);
            return false;
        }
        for (CK_ULONG i = 0; i < found; ++i) {
            const CK_OBJECT_HANDLE obj = batch[i];
            std::vector<unsigned char> clsBytes;
            CK_ULONG cls = 0;
            if (getAttr(*m_fn, m_session, obj, CKA_CLASS, clsBytes))
                for (size_t b = 0; b < clsBytes.size() && b < sizeof(cls); ++b)
                    cls |= CK_ULONG(clsBytes[b]) << (8 * b);
            std::vector<unsigned char> id;
            getAttr(*m_fn, m_session, obj, CKA_ID, id);
            if (cls == CKO_PRIVATE_KEY) {
                KeyObj k;
                k.handle = obj;
                k.id = std::move(id);
                std::vector<unsigned char> label;
                if (getAttr(*m_fn, m_session, obj, CKA_LABEL, label))
                    k.label.assign(reinterpret_cast<const char *>(label.data()),
                                   label.size());
                keys.push_back(std::move(k));
            } else if (cls == CKO_CERTIFICATE) {
                CertObj c;
                c.handle = obj;
                c.id = std::move(id);
                if (!getAttr(*m_fn, m_session, obj, CKA_VALUE, c.der) || c.der.empty())
                    continue;
                c.meta = certMetadata(c.der, c.id);
                certs.push_back(std::move(c));
            }
        }
        if (found < 64)
            break;
    }
    if (m_fn->C_FindObjectsFinal)
        m_fn->C_FindObjectsFinal(m_session);

    // Prefer a key/certificate pair with the same CKA_ID, then a DSx pair,
    // then a currently-valid certificate, then the latest expiry. This keeps
    // working after a renewal moves the signature identity from DS3 to DS4,
    // DS5, ...
    const KeyObj *bestKey = nullptr;
    const CertObj *bestCert = nullptr;
    for (const KeyObj &k : keys) {
        for (const CertObj &c : certs) {
            const bool sameId = !k.id.empty() && !c.id.empty() && k.id == c.id;
            const bool bothUnknown = k.id.empty() && c.id.empty();
            if (!sameId && !bothUnknown)
                continue;
            if (!bestCert || certBetter(c.meta, bestCert->meta)) {
                bestKey = &k;
                bestCert = &c;
            }
        }
    }
    if (!bestCert || !bestKey) {
        // Fallback for modules that do not expose CKA_ID at all (SoftHSM):
        // use the best certificate and the first private key.
        for (const CertObj &c : certs)
            if (!bestCert || certBetter(c.meta, bestCert->meta))
                bestCert = &c;
        if (!keys.empty())
            bestKey = &keys.front();
    }

    if (!bestKey) {
        if (error)
            *error = "chiave privata non trovata sul token";
        return false;
    }
    if (!bestCert) {
        if (error)
            *error = "certificato non trovato sul token";
        return false;
    }

    m_keyHandle = bestKey->handle;
    auto s = Signer{};
    s.certDer = bestCert->der;
    s.keyId = idDisplay(bestKey->id);
    s.keyLabel = bestKey->label;
    s.certNotAfter = bestCert->meta.notAfter;
    s.certExpired = bestCert->meta.expired;
    m_signer = std::move(s);
    return true;
}

bool Pkcs11::sign(const std::vector<unsigned char> &data,
                  std::vector<unsigned char> &out, std::string *error)
{
    if (!m_sessionOpen || !m_fn || !m_signer) {
        if (error)
            *error = "not logged in / no signer";
        return false;
    }
    // SHA256 + RSA PKCS#1 v1.5 signature. The OASIS PKCS#11 spec assigns
    // 0x1051, but some modules (e.g. SoftHSM built against a non-standard
    // p11-kit) encode the same mechanism as 0x40. Try each candidate until
    // C_SignInit accepts one so the layer works across heterogeneous tokens.
    static const CK_ULONG kSha256RsaPkcs[] = { CKM_SHA256_RSA_PKCS, 0x40 };
    CK_RV lastRv = CKR_MECHANISM_INVALID;
    CK_RV rv;
    bool initialised = false;
    for (CK_ULONG cand : kSha256RsaPkcs) {
        CK_MECHANISM nativeMech{ cand, nullptr, 0 };
        CK_MECHANISM_PACKED packedMech{ cand, nullptr, 0 };
        CK_MECHANISM_PTR mechPtr = m_fn->packedAbi
            ? reinterpret_cast<CK_MECHANISM_PTR>(&packedMech)
            : &nativeMech;
        rv = m_fn->C_SignInit(m_session, mechPtr, m_keyHandle);
        if (rv == CKR_OK) {
            initialised = true;
            break;
        }
        lastRv = rv;
        if (rv != CKR_MECHANISM_INVALID)
            break;
    }
    if (!initialised) {
        if (error)
            *error = std::string("C_SignInit failed: ") + rvName(lastRv);
        return false;
    }

    CK_ULONG sigLen = 0;
    rv = m_fn->C_Sign(m_session, const_cast<CK_BYTE_PTR>(data.data()),
                      static_cast<CK_ULONG>(data.size()), nullptr, &sigLen);
    if (rv != CKR_OK) {
        if (error)
            *error = std::string("C_Sign (length probe) failed: ") + rvName(rv);
        return false;
    }
    out.resize(sigLen);
    rv = m_fn->C_Sign(m_session, const_cast<CK_BYTE_PTR>(data.data()),
                      static_cast<CK_ULONG>(data.size()), out.data(), &sigLen);
    if (rv != CKR_OK) {
        if (error)
            *error = std::string("C_Sign failed: ") + rvName(rv);
        return false;
    }
    out.resize(sigLen);
    return true;
}

std::vector<Pkcs11Slot> Pkcs11::enumerateSlots(const std::string &libPath,
                                               std::string *error)
{
    std::vector<Pkcs11Slot> out;
    tracePkcs11("enumerateSlots: lib=%s", libPath.c_str());
    FnTable t;
    if (!loadFnTable(t, libPath, error)) {
        tracePkcs11("enumerateSlots: loadFnTable failed: %s",
                    error ? error->c_str() : "(no error)");
        return out;
    }

    tracePkcs11("C_Initialize");
    CK_RV rv = t.C_Initialize(nullptr);
    tracePkcs11("C_Initialize -> 0x%lx", static_cast<unsigned long>(rv));
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        if (error)
            *error = "C_Initialize failed: " + std::string(rvName(rv));
        closeLibrary(t.handle);
        return out;
    }

    CK_ULONG count = 0;
    tracePkcs11("C_GetSlotList(NULL)");
    rv = t.C_GetSlotList(CK_TRUE, nullptr, &count);
    tracePkcs11("C_GetSlotList(NULL) -> 0x%lx count=%lu",
                static_cast<unsigned long>(rv), static_cast<unsigned long>(count));
    if (rv == CKR_OK && count > 0) {
        std::vector<CK_SLOT_ID> slots(count);
        tracePkcs11("C_GetSlotList(buffer)");
        rv = t.C_GetSlotList(CK_TRUE, slots.data(), &count);
        tracePkcs11("C_GetSlotList(buffer) -> 0x%lx count=%lu",
                    static_cast<unsigned long>(rv),
                    static_cast<unsigned long>(count));
        if (rv == CKR_OK) {
            for (CK_ULONG i = 0; i < count; ++i) {
                Pkcs11Slot s;
                s.index = slots[i];
                tracePkcs11("slot %lu: C_GetSlotInfo",
                            static_cast<unsigned long>(slots[i]));
                CK_SLOT_INFO si{};
                rv = t.C_GetSlotInfo(slots[i], &si);
                if (rv == CKR_OK) {
                    s.slotDescription =
                        fixedString(si.slotDescription, sizeof(si.slotDescription));
                    s.tokenPresent = (si.flags & CKF_TOKEN_PRESENT) != 0;
                }
                tracePkcs11("slot %lu: C_GetSlotInfo -> 0x%lx present=%d desc=%s",
                            static_cast<unsigned long>(slots[i]),
                            static_cast<unsigned long>(rv), s.tokenPresent ? 1 : 0,
                            s.slotDescription.c_str());
                if (!s.tokenPresent)
                    continue;

                // Diagnostic/workaround mode: only use the reader-supplied
                // slot description. Skips C_GetTokenInfo and the whole
                // session/object/certificate probe, which is where vendor
                // modules can crash with some cards.
                if (std::getenv("FDO_PKCS11_MINIMAL")) {
                    s.tokenLabel = s.slotDescription;
                    s.loginRequired = true;
                    tracePkcs11("slot %lu: minimal mode (no token/cert probe)",
                                static_cast<unsigned long>(slots[i]));
                    out.push_back(std::move(s));
                    continue;
                }

                tracePkcs11("slot %lu: C_GetTokenInfo",
                            static_cast<unsigned long>(slots[i]));
                CK_TOKEN_INFO ti{};
                rv = t.C_GetTokenInfo(slots[i], &ti);
                if (rv == CKR_OK) {
                    s.tokenLabel = fixedString(ti.label, sizeof(ti.label));
                    s.loginRequired = (ti.flags & CKF_LOGIN_REQUIRED) != 0;
                }
                tracePkcs11("slot %lu: C_GetTokenInfo -> 0x%lx label=%s",
                            static_cast<unsigned long>(slots[i]),
                            static_cast<unsigned long>(rv), s.tokenLabel.c_str());

                // Best-effort: open a RO session and read the first certificate.
                CK_SESSION_HANDLE session = 0;
                tracePkcs11("slot %lu: C_OpenSession",
                            static_cast<unsigned long>(slots[i]));
                rv = t.C_OpenSession(slots[i], CKF_SERIAL_SESSION, nullptr, nullptr,
                                     &session);
                tracePkcs11("slot %lu: C_OpenSession -> 0x%lx",
                            static_cast<unsigned long>(slots[i]),
                            static_cast<unsigned long>(rv));
                if (rv == CKR_OK) {
                    CK_ULONG cls = CKO_CERTIFICATE;
                    CK_ATTRIBUTE nativeTmpl = { CKA_CLASS, &cls, sizeof(cls) };
                    CK_ATTRIBUTE_PACKED packedTmpl = { CKA_CLASS, &cls, sizeof(cls) };
                    CK_ATTRIBUTE_PTR tmplPtr = t.packedAbi
                        ? reinterpret_cast<CK_ATTRIBUTE_PTR>(&packedTmpl)
                        : &nativeTmpl;
                    CK_OBJECT_HANDLE batch[64];
                    CK_ULONG foundCount = 0;
                    CertMetadata bestMeta;
                    tracePkcs11("C_FindObjectsInit(CKA_CLASS=CKO_CERTIFICATE, packed=%d)",
                                t.packedAbi ? 1 : 0);
                    rv = t.C_FindObjectsInit(session, tmplPtr, 1);
                    tracePkcs11("C_FindObjectsInit -> 0x%lx",
                                static_cast<unsigned long>(rv));
                    const bool findActive = rv == CKR_OK;
                    if (findActive) {
                        for (;;) {
                            tracePkcs11("C_FindObjects");
                            rv = t.C_FindObjects(session, batch, 64, &foundCount);
                            tracePkcs11("C_FindObjects -> 0x%lx count=%lu",
                                        static_cast<unsigned long>(rv),
                                        static_cast<unsigned long>(foundCount));
                            if (rv != CKR_OK)
                                break;
                            for (CK_ULONG n = 0; n < foundCount; ++n) {
                                std::vector<unsigned char> id;
                                getAttr(t, session, batch[n], CKA_ID, id);
                                std::vector<unsigned char> der;
                                if (!getAttr(t, session, batch[n], CKA_VALUE, der) ||
                                    der.empty())
                                    continue;
                                const CertMetadata meta = certMetadata(der, id);
                                if (!meta.ok)
                                    continue;
                                if (!s.hasCert || certBetter(meta, bestMeta)) {
                                    bestMeta = meta;
                                    s.hasCert = true;
                                    s.certSubject = meta.subject;
                                    s.certGivenName = meta.givenName;
                                    s.certSurname = meta.surname;
                                    s.certSerialHex = meta.serialHex;
                                    s.certKeyId = meta.keyId;
                                    s.certKeyIdIsDs = meta.keyIdIsDs;
                                    s.certNotAfter = meta.notAfter;
                                    s.certNotAfterEpoch = meta.notAfterEpoch;
                                    s.certExpired = meta.expired;
                                }
                            }
                            if (foundCount < 64)
                                break;
                        }
                    }
                    if (findActive) {
                        tracePkcs11("C_FindObjectsFinal");
                        if (t.C_FindObjectsFinal)
                            t.C_FindObjectsFinal(session);
                        else
                            t.C_FindObjectsInit(session, nullptr, 0);
                    }
                    tracePkcs11("C_CloseSession");
                    t.C_CloseSession(session);
                }
                out.push_back(std::move(s));
            }
        }
    }
#ifndef _WIN32
    tracePkcs11("C_Finalize");
    t.C_Finalize(nullptr);
    tracePkcs11("C_Finalize -> done");
    tracePkcs11("closeLibrary");
    closeLibrary(t.handle);
    tracePkcs11("closeLibrary -> done");
#else
    // Keep the vendor module loaded and initialized for the process lifetime:
    // Bit4id's notify thread must not be torn down while a card is present.
    tracePkcs11("keeping PKCS#11 module loaded (Windows)");
#endif
    tracePkcs11("enumerateSlots: done (%zu slots)", out.size());
    return out;
}

} // namespace fdo
