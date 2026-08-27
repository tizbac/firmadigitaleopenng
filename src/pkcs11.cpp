#include "pkcs11.h"
#include "x509util.h"

#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <fstream>

#include <openssl/x509.h>

namespace fdo {

using namespace p11;

bool loadFnTable(FnTable &t, const std::string &path, std::string *error)
{
    t.handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!t.handle) {
        if (error)
            *error = std::string("dlopen: ") + dlerror();
        return false;
    }
    auto sym = [&](const char *name) {
        return reinterpret_cast<void *>(dlsym(t.handle, name));
    };
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
        dlclose(t.handle);
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
        m_fn->C_Finalize(nullptr);
        if (m_fn->handle)
            dlclose(m_fn->handle);
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
    if (m_fn->C_Initialize(nullptr) != CKR_OK) {
        if (error)
            *error = std::string("C_Initialize failed: ") + rvName(m_fn->C_Initialize(nullptr));
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
    const unsigned char ds3[] = {'D', 'S', '3'};

    // Enumerate every object on the token (a NULL template matches all
    // objects) and match class + CKA_ID on the host side with memcmp,
    // instead of relying on the module's template filtering.
    if (m_fn->C_FindObjectsInit(m_session, nullptr, 0) != CKR_OK) {
        if (error)
            *error = "C_FindObjectsInit failed";
        return false;
    }
    CK_OBJECT_HANDLE key = 0, cert = 0, keyAny = 0, certAny = 0;
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
            const bool hasId = getAttr(*m_fn, m_session, obj, CKA_ID, id);
            std::printf("object 0x%lx class=0x%lx id=", static_cast<unsigned long>(obj),
                        static_cast<unsigned long>(cls));
            if (hasId)
                for (unsigned char b : id)
                    std::printf("%02x", b);
            else
                std::printf("(none)");
            std::printf("\n");
            const bool isDs3 = hasId && id.size() == sizeof(ds3) &&
                               std::memcmp(id.data(), ds3, sizeof(ds3)) == 0;
            if (cls == CKO_PRIVATE_KEY) {
                if (isDs3)
                    key = obj;
                else if (!keyAny)
                    keyAny = obj;
            } else if (cls == CKO_CERTIFICATE) {
                if (isDs3)
                    cert = obj;
                else if (!certAny)
                    certAny = obj;
            }
        }
        if (found < 64)
            break;
    }
    if (m_fn->C_FindObjectsFinal)
        m_fn->C_FindObjectsFinal(m_session);

    if (!key)
        key = keyAny;
    if (!cert)
        cert = certAny;
    m_keyHandle = key;

    if (!key) {
        if (error)
            *error = "chiave privata non trovata sul token";
        return false;
    }
    if (!cert) {
        if (error)
            *error = "certificato non trovato sul token";
        return false;
    }

    auto s = Signer{};
    if (!getAttr(*m_fn, m_session, cert, CKA_VALUE, s.certDer)) {
        if (error)
            *error = "impossibile leggere il certificato dal token";
        return false;
    }
    std::vector<unsigned char> idBytes;
    getAttr(*m_fn, m_session, key, CKA_ID, idBytes);
    s.keyId.assign(reinterpret_cast<const char *>(idBytes.data()), idBytes.size());
    std::vector<unsigned char> labelBytes;
    if (getAttr(*m_fn, m_session, key, CKA_LABEL, labelBytes))
        s.keyLabel.assign(reinterpret_cast<const char *>(labelBytes.data()),
                          labelBytes.size());
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
        CK_MECHANISM mech{ cand, nullptr, 0 };
        rv = m_fn->C_SignInit(m_session, &mech, m_keyHandle);
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
    FnTable t;
    if (!loadFnTable(t, libPath, error))
        return out;
    if (t.C_Initialize(nullptr) != CKR_OK) {
        if (error)
            *error = "C_Initialize failed";
        dlclose(t.handle);
        return out;
    }

    CK_ULONG count = 0;
    CK_RV rv = t.C_GetSlotList(CK_TRUE, nullptr, &count);
    if (rv == CKR_OK && count > 0) {
        std::vector<CK_SLOT_ID> slots(count);
        rv = t.C_GetSlotList(CK_TRUE, slots.data(), &count);
        if (rv == CKR_OK) {
            for (CK_ULONG i = 0; i < count; ++i) {
                Pkcs11Slot s;
                s.index = slots[i];
                CK_SLOT_INFO_MIN si{};
                if (t.C_GetSlotInfo(slots[i], &si) == CKR_OK) {
                    s.slotDescription = si.slotDescription;
                    s.tokenPresent = (si.flags & CKF_TOKEN_PRESENT) != 0;
                }
                if (!s.tokenPresent)
                    continue;
                CK_TOKEN_INFO_MIN ti{};
                if (t.C_GetTokenInfo(slots[i], &ti) == CKR_OK) {
                    s.tokenLabel = ti.label;
                    s.loginRequired = (ti.flags & CKF_LOGIN_REQUIRED) != 0;
                }

                // Best-effort: open a RO session and read the first certificate.
                CK_SESSION_HANDLE session = 0;
                if (t.C_OpenSession(slots[i], CKF_SERIAL_SESSION, nullptr, nullptr,
                                    &session) == CKR_OK) {
                    CK_ULONG cls = CKO_CERTIFICATE;
                    CK_ATTRIBUTE tmpl = { CKA_CLASS, &cls, sizeof(cls) };
                    CK_OBJECT_HANDLE obj = 0;
                    CK_ULONG foundCount = 0;
                    const bool findActive = t.C_FindObjectsInit(session, &tmpl, 1) == CKR_OK;
                    // Some modules (e.g. SoftHSM) require a non-NULL count pointer.
                    if (findActive &&
                        t.C_FindObjects(session, &obj, 1, &foundCount) == CKR_OK && obj != 0) {
                        std::vector<unsigned char> der;
                        if (getAttr(t, session, obj, CKA_VALUE, der) && !der.empty()) {
                            const unsigned char *p = der.data();
                            X509 *x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
                            if (x) {
                                s.hasCert = true;
                                char buf[1024];
                                char *sub = X509_NAME_oneline(X509_get_subject_name(x), nullptr, 0);
                                if (sub) {
                                    s.certSubject = sub;
                                    OPENSSL_free(sub);
                                }
                                int n = X509_NAME_get_text_by_NID(
                                    X509_get_subject_name(x), NID_givenName, buf,
                                    sizeof(buf));
                                if (n > 0)
                                    s.certGivenName.assign(buf, static_cast<size_t>(n));
                                n = X509_NAME_get_text_by_NID(
                                    X509_get_subject_name(x), NID_surname, buf,
                                    sizeof(buf));
                                if (n > 0)
                                    s.certSurname.assign(buf, static_cast<size_t>(n));
                                BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), nullptr);
                                if (bn) {
                                    char *h = BN_bn2hex(bn);
                                    if (h) {
                                        s.certSerialHex = h;
                                        OPENSSL_free(h);
                                    }
                                    BN_free(bn);
                                }
                                X509_free(x);
                            }
                        }
                    }
                    if (findActive) {
                        if (t.C_FindObjectsFinal)
                            t.C_FindObjectsFinal(session);
                        else
                            t.C_FindObjectsInit(session, nullptr, 0);
                    }
                    t.C_CloseSession(session);
                }
                out.push_back(std::move(s));
            }
        }
    }
    t.C_Finalize(nullptr);
    dlclose(t.handle);
    return out;
}

} // namespace fdo
