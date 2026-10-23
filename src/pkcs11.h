#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pkcs11_abi.h"

namespace fdo {

struct Pkcs11Slot
{
    unsigned long index = 0; // real CK_SLOT_ID, not a list position
    std::string slotDescription;
    std::string tokenLabel;
    bool tokenPresent = false;
    bool loginRequired = false;

    // Best-effort info from the first certificate on the token.
    bool hasCert = false;
    std::string certSubject;
    std::string certGivenName;
    std::string certSurname;
    std::string certSerialHex;
};

// Thin wrapper around a PKCS#11 module (Bit4id token in the original app).
// Loads the library with dlopen (POSIX) / LoadLibraryW (Windows); no system
// PKCS#11 headers required.
class Pkcs11
{
public:
    struct Signer
    {
        std::vector<unsigned char> certDer;
        std::string keyLabel;
        std::string keyId;
    };

    ~Pkcs11();
    Pkcs11() = default;
    Pkcs11(const Pkcs11 &) = delete;
    Pkcs11 &operator=(const Pkcs11 &) = delete;

    // Lists slots that have a token present, with signer info if readable.
    static std::vector<Pkcs11Slot> enumerateSlots(const std::string &libPath,
                                                  std::string *error = nullptr);

    bool loadLibrary(const std::string &libPath, std::string *error = nullptr);
    bool login(unsigned long slotIndex, const std::string &pin, std::string *error = nullptr);

    // Locates the private key and certificate whose CKA_ID is "DS3"
    // (falling back to the only key/certificate on the token).
    bool findSigner(std::string *error = nullptr);

    const Signer *signer() const { return m_signer ? &m_signer.value() : nullptr; }

    // RSA PKCS#1 v1.5 + SHA-256 (CKM_SHA256_RSA_PKCS) over `data`.
    bool sign(const std::vector<unsigned char> &data, std::vector<unsigned char> &out,
              std::string *error = nullptr);

    void close();

private:
    std::unique_ptr<p11::FnTable> m_fn;
    unsigned long m_slotIndex = 0;
    unsigned long long m_session = 0;
    bool m_sessionOpen = false;
    unsigned long long m_keyHandle = 0;
    std::optional<Signer> m_signer;
};

} // namespace fdo
