#pragma once

// ---------------------------------------------------------------------------
// Minimal PKCS#11 ABI (subset, from the OASIS spec; layout-stable).
// ---------------------------------------------------------------------------
namespace p11 {

using CK_ULONG = unsigned long;
using CK_ULONG_PTR = CK_ULONG *;
using CK_BYTE = unsigned char;
using CK_BYTE_PTR = CK_BYTE *;
using CK_BBOOL = unsigned char;
using CK_FLAGS = CK_ULONG;
using CK_RV = unsigned long;
using CK_SLOT_ID = CK_ULONG;
using CK_SLOT_ID_PTR = CK_SLOT_ID *;
using CK_SESSION_HANDLE = CK_ULONG;
using CK_SESSION_HANDLE_PTR = CK_SESSION_HANDLE *;
using CK_OBJECT_HANDLE = CK_ULONG;
using CK_OBJECT_HANDLE_PTR = CK_OBJECT_HANDLE *;
using CK_USER_TYPE = CK_ULONG;
using CK_MECHANISM_TYPE = CK_ULONG;
using CK_ATTRIBUTE_TYPE = CK_ULONG;
using CK_VOID_PTR = void *;
using CK_VOID_PTR_PTR = void **;
using CK_UTF8CHAR = char;
using CK_UTF8CHAR_PTR = CK_UTF8CHAR *;
using CK_NOTIFICATION = CK_ULONG;
using CK_NOTIFY = void (*)(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_OBJECT_HANDLE,
                           CK_ULONG, CK_VOID_PTR);

// Return-value codes (OASIS PKCS#11 v2.40+).
constexpr CK_RV CKR_OK = 0x0;
constexpr CK_RV CKR_CANCEL = 0x1;
constexpr CK_RV CKR_HOST_MEMORY = 0x2;
constexpr CK_RV CKR_SLOT_ID_INVALID = 0x3;
constexpr CK_RV CKR_GENERAL_ERROR = 0x5;
constexpr CK_RV CKR_FUNCTION_FAILED = 0x6;
constexpr CK_RV CKR_ARGUMENTS_BAD = 0x7;
constexpr CK_RV CKR_DATA_INVALID = 0x20;
constexpr CK_RV CKR_MECHANISM_INVALID = 0x70;
constexpr CK_RV CKR_KEY_HANDLE_INVALID = 0x60;
constexpr CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED = 0x68;
constexpr CK_RV CKR_OBJECT_HANDLE_INVALID = 0x82;
constexpr CK_RV CKR_OPERATION_NOT_INITIALIZED = 0x91;
constexpr CK_RV CKR_PIN_INCORRECT = 0xA0;
constexpr CK_RV CKR_PIN_INVALID = 0xA1;
constexpr CK_RV CKR_SESSION_HANDLE_INVALID = 0xB3;
constexpr CK_RV CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0xB4;
constexpr CK_RV CKR_TOKEN_NOT_PRESENT = 0xE0;
constexpr CK_RV CKR_TOKEN_NOT_RECOGNIZED = 0xE1;
constexpr CK_RV CKR_USER_NOT_LOGGED_IN = 0x101;
constexpr CK_RV CKR_BUFFER_TOO_SMALL = 0x150;

constexpr CK_BBOOL CK_TRUE = 1;
constexpr CK_BBOOL CK_FALSE = 0;

constexpr CK_ULONG CKO_CERTIFICATE = 0x1;
constexpr CK_ULONG CKO_PRIVATE_KEY = 0x3;
constexpr CK_ULONG CKA_CLASS = 0x0;
constexpr CK_ULONG CKA_LABEL = 0x3;
constexpr CK_ULONG CKA_ID = 0x102;
constexpr CK_ULONG CKA_VALUE = 0x11;
constexpr CK_ULONG CKA_SIGN = 0x108;
constexpr CK_ULONG CKA_TOKEN = 0x1;

constexpr CK_ULONG CKM_SHA256_RSA_PKCS = 0x1051;
constexpr CK_ULONG CKU_USER = 1;
// Session flags (C_OpenSession): CKF_RW_SESSION | CKF_SERIAL_SESSION
constexpr CK_FLAGS CKF_SERIAL_SESSION = 0x4;
constexpr CK_FLAGS CKF_RW_SESSION = 0x2;
// Slot flags (CK_SLOT_INFO): CKF_TOKEN_PRESENT
constexpr CK_FLAGS CKF_TOKEN_PRESENT = 0x1;
// Token flags (CK_TOKEN_INFO): CKF_LOGIN_REQUIRED
constexpr CK_FLAGS CKF_LOGIN_REQUIRED = 0x8;

constexpr CK_ULONG CK_UNAVAILABLE_INFORMATION = 0xFFFFFFFF;

struct CK_SLOT_INFO_MIN
{
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
};

struct CK_TOKEN_INFO_MIN
{
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_ULONG serialNumber[16];
    CK_FLAGS flags;
};

struct CK_ATTRIBUTE
{
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
};
using CK_ATTRIBUTE_PTR = CK_ATTRIBUTE *;

struct CK_MECHANISM
{
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
};
using CK_MECHANISM_PTR = CK_MECHANISM *;

using C_Initialize_t = CK_RV (*)(CK_VOID_PTR);
using C_Finalize_t = CK_RV (*)(CK_VOID_PTR);
using C_GetSlotList_t = CK_RV (*)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
using C_GetSlotInfo_t = CK_RV (*)(CK_SLOT_ID, CK_SLOT_INFO_MIN *);
using C_GetTokenInfo_t = CK_RV (*)(CK_SLOT_ID, CK_TOKEN_INFO_MIN *);
using C_OpenSession_t = CK_RV (*)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY,
                                  CK_SESSION_HANDLE_PTR);
using C_CloseSession_t = CK_RV (*)(CK_SESSION_HANDLE);
using C_Login_t = CK_RV (*)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
using C_FindObjectsInit_t = CK_RV (*)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
using C_FindObjects_t = CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG,
                                  CK_ULONG_PTR);
using C_FindObjectsFinal_t = CK_RV (*)(CK_SESSION_HANDLE);
using C_GetAttributeValue_t = CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                        CK_ATTRIBUTE_PTR, CK_ULONG);
using C_SignInit_t = CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
using C_Sign_t = CK_RV (*)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                           CK_ULONG_PTR);

struct FnTable
{
    void *handle = nullptr;
    C_Initialize_t C_Initialize = nullptr;
    C_Finalize_t C_Finalize = nullptr;
    C_GetSlotList_t C_GetSlotList = nullptr;
    C_GetSlotInfo_t C_GetSlotInfo = nullptr;
    C_GetTokenInfo_t C_GetTokenInfo = nullptr;
    C_OpenSession_t C_OpenSession = nullptr;
    C_CloseSession_t C_CloseSession = nullptr;
    C_Login_t C_Login = nullptr;
    C_FindObjectsInit_t C_FindObjectsInit = nullptr;
    C_FindObjects_t C_FindObjects = nullptr;
    C_FindObjectsFinal_t C_FindObjectsFinal = nullptr;
    C_GetAttributeValue_t C_GetAttributeValue = nullptr;
    C_SignInit_t C_SignInit = nullptr;
    C_Sign_t C_Sign = nullptr;
};

inline const char *rvName(CK_RV rv)
{
    switch (rv) {
    case CKR_OK: return "CKR_OK";
    case CKR_CANCEL: return "CKR_CANCEL";
    case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
    case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
    case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
    case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
    case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
    case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
    default:
        return "CKR_UNKNOWN";
    }
}

// Reads an attribute value, handling the length-probe protocol.
inline bool getAttr(FnTable &t, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
             CK_ATTRIBUTE_TYPE type, std::vector<unsigned char> &out)
{
    CK_ATTRIBUTE attr{ type, nullptr, 0 };
    CK_RV rv = t.C_GetAttributeValue(session, obj, &attr, 1);
    CK_ULONG len = attr.ulValueLen;
    if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
        if (len == CK_UNAVAILABLE_INFORMATION)
            return false;
        out.resize(len);
        attr.pValue = out.empty() ? nullptr : out.data();
        attr.ulValueLen = len;
        rv = t.C_GetAttributeValue(session, obj, &attr, 1);
        if (rv == CKR_OK) {
            out.resize(attr.ulValueLen);
            return true;
        }
        if (rv == CKR_BUFFER_TOO_SMALL) {
            out.resize(attr.ulValueLen);
            attr.pValue = out.empty() ? nullptr : out.data();
            attr.ulValueLen = attr.ulValueLen;
            return t.C_GetAttributeValue(session, obj, &attr, 1) == CKR_OK;
        }
    }
    return false;
}

} // namespace p11
