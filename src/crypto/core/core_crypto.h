#ifndef CORE_CRYPTO_H
#define CORE_CRYPTO_H

#include "core.h"

#include <bcrypt.h>
#include <wincrypt.h>


#ifndef CRYPT_STRING_BASE64RAW
#define CRYPT_STRING_BASE64RAW 0x00000009
#endif

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")


#ifdef __cplusplus
extern "C"
{
#endif

#ifndef LPCBYTE
typedef const BYTE *LPCBYTE;
#endif

    // ---- Hash simple ----
    CORE_API int MD5(const char *pData, size_t dataLen, char *outputHex);
    CORE_API int SHA1(const char *pData, size_t dataLen, char *outputHex);
    CORE_API int SHA256(const char *pData, size_t dataLen, char *outputHex);
    CORE_API int SHA384(const char *pData, size_t dataLen, char *outputHex);
    CORE_API int SHA512(const char *pData, size_t dataLen, char *outputHex);
    CORE_API int GenerateHashAlgorithm(const char *pData, size_t dataLen, const wchar_t *wAlgorithm, char *outputHex);

    // ---- HMAC ----
    CORE_API int HMACMD5(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA1(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA256(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA384(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA512(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int GenerateHmacAlgorithm(const char *pData, size_t dataLen, const char *pKey, size_t keyLen,
                              const wchar_t *wAlgorithm, char *outputHex);

    // ---- Hash File ----
    CORE_API int MD5File(const wchar_t *wFilePath, char *outputHex);
    CORE_API int SHA1File(const wchar_t *wFilePath, char *outputHex);
    CORE_API int SHA256File(const wchar_t *wFilePath, char *outputHex);
    CORE_API int SHA512File(const wchar_t *wFilePath, char *outputHex);
    CORE_API int GenerateFileHashAlgorithm(const wchar_t *wFilePath, const wchar_t *wAlgorithm, char *outputHex);

    // ---- HMAC de archivo (streaming) ----
    CORE_API int HMACMD5File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA1File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA256File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA384File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int HMACSHA512File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex);
    CORE_API int GenerateFileHmacAlgorithm(const wchar_t *wFilePath, const char *pKey, size_t keyLen,
                                  const wchar_t *wAlgorithm, char *outputHex);

    CORE_API void CreateSecureNonce(
        char *outputHex,
        DWORD maxLen);

    CORE_API int GenerateHashAlgorithm(
        const char *pData,
        size_t dataLen,
        const wchar_t *wAlgorithm,
        char *outputHex);

    // PENDIENTE DE REVISAR    
    CORE_API wchar_t *UnicodeToUtf8Base64(const wchar_t *wInput);
    // PENDIENTE DE REVISAR    
    CORE_API wchar_t *Utf8Base64ToUnicode(const wchar_t *wBase64Input);

    CORE_API BOOL BytesToBase64(
    const BYTE *pBinaryData,
    DWORD dwBinaryLen,
    char **ppOutBase64Text);

    CORE_API BOOL Base64ToBytes(
    const char *szBase64Text,
    BYTE **ppOutBinaryData,
    DWORD *pOutBinaryLen);

    CORE_API BOOL EncryptAES256(
    const char *szPlainText,
    const char *szKey,
    BYTE **ppOutEncryptedData,
    DWORD *pOutDataLen);

    CORE_API BOOL DecryptAES256(
    const BYTE *pEncryptedData,
    DWORD dwDataLen,
    const char *szKey,
    char **ppOutPlainText);

    CORE_API BOOL SecureEncryptString(
    const char *szPlainText,
    const char *szKey,
    char **ppOutBase64Result);

    CORE_API BOOL SecureDecryptString(
    const char *szBase64Text,
    const char *szKey,
    char **ppOutPlainTextResult);

#ifdef __cplusplus
}
#endif

#endif // CORE_CRYPTO_H
