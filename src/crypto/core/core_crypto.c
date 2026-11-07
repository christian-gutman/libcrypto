#include "core_crypto.h"

static int HashGeneric(LPCWSTR pszAlgId, const char *pData, size_t dataLen, char *outputHex)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    int success = 0;
    NTSTATUS status;

    if (!pData || dataLen == 0 || !outputHex)
    {
        if (outputHex)
            outputHex[0] = '\0';
        return 0;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        // char dbg[96];
        // sprintf_s(dbg, sizeof(dbg), "HashGeneric OpenProvider(%ls) failed: 0x%08X", pszAlgId, (unsigned int)status);
        // _PutStr(dbg);
        // outputHex[0] = '\0';
        return 0;
    }

    if (BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) &&
        BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        pbHashObject = (PBYTE)malloc(cbHashObject);
        pbHash = (PBYTE)malloc(cbHash);

        if (pbHashObject && pbHash)
        {
            if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
            {
                if (BCRYPT_SUCCESS(BCryptHashData(hHash, (PBYTE)pData, (ULONG)dataLen, 0)))
                {
                    if (BCRYPT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbHash, 0)))
                    {
                        for (DWORD i = 0; i < cbHash; i++)
                            sprintf_s(outputHex + (i * 2), 3, "%02x", pbHash[i]);
                        success = 1;
                    }
                }
                BCryptDestroyHash(hHash);
            }
        }
    }

    if (pbHashObject)
        free(pbHashObject);
    if (pbHash)
        free(pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!success)
        outputHex[0] = '\0';
    return success;
}
int MD5(const char *pData, size_t dataLen, char *outputHex)
{
    return HashGeneric(BCRYPT_MD5_ALGORITHM, pData, dataLen, outputHex);
}
int SHA1(const char *pData, size_t dataLen, char *outputHex)
{
    return HashGeneric(BCRYPT_SHA1_ALGORITHM, pData, dataLen, outputHex);
}
int SHA256(const char *pData, size_t dataLen, char *outputHex)
{
    return HashGeneric(BCRYPT_SHA256_ALGORITHM, pData, dataLen, outputHex);
}
int SHA384(const char *pData, size_t dataLen, char *outputHex)
{
    return HashGeneric(BCRYPT_SHA384_ALGORITHM, pData, dataLen, outputHex);
}
int SHA512(const char *pData, size_t dataLen, char *outputHex)
{
    return HashGeneric(BCRYPT_SHA512_ALGORITHM, pData, dataLen, outputHex);
}
int GenerateHashAlgorithm(const char *pData, size_t dataLen, const wchar_t *wAlgorithm, char *outputHex)
{
    if (wAlgorithm[0] == L'\0' || _wcsicmp(wAlgorithm, L"MD5") == 0)
        return HashGeneric(BCRYPT_MD5_ALGORITHM, pData, dataLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA1") == 0)
        return HashGeneric(BCRYPT_SHA1_ALGORITHM, pData, dataLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-256") == 0 || _wcsicmp(wAlgorithm, L"SHA256") == 0)
        return HashGeneric(BCRYPT_SHA256_ALGORITHM, pData, dataLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-384") == 0 || _wcsicmp(wAlgorithm, L"SHA384") == 0)
        return HashGeneric(BCRYPT_SHA384_ALGORITHM, pData, dataLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-512") == 0 || _wcsicmp(wAlgorithm, L"SHA512") == 0)
        return HashGeneric(BCRYPT_SHA512_ALGORITHM, pData, dataLen, outputHex);

    if (outputHex)
        outputHex[0] = '\0';
    return 0;
}

// Núcleo genérico HMAC — todas las variantes (HMAC-MD5, HMAC-SHA1, HMAC-SHA256, etc.)
// delegan acá, solo cambia el algId
static int HmacGeneric(LPCWSTR pszAlgId, const char *pData, size_t dataLen,
                       const char *pKey, size_t keyLen, char *outputHex)
{
    if (!pData || dataLen == 0 || !pKey || keyLen == 0 || !outputHex)
    {
        if (outputHex)
            outputHex[0] = '\0';
        return 0;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    int success = 0;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
    {
        // char dbg[96];
        // sprintf_s(dbg, sizeof(dbg), "HmacGeneric OpenProvider(%ls) failed: 0x%08X", pszAlgId, (unsigned int)status);
        // _PutStr(dbg);
        // outputHex[0] = '\0';
        return 0;
    }

    if (BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) &&
        BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        pbHashObject = (PBYTE)malloc(cbHashObject);
        pbHash = (PBYTE)malloc(cbHash);

        if (pbHashObject && pbHash)
        {
            // La clave se pasa acá para habilitar HMAC (a diferencia del hash simple)
            if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PBYTE)pKey, (ULONG)keyLen, 0)))
            {
                if (BCRYPT_SUCCESS(BCryptHashData(hHash, (PBYTE)pData, (ULONG)dataLen, 0)))
                {
                    if (BCRYPT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbHash, 0)))
                    {
                        for (DWORD i = 0; i < cbHash; i++)
                            sprintf_s(outputHex + (i * 2), 3, "%02x", pbHash[i]);
                        success = 1;
                    }
                }
                BCryptDestroyHash(hHash);
            }
        }
    }

    if (pbHashObject)
        free(pbHashObject);
    if (pbHash)
        free(pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!success)
        outputHex[0] = '\0';
    return success;
}
int HMACMD5(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacGeneric(BCRYPT_MD5_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
}

int HMACSHA1(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacGeneric(BCRYPT_SHA1_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
}

int HMACSHA256(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacGeneric(BCRYPT_SHA256_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
}

int HMACSHA384(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacGeneric(BCRYPT_SHA384_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
}

int HMACSHA512(const char *pData, size_t dataLen, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacGeneric(BCRYPT_SHA512_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
}
int GenerateHmacAlgorithm(const char *pData, size_t dataLen,
                          const char *pKey, size_t keyLen,
                          const wchar_t *wAlgorithm, char *outputHex)
{
    if (wAlgorithm[0] == L'\0' || _wcsicmp(wAlgorithm, L"SHA-256") == 0 || _wcsicmp(wAlgorithm, L"SHA256") == 0)
        return HmacGeneric(BCRYPT_SHA256_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"MD5") == 0)
        return HmacGeneric(BCRYPT_MD5_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA1") == 0)
        return HmacGeneric(BCRYPT_SHA1_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-384") == 0 || _wcsicmp(wAlgorithm, L"SHA384") == 0)
        return HmacGeneric(BCRYPT_SHA384_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-512") == 0 || _wcsicmp(wAlgorithm, L"SHA512") == 0)
        return HmacGeneric(BCRYPT_SHA512_ALGORITHM, pData, dataLen, pKey, keyLen, outputHex);

    if (outputHex)
        outputHex[0] = '\0';
    return 0;
}

// Hashea un archivo en streaming (no carga todo a memoria), soporta cualquier algId de BCrypt
static int HashFileGeneric(LPCWSTR pszAlgId, const wchar_t *wFilePath, char *outputHex)
{
    if (!wFilePath || !outputHex)
    {
        if (outputHex)
            outputHex[0] = '\0';
        return 0;
    }

    HANDLE hFile = CreateFileW(wFilePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        /*char dbg[300];
        sprintf_s(dbg, sizeof(dbg), "HashFileGeneric: no se pudo abrir archivo (error 0x%08X)", (unsigned int)GetLastError());
        _PutStr(dbg);
        outputHex[0] = '\0';*/
        return 0;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    int success = 0;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        /* char dbg[96];
         sprintf_s(dbg, sizeof(dbg), "HashFileGeneric OpenProvider(%ls) failed: 0x%08X", pszAlgId, (unsigned int)status);
         _PutStr(dbg);
         CloseHandle(hFile);
         outputHex[0] = '\0';*/
        return 0;
    }

    if (BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) &&
        BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        pbHashObject = (PBYTE)malloc(cbHashObject);
        pbHash = (PBYTE)malloc(cbHash);

        if (pbHashObject && pbHash)
        {
            if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
            {
                const DWORD CHUNK_SIZE = 64 * 1024; // 64KB por lectura
                BYTE *pBuffer = (BYTE *)malloc(CHUNK_SIZE);
                int readError = 0;

                if (pBuffer)
                {
                    DWORD bytesRead = 0;
                    BOOL readOk = TRUE;

                    while (readOk && ReadFile(hFile, pBuffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0)
                    {
                        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, pBuffer, bytesRead, 0)))
                        {
                            readError = 1;
                            break;
                        }
                    }
                    free(pBuffer);
                }
                else
                {
                    readError = 1;
                }

                if (!readError && BCRYPT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbHash, 0)))
                {
                    for (DWORD i = 0; i < cbHash; i++)
                        sprintf_s(outputHex + (i * 2), 3, "%02x", pbHash[i]);
                    success = 1;
                }
                BCryptDestroyHash(hHash);
            }
        }
    }

    if (pbHashObject)
        free(pbHashObject);
    if (pbHash)
        free(pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    if (!success)
        outputHex[0] = '\0';
    return success;
}
int MD5File(const wchar_t *wFilePath, char *outputHex)
{
    return HashFileGeneric(BCRYPT_MD5_ALGORITHM, wFilePath, outputHex);
}
int SHA1File(const wchar_t *wFilePath, char *outputHex)
{
    return HashFileGeneric(BCRYPT_SHA1_ALGORITHM, wFilePath, outputHex);
}
int SHA256File(const wchar_t *wFilePath, char *outputHex)
{
    return HashFileGeneric(BCRYPT_SHA256_ALGORITHM, wFilePath, outputHex);
}
int SHA512File(const wchar_t *wFilePath, char *outputHex)
{
    return HashFileGeneric(BCRYPT_SHA512_ALGORITHM, wFilePath, outputHex);
}

int GenerateFileHashAlgorithm(const wchar_t *wFilePath, const wchar_t *wAlgorithm, char *outputHex)
{
    if (wAlgorithm[0] == L'\0' || _wcsicmp(wAlgorithm, L"MD5") == 0)
        return HashFileGeneric(BCRYPT_MD5_ALGORITHM, wFilePath, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA1") == 0)
        return HashFileGeneric(BCRYPT_SHA1_ALGORITHM, wFilePath, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-256") == 0 || _wcsicmp(wAlgorithm, L"SHA256") == 0)
        return HashFileGeneric(BCRYPT_SHA256_ALGORITHM, wFilePath, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-384") == 0 || _wcsicmp(wAlgorithm, L"SHA384") == 0)
        return HashFileGeneric(BCRYPT_SHA384_ALGORITHM, wFilePath, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-512") == 0 || _wcsicmp(wAlgorithm, L"SHA512") == 0)
        return HashFileGeneric(BCRYPT_SHA512_ALGORITHM, wFilePath, outputHex);

    if (outputHex)
        outputHex[0] = '\0';
    return 0;
}

// Firma un archivo con HMAC en streaming (no carga todo a memoria)
static int HmacFileGeneric(LPCWSTR pszAlgId, const wchar_t *wFilePath,
                           const char *pKey, size_t keyLen, char *outputHex)
{
    if (!wFilePath || !pKey || keyLen == 0 || !outputHex)
    {
        if (outputHex)
            outputHex[0] = '\0';
        return 0;
    }

    HANDLE hFile = CreateFileW(wFilePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        /*char dbg[300];
         sprintf_s(dbg, sizeof(dbg), "HmacFileGeneric: no se pudo abrir archivo (error 0x%08X)", (unsigned int)GetLastError());
         _PutStr(dbg);
         outputHex[0] = '\0';*/
        return 0;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    int success = 0;
    NTSTATUS status;

    // Abrir con flag HMAC (igual que HmacGeneric para strings)
    status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
    {
        /* char dbg[96];
         sprintf_s(dbg, sizeof(dbg), "HmacFileGeneric OpenProvider(%ls) failed: 0x%08X", pszAlgId, (unsigned int)status);
         _PutStr(dbg);
         CloseHandle(hFile);
         outputHex[0] = '\0';*/
        return 0;
    }

    if (BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) &&
        BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        pbHashObject = (PBYTE)malloc(cbHashObject);
        pbHash = (PBYTE)malloc(cbHash);

        if (pbHashObject && pbHash)
        {
            // La clave se pasa acá, igual que en HmacGeneric
            if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PBYTE)pKey, (ULONG)keyLen, 0)))
            {
                const DWORD CHUNK_SIZE = 64 * 1024; // 64KB por lectura
                BYTE *pBuffer = (BYTE *)malloc(CHUNK_SIZE);
                int readError = 0;

                if (pBuffer)
                {
                    DWORD bytesRead = 0;
                    BOOL readOk = TRUE;

                    while (readOk && ReadFile(hFile, pBuffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0)
                    {
                        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, pBuffer, bytesRead, 0)))
                        {
                            readError = 1;
                            break;
                        }
                    }
                    free(pBuffer);
                }
                else
                {
                    readError = 1;
                }

                if (!readError && BCRYPT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbHash, 0)))
                {
                    for (DWORD i = 0; i < cbHash; i++)
                        sprintf_s(outputHex + (i * 2), 3, "%02x", pbHash[i]);
                    success = 1;
                }
                BCryptDestroyHash(hHash);
            }
        }
    }

    if (pbHashObject)
        free(pbHashObject);
    if (pbHash)
        free(pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    if (!success)
        outputHex[0] = '\0';
    return success;
}

// ---- Funciones con nombre sobre HmacFileGeneric ----

int HMACMD5File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacFileGeneric(BCRYPT_MD5_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
}
int HMACSHA1File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacFileGeneric(BCRYPT_SHA1_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
}
int HMACSHA256File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacFileGeneric(BCRYPT_SHA256_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
}
int HMACSHA384File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacFileGeneric(BCRYPT_SHA384_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
}
int HMACSHA512File(const wchar_t *wFilePath, const char *pKey, size_t keyLen, char *outputHex)
{
    return HmacFileGeneric(BCRYPT_SHA512_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
}

// ---- Dispatcher genérico ----

int GenerateFileHmacAlgorithm(const wchar_t *wFilePath, const char *pKey, size_t keyLen,
                              const wchar_t *wAlgorithm, char *outputHex)
{
    if (wAlgorithm[0] == L'\0' || _wcsicmp(wAlgorithm, L"SHA-256") == 0 || _wcsicmp(wAlgorithm, L"SHA256") == 0)
        return HmacFileGeneric(BCRYPT_SHA256_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"MD5") == 0)
        return HmacFileGeneric(BCRYPT_MD5_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA1") == 0)
        return HmacFileGeneric(BCRYPT_SHA1_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-384") == 0 || _wcsicmp(wAlgorithm, L"SHA384") == 0)
        return HmacFileGeneric(BCRYPT_SHA384_ALGORITHM, wFilePath, pKey, keyLen, outputHex);
    if (_wcsicmp(wAlgorithm, L"SHA-512") == 0 || _wcsicmp(wAlgorithm, L"SHA512") == 0)
        return HmacFileGeneric(BCRYPT_SHA512_ALGORITHM, wFilePath, pKey, keyLen, outputHex);

    if (outputHex)
        outputHex[0] = '\0';
    return 0;
}
void CreateSecureNonce(char *outputHex, DWORD maxLen)
{
    if (!outputHex || maxLen == 0)
        return;

    // Necesitamos espacio para al menos 2 hex chars + '\0'
    if (maxLen < 3)
    {
        outputHex[0] = '\0';
        return;
    }

    // Cuántos bytes de entropía caben en (maxLen - 1) hex chars,
    // reservando 1 byte para el '\0' final
    DWORD nBytes = (maxLen - 1) / 2;

    BYTE *bA = (BYTE *)malloc(nBytes);
    if (!bA)
    {
        outputHex[0] = '\0';
        return;
    }

    if (BCRYPT_SUCCESS(BCryptGenRandom(NULL, bA, nBytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        for (DWORD i = 0; i < nBytes; i++)
        {
            sprintf_s(outputHex + (i * 2), maxLen - (i * 2), "%02x", bA[i]);
        }
        outputHex[nBytes * 2] = '\0';
    }
    else
    {
        // Fallback si BCryptGenRandom falla: NO usar un valor fijo predecible
        // (el "abcdef0123456789" original rompe la garantía de aleatoriedad de un nonce)
        /* char dbg[64];
         sprintf_s(dbg, sizeof(dbg), "CreateSecureNonce: BCryptGenRandom failed");
         _PutStr(dbg);*/
        outputHex[0] = '\0';
    }

    free(bA);
}

wchar_t *UnicodeToUtf8Base64(const wchar_t *wInput)
{
    if (!wInput || wInput[0] == L'\0')
        return _wcsdup(L"");

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wInput, -1, NULL, 0, NULL, NULL);
    if (utf8Len <= 1)
        return _wcsdup(L"");

    char *utf8Buf = (char *)malloc(utf8Len);
    if (!utf8Buf)
        return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wInput, -1, utf8Buf, utf8Len, NULL, NULL);

    // Los datos reales excluyen el terminador nulo de la cadena UTF-8
    DWORD cbBinary = (DWORD)(utf8Len - 1);
    DWORD cchBase64 = 0;

    if (!CryptBinaryToStringW((const BYTE *)utf8Buf, cbBinary,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              NULL, &cchBase64))
    {
        free(utf8Buf);
        return NULL;
    }

    wchar_t *wBase64Output = (wchar_t *)malloc(cchBase64 * sizeof(wchar_t));
    if (!wBase64Output)
    {
        free(utf8Buf);
        return NULL;
    }

    if (!CryptBinaryToStringW((const BYTE *)utf8Buf, cbBinary,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              wBase64Output, &cchBase64))
    {
        free(utf8Buf);
        free(wBase64Output);
        return NULL;
    }

    free(utf8Buf);
    return wBase64Output;
}

wchar_t *Utf8Base64ToUnicode(const wchar_t *wBase64Input)
{
    if (!wBase64Input || wBase64Input[0] == L'\0')
        return _wcsdup(L"");

    DWORD cbBinary = 0;
    DWORD dwSkip = 0;
    DWORD dwFlags = 0;

    if (!CryptStringToBinaryW(wBase64Input, 0, CRYPT_STRING_BASE64,
                              NULL, &cbBinary, &dwSkip, &dwFlags))
    {
        return NULL;
    }

    BYTE *pUtf8Buf = (BYTE *)malloc(cbBinary + 1);
    if (!pUtf8Buf)
        return NULL;

    if (!CryptStringToBinaryW(wBase64Input, 0, CRYPT_STRING_BASE64,
                              pUtf8Buf, &cbBinary, &dwSkip, &dwFlags))
    {
        free(pUtf8Buf);
        return NULL;
    }
    pUtf8Buf[cbBinary] = '\0';

    int unicodeLen = MultiByteToWideChar(CP_UTF8, 0, (const char *)pUtf8Buf, cbBinary, NULL, 0);
    if (unicodeLen <= 0)
    {
        free(pUtf8Buf);
        return NULL;
    }

    wchar_t *wOutput = (wchar_t *)malloc((unicodeLen + 1) * sizeof(wchar_t));
    if (!wOutput)
    {
        free(pUtf8Buf);
        return NULL;
    }

    MultiByteToWideChar(CP_UTF8, 0, (const char *)pUtf8Buf, cbBinary, wOutput, unicodeLen);
    wOutput[unicodeLen] = L'\0'; // Asegurar el terminador nulo final en la cadena ancha

    free(pUtf8Buf);

    return wOutput;
}

BOOL EncryptAES256(const char *szPlainText, const char *szKey, BYTE **ppOutEncryptedData, DWORD *pOutDataLen)
{
    if (!szPlainText || !szKey || !ppOutEncryptedData || !pOutDataLen)
        return FALSE;
    *ppOutEncryptedData = NULL;
    *pOutDataLen = 0;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL bSuccess = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return FALSE;

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0)
    {
        BYTE keyBuffer[32] = {0};
        strncpy_s((char *)keyBuffer, sizeof(keyBuffer), szKey, _TRUNCATE);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, keyBuffer, sizeof(keyBuffer), 0) == 0)
        {
            DWORD dwPlainTextLen = (DWORD)strlen(szPlainText);
            DWORD dwBufLen = 0;

            BYTE ivForSize[16] = {0};

            if (BCryptEncrypt(hKey, (PUCHAR)szPlainText, dwPlainTextLen, NULL, ivForSize, sizeof(ivForSize), NULL, 0, &dwBufLen, BCRYPT_BLOCK_PADDING) == 0)
            {
                BYTE *pCipherBuffer = (BYTE *)malloc(dwBufLen);
                if (pCipherBuffer)
                {
                    BYTE ivForReal[16] = {0};

                    if (BCryptEncrypt(hKey, (PUCHAR)szPlainText, dwPlainTextLen, NULL, ivForReal, sizeof(ivForReal), pCipherBuffer, dwBufLen, pOutDataLen, BCRYPT_BLOCK_PADDING) == 0)
                    {
                        *ppOutEncryptedData = pCipherBuffer;
                        bSuccess = TRUE;
                    }
                    else
                    {
                        free(pCipherBuffer);
                    }
                }
            }
        }
    }

    if (hKey)
        BCryptDestroyKey(hKey);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return bSuccess;
}

BOOL DecryptAES256(const BYTE *pEncryptedData, DWORD dwDataLen, const char *szKey, char **ppOutPlainText)
{
    if (!pEncryptedData || dwDataLen == 0 || !szKey || !ppOutPlainText)
        return FALSE;
    *ppOutPlainText = NULL;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL bSuccess = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return FALSE;
//LPCBYTE >PUCHAR o  LPCBYTE >(PBYTE)(ULONG_PTR)
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0)
    {
        BYTE keyBuffer[32] = {0};
        strncpy_s((char *)keyBuffer, sizeof(keyBuffer), szKey, _TRUNCATE);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, keyBuffer, sizeof(keyBuffer), 0) == 0)
        {
            DWORD dwPlainLen = 0;

            BYTE ivForSize[16] = {0};

            if (BCryptDecrypt(hKey, (PUCHAR)pEncryptedData, dwDataLen, NULL, ivForSize, sizeof(ivForSize), NULL, 0, &dwPlainLen, BCRYPT_BLOCK_PADDING) == 0)
            {
                char *pPlainBuffer = (char *)malloc(dwPlainLen + 1);
                if (pPlainBuffer)
                {
                    BYTE ivForReal[16] = {0};
                    DWORD dwBytesWritten = 0;

                    if (BCryptDecrypt(hKey, (PUCHAR)pEncryptedData, dwDataLen, NULL, ivForReal, sizeof(ivForReal), (PUCHAR)pPlainBuffer, dwPlainLen, &dwBytesWritten, BCRYPT_BLOCK_PADDING) == 0)
                    {
                        pPlainBuffer[dwBytesWritten] = '\0';
                        *ppOutPlainText = pPlainBuffer;
                        bSuccess = TRUE;
                    }
                    else
                    {
                        free(pPlainBuffer);
                    }
                }
            }
        }
    }

    if (hKey)
        BCryptDestroyKey(hKey);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return bSuccess;
}

BOOL BytesToBase64(
    const BYTE *pBinaryData,
    DWORD dwBinaryLen,
    char **ppOutBase64Text)
{

    if (!pBinaryData || dwBinaryLen == 0 || !ppOutBase64Text)
        return FALSE;
    *ppOutBase64Text = NULL;
    DWORD dwStrLen = 0;

    if (!CryptBinaryToStringA(pBinaryData, dwBinaryLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwStrLen))
    {
        return FALSE;
    }
    char *szBase64 = (char *)malloc(dwStrLen);
    if (!szBase64)
        return FALSE;

    if (CryptBinaryToStringA(pBinaryData, dwBinaryLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, szBase64, &dwStrLen))
    {
        *ppOutBase64Text = szBase64;
        return TRUE;
    }
    free(szBase64);
    return FALSE;
}

BOOL Base64ToBytes(
    const char *szBase64Text,
    BYTE **ppOutBinaryData,
    DWORD *pOutBinaryLen)
{
    if (!szBase64Text || !ppOutBinaryData || !pOutBinaryLen)
        return FALSE;

    *ppOutBinaryData = NULL;
    *pOutBinaryLen = 0;
    DWORD dwBinaryLen = 0, dwSkip = 0, dwFlags = 0;

    if (!CryptStringToBinaryA(szBase64Text, 0, CRYPT_STRING_BASE64, NULL, &dwBinaryLen, &dwSkip, &dwFlags))
    {
        return FALSE;
    }
    BYTE *pBinary = (BYTE *)malloc(dwBinaryLen);
    if (!pBinary)
        return FALSE;

    if (CryptStringToBinaryA(szBase64Text, 0, CRYPT_STRING_BASE64, pBinary, &dwBinaryLen, &dwSkip, &dwFlags))
    {
        *ppOutBinaryData = pBinary;
        *pOutBinaryLen = dwBinaryLen;
        return TRUE;
    }
    free(pBinary);
    return FALSE;
}

BOOL SecureEncryptString(
    const char *szPlainText,
    const char *szKey,
    char **ppOutBase64Result)
{

    if (!szPlainText || !szKey || !ppOutBase64Result)
        return FALSE;
    *ppOutBase64Result = NULL;

    BYTE *pBinaryBuffer = NULL;
    DWORD dwBinaryLen = 0;
    BOOL bResult = FALSE;

    if (EncryptAES256(szPlainText, szKey, &pBinaryBuffer, &dwBinaryLen))
    {

        bResult = BytesToBase64(pBinaryBuffer, dwBinaryLen, ppOutBase64Result);
        free(pBinaryBuffer);
    }
    return bResult;
}

BOOL SecureDecryptString(
    const char *szBase64Text,
    const char *szKey,
    char **ppOutPlainTextResult)
{
    if (!szBase64Text || !szKey || !ppOutPlainTextResult)
        return FALSE;

    *ppOutPlainTextResult = NULL;

    BYTE *pBinaryBuffer = NULL;
    DWORD dwBinaryLen = 0;
    BOOL bResult = FALSE;

    if (Base64ToBytes(szBase64Text, &pBinaryBuffer, &dwBinaryLen))
    {
        bResult = DecryptAES256(pBinaryBuffer, dwBinaryLen, szKey, ppOutPlainTextResult);
        free(pBinaryBuffer);
    }
    return bResult;
}