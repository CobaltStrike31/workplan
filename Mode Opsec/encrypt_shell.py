#!/usr/bin/env python3
import os, sys, struct, secrets, hashlib
from Crypto.Cipher import AES

def e(data, key, algo=1):
    """Chiffre un shellcode avec clé (AES-CBC pour compatibilité)"""
    # Génération d'éléments aléatoires
    salt = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)  # AES-CBC utilise toujours 16 octets
    
    # Dérivation de clé sans PBKDF2 externe
    key_bytes = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000, 32)
    
    # Rembourrage PKCS#7 pour CBC
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len]) * pad_len
    
    # Chiffrement CBC (au lieu de GCM)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded_data)
    
    # Format compatible avec le loader
    header = struct.pack(">BBHH", 1, 2, 32, 16)  # algo=2 pour CBC
    result = bytearray(header)
    result.extend(salt)
    result.extend(iv)
    result.extend(ct)
    
    return bytes(result)

def main():
    if len(sys.argv) < 3:
        return 1
    
    # Lecture binaire avec gestion d'erreur
    try:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
    except:
        return 1
    
    # Extraction arguments avec validation
    key = sys.argv[2]
    if not key:
        return 1
        
    output = sys.argv[3] if len(sys.argv) > 3 else sys.argv[1] + ".enc"
    
    # Chiffrement
    result = e(data, key)
    if not result:
        return 1
    
    # Écriture sécurisée
    try:
        # Écrire d'abord dans un fichier temporaire
        temp_file = output + ".tmp"
        with open(temp_file, 'wb') as f:
            f.write(result)
        
        # Renommer pour atomicité
        if os.path.exists(output):
            os.remove(output)
        os.rename(temp_file, output)
    except:
        if os.path.exists(temp_file):
            try: os.remove(temp_file)
            except: pass
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())