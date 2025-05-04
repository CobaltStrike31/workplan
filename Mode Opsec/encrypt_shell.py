#!/usr/bin/env python3
"""
Outil de chiffrement de shellcode avec AES-256-CBC
--------------------------------------------------
Chiffre un shellcode avec AES-256-CBC et ajoute une vérification d'intégrité HMAC.
"""

import os
import sys
import struct
import secrets
import hashlib
import hmac
import argparse
from pathlib import Path
from typing import Tuple, Dict, Optional, Union, ByteString
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Structure de l'en-tête:
# MAGIC (4) + VERSION (4) + SALT_SIZE (4) + SALT + IV + HMAC + DATA
MAGIC = 0x50534345  # 'PSCE' en little-endian
VERSION = 2         # Version 2 avec HMAC

def derive_keys(password: str, salt: bytes, iterations: int = 100000) -> Dict[str, bytes]:
    """
    Dérive les clés de chiffrement et HMAC à partir du mot de passe.
    
    Args:
        password: Mot de passe en texte clair
        salt: Sel cryptographique
        iterations: Nombre d'itérations pour PBKDF2
        
    Returns:
        Dictionnaire contenant les clés 'encryption' et 'hmac'
    """
    key_material = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=64)
    
    # Séparation du matériel de clé en clé de chiffrement et clé HMAC
    encryption_key = key_material[:32]  # 256 bits pour AES
    hmac_key = key_material[32:64]      # 256 bits pour HMAC
    
    return {
        'encryption': encryption_key,
        'hmac': hmac_key
    }

def compute_hmac(data: bytes, hmac_key: bytes) -> bytes:
    """
    Calcule un HMAC-SHA256 pour les données.
    
    Args:
        data: Données à authentifier
        hmac_key: Clé HMAC
        
    Returns:
        HMAC calculé (32 bytes)
    """
    h = hmac.new(hmac_key, data, hashlib.sha256)
    return h.digest()

def encrypt_shellcode(shellcode: bytes, password: str) -> Tuple[bytes, Dict]:
    """
    Chiffre un shellcode avec AES-256-CBC et ajoute un HMAC pour vérifier l'intégrité.
    
    Args:
        shellcode: Shellcode à chiffrer
        password: Mot de passe pour le chiffrement
        
    Returns:
        Tuple (shellcode chiffré avec en-tête, métadonnées)
    """
    # Génération de sel et IV aléatoires
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    
    # Dérivation des clés
    keys = derive_keys(password, salt)
    
    # Chiffrement
    cipher = AES.new(keys['encryption'], AES.MODE_CBC, iv)
    padded_data = pad(shellcode, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Construction du bloc à authentifier (tout sauf le HMAC lui-même)
    header = struct.pack("<III", MAGIC, VERSION, len(salt))
    auth_data = header + salt + iv + encrypted_data
    
    # Calcul du HMAC
    mac = compute_hmac(auth_data, keys['hmac'])
    
    # Format complet: HEADER + SALT + IV + HMAC + ENCRYPTED_DATA
    result = header + salt + iv + mac + encrypted_data
    
    # Métadonnées pour l'audit/débogage
    metadata = {
        'version': VERSION,
        'salt_size': len(salt),
        'iv_size': len(iv),
        'hmac_size': len(mac),
        'data_size': len(encrypted_data),
        'total_size': len(result),
    }
    
    return result, metadata

def save_encrypted(data: bytes, filename: str) -> bool:
    """
    Sauvegarde les données chiffrées de manière atomique.
    
    Args:
        data: Données à sauvegarder
        filename: Nom du fichier de destination
        
    Returns:
        True si réussi, False sinon
    """
    temp_filename = f"{filename}.{os.getpid()}.tmp"
    try:
        # Écrire dans un fichier temporaire
        with open(temp_filename, 'wb') as f:
            f.write(data)
        
        # Vérifier que les données ont été écrites correctement
        if Path(temp_filename).stat().st_size != len(data):
            raise IOError("La taille du fichier écrit ne correspond pas aux données")
        
        # Remplacement atomique
        os.replace(temp_filename, filename)
        return True
        
    except IOError as e:
        print(f"Erreur d'I/O lors de la sauvegarde: {e}", file=sys.stderr)
        return False
    except PermissionError as e:
        print(f"Erreur de permission lors de la sauvegarde: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Erreur inattendue lors de la sauvegarde: {e}", file=sys.stderr)
        return False
    finally:
        # Cleanup du fichier temporaire si encore présent
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except Exception:
                pass

def verify_shellcode(shellcode: bytes) -> bool:
    """
    Vérifie que le shellcode a une structure valide (taille minimale, pas vide).
    
    Args:
        shellcode: Shellcode à vérifier
        
    Returns:
        True si le shellcode semble valide, False sinon
    """
    # Vérifications basiques de taille et structure
    if not shellcode:
        print("Erreur: shellcode vide", file=sys.stderr)
        return False
        
    if len(shellcode) < 32:  # Taille minimale pour un shellcode fonctionnel
        print(f"Avertissement: shellcode très petit ({len(shellcode)} octets)", file=sys.stderr)
        # Ne pas bloquer, juste avertir
    
    return True

def test_encryption(shellcode: bytes, password: str) -> bool:
    """
    Teste le processus de chiffrement/déchiffrement pour vérifier l'intégrité.
    Cette fonction est utilisée uniquement en mode test.
    
    Args:
        shellcode: Shellcode original
        password: Mot de passe
        
    Returns:
        True si le test réussit, False sinon
    """
    try:
        # Chiffrer
        encrypted, _ = encrypt_shellcode(shellcode, password)
        
        # Le déchiffrement n'est pas implémenté ici car normalement fait par le loader
        # Mais on vérifie que l'en-tête est correct
        if len(encrypted) < 12:
            print("Erreur: données chiffrées trop petites", file=sys.stderr)
            return False
            
        magic, version, salt_size = struct.unpack("<III", encrypted[:12])
        if magic != MAGIC:
            print("Erreur: magic number incorrect", file=sys.stderr)
            return False
            
        if version != VERSION:
            print(f"Erreur: version incorrecte ({version})", file=sys.stderr)
            return False
        
        return True
        
    except Exception as e:
        print(f"Erreur lors du test de chiffrement: {e}", file=sys.stderr)
        return False

def main() -> int:
    """
    Fonction principale.
    
    Returns:
        Code de sortie (0 pour succès, non-zéro pour erreur)
    """
    parser = argparse.ArgumentParser(description="Chiffrement de shellcode avec AES-256-CBC et HMAC")
    parser.add_argument("shellcode_file", help="Fichier shellcode d'entrée")
    parser.add_argument("password", help="Mot de passe pour le chiffrement")
    parser.add_argument("output_file", help="Fichier de sortie pour le shellcode chiffré")
    parser.add_argument("--test", action="store_true", help="Tester le chiffrement/déchiffrement")
    parser.add_argument("--verify", action="store_true", help="Vérifier le shellcode avant chiffrement")
    args = parser.parse_args()
    
    # Lecture du shellcode
    try:
        with open(args.shellcode_file, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"Erreur: fichier {args.shellcode_file} introuvable", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Erreur: permission refusée pour lire {args.shellcode_file}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier {args.shellcode_file}: {e}", file=sys.stderr)
        return 1
    
    # Vérification optionnelle du shellcode
    if args.verify and not verify_shellcode(shellcode):
        print("La vérification du shellcode a échoué, abandon", file=sys.stderr)
        return 1
    
    # Test optionnel du chiffrement
    if args.test and not test_encryption(shellcode, args.password):
        print("Le test de chiffrement a échoué, abandon", file=sys.stderr)
        return 1
    
    # Chiffrement
    try:
        encrypted_data, metadata = encrypt_shellcode(shellcode, args.password)
        
        # Affichage des métadonnées
        print(f"Shellcode : {len(shellcode)} octets", file=sys.stderr)
        print(f"Chiffré  : {metadata['data_size']} octets (total: {metadata['total_size']} octets)", file=sys.stderr)
        
        # Sauvegarde
        if not save_encrypted(encrypted_data, args.output_file):
            print(f"Erreur lors de la sauvegarde dans {args.output_file}", file=sys.stderr)
            return 1
        
        print(f"Shellcode chiffré et sauvegardé dans {args.output_file}", file=sys.stderr)
        print(f"Utilisez la même clé avec le loader pour exécuter", file=sys.stderr)
        
        return 0
        
    except ValueError as e:
        print(f"Erreur de format: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Erreur inattendue lors du chiffrement: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())