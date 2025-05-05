"""
Wrapper sécurisé pour encrypt_shell.py du framework OPSEC Loader

Ce module fournit une interface sécurisée et robuste pour le chiffrement et déchiffrement
de shellcode, en ajoutant des vérifications d'intégrité (HMAC) et une gestion d'erreurs
améliorées sans modifier le script original.
"""

import os
import sys
import tempfile
import hashlib
import hmac
import base64
import logging
import traceback
from typing import Dict, Any, Optional, Tuple, Union, BinaryIO

# Configuration du logger
logger = logging.getLogger("safe_encryption")
logger.setLevel(logging.INFO)

class SafeEncryption:
    """
    Wrapper sécurisé pour le chiffrement/déchiffrement de shellcode
    
    Cette classe encapsule les fonctionnalités du module encrypt_shell.py
    en ajoutant des vérifications de sécurité et une meilleure gestion des erreurs.
    """
    
    def __init__(self, framework_path: str, debug: bool = False):
        """
        Initialise le wrapper sécurisé
        
        Args:
            framework_path (str): Chemin vers le répertoire contenant le module encrypt_shell.py
            debug (bool): Active les logs de débogage détaillés
        
        Raises:
            ValueError: Si framework_path est invalide ou si le module n'est pas trouvé
        """
        self.framework_path = os.path.abspath(framework_path)
        
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Vérifier que le framework_path existe et contient le module encrypt_shell.py
        if not os.path.isdir(self.framework_path):
            raise ValueError(f"Le chemin du framework '{self.framework_path}' n'existe pas ou n'est pas un répertoire")
        
        encrypt_path = os.path.join(self.framework_path, "encrypt_shell.py")
        if not os.path.isfile(encrypt_path):
            raise ValueError(f"Le module encrypt_shell.py n'a pas été trouvé dans {self.framework_path}")
        
        # Ajouter le framework_path au sys.path pour pouvoir importer encrypt_shell
        if self.framework_path not in sys.path:
            sys.path.append(self.framework_path)
        
        # Importer le module encrypt_shell
        try:
            import encrypt_shell
            self.encrypt_module = encrypt_shell
            logger.debug(f"Module encrypt_shell importé avec succès depuis {self.framework_path}")
        except ImportError as e:
            logger.error(f"Erreur lors de l'importation du module encrypt_shell: {str(e)}")
            raise ImportError(f"Impossible d'importer le module encrypt_shell depuis {self.framework_path}: {str(e)}")
        
        # Importer également les modules de crypto
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            from Crypto.Random import get_random_bytes
            self.AES = AES
            self.pad = pad
            self.unpad = unpad
            self.get_random_bytes = get_random_bytes
            logger.debug("Modules crypto importés avec succès")
        except ImportError as e:
            logger.error(f"Erreur lors de l'importation des modules crypto: {str(e)}")
            raise ImportError(f"Impossible d'importer les modules crypto: {str(e)}")
    
    def validate_shellcode_file(self, shellcode_path: str) -> Tuple[bool, str]:
        """
        Valide un fichier de shellcode d'entrée
        
        Args:
            shellcode_path (str): Chemin vers le fichier de shellcode à valider
        
        Returns:
            Tuple[bool, str]: (succès, message d'erreur ou chemin du fichier)
        """
        # Vérifier si le fichier existe
        if not os.path.isfile(shellcode_path):
            return False, f"Le fichier '{shellcode_path}' n'existe pas"
        
        # Vérifier la taille du fichier (max 10MB)
        max_size = 10 * 1024 * 1024  # 10MB
        file_size = os.path.getsize(shellcode_path)
        if file_size == 0:
            return False, f"Le fichier '{shellcode_path}' est vide"
        if file_size > max_size:
            return False, f"Le fichier est trop volumineux ({file_size} octets). Taille maximale: 10MB"
        
        # Vérifier l'extension du fichier
        allowed_extensions = ['.bin', '.sc', '.raw', '.shellcode']
        file_ext = os.path.splitext(shellcode_path)[1].lower()
        if file_ext and file_ext not in allowed_extensions:
            logger.warning(f"Extension de fichier non standard: {file_ext}")
        
        return True, shellcode_path
    
    def encrypt_shellcode(self, 
                         shellcode_path: str, 
                         output_format: str = "bin",
                         encryption_method: str = "aes-256-cbc",
                         encryption_key: Optional[str] = None,
                         verify_integrity: bool = True) -> Dict[str, Any]:
        """
        Chiffre un shellcode de manière sécurisée
        
        Args:
            shellcode_path (str): Chemin vers le fichier de shellcode à chiffrer
            output_format (str): Format du shellcode chiffré (bin, c, cpp, py)
            encryption_method (str): Méthode de chiffrement (aes-256-cbc, aes-128-cbc, xor)
            encryption_key (Optional[str]): Clé de chiffrement (générée automatiquement si None)
            verify_integrity (bool): Si True, ajoute une vérification HMAC
        
        Returns:
            Dict[str, Any]: Résultats du chiffrement avec des informations supplémentaires
        
        Raises:
            ValueError: Si les paramètres sont invalides
            RuntimeError: Si une erreur se produit pendant le chiffrement
        """
        result = {
            "success": False,
            "error": None,
            "file_id": None,
            "original_size": 0,
            "encrypted_size": 0,
            "method": encryption_method,
            "key": None,
            "output_path": None
        }
        
        temp_dir = None
        temp_output = None
        
        try:
            # Valider le fichier d'entrée
            valid, message = self.validate_shellcode_file(shellcode_path)
            if not valid:
                raise ValueError(message)
            
            # Obtenir les détails du fichier d'entrée
            result["original_size"] = os.path.getsize(shellcode_path)
            
            # Valider les paramètres
            if output_format not in ["bin", "c", "cpp", "py"]:
                raise ValueError(f"Format de sortie '{output_format}' non pris en charge")
            
            if encryption_method not in ["aes-256-cbc", "aes-128-cbc", "xor"]:
                raise ValueError(f"Méthode de chiffrement '{encryption_method}' non prise en charge")
            
            # Créer un répertoire temporaire pour les fichiers de sortie
            temp_dir = tempfile.mkdtemp(prefix="safe_encrypt_")
            output_ext = {"bin": "bin", "c": "h", "cpp": "cpp", "py": "py"}
            temp_output = os.path.join(temp_dir, f"encrypted.{output_ext.get(output_format, 'bin')}")
            
            # Générer ou valider la clé de chiffrement
            key_size = 32  # Par défaut pour AES-256
            if encryption_method == "aes-128-cbc":
                key_size = 16
            
            if encryption_key is None:
                # Générer une clé aléatoire sécurisée
                if encryption_method.startswith("aes"):
                    from Crypto.Random import get_random_bytes
                    key_bytes = get_random_bytes(key_size)
                    encryption_key = key_bytes.hex()
                else:  # XOR
                    import random
                    key_bytes = bytes([random.randint(0, 255) for _ in range(16)])
                    encryption_key = key_bytes.hex()
                
                logger.info(f"Clé de chiffrement générée pour {encryption_method}: {encryption_key[:8]}...")
            else:
                # Valider la clé fournie
                if encryption_method.startswith("aes"):
                    if len(encryption_key) < key_size * 2:  # Clé hex doit être 2x la taille en octets
                        raise ValueError(f"Clé de chiffrement trop courte pour {encryption_method}. Attendu: {key_size*2} caractères hex")
                    
                    # Essayer de convertir en bytes
                    try:
                        key_bytes = bytes.fromhex(encryption_key[:key_size*2])
                    except ValueError:
                        # Essayer d'utiliser la clé comme utf-8
                        if len(encryption_key.encode()) < key_size:
                            raise ValueError(f"Clé de chiffrement invalide pour {encryption_method}")
                        
                        # Utiliser un hachage pour obtenir une clé de la bonne taille
                        key_bytes = hashlib.sha256(encryption_key.encode()).digest()[:key_size]
                        encryption_key = key_bytes.hex()
                else:  # XOR
                    # La clé XOR peut être de n'importe quelle taille, mais la convertir en hex
                    try:
                        key_bytes = bytes.fromhex(encryption_key)
                    except ValueError:
                        key_bytes = encryption_key.encode()
                        encryption_key = key_bytes.hex()
            
            # Déterminer les paramètres de chiffrement
            encryption_params = {
                "input_file": shellcode_path,
                "output_file": temp_output,
                "encryption_method": encryption_method,
                "key": encryption_key,
                "output_format": output_format
            }
            
            # Ajouter des options de sécurité supplémentaires
            if verify_integrity:
                encryption_params["verify_integrity"] = True
            
            logger.info(f"Chiffrement lancé avec paramètres: {encryption_params}")
            
            # Appeler le module de chiffrement
            try:
                # Si la méthode de chiffrement accepte des paramètres nommés
                success, details = self.encrypt_module.encrypt_shellcode(**encryption_params)
                
                if not success:
                    raise RuntimeError(f"Échec du chiffrement: {details}")
            except (AttributeError, TypeError):
                # Méthode alternative si l'API a changé
                logger.warning("API du module encrypt_shell non standard, utilisation d'une approche alternative")
                
                # Implémenter notre propre chiffrement
                with open(shellcode_path, 'rb') as f:
                    shellcode_data = f.read()
                
                if encryption_method.startswith("aes"):
                    iv = self.get_random_bytes(16)
                    
                    if encryption_method == "aes-256-cbc":
                        cipher = self.AES.new(key_bytes, self.AES.MODE_CBC, iv)
                    else:  # aes-128-cbc
                        cipher = self.AES.new(key_bytes, self.AES.MODE_CBC, iv)
                    
                    # Padding et chiffrement
                    padded_data = self.pad(shellcode_data, self.AES.block_size)
                    encrypted_data = cipher.encrypt(padded_data)
                    
                    # Ajouter l'entête et le HMAC si demandé
                    if verify_integrity:
                        # Calculer un HMAC
                        h = hmac.new(key_bytes, encrypted_data, hashlib.sha256)
                        hmac_digest = h.digest()
                        
                        # Format: signature + version + IV + HMAC + données chiffrées
                        header = b'ESEC' + b'\x02\x00\x00\x00' + iv + hmac_digest
                    else:
                        # Format: signature + version + IV + données chiffrées
                        header = b'ESEC' + b'\x01\x00\x00\x00' + iv
                    
                    data_to_write = header + encrypted_data
                else:  # XOR
                    # Chiffrement XOR simple
                    encrypted_data = bytearray()
                    for i, b in enumerate(shellcode_data):
                        encrypted_data.append(b ^ key_bytes[i % len(key_bytes)])
                    
                    # Ajouter un en-tête simple
                    header = b'ESEC' + b'\x00\x00\x00\x00'
                    data_to_write = header + encrypted_data
                
                # Écrire les données selon le format
                if output_format == "bin":
                    with open(temp_output, 'wb') as f:
                        f.write(data_to_write)
                elif output_format == "c":
                    with open(temp_output, 'w') as f:
                        f.write('unsigned char encrypted_shellcode[] = {\n    ')
                        for i, b in enumerate(data_to_write):
                            f.write(f"0x{b:02x}")
                            if i < len(data_to_write) - 1:
                                f.write(", ")
                            if (i + 1) % 12 == 0:
                                f.write("\n    ")
                        f.write("\n};\n")
                        f.write(f"unsigned int encrypted_shellcode_len = {len(data_to_write)};\n")
                        if encryption_method.startswith("aes"):
                            f.write(f'unsigned char key[] = {{{", ".join([f"0x{b:02x}" for b in key_bytes])}}};\n')
                elif output_format == "cpp":
                    with open(temp_output, 'w') as f:
                        f.write('#include <vector>\n\n')
                        f.write('std::vector<unsigned char> encrypted_shellcode = {\n    ')
                        for i, b in enumerate(data_to_write):
                            f.write(f"0x{b:02x}")
                            if i < len(data_to_write) - 1:
                                f.write(", ")
                            if (i + 1) % 12 == 0:
                                f.write("\n    ")
                        f.write("\n};\n")
                        if encryption_method.startswith("aes"):
                            f.write(f'std::vector<unsigned char> key = {{{", ".join([f"0x{b:02x}" for b in key_bytes])}}};\n')
                elif output_format == "py":
                    with open(temp_output, 'w') as f:
                        f.write('encrypted_shellcode = b"')
                        for b in data_to_write:
                            f.write(f"\\x{b:02x}")
                        f.write('"\n')
                        if encryption_method.startswith("aes"):
                            f.write(f'key = b"{key_bytes.hex()}"\n')
                
                success = True
            
            # Vérifier que le fichier de sortie a été créé
            if not os.path.exists(temp_output):
                raise RuntimeError(f"Le fichier de sortie '{temp_output}' n'a pas été créé")
            
            # Obtenir la taille du shellcode chiffré
            result["encrypted_size"] = os.path.getsize(temp_output)
            
            # Calculer l'empreinte SHA-256 du shellcode chiffré
            sha256 = hashlib.sha256()
            with open(temp_output, 'rb') as f:
                sha256.update(f.read())
            result["sha256"] = sha256.hexdigest()
            
            # Générer un ID unique pour le fichier
            from uuid import uuid4
            result["file_id"] = uuid4().hex
            
            result["success"] = True
            result["key"] = encryption_key
            result["output_path"] = temp_output
            
            logger.info(f"Chiffrement réussi: {result['original_size']} -> {result['encrypted_size']} octets")
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement du shellcode: {str(e)}")
            logger.debug(traceback.format_exc())
            
            result["success"] = False
            result["error"] = str(e)
            
            # Nettoyer les fichiers temporaires en cas d'erreur
            if temp_output and os.path.exists(temp_output):
                try:
                    os.unlink(temp_output)
                except:
                    pass
            
            if temp_dir and os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except:
                    pass
            
            return result
    
    def decrypt_shellcode(self, 
                         encrypted_path: str, 
                         encryption_key: str,
                         output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Déchiffre un shellcode de manière sécurisée
        
        Args:
            encrypted_path (str): Chemin vers le fichier de shellcode chiffré
            encryption_key (str): Clé de chiffrement
            output_file (Optional[str]): Chemin du fichier de sortie (généré si None)
        
        Returns:
            Dict[str, Any]: Résultats du déchiffrement avec des informations supplémentaires
        
        Raises:
            ValueError: Si les paramètres sont invalides
            RuntimeError: Si une erreur se produit pendant le déchiffrement
        """
        result = {
            "success": False,
            "error": None,
            "encrypted_size": 0,
            "decrypted_size": 0,
            "method": "unknown",
            "output_path": None,
            "integrity_verified": False
        }
        
        temp_dir = None
        temp_output = None
        
        try:
            # Vérifier si le fichier existe
            if not os.path.isfile(encrypted_path):
                raise ValueError(f"Le fichier '{encrypted_path}' n'existe pas")
            
            # Obtenir les détails du fichier d'entrée
            result["encrypted_size"] = os.path.getsize(encrypted_path)
            
            # Créer un répertoire temporaire pour les fichiers de sortie
            temp_dir = tempfile.mkdtemp(prefix="safe_decrypt_")
            temp_output = os.path.join(temp_dir, "decrypted.bin")
            if output_file is None:
                output_file = temp_output
            
            # Valider la clé de chiffrement
            if not encryption_key:
                raise ValueError("Clé de chiffrement requise")
            
            # Convertir la clé en bytes si c'est une chaîne hex
            try:
                key_bytes = bytes.fromhex(encryption_key)
            except ValueError:
                # Utiliser la clé telle quelle
                key_bytes = encryption_key.encode()
            
            # Lire le fichier d'entrée
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Vérifier l'en-tête du fichier
            if len(encrypted_data) < 8 or encrypted_data[:4] != b'ESEC':
                logger.warning("Format non reconnu, tentative de déchiffrement direct...")
                
                # Essayer d'appeler le module de déchiffrement du framework
                try:
                    success = self.encrypt_module.decrypt_shellcode(
                        encrypted_path, 
                        output_file,
                        encryption_key
                    )
                    
                    if not success:
                        raise RuntimeError("Échec du déchiffrement")
                    
                    # Vérifier que le fichier de sortie a été créé
                    if not os.path.exists(output_file):
                        raise RuntimeError(f"Le fichier de sortie '{output_file}' n'a pas été créé")
                    
                    # Obtenir la taille du shellcode déchiffré
                    result["decrypted_size"] = os.path.getsize(output_file)
                    result["success"] = True
                    result["output_path"] = output_file
                    
                    return result
                except Exception as e:
                    logger.error(f"Échec du déchiffrement avec le module original: {str(e)}")
                    raise RuntimeError(f"Format de fichier non reconnu et échec du déchiffrement: {str(e)}")
            
            # Déterminer la version du format
            version = int.from_bytes(encrypted_data[4:8], byteorder='little')
            
            if version == 0:
                # Format XOR simple: signature(4) + version(4) + données
                xor_data = encrypted_data[8:]
                decrypted_data = bytearray()
                for i, b in enumerate(xor_data):
                    decrypted_data.append(b ^ key_bytes[i % len(key_bytes)])
                
                # Écrire les données déchiffrées
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
                result["method"] = "xor"
                
            elif version == 1:
                # Format AES v1: signature(4) + version(4) + IV(16) + données
                iv = encrypted_data[8:24]
                aes_data = encrypted_data[24:]
                
                # Déchiffrer avec AES
                if len(key_bytes) == 32:
                    cipher = self.AES.new(key_bytes, self.AES.MODE_CBC, iv)
                    result["method"] = "aes-256-cbc"
                else:
                    cipher = self.AES.new(key_bytes[:16], self.AES.MODE_CBC, iv)
                    result["method"] = "aes-128-cbc"
                
                try:
                    decrypted_data = self.unpad(cipher.decrypt(aes_data), self.AES.block_size)
                except ValueError as e:
                    raise RuntimeError(f"Erreur de padding lors du déchiffrement: {str(e)}")
                
                # Écrire les données déchiffrées
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
            elif version == 2:
                # Format AES v2 avec HMAC: signature(4) + version(4) + IV(16) + HMAC(32) + données
                iv = encrypted_data[8:24]
                hmac_digest = encrypted_data[24:56]
                aes_data = encrypted_data[56:]
                
                # Vérifier le HMAC
                h = hmac.new(key_bytes, aes_data, hashlib.sha256)
                calculated_hmac = h.digest()
                
                if not hmac.compare_digest(calculated_hmac, hmac_digest):
                    raise RuntimeError("Échec de la vérification d'intégrité HMAC")
                
                result["integrity_verified"] = True
                
                # Déchiffrer avec AES
                if len(key_bytes) == 32:
                    cipher = self.AES.new(key_bytes, self.AES.MODE_CBC, iv)
                    result["method"] = "aes-256-cbc"
                else:
                    cipher = self.AES.new(key_bytes[:16], self.AES.MODE_CBC, iv)
                    result["method"] = "aes-128-cbc"
                
                try:
                    decrypted_data = self.unpad(cipher.decrypt(aes_data), self.AES.block_size)
                except ValueError as e:
                    raise RuntimeError(f"Erreur de padding lors du déchiffrement: {str(e)}")
                
                # Écrire les données déchiffrées
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
            else:
                raise RuntimeError(f"Version de format non prise en charge: {version}")
            
            # Vérifier que le fichier de sortie a été créé
            if not os.path.exists(output_file):
                raise RuntimeError(f"Le fichier de sortie '{output_file}' n'a pas été créé")
            
            # Obtenir la taille du shellcode déchiffré
            result["decrypted_size"] = os.path.getsize(output_file)
            
            result["success"] = True
            result["output_path"] = output_file
            
            logger.info(f"Déchiffrement réussi: {result['encrypted_size']} -> {result['decrypted_size']} octets")
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement du shellcode: {str(e)}")
            logger.debug(traceback.format_exc())
            
            result["success"] = False
            result["error"] = str(e)
            
            # Nettoyer les fichiers temporaires en cas d'erreur
            if temp_output and os.path.exists(temp_output):
                try:
                    os.unlink(temp_output)
                except:
                    pass
            
            if temp_dir and os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except:
                    pass
            
            return result
    
    def cleanup(self, output_path: Optional[str] = None):
        """
        Nettoie les fichiers temporaires
        
        Args:
            output_path (Optional[str]): Chemin du fichier de sortie à supprimer
        """
        if output_path and os.path.exists(output_path):
            try:
                os.unlink(output_path)
                parent_dir = os.path.dirname(output_path)
                if os.path.isdir(parent_dir) and parent_dir.startswith(tempfile.gettempdir()):
                    os.rmdir(parent_dir)
                logger.debug(f"Fichier temporaire supprimé: {output_path}")
            except Exception as e:
                logger.warning(f"Erreur lors de la suppression du fichier temporaire '{output_path}': {str(e)}")


# Fonctions utilitaires pour une utilisation directe
def safe_encrypt_shellcode(framework_path: str, shellcode_path: str, **kwargs) -> Dict[str, Any]:
    """
    Fonction utilitaire pour chiffrer un shellcode de manière sécurisée
    
    Args:
        framework_path (str): Chemin vers le répertoire du framework
        shellcode_path (str): Chemin vers le fichier de shellcode à chiffrer
        **kwargs: Arguments supplémentaires passés à encrypt_shellcode
    
    Returns:
        Dict[str, Any]: Résultats du chiffrement
    """
    encryptor = SafeEncryption(framework_path)
    return encryptor.encrypt_shellcode(shellcode_path, **kwargs)


def safe_decrypt_shellcode(framework_path: str, encrypted_path: str, encryption_key: str, **kwargs) -> Dict[str, Any]:
    """
    Fonction utilitaire pour déchiffrer un shellcode de manière sécurisée
    
    Args:
        framework_path (str): Chemin vers le répertoire du framework
        encrypted_path (str): Chemin vers le fichier de shellcode chiffré
        encryption_key (str): Clé de chiffrement
        **kwargs: Arguments supplémentaires passés à decrypt_shellcode
    
    Returns:
        Dict[str, Any]: Résultats du déchiffrement
    """
    encryptor = SafeEncryption(framework_path)
    return encryptor.decrypt_shellcode(encrypted_path, encryption_key, **kwargs)