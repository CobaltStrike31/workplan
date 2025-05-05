"""
Wrapper sécurisé pour key_formatter_.py du framework OPSEC Loader

Ce module fournit une interface sécurisée et robuste pour le formatage des clés
de chiffrement, en ajoutant des vérifications de sécurité et une gestion d'erreurs
améliorées sans modifier le script original.
"""

import os
import sys
import tempfile
import hashlib
import logging
import traceback
from typing import Dict, Any, Optional, Tuple, Union, List

# Configuration du logger
logger = logging.getLogger("safe_key_formatter")
logger.setLevel(logging.INFO)

class SafeKeyFormatter:
    """
    Wrapper sécurisé pour le formatage des clés de chiffrement
    
    Cette classe encapsule les fonctionnalités du module key_formatter_.py
    en ajoutant des vérifications de sécurité et une meilleure gestion des erreurs.
    """
    
    def __init__(self, framework_path: str, debug: bool = False):
        """
        Initialise le wrapper sécurisé
        
        Args:
            framework_path (str): Chemin vers le répertoire contenant le module key_formatter_.py
            debug (bool): Active les logs de débogage détaillés
        
        Raises:
            ValueError: Si framework_path est invalide ou si le module n'est pas trouvé
        """
        self.framework_path = os.path.abspath(framework_path)
        
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Vérifier que le framework_path existe et contient le module key_formatter_.py
        if not os.path.isdir(self.framework_path):
            raise ValueError(f"Le chemin du framework '{self.framework_path}' n'existe pas ou n'est pas un répertoire")
        
        formatter_path = os.path.join(self.framework_path, "key_formatter_.py")
        if not os.path.isfile(formatter_path):
            raise ValueError(f"Le module key_formatter_.py n'a pas été trouvé dans {self.framework_path}")
        
        # Ajouter le framework_path au sys.path pour pouvoir importer key_formatter_
        if self.framework_path not in sys.path:
            sys.path.append(self.framework_path)
        
        # Importer le module key_formatter_
        try:
            import key_formatter_
            self.formatter_module = key_formatter_
            logger.debug(f"Module key_formatter_ importé avec succès depuis {self.framework_path}")
        except ImportError as e:
            logger.error(f"Erreur lors de l'importation du module key_formatter_: {str(e)}")
            raise ImportError(f"Impossible d'importer le module key_formatter_ depuis {self.framework_path}: {str(e)}")
    
    def validate_key(self, key: str) -> Tuple[bool, str]:
        """
        Valide une clé de chiffrement
        
        Args:
            key (str): Clé à valider (format hexadécimal)
        
        Returns:
            Tuple[bool, str]: (succès, message d'erreur ou clé validée)
        """
        if not key:
            return False, "Clé vide"
        
        # Si la clé est déjà en hexadécimal
        if all(c in '0123456789abcdefABCDEF' for c in key):
            # Vérifier que la longueur est valide (multiple de 2)
            if len(key) % 2 != 0:
                return False, "La longueur de la clé hex doit être un multiple de 2"
            
            # Vérifier la taille minimale (128 bits = 16 octets = 32 caractères hex)
            if len(key) < 32:
                logger.warning(f"Clé de taille inférieure à 128 bits ({len(key)//2 * 8} bits)")
            
            return True, key.lower()
        
        # Si la clé est en ASCII, la convertir en hex
        try:
            key_bytes = key.encode('utf-8')
            hex_key = key_bytes.hex()
            
            # Vérifier la taille minimale (128 bits = 16 octets)
            if len(key_bytes) < 16:
                logger.warning(f"Clé de taille inférieure à 128 bits ({len(key_bytes) * 8} bits)")
            
            return True, hex_key
        except Exception as e:
            return False, f"Erreur lors de la conversion de la clé en hexadécimal: {str(e)}"
    
    def format_key(self, 
                  key: str, 
                  format_type: str = "cpp",
                  var_name: str = "AES_KEY",
                  add_comments: bool = True,
                  add_checksum: bool = True) -> Dict[str, Any]:
        """
        Formate une clé de chiffrement pour l'inclusion dans le code
        
        Args:
            key (str): Clé à formater (format hexadécimal)
            format_type (str): Type de format (cpp, c, python)
            var_name (str): Nom de la variable pour la clé
            add_comments (bool): Si True, ajoute des commentaires
            add_checksum (bool): Si True, ajoute une vérification de la somme de contrôle
        
        Returns:
            Dict[str, Any]: Résultats du formatage
        
        Raises:
            ValueError: Si les paramètres sont invalides
            RuntimeError: Si une erreur se produit pendant le formatage
        """
        result = {
            "success": False,
            "error": None,
            "formatted_key": None,
            "key_info": None,
            "format_type": format_type,
            "checksum": None
        }
        
        try:
            # Valider la clé
            valid, message = self.validate_key(key)
            if not valid:
                raise ValueError(message)
            
            hex_key = message  # message contient la clé validée
            
            # Valider le type de format
            if format_type not in ["cpp", "c", "python"]:
                raise ValueError(f"Type de format '{format_type}' non pris en charge")
            
            # Valider le nom de variable
            if not var_name:
                var_name = "AES_KEY"
            elif not var_name.isidentifier():
                var_name = "AES_KEY"
                logger.warning(f"Nom de variable '{var_name}' non valide, utilisation de 'AES_KEY'")
            
            # Calculer le checksum
            key_bytes = bytes.fromhex(hex_key)
            sha256 = hashlib.sha256(key_bytes).hexdigest()
            result["checksum"] = sha256
            
            # Évaluer la force de la clé
            key_strength = "Faible"
            if len(key_bytes) >= 16:
                key_strength = "Moyenne"
            if len(key_bytes) >= 24:
                key_strength = "Bonne"
            if len(key_bytes) >= 32:
                key_strength = "Excellente"
            
            # Obtenir des informations sur la clé
            key_info = {
                "size_bytes": len(key_bytes),
                "size_bits": len(key_bytes) * 8,
                "strength": key_strength,
                "checksum": sha256[:8]  # Premiers 8 caractères du SHA-256
            }
            result["key_info"] = key_info
            
            # Appeler le formateur du module
            try:
                # Utiliser la fonction de formatage du module original
                formatted_key, info = self.formatter_module.format_key(
                    hex_key,
                    format_type,
                    add_info=add_comments
                )
                
                # Ajouter le checksum si demandé
                if add_checksum and formatted_key:
                    if format_type == "python":
                        checksum_line = f"# Checksum (SHA-256): {sha256}\n"
                        formatted_key = checksum_line + formatted_key
                    elif format_type in ["c", "cpp"]:
                        checksum_line = f"// Checksum (SHA-256): {sha256}\n"
                        formatted_key = checksum_line + formatted_key
                
                result["formatted_key"] = formatted_key
                
            except (AttributeError, TypeError):
                # Implémentation alternative si l'API a changé
                logger.warning("API du module key_formatter_ non standard, utilisation d'une approche alternative")
                
                # Formater la clé selon le type
                if format_type == "cpp":
                    # Format C++
                    formatted_lines = []
                    
                    if add_comments:
                        formatted_lines.append(f"// Clé AES ({key_info['size_bits']} bits)")
                        formatted_lines.append(f"// Strength: {key_strength}")
                        if add_checksum:
                            formatted_lines.append(f"// Checksum (SHA-256): {sha256}")
                        formatted_lines.append("")
                    
                    formatted_lines.append(f"const uint8_t {var_name}[] = {{")
                    
                    # Formater les octets
                    hex_bytes = [hex_key[i:i+2] for i in range(0, len(hex_key), 2)]
                    rows = []
                    current_row = []
                    
                    for i, byte in enumerate(hex_bytes):
                        current_row.append(f"0x{byte}")
                        if (i + 1) % 12 == 0 or i == len(hex_bytes) - 1:
                            rows.append(", ".join(current_row))
                            current_row = []
                    
                    for i, row in enumerate(rows):
                        if i < len(rows) - 1:
                            formatted_lines.append(f"    {row},")
                        else:
                            formatted_lines.append(f"    {row}")
                    
                    formatted_lines.append("};")
                    formatted_lines.append("")
                    formatted_lines.append(f"const size_t {var_name}_LEN = sizeof({var_name});")
                    
                    formatted_key = "\n".join(formatted_lines)
                
                elif format_type == "c":
                    # Format C
                    formatted_lines = []
                    
                    if add_comments:
                        formatted_lines.append(f"/* Clé AES ({key_info['size_bits']} bits) */")
                        formatted_lines.append(f"/* Strength: {key_strength} */")
                        if add_checksum:
                            formatted_lines.append(f"/* Checksum (SHA-256): {sha256} */")
                        formatted_lines.append("")
                    
                    formatted_lines.append(f"unsigned char {var_name}[] = {{")
                    
                    # Formater les octets
                    hex_bytes = [hex_key[i:i+2] for i in range(0, len(hex_key), 2)]
                    rows = []
                    current_row = []
                    
                    for i, byte in enumerate(hex_bytes):
                        current_row.append(f"0x{byte}")
                        if (i + 1) % 12 == 0 or i == len(hex_bytes) - 1:
                            rows.append(", ".join(current_row))
                            current_row = []
                    
                    for i, row in enumerate(rows):
                        if i < len(rows) - 1:
                            formatted_lines.append(f"    {row},")
                        else:
                            formatted_lines.append(f"    {row}")
                    
                    formatted_lines.append("};")
                    formatted_lines.append("")
                    formatted_lines.append(f"unsigned int {var_name}_LEN = sizeof({var_name});")
                    
                    formatted_key = "\n".join(formatted_lines)
                
                elif format_type == "python":
                    # Format Python
                    formatted_lines = []
                    
                    if add_comments:
                        formatted_lines.append(f"# Clé AES ({key_info['size_bits']} bits)")
                        formatted_lines.append(f"# Strength: {key_strength}")
                        if add_checksum:
                            formatted_lines.append(f"# Checksum (SHA-256): {sha256}")
                        formatted_lines.append("")
                    
                    # Version courte (utilisant bytes.fromhex)
                    formatted_lines.append(f"{var_name} = bytes.fromhex('{hex_key}')")
                    
                    # Version alternative (utilisant une chaîne d'octets)
                    formatted_lines.append("")
                    formatted_lines.append(f"# Alternative:")
                    hex_escaped = "".join([f"\\x{hex_key[i:i+2]}" for i in range(0, len(hex_key), 2)])
                    formatted_lines.append(f"{var_name}_alt = b'{hex_escaped}'")
                    
                    formatted_key = "\n".join(formatted_lines)
                
                result["formatted_key"] = formatted_key
            
            result["success"] = True
            logger.info(f"Formatage réussi pour une clé de {key_info['size_bits']} bits")
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors du formatage de la clé: {str(e)}")
            logger.debug(traceback.format_exc())
            
            result["success"] = False
            result["error"] = str(e)
            
            return result
    
    def generate_key(self, size_bytes: int = 32, format_type: str = "cpp") -> Dict[str, Any]:
        """
        Génère une clé de chiffrement aléatoire et la formate
        
        Args:
            size_bytes (int): Taille de la clé en octets (16, 24 ou 32)
            format_type (str): Type de format (cpp, c, python)
        
        Returns:
            Dict[str, Any]: Résultats de la génération et du formatage
        
        Raises:
            ValueError: Si les paramètres sont invalides
            RuntimeError: Si une erreur se produit pendant la génération
        """
        result = {
            "success": False,
            "error": None,
            "key": None,
            "formatted_key": None,
            "key_info": None
        }
        
        try:
            # Valider la taille de la clé
            valid_sizes = [16, 24, 32]  # 128, 192, 256 bits
            if size_bytes not in valid_sizes:
                logger.warning(f"Taille de clé non standard: {size_bytes} octets")
                # Utiliser la taille valide la plus proche
                size_bytes = min(valid_sizes, key=lambda x: abs(x - size_bytes))
                logger.info(f"Utilisation de la taille standard la plus proche: {size_bytes} octets")
            
            # Générer une clé aléatoire
            try:
                from Crypto.Random import get_random_bytes
                key_bytes = get_random_bytes(size_bytes)
            except ImportError:
                # Méthode alternative avec os.urandom
                import os
                key_bytes = os.urandom(size_bytes)
            
            # Convertir en hexadécimal
            hex_key = key_bytes.hex()
            result["key"] = hex_key
            
            # Formater la clé
            format_result = self.format_key(hex_key, format_type)
            if not format_result["success"]:
                raise RuntimeError(f"Erreur lors du formatage de la clé: {format_result['error']}")
            
            result.update(format_result)
            result["success"] = True
            
            logger.info(f"Génération et formatage réussis pour une clé de {size_bytes * 8} bits")
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération de la clé: {str(e)}")
            logger.debug(traceback.format_exc())
            
            result["success"] = False
            result["error"] = str(e)
            
            return result


# Fonctions utilitaires pour une utilisation directe
def safe_format_key(framework_path: str, key: str, **kwargs) -> Dict[str, Any]:
    """
    Fonction utilitaire pour formater une clé de manière sécurisée
    
    Args:
        framework_path (str): Chemin vers le répertoire du framework
        key (str): Clé à formater (format hexadécimal)
        **kwargs: Arguments supplémentaires passés à format_key
    
    Returns:
        Dict[str, Any]: Résultats du formatage
    """
    formatter = SafeKeyFormatter(framework_path)
    return formatter.format_key(key, **kwargs)


def safe_generate_key(framework_path: str, size_bytes: int = 32, **kwargs) -> Dict[str, Any]:
    """
    Fonction utilitaire pour générer et formater une clé de manière sécurisée
    
    Args:
        framework_path (str): Chemin vers le répertoire du framework
        size_bytes (int): Taille de la clé en octets (16, 24 ou 32)
        **kwargs: Arguments supplémentaires passés à format_key
    
    Returns:
        Dict[str, Any]: Résultats de la génération et du formatage
    """
    formatter = SafeKeyFormatter(framework_path)
    return formatter.generate_key(size_bytes, **kwargs)