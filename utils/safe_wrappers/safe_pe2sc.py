"""
Wrapper sécurisé pour custom_pe2sc.py du framework OPSEC Loader

Ce module fournit une interface sécurisée et robuste pour convertir les fichiers PE
en shellcode, en appliquant des vérifications de sécurité et une gestion d'erreurs
améliorées sans modifier le script original.
"""

import os
import sys
import tempfile
import hashlib
import logging
import traceback
from typing import Dict, Any, Optional, Tuple, Union

# Configuration du logger
logger = logging.getLogger("safe_pe2sc")
logger.setLevel(logging.INFO)

class SafePE2SC:
    """
    Wrapper sécurisé pour le convertisseur PE to Shellcode
    
    Cette classe encapsule les fonctionnalités du module custom_pe2sc.py
    en ajoutant des vérifications de sécurité et une meilleure gestion des erreurs.
    """
    
    def __init__(self, framework_path: str, debug: bool = False):
        """
        Initialise le wrapper sécurisé
        
        Args:
            framework_path (str): Chemin vers le répertoire contenant le module custom_pe2sc.py
            debug (bool): Active les logs de débogage détaillés
        
        Raises:
            ValueError: Si framework_path est invalide ou si le module n'est pas trouvé
        """
        self.framework_path = os.path.abspath(framework_path)
        
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Vérifier que le framework_path existe et contient le module custom_pe2sc.py
        if not os.path.isdir(self.framework_path):
            raise ValueError(f"Le chemin du framework '{self.framework_path}' n'existe pas ou n'est pas un répertoire")
        
        pe2sc_path = os.path.join(self.framework_path, "custom_pe2sc.py")
        if not os.path.isfile(pe2sc_path):
            raise ValueError(f"Le module custom_pe2sc.py n'a pas été trouvé dans {self.framework_path}")
        
        # Ajouter le framework_path au sys.path pour pouvoir importer custom_pe2sc
        if self.framework_path not in sys.path:
            sys.path.append(self.framework_path)
        
        # Importer le module custom_pe2sc
        try:
            import custom_pe2sc
            self.pe2sc_module = custom_pe2sc
            logger.debug(f"Module custom_pe2sc importé avec succès depuis {self.framework_path}")
        except ImportError as e:
            logger.error(f"Erreur lors de l'importation du module custom_pe2sc: {str(e)}")
            raise ImportError(f"Impossible d'importer le module custom_pe2sc depuis {self.framework_path}: {str(e)}")
    
    def validate_input_file(self, pe_file_path: str) -> Tuple[bool, str]:
        """
        Valide un fichier PE d'entrée
        
        Args:
            pe_file_path (str): Chemin vers le fichier PE à valider
        
        Returns:
            Tuple[bool, str]: (succès, message d'erreur ou chemin du fichier)
        """
        # Vérifier si le fichier existe
        if not os.path.isfile(pe_file_path):
            return False, f"Le fichier '{pe_file_path}' n'existe pas"
        
        # Vérifier la taille du fichier (max 10MB)
        max_size = 10 * 1024 * 1024  # 10MB
        file_size = os.path.getsize(pe_file_path)
        if file_size > max_size:
            return False, f"Le fichier est trop volumineux ({file_size} octets). Taille maximale: 10MB"
        
        # Vérifier l'extension du fichier
        allowed_extensions = ['.exe', '.dll', '.sys']
        file_ext = os.path.splitext(pe_file_path)[1].lower()
        if file_ext not in allowed_extensions:
            return False, f"Type de fichier non autorisé '{file_ext}'. Extensions autorisées: {', '.join(allowed_extensions)}"
        
        # Vérifier les en-têtes du fichier PE (première signature MZ)
        try:
            with open(pe_file_path, 'rb') as f:
                header = f.read(2)
                if header != b'MZ':
                    return False, "Le fichier n'est pas un fichier PE valide (signature MZ manquante)"
        except Exception as e:
            return False, f"Erreur lors de la lecture du fichier: {str(e)}"
        
        return True, pe_file_path
    
    def convert_pe_to_shellcode(self, 
                               pe_file_path: str, 
                               output_format: str = "bin",
                               encoding_method: str = "polymorphic",
                               architecture: str = "auto",
                               apply_obfuscation: bool = True,
                               bypass_edr: bool = True) -> Dict[str, Any]:
        """
        Convertit un fichier PE en shellcode de manière sécurisée
        
        Args:
            pe_file_path (str): Chemin vers le fichier PE à convertir
            output_format (str): Format du shellcode de sortie (bin, c, cpp, py, raw)
            encoding_method (str): Méthode d'encodage (polymorphic, xor, none)
            architecture (str): Architecture cible (auto, x64, x86)
            apply_obfuscation (bool): Si True, applique des techniques d'obfuscation
            bypass_edr (bool): Si True, utilise des techniques d'évasion EDR
        
        Returns:
            Dict[str, Any]: Résultats de la conversion avec des informations supplémentaires
        
        Raises:
            ValueError: Si les paramètres sont invalides
            RuntimeError: Si une erreur se produit pendant la conversion
        """
        result = {
            "success": False,
            "error": None,
            "output_path": None,
            "original_size": 0,
            "shellcode_size": 0,
            "preview": None,
            "architecture": architecture,
            "encoding_method": encoding_method,
            "conversion_details": None
        }
        
        temp_dir = None
        temp_output = None
        
        try:
            # Valider le fichier d'entrée
            valid, message = self.validate_input_file(pe_file_path)
            if not valid:
                raise ValueError(message)
            
            # Obtenir les détails du fichier d'entrée
            result["original_size"] = os.path.getsize(pe_file_path)
            
            # Valider les paramètres
            if output_format not in ["bin", "c", "cpp", "py", "raw"]:
                raise ValueError(f"Format de sortie '{output_format}' non pris en charge")
            
            if encoding_method not in ["polymorphic", "xor", "none"]:
                raise ValueError(f"Méthode d'encodage '{encoding_method}' non prise en charge")
            
            if architecture not in ["auto", "x64", "x86"]:
                raise ValueError(f"Architecture '{architecture}' non prise en charge")
            
            # Créer un répertoire temporaire pour les fichiers de sortie
            temp_dir = tempfile.mkdtemp(prefix="safe_pe2sc_")
            temp_output = os.path.join(temp_dir, f"shellcode.{output_format}")
            
            # Déterminer les paramètres de conversion
            conversion_params = {
                "INPUT_FILE": pe_file_path,
                "OUTPUT_FILE": temp_output,
                "TECHNIQUE": "custom" if bypass_edr else "reflective",
                "ENCODE": encoding_method,
                "ARCH": architecture,
                "OBFUSCATE": apply_obfuscation
            }
            
            logger.info(f"Conversion PE to Shellcode lancée avec paramètres: {conversion_params}")
            
            # Appeler le module de conversion PE to Shellcode
            try:
                success, details = self.pe2sc_module.convert_pe_to_shellcode(**conversion_params)
                
                if not success:
                    raise RuntimeError(f"Échec de la conversion PE to Shellcode: {details}")
                
                result["conversion_details"] = details
            except AttributeError:
                # Méthode alternative si l'API a changé
                import inspect
                logger.warning("API du module custom_pe2sc non standard, utilisation d'une approche alternative")
                
                # Trouver la fonction principale
                main_func = None
                for name, obj in inspect.getmembers(self.pe2sc_module):
                    if inspect.isfunction(obj) and name.startswith(("convert", "process", "main")):
                        main_func = obj
                        break
                
                if main_func is None:
                    raise RuntimeError("Impossible de trouver la fonction de conversion dans le module custom_pe2sc")
                
                # Appeler la fonction avec les bons arguments
                args = [pe_file_path, temp_output]
                success = main_func(*args)
                
                if not success:
                    raise RuntimeError("Échec de la conversion PE to Shellcode")
            
            # Vérifier que le fichier de sortie a été créé
            if not os.path.exists(temp_output):
                raise RuntimeError(f"Le fichier de sortie '{temp_output}' n'a pas été créé")
            
            # Obtenir la taille du shellcode généré
            result["shellcode_size"] = os.path.getsize(temp_output)
            
            # Calculer l'empreinte SHA-256 du shellcode
            sha256 = hashlib.sha256()
            with open(temp_output, 'rb') as f:
                sha256.update(f.read())
            result["sha256"] = sha256.hexdigest()
            
            # Générer un aperçu du shellcode
            with open(temp_output, 'rb') as f:
                preview_data = f.read(min(64, result["shellcode_size"]))
                result["preview"] = preview_data.hex()
            
            result["success"] = True
            result["output_path"] = temp_output
            
            logger.info(f"Conversion PE to Shellcode réussie: {result['original_size']} -> {result['shellcode_size']} octets")
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la conversion PE to Shellcode: {str(e)}")
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


# Fonction utilitaire pour une utilisation directe
def safe_convert_pe_to_shellcode(framework_path: str, pe_file_path: str, **kwargs) -> Dict[str, Any]:
    """
    Fonction utilitaire pour convertir un fichier PE en shellcode de manière sécurisée
    
    Args:
        framework_path (str): Chemin vers le répertoire du framework
        pe_file_path (str): Chemin vers le fichier PE à convertir
        **kwargs: Arguments supplémentaires passés à convert_pe_to_shellcode
    
    Returns:
        Dict[str, Any]: Résultats de la conversion
    """
    converter = SafePE2SC(framework_path)
    return converter.convert_pe_to_shellcode(pe_file_path, **kwargs)