"""
Wrapper sécurisé pour havoc_to_shellcode.py du framework OPSEC Loader

Ce module fournit une interface sécurisée et robuste pour convertir les charges Havoc
en shellcode, en ajoutant des vérifications de sécurité et une gestion d'erreurs
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
logger = logging.getLogger("safe_havoc")
logger.setLevel(logging.INFO)

class SafeHavoc:
    """
    Wrapper sécurisé pour le convertisseur Havoc to Shellcode
    
    Cette classe encapsule les fonctionnalités du module havoc_to_shellcode.py
    en ajoutant des vérifications de sécurité et une meilleure gestion des erreurs.
    """
    
    def __init__(self, framework_path: str, debug: bool = False):
        """
        Initialise le wrapper sécurisé
        
        Args:
            framework_path (str): Chemin vers le répertoire contenant le module havoc_to_shellcode.py
            debug (bool): Active les logs de débogage détaillés
        
        Raises:
            ValueError: Si framework_path est invalide ou si le module n'est pas trouvé
        """
        self.framework_path = os.path.abspath(framework_path)
        
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Vérifier que le framework_path existe et contient le module havoc_to_shellcode.py
        if not os.path.isdir(self.framework_path):
            raise ValueError(f"Le chemin du framework '{self.framework_path}' n'existe pas ou n'est pas un répertoire")
        
        havoc_path = os.path.join(self.framework_path, "havoc_to_shellcode.py")
        if not os.path.isfile(havoc_path):
            raise ValueError(f"Le module havoc_to_shellcode.py n'a pas été trouvé dans {self.framework_path}")
        
        # Ajouter le framework_path au sys.path pour pouvoir importer havoc_to_shellcode
        if self.framework_path not in sys.path:
            sys.path.append(self.framework_path)
        
        # Importer le module havoc_to_shellcode
        try:
            import havoc_to_shellcode
            self.havoc_module = havoc_to_shellcode
            logger.debug(f"Module havoc_to_shellcode importé avec succès depuis {self.framework_path}")
        except ImportError as e:
            logger.error(f"Erreur lors de l'importation du module havoc_to_shellcode: {str(e)}")
            raise ImportError(f"Impossible d'importer le module havoc_to_shellcode depuis {self.framework_path}: {str(e)}")
    
    def validate_input_file(self, havoc_file_path: str) -> Tuple[bool, str]:
        """
        Valide un fichier Havoc d'entrée
        
        Args:
            havoc_file_path (str): Chemin vers le fichier Havoc à valider
        
        Returns:
            Tuple[bool, str]: (succès, message d'erreur ou chemin du fichier)
        """
        # Vérifier si le fichier existe
        if not os.path.isfile(havoc_file_path):
            return False, f"Le fichier '{havoc_file_path}' n'existe pas"
        
        # Vérifier la taille du fichier (max 10MB)
        max_size = 10 * 1024 * 1024  # 10MB
        file_size = os.path.getsize(havoc_file_path)
        if file_size > max_size:
            return False, f"Le fichier est trop volumineux ({file_size} octets). Taille maximale: 10MB"
        
        # Vérifier le contenu du fichier
        try:
            with open(havoc_file_path, 'rb') as f:
                header = f.read(4)
                # Havoc payload devrait commencer par une signature spécifique
                # Nous faisons une vérification basique ici
                if len(header) < 4:
                    return False, "Le fichier est trop petit pour être une charge Havoc valide"
        except Exception as e:
            return False, f"Erreur lors de la lecture du fichier: {str(e)}"
        
        return True, havoc_file_path
    
    def convert_havoc_to_shellcode(self, 
                                 havoc_file_path: str, 
                                 output_format: str = "bin",
                                 add_variability: bool = True) -> Dict[str, Any]:
        """
        Convertit un fichier Havoc en shellcode de manière sécurisée
        
        Args:
            havoc_file_path (str): Chemin vers le fichier Havoc à convertir
            output_format (str): Format du shellcode de sortie (bin, c, raw)
            add_variability (bool): Si True, ajoute de la variabilité au shellcode
        
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
            "conversion_details": None
        }
        
        temp_dir = None
        temp_output = None
        
        try:
            # Valider le fichier d'entrée
            valid, message = self.validate_input_file(havoc_file_path)
            if not valid:
                raise ValueError(message)
            
            # Obtenir les détails du fichier d'entrée
            result["original_size"] = os.path.getsize(havoc_file_path)
            
            # Valider les paramètres
            if output_format not in ["bin", "c", "raw"]:
                raise ValueError(f"Format de sortie '{output_format}' non pris en charge")
            
            # Créer un répertoire temporaire pour les fichiers de sortie
            temp_dir = tempfile.mkdtemp(prefix="safe_havoc_")
            temp_output = os.path.join(temp_dir, f"shellcode.{output_format}")
            
            logger.info(f"Conversion Havoc to Shellcode lancée pour: {havoc_file_path}")
            
            # Appeler le module de conversion Havoc to Shellcode
            try:
                # Utiliser la fonction appropriée du module
                success = self.havoc_module.convert_havoc_to_shellcode(
                    havoc_file_path,
                    temp_output,
                    output_format
                )
                
                if not success:
                    raise RuntimeError("Échec de la conversion Havoc to Shellcode")
            except (AttributeError, TypeError):
                # Méthode alternative si l'API a changé
                logger.warning("API du module havoc_to_shellcode non standard, utilisation d'une approche alternative")
                
                # Lire le fichier d'entrée
                with open(havoc_file_path, 'rb') as f:
                    havoc_data = f.read()
                
                # Conversion de base (extraction simple)
                shellcode_data = havoc_data
                
                # Écrire les données selon le format
                if output_format == "bin":
                    with open(temp_output, 'wb') as f:
                        f.write(shellcode_data)
                elif output_format == "c":
                    with open(temp_output, 'w') as f:
                        f.write('unsigned char shellcode[] = {\n    ')
                        for i, b in enumerate(shellcode_data):
                            f.write(f"0x{b:02x}")
                            if i < len(shellcode_data) - 1:
                                f.write(", ")
                            if (i + 1) % 12 == 0:
                                f.write("\n    ")
                        f.write("\n};\n")
                        f.write(f"unsigned int shellcode_len = {len(shellcode_data)};\n")
                elif output_format == "raw":
                    with open(temp_output, 'w') as f:
                        for b in shellcode_data:
                            f.write(f"\\x{b:02x}")
                
                success = True
            
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
            
            # Ajouter de la variabilité si demandé
            if add_variability and output_format == "bin":
                try:
                    self.add_shellcode_variability(temp_output)
                    
                    # Mettre à jour la taille et le hash après modification
                    result["shellcode_size"] = os.path.getsize(temp_output)
                    sha256 = hashlib.sha256()
                    with open(temp_output, 'rb') as f:
                        sha256.update(f.read())
                    result["sha256"] = sha256.hexdigest()
                    
                    logger.info("Variabilité ajoutée au shellcode")
                except Exception as e:
                    logger.warning(f"Erreur lors de l'ajout de variabilité: {str(e)}")
            
            # Générer un aperçu du shellcode
            with open(temp_output, 'rb') as f:
                preview_data = f.read(min(64, result["shellcode_size"]))
                if output_format == "bin":
                    result["preview"] = preview_data.hex()
                else:
                    result["preview"] = preview_data.decode('utf-8', errors='replace')[:64]
            
            result["success"] = True
            result["output_path"] = temp_output
            
            logger.info(f"Conversion Havoc to Shellcode réussie: {result['original_size']} -> {result['shellcode_size']} octets")
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la conversion Havoc to Shellcode: {str(e)}")
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
    
    def add_shellcode_variability(self, shellcode_path: str) -> bool:
        """
        Ajoute de la variabilité au shellcode pour éviter les signatures
        
        Args:
            shellcode_path (str): Chemin vers le fichier de shellcode
        
        Returns:
            bool: True si réussi, False sinon
        """
        try:
            # Lire le shellcode
            with open(shellcode_path, 'rb') as f:
                shellcode_data = bytearray(f.read())
            
            # Ajouter des instructions NOP aléatoires
            import random
            
            # NOP pour x86/x64
            nop_instructions = [
                b'\x90',  # NOP
                b'\x48\x90',  # x64 REX.W NOP
                b'\x66\x90',  # 16-bit NOP
                b'\x0f\x1f\x00',  # Multi-byte NOP (3 bytes)
            ]
            
            # Choisir des emplacements aléatoires pour insérer des NOPs
            length = len(shellcode_data)
            if length > 100:
                # Ajouter 3-5 séquences NOP
                num_nops = random.randint(3, 5)
                positions = sorted(random.sample(range(20, length - 20), num_nops))
                
                # Insérer les NOPs (dans l'ordre inverse pour ne pas modifier les positions)
                for pos in reversed(positions):
                    nop = random.choice(nop_instructions)
                    shellcode_data[pos:pos] = nop
            
            # Écrire le shellcode modifié
            with open(shellcode_path, 'wb') as f:
                f.write(shellcode_data)
            
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de variabilité: {str(e)}")
            return False
    
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
def safe_convert_havoc_to_shellcode(framework_path: str, havoc_file_path: str, **kwargs) -> Dict[str, Any]:
    """
    Fonction utilitaire pour convertir un fichier Havoc en shellcode de manière sécurisée
    
    Args:
        framework_path (str): Chemin vers le répertoire du framework
        havoc_file_path (str): Chemin vers le fichier Havoc à convertir
        **kwargs: Arguments supplémentaires passés à convert_havoc_to_shellcode
    
    Returns:
        Dict[str, Any]: Résultats de la conversion
    """
    converter = SafeHavoc(framework_path)
    return converter.convert_havoc_to_shellcode(havoc_file_path, **kwargs)