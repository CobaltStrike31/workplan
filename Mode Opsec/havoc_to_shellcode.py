#!/usr/bin/env python3
"""
Script de pont entre Havoc et custom_pe2sc.py
---------------------------------------------
Assure la compatibilité avec les workflows existants tout en utilisant
exclusivement le convertisseur PE personnalisé pour garantir l'OPSEC.
"""

import sys
import os
import subprocess
import logging
from pathlib import Path
from typing import Optional, Union, List

# Configuration du logging pour tracer les erreurs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger('havoc_bridge')

def execute_process(command: List[str], silent: bool = True) -> subprocess.CompletedProcess:
    """
    Exécute un processus externe avec gestion d'erreurs améliorée.
    
    Args:
        command: Liste des arguments de la commande
        silent: Si True, redirige stdout/stderr vers PIPE
    
    Returns:
        Objet CompletedProcess avec résultat de l'exécution
        
    Raises:
        FileNotFoundError: Si l'exécutable n'est pas trouvé
        PermissionError: Si les permissions sont insuffisantes
        subprocess.SubprocessError: Pour les autres erreurs de subprocess
    """
    try:
        if silent:
            return subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                check=False  # Ne pas lever d'exception sur returncode != 0
            )
        return subprocess.run(command, check=False)
    except FileNotFoundError as e:
        logger.error(f"Exécutable non trouvé: {command[0]}")
        raise e
    except PermissionError as e:
        logger.error(f"Permissions insuffisantes pour exécuter: {command[0]}")
        raise e
    except subprocess.SubprocessError as e:
        logger.error(f"Erreur lors de l'exécution de {command[0]}: {str(e)}")
        raise e

def modify_shellcode(shellcode_bytes: bytes) -> bytes:
    """
    Applique des modifications mineures au shellcode pour perturber les signatures.
    
    Args:
        shellcode_bytes: Shellcode brut
        
    Returns:
        Shellcode modifié avec subtiles variations
    """
    import random
    
    data = bytearray(shellcode_bytes)
    
    # Seeding pour reproductibilité si nécessaire
    random.seed(sum(data) % 65537)
    
    # Modifications tous les 64 octets pour éviter de casser la fonctionnalité
    for i in range(0, len(data), 64):
        if i + 4 < len(data):
            offset = random.randint(0, 3)
            data[i + offset] ^= random.randint(1, 5)
            
    return bytes(data)

def convert_pe_to_shellcode(input_file: str, output_file: Optional[str] = None) -> Optional[bytes]:
    """
    Convertit un fichier PE en shellcode en utilisant custom_pe2sc.py.
    
    Args:
        input_file: Chemin vers le fichier PE d'entrée
        output_file: Chemin de sortie pour le shellcode (optionnel)
        
    Returns:
        Shellcode généré (bytes) ou None en cas d'échec
        
    Raises:
        FileNotFoundError: Si le fichier d'entrée n'existe pas
        RuntimeError: Si la conversion échoue
    """
    # Vérification des paramètres
    if not output_file:
        output_file = f"{input_file}.bin"
    
    input_path = Path(input_file)
    if not input_path.is_file():
        error_msg = f"Erreur: le fichier d'entrée '{input_file}' n'existe pas"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    # Chemin complet vers le convertisseur
    script_dir = Path(__file__).parent.absolute()
    converter_path = script_dir / "custom_pe2sc.py"
    
    if not converter_path.exists():
        error_msg = f"Convertisseur '{converter_path}' introuvable"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    logger.info(f"Conversion de {input_file} en shellcode...")
    
    # Exécution du convertisseur
    try:
        result = execute_process([
            sys.executable, 
            str(converter_path), 
            input_file, 
            output_file
        ])
        
        # Analyser la sortie et les erreurs
        stdout = result.stdout.decode('utf-8', errors='ignore').strip() if result.stdout else ""
        stderr = result.stderr.decode('utf-8', errors='ignore').strip() if result.stderr else ""
        
        # Vérification du code de retour et du fichier généré
        if result.returncode != 0:
            error_msg = f"Échec de la conversion avec code {result.returncode}"
            if stderr:
                error_msg += f"\nErreurs: {stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        output_path = Path(output_file)
        if not output_path.exists():
            error_msg = "Le fichier de sortie n'a pas été créé malgré un code de retour 0"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # Vérifier la taille du fichier de sortie
        file_size = output_path.stat().st_size
        if file_size == 0:
            error_msg = "Le fichier de sortie est vide"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        logger.info(f"Conversion réussie: shellcode de {file_size} octets généré dans {output_file}")
        
        # Lire le shellcode généré
        with open(output_file, 'rb') as f:
            shellcode = f.read()
            
        # Appliquer des modifications optionnelles si flag activé
        # Les modifications sont désactivées par défaut, car la polymorphie est 
        # déjà gérée par custom_pe2sc.py
        #shellcode = modify_shellcode(shellcode)
            
        return shellcode
        
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Erreur d'accès: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la conversion: {str(e)}")
        # Remonter l'exception avec un contexte plus clair
        raise RuntimeError(f"Échec de la conversion PE-to-shellcode: {str(e)}") from e

def main() -> int:
    """
    Fonction principale - point d'entrée du script.
    
    Returns:
        Code de retour (0=succès, 1=erreur)
    """
    if len(sys.argv) < 2:
        logger.error("Usage: python havoc_to_shellcode.py <input_pe> [output_file]")
        return 1
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        shellcode = convert_pe_to_shellcode(input_file, output_file)
        if not shellcode:
            return 1
            
        # Si le fichier de sortie n'était pas spécifié et qu'on veut 
        # diriger le shellcode vers stdout (fonctionnalité de pipe)
        if not output_file:
            sys.stdout.buffer.write(shellcode)
        
        return 0
        
    except FileNotFoundError:
        return 1
    except RuntimeError:
        return 1
    except Exception as e:
        logger.error(f"Erreur non gérée: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())