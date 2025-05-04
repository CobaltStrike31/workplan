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
import tempfile
import random

def x(p, silent=True):
    """Exécute un processus sans traces"""
    try:
        if silent:
            return subprocess.run(p, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return subprocess.run(p)
    except:
        return None

def m(b):
    """Modifications mineures pour compatibilité avec anciens scripts"""
    d = bytearray(b)
    for i in range(0, len(d), 64):
        if i + 4 < len(d):
            offset = random.randint(0,3)
            d[i+offset] ^= random.randint(1,5)
    return d

def c(f_in, f_out=None):
    """Fonction principale - appelle uniquement custom_pe2sc.py"""
    if not f_out:
        f_out = f_in + ".bin"
    
    # Vérification des fichiers
    if not os.path.isfile(f_in):
        print(f"Erreur: {f_in} n'existe pas", file=sys.stderr)
        return None
    
    # PRIORITÉ ABSOLUE: Notre convertisseur personnalisé avancé
    custom_converter = "custom_pe2sc.py"
    
    # Chemin absolu vers le répertoire du script
    self_path = os.path.dirname(os.path.abspath(__file__))
    converter_path = os.path.join(self_path, custom_converter)
    
    if os.path.exists(converter_path):
        try:
            cmd = [sys.executable, converter_path, f_in, f_out]
            result = x(cmd)
            
            if result.returncode == 0 and os.path.exists(f_out):
                print(f"[+] Conversion réussie avec {custom_converter}", file=sys.stderr)
                with open(f_out, 'rb') as f:
                    return f.read()
            else:
                print(f"[-] Échec de la conversion avec {custom_converter}", file=sys.stderr)
        except Exception as e:
            print(f"[-] Erreur lors de l'appel à {custom_converter}: {e}", file=sys.stderr)
    else:
        print(f"[-] Convertisseur personnalisé {custom_converter} introuvable", file=sys.stderr)
    
    # PLUS DE FALLBACK VERS DONUT OU PE2SHC - PROTECTION OPSEC
    print("[-] ERREUR: Utilisation exclusive du convertisseur personnalisé pour garantir l'OPSEC", file=sys.stderr)
    print("[-] Assurez-vous que custom_pe2sc.py est présent et fonctionnel", file=sys.stderr)
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python havoc_to_shellcode.py <input_pe> [output_file]", file=sys.stderr)
        sys.exit(1)
    
    f_in = sys.argv[1]
    f_out = sys.argv[2] if len(sys.argv) > 2 else None
    
    result = c(f_in, f_out)
    if not result:
        sys.exit(1)
    
    print(f"[+] Shellcode généré et sauvegardé dans {f_out}", file=sys.stderr)
    sys.exit(0)