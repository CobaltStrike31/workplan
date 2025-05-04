#!/usr/bin/env python3
"""
Utilitaire de formatage de clés pour opérations offensives
--------------------------------------------------------
Convertit et génère des clés cryptographiques dans différents formats.
"""

import sys
import re
import os
import base64
import argparse
import secrets

# Tailles de clé standards (octets)
KEY_SIZES = {
    128: 16,  # AES-128
    192: 24,  # AES-192
    256: 32,  # AES-256
    384: 48,  # SHA-384
    512: 64   # SHA-512
}

# Formats supportés avec extensions
FORMATS = {
    "cpp": "h",
    "c": "h",
    "csharp": "cs",
    "rust": "rs", 
    "python": "py",
    "go": "go",
    "java": "java",
    "powershell": "ps1",
    "raw": "bin"
}

def gen_key(bits=256):
    """Génère une clé cryptographique sans métadonnées identifiables"""
    if bits not in KEY_SIZES:
        bits = 256
    size = KEY_SIZES[bits]
    return secrets.token_bytes(size).hex()

def clean_key(hex_key):
    """Nettoie et valide une clé hexadécimale"""
    if not hex_key:
        return None, "Clé vide"
    
    # Nettoyage
    clean = re.sub(r'\s+', '', hex_key.lower())
    
    # Validation hexadécimale
    if not all(c in '0123456789abcdef' for c in clean):
        return None, "Format non hexadécimal"
    
    # Correction longueur paire
    if len(clean) % 2 != 0:
        clean = '0' + clean
    
    return clean, None

def read_key_file(filepath):
    """Extrait une clé depuis un fichier (hex, b64 ou binaire)"""
    try:
        # Essayer comme texte
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read().strip()
            # Tester si hexadécimal
            if re.match(r'^[0-9a-fA-F\s]+$', content):
                return re.sub(r'\s+', '', content)
            
            # Tester si base64
            try:
                decoded = base64.b64decode(content)
                return decoded.hex()
            except:
                pass
        
        # Essayer comme binaire
        with open(filepath, 'rb') as f:
            return f.read().hex()
    
    except:
        return None

def format_key(hex_key, fmt="cpp", add_info=False):
    """Formate une clé pour le langage cible"""
    # Préparer bytes
    byte_arr = []
    for i in range(0, len(hex_key), 2):
        byte_arr.append(f"0x{hex_key[i:i+2]}")
    
    byte_count = len(byte_arr)
    result = ""
    
    # Ajouter infos minimales si demandé
    if add_info:
        result += f"// Clé: {byte_count} octets ({byte_count*8} bits)\n"
    
    # Formater selon le langage
    if fmt in ["c", "cpp"]:
        result += f"unsigned char k[{byte_count}] = {{\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
        result += "\n};"
        
    elif fmt == "csharp":
        result += f"byte[] k = new byte[{byte_count}] {{\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
        result += "\n};"
        
    elif fmt == "rust":
        result += f"let k: [u8; {byte_count}] = [\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
            elif i + 8 >= len(byte_arr):
                result += ","
        result += "\n];"
        
    elif fmt == "python":
        result += f"k = bytearray([\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
        result += "\n])"
        
    elif fmt == "go":
        result += f"k := []byte{{\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
        result += ",\n}"
        
    elif fmt == "java":
        result += f"byte[] k = new byte[] {{\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
        result += "\n};"
        
    elif fmt == "powershell":
        result += f"$k = @(\n    "
        for i in range(0, len(byte_arr), 8):
            result += ", ".join(byte_arr[i:i+8])
            if i + 8 < len(byte_arr):
                result += ",\n    "
        result += "\n)"
        
    elif fmt == "raw":
        # Format compact sans formatage
        result += ",".join(byte_arr)
        
    return result, byte_count

def write_file(content, filepath):
    """Écrit le contenu dans un fichier de manière sécurisée"""
    try:
        # Écrire d'abord dans un temporaire
        temp = filepath + ".tmp"
        with open(temp, 'w') as f:
            f.write(content)
            
        # Renommer pour atomicité
        if os.path.exists(filepath):
            os.unlink(filepath)
        os.rename(temp, filepath)
        return True
    except:
        if os.path.exists(temp):
            try: os.unlink(temp)
            except: pass
        return False

def copy_to_clipboard(text):
    """Copie dans le presse-papiers sans dépendances externes"""
    try:
        if os.name == 'nt':  # Windows
            import subprocess
            subprocess.run(['clip'], input=text.encode('utf-8'), check=False)
            return True
        elif os.name == 'posix' and hasattr(os, 'uname') and os.uname().sysname == 'Darwin':  # macOS
            import subprocess
            subprocess.run(['pbcopy'], input=text.encode('utf-8'), check=False)
            return True
        elif os.name == 'posix':  # Linux
            import subprocess
            try:
                subprocess.run(['xclip', '-selection', 'clipboard'], 
                              input=text.encode('utf-8'), check=False)
                return True
            except FileNotFoundError:
                try:
                    subprocess.run(['xsel', '--clipboard', '--input'], 
                                  input=text.encode('utf-8'), check=False)
                    return True
                except FileNotFoundError:
                    pass
    except:
        pass
    return False

def main():
    # Parser arguments
    p = argparse.ArgumentParser(description="Formatage de clés cryptographiques", 
                               formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # Sources de clé mutuellement exclusives
    src = p.add_mutually_exclusive_group()
    src.add_argument("key", nargs="?", help="Clé hexadécimale", default=None)
    src.add_argument("-g", "--gen", type=int, choices=[128, 192, 256, 384, 512], 
                    help="Générer clé de X bits")
    src.add_argument("-f", "--file", help="Lire depuis fichier")
    
    # Options
    p.add_argument("-t", "--type", choices=FORMATS.keys(), default="cpp", 
                  help="Format de sortie (défaut: cpp)")
    p.add_argument("-o", "--out", help="Fichier de sortie")
    p.add_argument("-i", "--info", action="store_true", 
                  help="Inclure informations non-identifiantes")
    p.add_argument("-q", "--quiet", action="store_true", 
                  help="Mode silencieux")
    p.add_argument("--no-clip", action="store_true",
                  help="Ne pas copier dans presse-papiers")
    
    args = p.parse_args()
    
    # Obtenir clé hexadécimale
    hex_key = None
    
    if args.key:
        hex_key = args.key
    elif args.gen:
        hex_key = gen_key(args.gen)
        if not args.quiet:
            print(f"[+] Clé générée: {args.gen} bits")
    elif args.file:
        hex_key = read_key_file(args.file)
        if not hex_key and not args.quiet:
            print(f"[-] Impossible de lire une clé depuis '{args.file}'")
            return 1
    else:
        if not args.quiet:
            print("Entrez votre clé hexadécimale (vide = générer 256 bits):")
        try:
            hex_key = input().strip()
        except (KeyboardInterrupt, EOFError):
            return 1
            
        if not hex_key:
            hex_key = gen_key(256)
            if not args.quiet:
                print("[+] Clé générée: 256 bits")
    
    # Valider et nettoyer
    hex_key, error = clean_key(hex_key)
    if not hex_key:
        if not args.quiet:
            print(f"[-] Clé invalide: {error}")
        return 1
    
    # Formater
    fmt_key, byte_count = format_key(hex_key, args.type, args.info)
    
    # Afficher résultat
    if not args.quiet:
        bit_count = byte_count * 8
        print(f"\n[+] Clé formatée: {byte_count} octets ({bit_count} bits)")
        print(fmt_key)
    
    # Copier dans presse-papiers
    if not args.no_clip:
        if copy_to_clipboard(fmt_key) and not args.quiet:
            print("[+] Copié dans presse-papiers")
    
    # Sauvegarder dans fichier
    if args.out:
        if write_file(fmt_key, args.out) and not args.quiet:
            print(f"[+] Sauvegardé: {args.out}")
        elif not args.quiet:
            print(f"[-] Échec d'écriture: {args.out}")
    elif not args.quiet:
        save = input("\nSauvegarder dans un fichier? (o/n): ").lower()
        if save == "o" or save == "y":
            ext = FORMATS.get(args.type, "txt")
            default = f"key.{ext}"
            filename = input(f"Nom du fichier [{default}]: ").strip() or default
            if write_file(fmt_key, filename):
                print(f"[+] Sauvegardé: {filename}")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"[-] {str(e)}\n")
        sys.exit(1)