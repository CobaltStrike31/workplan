#!/bin/bash
# Effacer toutes les traces potentielles
# ATTENTION: Utiliser avec précaution

# Effacer l'historique bash récent
if [ -f ~/.bash_history ]; then
    shred -u ~/.bash_history 2>/dev/null || echo '' > ~/.bash_history
fi

# Effacer l'historique Python
if [ -f ~/.python_history ]; then
    shred -u ~/.python_history 2>/dev/null || echo '' > ~/.python_history
fi

# Effacer les fichiers temporaires
rm -rf /tmp/tmp* /var/tmp/tmp* 2>/dev/null

# Effacer les logs systèmes (nécessite sudo)
if [ "$EUID" -eq 0 ]; then
    for log in /var/log/syslog* /var/log/auth.log* /var/log/secure* /var/log/messages*; do
        if [ -f "$log" ]; then
            echo '' > "$log" 2>/dev/null
        fi
    done
fi

# Effacer l'historique des commandes en mémoire
history -c

# Effacer les caches d'applications
rm -rf ~/.cache/* 2>/dev/null

echo "Traces effacées. Fermez votre terminal immédiatement."

# Pour sortie sans trace dans l'historique
kill -9 $$ 2>/dev/null