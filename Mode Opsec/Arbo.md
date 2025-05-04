## Description des fichiers principaux

### Convertisseurs et outils de base

- **custom_pe2sc.py**: Convertisseur PE-to-shellcode avancé implémentant:
  - Routines de reflective loading en assembleur
  - 4 méthodes d'encodage polymorphique
  - Techniques d'évasion EDR (API hashing, junk code)
  - Support multi-architecture (x86/x64)

- **encrypt_shell.py**: Outil de chiffrement utilisant:
  - Algorithme AES-256-CBC
  - Dérivation de clé PBKDF2 (100 000 itérations)
  - Format de fichier compatible avec opsec_loader

- **key_formatter.py**: Générateur de clés cryptographiques avec:
  - Génération sécurisée via secrets.token_bytes()
  - Export en plusieurs formats (C++, Python, texte brut)
  - Options pour incorporation dans le code source

- **opsec_loader.cpp**: Loader C++ qui:
  - Charge et déchiffre le shellcode
  - Alloue de la mémoire avec protections appropriées
  - Exécute le shellcode via thread dédié
  - Efface les données sensibles de la mémoire

### Scripts d'automatisation

- **compile.sh**: Compile opsec_loader.cpp avec:
  - Optimisations pour réduire la taille
  - Suppression des métadonnées de débogage
  - Options de sécurité renforcées

- **opsec_run.sh/ps1**: Orchestre le workflow complet:
  - Conversion PE → shellcode
  - Génération de clé et chiffrement
  - Exécution du shellcode
  - Nettoyage des artefacts intermédiaires

- **clean_traces.sh/ps1**: Supprime de façon sécurisée:
  - Fichiers temporaires et intermédiaires
  - Entrées d'historique de commandes
  - Journaux et caches potentiels

- **build_workflow.sh**: Script d'initialisation qui:
  - Vérifie les prérequis et dépendances
  - Configure les permissions des fichiers
  - Prépare l'environnement d'exécution

### Documentation

- **README.md**: Documentation principale avec:
  - Instructions d'installation et d'utilisation
  - Détails techniques sur chaque composant
  - Guide de dépannage et FAQ

- **FICHIERS.md**: Ce document détaillant la structure et les relations entre les fichiers

## Fichiers générés

Lors de l'utilisation du framework, plusieurs fichiers sont générés:

- **loader_key.h**: En-tête C++ contenant la clé de chiffrement (généré par key_formatter.py)
- **opsec_loader**: Binaire exécutable du loader (Linux)
- **opsec_loader.exe**: Binaire exécutable du loader (Windows)
- **\*.bin**: Fichiers shellcode temporaires (supprimés après utilisation)
- **\*.enc**: Fichiers shellcode chiffrés (résultat final)

## Flux de données
