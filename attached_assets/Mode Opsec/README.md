# Havoc Payload Deployment Framework

**OPSEC Loader Framework** - Un cadre de travail sécurisé pour le déploiement de payloads offensifs avec évasion avancée.

![Version](https://img.shields.io/badge/version-1.1.0-blue)
![Langage](https://img.shields.io/badge/language-C%2B%2B%2FPython%2FASM-green)
![OPSEC](https://img.shields.io/badge/OPSEC-Maximum-red)

---

## Table des matières

- [Introduction](#introduction)
- [Caractéristiques](#caractéristiques)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
  - [Étape 1: Génération du payload](#étape-1-génération-du-payload)
  - [Étape 2: Conversion en shellcode](#étape-2-conversion-en-shellcode)
  - [Étape 3: Chiffrement du shellcode](#étape-3-chiffrement-du-shellcode)
  - [Étape 4: Compilation du loader](#étape-4-compilation-du-loader)
  - [Étape 5: Déploiement et exécution](#étape-5-déploiement-et-exécution)
  - [Étape 6: Nettoyage OPSEC](#étape-6-nettoyage-opsec)
- [Composants du framework](#composants-du-framework)
- [Convertisseur PE-to-Shellcode avancé](#convertisseur-pe-to-shellcode-avancé)
- [Aspects techniques](#aspects-techniques)
- [Dépannage](#dépannage)
- [Considérations de sécurité](#considérations-de-sécurité)
- [FAQ](#faq)

---

## Introduction

Ce framework permet de déployer des charges utiles (payloads) Havoc de manière sécurisée, en minimisant les risques de détection. Il implémente:
- Conversion de binaires en shellcode polymorphique
- Reflective loading pour exécution en mémoire
- Chiffrement robuste des charges utiles
- Techniques avancées d'évasion des EDR

L'ensemble est conçu pour maintenir une hygiène OPSEC (sécurité opérationnelle) stricte tout au long du workflow.

## Caractéristiques

- **Convertisseur PE avancé**: Transformation d'exécutables en shellcode polymorphique avec reflective loading
- **Évasion EDR**: Techniques sophistiquées d'évasion des défenses (API hashing, code polymorphique)
- **Chiffrement robuste**: AES-256 avec génération sécurisée de clés
- **Minimalisme**: Empreinte discrète en mémoire et sur disque
- **Polymorphie multi-niveaux**: Shellcode différent à chaque génération
- **Nettoyage intégré**: Effacement sécurisé des artefacts sensibles

## Prérequis

### Logiciels requis

- **Linux/Windows**: Système d'exploitation compatible
- **Python 3.8+**: Environnement d'exécution pour les scripts
- **GCC/MinGW/MSVC**: Compilateur C/C++
- **Havoc Framework**: Pour la génération des payloads initiaux

### Bibliothèques Python

```bash
pip install pycryptodome argparse secrets
```

### Windows uniquement

```powershell
# Installation de chocolatey si non installé
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Installation des outils requis
choco install python mingw visualstudio2019-workload-vctools -y
```

## Installation

1. **Cloner ou télécharger le framework**

```bash
git clone https://github.com/username/opsec-loader.git
cd opsec-loader
```

2. **Rendre les scripts exécutables**

```bash
chmod +x *.py *.sh
```

3. **Vérifier la configuration**

```bash
# Vérifier que tout est prêt
./build_workflow.sh
```

## Utilisation

### Étape 1: Génération du payload

#### Configuration de Havoc

1. Démarrer le serveur Havoc
```bash
cd /opt/Havoc
sudo ./teamserver server --profile ./profiles/havoc.yaotl -v
```

2. Démarrer le client Havoc dans un autre terminal
```bash
cd /opt/Havoc
./client
```

#### Génération du payload dans l'interface

1. Connectez-vous au serveur TeamServer
2. Accédez à **Attack > Payload**
3. Configurez les paramètres:
   - **Agent Type**: Havoc
   - **Listener**: Sélectionnez votre listener (créez-en un si nécessaire)
   - **Architecture**: x64 (recommandé)
   - **Output Format**: Windows Executable (.exe)

4. Cliquez sur **Generate** et enregistrez le fichier (ex: `payload.exe`)

> **Note**: Pour une meilleure OPSEC, créez votre payload avec une configuration minimisant la signature (options Sleep, Jitter, etc.)

### Étape 2: Conversion en shellcode

Le framework utilise notre convertisseur PE-to-shellcode personnalisé avec polymorphie et reflective loading intégrés.

```bash
# Convertir l'exécutable Havoc en shellcode polymorphique
python3 custom_pe2sc.py payload.exe shellcode.bin

# Vérifier la génération
ls -la shellcode.bin
```

**Que se passe-t-il en arrière-plan**:
1. Analyse du PE et détection d'architecture (x86/x64)
2. Sélection d'un algorithme d'encodage polymorphique aléatoire
3. Génération d'un shellcode avec stub de reflective loading
4. Application de techniques de polymorphie (junk code, variations de code)
5. Obfuscation des chaînes et API (technique de hachage)

### Étape 3: Chiffrement du shellcode

Cette étape utilise deux scripts:

#### 3.1. Génération de clé cryptographique

```bash
# Générer une clé AES-256 et l'exporter au format C++
python3 key_formatter.py -g 256 -t cpp -o loader_key.h -q

# Ou générer uniquement la clé brute pour utilisation immédiate
KEY=$(python3 key_formatter.py -g 256 -t raw -q)
echo $KEY > crypto.key
```

**Détails de l'opération**:
- Utilisation de `secrets.token_bytes()` pour une génération cryptographiquement sûre
- Formatage adapté au langage cible sans métadonnées identifiables

#### 3.2. Chiffrement du shellcode

```bash
# Chiffrer le shellcode avec la clé générée
python3 encrypt_shell.py shellcode.bin $(cat crypto.key) payload.enc

# Vérifier la sortie
ls -la payload.enc
```

**Processus de chiffrement**:
1. Lecture du shellcode polymorphique
2. Génération de sel et vecteur d'initialisation (IV) aléatoires
3. Dérivation de clé par PBKDF2 avec 100 000 itérations
4. Chiffrement AES-256-CBC avec rembourrage PKCS#7
5. Sauvegarde atomique pour éviter les fichiers corrompus

### Étape 4: Compilation du loader

Le loader est le composant qui déchiffre et exécute le shellcode en mémoire.

#### 4.1. Compilation sur Linux

```bash
# Option 1: Utiliser le script de compilation
./compile.sh

# Option 2: Compilation manuelle
gcc -O2 -s -DNDEBUG -fvisibility=hidden -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -o opsec_loader opsec_loader.cpp -include loader_key.h -lcrypt32
```

#### 4.2. Compilation sur Windows

```powershell
# Avec MinGW
gcc -O2 -s -DNDEBUG -fvisibility=hidden -o opsec_loader.exe opsec_loader.cpp -include loader_key.h -lcrypt32 -ladvapi32

# Avec MSVC (Ouvrir Developer Command Prompt)
cl.exe /O2 /GL /GS- opsec_loader.cpp /Feopsec_loader.exe /link advapi32.lib crypt32.lib /SUBSYSTEM:CONSOLE
```

### Étape 5: Déploiement et exécution

Deux méthodes sont proposées pour l'exécution:

#### 5.1. Exécution directe

```bash
# Linux
./opsec_loader payload.enc $(cat crypto.key)

# Windows
.\opsec_loader.exe payload.enc (Get-Content -Raw crypto.key)
```

#### 5.2. Utilisation du script d'automatisation (recommandé)

```bash
# Linux - Exécute tout le workflow
./opsec_run.sh payload.exe secretpassword

# Windows
.\opsec_run.ps1 -exe payload.exe -pwd secretpassword
```

**Processus d'exécution**:
1. Conversion automatique PE → shellcode polymorphique
2. Chiffrement avec la clé fournie
3. Exécution du shellcode après déchiffrement
4. Nettoyage des artefacts intermédiaires

### Étape 6: Nettoyage OPSEC

```bash
# Linux - Effacement sécurisé
./clean_traces.sh

# Windows
powershell -File .\clean_traces.ps1
```

## Composants du framework

Le framework se compose des éléments suivants:

### Scripts Python

| Fichier | Description |
|---------|-------------|
| `custom_pe2sc.py` | **Nouveau!** Convertisseur PE avancé avec reflective loading et polymorphie |
| `key_formatter.py` | Génère et formate des clés cryptographiques |
| `encrypt_shell.py` | Chiffre le shellcode avec AES-256 |

### Code C++

| Fichier | Description |
|---------|-------------|
| `opsec_loader.cpp` | Loader minimaliste qui déchiffre et exécute le shellcode |

### Scripts d'automatisation

| Fichier | Description |
|---------|-------------|
| `compile.sh` | Compile le loader avec les optimisations appropriées |
| `opsec_run.sh` | Automatise l'ensemble du workflow (Linux) |
| `opsec_run.ps1` | Automatise l'ensemble du workflow (Windows) |
| `clean_traces.sh` | Script avancé de nettoyage de traces |

## Convertisseur PE-to-Shellcode avancé

Notre convertisseur personnalisé `custom_pe2sc.py` implémente des techniques avancées d'évasion:

### Techniques de polymorphie

- **Encodage variable**: 4 algorithmes d'encodage différents sélectionnés aléatoirement
- **Templates de code**: Variations multiples du code d'initialisation et de décodage
- **Junk code**: Insertion de code non-fonctionnel pour perturber les signatures
- **Offsets variables**: Positionnement aléatoire des sections de code et données

### Reflective Loading

Le shellcode généré implémente un reflective loader complet:

1. **Localisation sans API**: Localise les API nécessaires sans GetProcAddress
2. **Chargement PE**: Parse et charge le PE en mémoire sans LoadLibrary
3. **Résolution d'imports**: Résout les imports sans utiliser les API surveillées
4. **Relocations**: Applique les relocations pour les adresses de base variables
5. **Exécution**: Saute vers le point d'entrée du PE chargé

### API Hashing

- **Résolution d'API sans chaînes**: Utilise des hachages au lieu de noms de fonctions
- **IAT dynamique**: Construction de la table d'import en mémoire
- **PEB Walking**: Navigation dans les structures internes Windows

## Aspects techniques

### Architecture de chiffrement

Le chiffrement utilise une approche robuste à deux couches:

1. **Couche externe**: AES-256-CBC avec dérivation de clé PBKDF2
2. **Couche interne**: Encodage polymorphique intégré au shellcode

### Format du shellcode polymorphique

```
+----------------+----------------+----------------+----------------+
|   Stub loader  |  Routine de    |  Code pour le  |  Tables de     |
| (polymorphique)|    décodage    | reflective load|   hachage      |
+----------------+----------------+----------------+----------------+
|                                                                   |
|                     En-tête polymorphique                         |
|                                                                   |
+-------------------------------------------------------------------+
|                                                                   |
|                    PE encodé avec méthode variable                |
|                                                                   |
+-------------------------------------------------------------------+
|                                                                   |
|                   Junk code / données aléatoires                  |
|                                                                   |
+-------------------------------------------------------------------+
```

### Techniques d'évasion EDR

Le framework implémente plusieurs techniques pour éviter la détection:
1. **Shellcode polymorphique**: Signature différente à chaque génération
2. **API Hashing**: Évite l'utilisation de chaînes pour les fonctions Windows
3. **Reflective Loading**: Chargement PE sans LoadLibrary/GetProcAddress
4. **Chiffrement multicouche**: Aucun shellcode ou PE visible sur disque
5. **Junk code**: Perturbation des signatures et analyses heuristiques

## Dépannage

### Problèmes courants et solutions

| Problème | Solution |
|----------|----------|
| `Erreur lors de la conversion` | Vérifiez que le PE est valide et compatible avec l'architecture cible |
| `Erreur lors du chiffrement` | Vérifiez que PyCryptodome est correctement installé |
| `Erreur lors de l'exécution` | Examinez les autorisations d'exécution et la compatibilité de l'OS |
| `Détection par EDR` | Augmentez le niveau de polymorphie ou utilisez des techniques d'évasion supplémentaires |

## Considérations de sécurité

### Bonnes pratiques OPSEC

1. **Environnement isolé**: Utilisez une VM ou un environnement dédié pour la génération des payloads
2. **Stockage sécurisé**: Ne stockez jamais la clé et le payload chiffré au même endroit
3. **Utilisation unique**: Générez une nouvelle clé et un nouveau shellcode polymorphique pour chaque opération
4. **Exécution discrète**: Évitez les exécutions directes à partir de disques scrutés
5. **Attribution minimale**: Évitez les métadonnées et indicateurs d'attribution

### Limitations connues

- Les EDR très avancés peuvent détecter certains comportements de reflective loading
- Certaines protections mémoire avancées peuvent détecter les allocations exécutables
- Les techniques d'API hashing ne sont pas infaillibles contre l'analyse comportementale

## FAQ

**Q: Pourquoi développer un convertisseur PE personnalisé plutôt qu'utiliser Donut?**  
R: Donut génère des signatures connues des EDR. Notre convertisseur implémente la polymorphie et des techniques d'évasion avancées qui produisent un shellcode unique à chaque génération.

**Q: Comment le reflective loading améliore-t-il l'évasion?**  
R: En chargeant le PE directement en mémoire sans API Windows standards, nous évitons les hooks et la surveillance des EDR sur LoadLibrary et fonctions similaires.

**Q: Comment tester si le shellcode est réellement polymorphique?**  
R: Générez plusieurs shellcodes à partir du même PE et comparez-les. Ils devraient être significativement différents. Vous pouvez aussi tester avec des règles YARA pour vérifier qu'ils ne correspondent pas aux mêmes signatures.

**Q: Le framework est-il compatible avec d'autres C2 que Havoc?**  
R: Oui, le convertisseur PE-to-shellcode peut fonctionner avec n'importe quel PE valide, incluant les payloads d'autres frameworks C2.

---

*Dernière mise à jour: 2025-05-04*  
*Auteur: CobaltStrike31*