# OPSEC Loader Web Interface

Interface web éducative pour démontrer les limitations des solutions antivirus et comprendre les techniques d'évasion des logiciels malveillants. Cette interface est conçue pour interagir avec le framework OPSEC Loader original sans le modifier.

## Fonctionnalités
- Conversion de fichiers PE en shellcode avec validation sécurisée des entrées
- Chiffrement de shellcode avec différentes méthodes (AES-256-CBC, AES-128-CBC, XOR)
- Génération de loaders en C++, C, et Python avec options d'obfuscation
- Système clé en main pour automatiser le workflow complet
- Analyse antivirus avec différentes APIs (VirusTotal, Hybrid Analysis, FileScan.io)
- Visualisation des métriques de sécurité basées sur des sources fiables
- Protection CSRF sur tous les formulaires
- Gestion sécurisée des fichiers temporaires
- Animations et visualisations dynamiques des données de sécurité

## Installation
```bash
pip install -r requirements.txt
python app.py
```

## Utilisation
Accédez à l'interface via http://localhost:5000

## Configuration des APIs d'analyse antivirus
Pour utiliser les fonctionnalités d'analyse antivirus, vous devez configurer les clés API dans des variables d'environnement:
- `VIRUSTOTAL_API_KEY` - Pour l'analyse via VirusTotal
- `HYBRID_ANALYSIS_API_KEY` - Pour l'analyse via Hybrid Analysis
- `FILESCAN_API_KEY` - Pour l'analyse via FileScan.io

## Architecture du projet

### Modules principaux
- `app.py` - Application Flask principale qui gère les routes et l'interface utilisateur
- `utils/safe_wrappers/` - Wrappers sécurisés pour interagir avec le framework original
  - `safe_pe2sc.py` - Wrapper pour la conversion PE à shellcode
  - `safe_encryption.py` - Wrapper pour le chiffrement et déchiffrement des shellcodes
  - `safe_key_formatter.py` - Wrapper pour formatage sécurisé des clés de chiffrement
  - `safe_havoc.py` - Wrapper pour la conversion Havoc à shellcode
- `scanners/` - Modules pour l'analyse antivirus
  - `av_scanner.py` - Interface d'analyse générique
  - `api_scanners.py` - Intégration avec les API d'analyse antivirus

### Sécurité
Le projet intègre plusieurs couches de sécurité :
- Protection CSRF sur tous les formulaires
- Validation et sanitisation des entrées utilisateur
- Gestion sécurisée des fichiers temporaires
- Wrappers sécurisés qui isolent les interactions avec le framework original

## Version
Version actuelle : 1.1.0
Dernière mise à jour : 5 mai 2025

## Avertissement
Ce projet est à but éducatif uniquement et ne doit pas être utilisé à des fins malveillantes. Il vise à démontrer les limitations des solutions antivirus et à sensibiliser les professionnels de la cybersécurité.