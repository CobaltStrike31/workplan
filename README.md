# OPSEC Loader Web Interface

Interface web éducative pour démontrer les limitations des solutions antivirus et comprendre les techniques d'évasion des logiciels malveillants.

## Fonctionnalités
- Conversion de fichiers PE en shellcode
- Chiffrement de shellcode avec différentes méthodes (AES-256-CBC, AES-128-CBC, XOR)
- Génération de loaders en C++, C, et Python
- Système clé en main pour automatiser le workflow complet
- Analyse antivirus avec différentes APIs (VirusTotal, Hybrid Analysis, FileScan.io)
- Visualisation des métriques de sécurité

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

## Avertissement
Ce projet est à but éducatif uniquement et ne doit pas être utilisé à des fins malveillantes.