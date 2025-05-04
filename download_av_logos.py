"""
Script simple pour télécharger des logos d'antivirus
"""
import os
import requests

# Créer le dossier s'il n'existe pas
os.makedirs("static/images/av_logos", exist_ok=True)

# Définir les URLs des logos
LOGOS = {
    "avast": "https://upload.wikimedia.org/wikipedia/commons/4/4a/Avast_Antivirus_logo.png",
    "bitdefender": "https://upload.wikimedia.org/wikipedia/commons/1/14/Bitdefender_logo.png",
    "kaspersky": "https://upload.wikimedia.org/wikipedia/commons/8/8a/Kaspersky_logo.svg",
    "mcafee": "https://upload.wikimedia.org/wikipedia/commons/3/39/McAfee_logo_%282017%29.svg",
    "microsoft": "https://upload.wikimedia.org/wikipedia/commons/9/96/Microsoft_logo_%282012%29.svg",
    "symantec": "https://upload.wikimedia.org/wikipedia/commons/0/0e/Symantec_logo10.svg",
    "trend": "https://upload.wikimedia.org/wikipedia/commons/2/29/Trend_Micro_logo.svg"
}

# Logos par défaut pour ceux qui n'ont pas d'URL spécifique
DEFAULT_LOGO_URL = "https://cdn-icons-png.flaticon.com/512/2370/2370264.png"

# Liste complète des antivirus
ALL_AV = [
    "avast", "bitdefender", "drweb", "escan", "gdata",
    "kaspersky", "mcafee", "microsoft", "clam", "fortinet",
    "trend", "symantec", "k7", "ikarus", "vba32"
]

def download_logo(name, url, dest_folder):
    """Télécharge un logo d'antivirus"""
    try:
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            # Déterminer l'extension de fichier
            content_type = response.headers.get('content-type', '')
            if 'svg' in content_type:
                ext = '.svg'
            elif 'png' in content_type:
                ext = '.png'
            elif 'jpeg' in content_type or 'jpg' in content_type:
                ext = '.jpg'
            else:
                ext = '.png'  # Extension par défaut
            
            # Écrire le fichier
            file_path = os.path.join(dest_folder, f"{name}{ext}")
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            print(f"Téléchargé: {name}{ext}")
            return True
        else:
            print(f"Erreur {response.status_code} pour {name}")
            return False
    except Exception as e:
        print(f"Erreur pour {name}: {str(e)}")
        return False

# Télécharger les logos
for av_name in ALL_AV:
    url = LOGOS.get(av_name, DEFAULT_LOGO_URL)
    download_logo(av_name, url, "static/images/av_logos")

# Télécharger un logo par défaut
download_logo("default", DEFAULT_LOGO_URL, "static/images/av_logos")

print("Téléchargement terminé.")