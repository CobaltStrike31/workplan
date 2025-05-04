"""
Module de scan antivirus
Inspiré du projet premantel (https://github.com/diljith369/premantel)
"""
import os
import json
import hashlib
import requests
import time
import uuid
import base64
from datetime import datetime

# Configuration
RESULTS_DIR = "saved_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Liste des antivirus et leur logo
AV_LOGOS = {
    "avast": "static/images/av_logos/avast.svg",
    "bitdefender": "static/images/av_logos/bitdefender.svg",
    "drweb": "static/images/av_logos/drweb.png",
    "escan": "static/images/av_logos/escan.png",
    "gdata": "static/images/av_logos/gdata.png",
    "kaspersky": "static/images/av_logos/kaspersky.svg",
    "mcafee": "static/images/av_logos/mcafee.svg",
    "microsoft": "static/images/av_logos/microsoft.svg",
    "clam": "static/images/av_logos/clam.png",
    "fortinet": "static/images/av_logos/fortinet.png",
    "trend": "static/images/av_logos/trend.svg",
    "symantec": "static/images/av_logos/symantec.svg",
    "k7": "static/images/av_logos/k7.png",
    "ikarus": "static/images/av_logos/ikarus.png",
    "vba32": "static/images/av_logos/vba32.png"
}

# Assurez-vous que le répertoire des images existe
os.makedirs("static/images/av_logos", exist_ok=True)

class ScanResult:
    """Classe pour stocker les résultats de scan"""
    def __init__(self, av_name, detection, detection_name="", logo_path=""):
        self.av_name = av_name
        self.detection = detection  # True si détecté, False sinon
        self.detection_name = detection_name
        self.logo_path = logo_path
        self.timestamp = datetime.now().strftime("%b %d, %Y")
    
    def to_dict(self):
        return {
            "av_name": self.av_name,
            "detection": self.detection,
            "detection_name": self.detection_name,
            "logo_path": self.logo_path,
            "timestamp": self.timestamp
        }

def get_file_hash(file_path):
    """Calcule le hash SHA256 d'un fichier"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_info(file_path):
    """Obtient les informations de base sur un fichier"""
    stat_info = os.stat(file_path)
    file_size = stat_info.st_size
    file_name = os.path.basename(file_path)
    first_seen = datetime.fromtimestamp(stat_info.st_ctime).strftime("%b %d, %Y at %H:%M:%S GMT+2")
    file_hash = get_file_hash(file_path)
    
    return {
        "name": file_name,
        "size": f"{file_size} bytes ({file_size/1024:.2f} KB)",
        "type": "Unknown",
        "first_seen": first_seen,
        "hash": file_hash,
        "sha1": "",  # Pourrait être implémenté si nécessaire
        "md5": ""    # Pourrait être implémenté si nécessaire
    }

def simulate_av_scan(file_info):
    """
    Simule un scan de fichier par plusieurs antivirus
    Cette fonction simule une analyse basée sur des heuristiques simples
    mais pourrait être connectée à des API réelles comme VirusTotal
    """
    file_name = file_info["name"].lower()
    file_size = int(file_info["size"].split(" ")[0])
    scan_id = str(uuid.uuid4())[:8]
    
    results = []
    
    # Liste des AV pour la simulation
    av_list = [
        "avast", "bitdefender", "drweb", "escan", "gdata",
        "kaspersky", "mcafee", "microsoft", "clam", "fortinet",
        "trend", "symantec", "k7", "ikarus", "vba32"
    ]
    
    # Patterns suspects (simulation)
    suspicious_extensions = [".exe", ".dll", ".scr", ".bat", ".vbs", ".ps1"]
    suspicious_names = ["trojan", "hack", "crack", "keygen", "patch", "warez", "virus"]
    
    # Calculer le niveau de suspicion basé sur des règles simples
    suspicion_level = 0
    
    # Vérifier l'extension
    for ext in suspicious_extensions:
        if file_name.endswith(ext):
            suspicion_level += 20
            break
    
    # Vérifier les noms suspects
    for name in suspicious_names:
        if name in file_name:
            suspicion_level += 30
            break
    
    # Ajouter un facteur aléatoire par antivirus
    for av_name in av_list:
        # Simuler différents niveaux de détection par AV
        av_sensitivity = {
            "avast": 60,
            "bitdefender": 75,
            "drweb": 65,
            "escan": 55,
            "gdata": 70,
            "kaspersky": 80,
            "mcafee": 60,
            "microsoft": 65,
            "clam": 50,
            "fortinet": 70,
            "trend": 65,
            "symantec": 75,
            "k7": 55,
            "ikarus": 65,
            "vba32": 60
        }
        
        # Déterminer si cet AV détecte ou non
        detection_threshold = av_sensitivity.get(av_name, 60)
        detected = suspicion_level >= detection_threshold
        
        # Générer un nom de détection si détecté
        detection_name = ""
        if detected:
            detection_prefixes = ["Trojan", "Generic", "Suspicious", "Malware", "PUA", "Backdoor", "Worm"]
            detection_families = ["Win32", "Havoc", "Marte", "Packed", "Agent", "Dropper", "Injector"]
            detection_suffixes = ["D.861", "Generic", "Variant", "Family.A", "Gen", str(hash(file_name))[:5]]
            
            import random
            prefix = random.choice(detection_prefixes)
            family = random.choice(detection_families)
            suffix = random.choice(detection_suffixes)
            detection_name = f"{prefix}.{family}.{suffix}" if detected else ""
        else:
            detection_name = "Found nothing"
        
        # Créer le résultat pour cet AV
        result = ScanResult(
            av_name=av_name,
            detection=detected,
            detection_name=detection_name,
            logo_path=AV_LOGOS.get(av_name, "")
        )
        results.append(result)
    
    # Calculer le taux de détection
    detection_count = sum(1 for r in results if r.detection)
    detection_rate = f"{detection_count}/{len(results)}"
    
    # Créer le résultat final
    scan_result = {
        "scan_id": f"{scan_id}",
        "file_info": file_info,
        "status": "Scan finished",
        "detection_rate": detection_rate,
        "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
        "results": [r.to_dict() for r in results]
    }
    
    # Sauvegarder le résultat dans un fichier
    result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    with open(result_path, "w") as f:
        json.dump(scan_result, f, indent=2)
    
    return scan_id

def display_scan_results(scan_id):
    """Récupère et formate les résultats d'un scan pour l'affichage"""
    result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    
    if not os.path.exists(result_path):
        return {"error": "Scan results not found"}
    
    with open(result_path, "r") as f:
        scan_result = json.load(f)
    
    return scan_result

def get_virustotal_report(api_key, file_hash):
    """
    Obtient un rapport VirusTotal pour un hash donné
    
    Args:
        api_key: API key VirusTotal
        file_hash: SHA256 hash du fichier
        
    Returns:
        dict: Rapport VirusTotal
    """
    if not api_key:
        return {"error": "No VirusTotal API key provided"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error connecting to VirusTotal: {str(e)}"}

if __name__ == "__main__":
    # Test du module
    test_file = __file__  # Utiliser ce script comme fichier de test
    file_info = get_file_info(test_file)
    scan_id = simulate_av_scan(file_info)
    print(f"Scan completed. Scan ID: {scan_id}")
    
    results = display_scan_results(scan_id)
    print(f"Detection rate: {results['detection_rate']}")