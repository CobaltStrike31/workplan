"""
Module de scan antivirus utilisant des API gratuites
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
    
    # Calculer MD5 aussi car certaines API utilisent ce format
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    md5 = md5_hash.hexdigest()
    
    # Calculer SHA1 aussi
    sha1_hash = hashlib.sha1()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha1_hash.update(byte_block)
    sha1 = sha1_hash.hexdigest()
    
    return {
        "name": file_name,
        "size": f"{file_size} bytes ({file_size/1024:.2f} KB)",
        "type": detect_file_type(file_path),
        "first_seen": first_seen,
        "hash": file_hash,
        "sha1": sha1,
        "md5": md5
    }

def detect_file_type(file_path):
    """Détecte le type de fichier basé sur sa signature"""
    with open(file_path, 'rb') as f:
        header = f.read(8)  # Lire les 8 premiers octets
    
    # Vérifier pour les signatures communes
    if header.startswith(b'MZ'):
        return "Executable Windows (PE)"
    elif header.startswith(b'\x7fELF'):
        return "Executable Linux (ELF)"
    elif header.startswith(b'PK\x03\x04'):
        return "Archive ZIP"
    elif header[0:4] == b'%PDF':
        return "Document PDF"
    elif header[0:5] == b'{\\rtf':
        return "Document RTF"
    elif header[0:4] == b'\xD0\xCF\x11\xE0':
        return "Document Microsoft Office"
    elif header.startswith(b'\xFF\xD8\xFF'):
        return "Image JPEG"
    elif header.startswith(b'\x89PNG\r\n\x1A\n'):
        return "Image PNG"
    elif header[0:3] == b'GIF':
        return "Image GIF"
    else:
        return "Fichier inconnu"

def check_with_virustotal_public(file_hash):
    """
    Vérifie un hash avec l'API non-officielle VirusTotal
    Cette méthode utilise une astuce pour accéder aux données sans clé API
    À utiliser uniquement à des fins éducatives
    
    Args:
        file_hash: Hash SHA256 du fichier
        
    Returns:
        dict: Rapport d'analyse
    """
    url = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        # Effectuer une requête pour voir si le fichier existe dans la base de données
        response = requests.get(url, headers=headers)
        exists = response.status_code == 200 and not "not found" in response.text.lower()
        
        if exists:
            return {
                "scan_id": file_hash,
                "permalink": url,
                "exists_in_vt": True,
                "message": "Ce fichier est présent dans la base de données VirusTotal. Consultez les résultats en visitant le lien.",
                "results": [
                    {"av_name": "VirusTotal", "detection": True, "detection_name": "Fichier trouvé dans la base de données", "logo_path": "static/images/av_logos/default.png"}
                ]
            }
        else:
            return {
                "scan_id": file_hash,
                "exists_in_vt": False,
                "message": "Ce fichier n'est pas présent dans la base de données VirusTotal.",
                "results": [
                    {"av_name": "VirusTotal", "detection": False, "detection_name": "Fichier non trouvé dans la base de données", "logo_path": "static/images/av_logos/default.png"}
                ]
            }
    except Exception as e:
        return {"error": f"Erreur lors de la vérification avec VirusTotal: {str(e)}"}

def check_with_malwarebazaar(file_hash):
    """
    Vérifie un hash avec l'API gratuite MalwareBazaar
    
    Args:
        file_hash: Hash du fichier (SHA256)
        
    Returns:
        dict: Rapport d'analyse
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_info",
        "hash": file_hash
    }
    
    try:
        response = requests.post(url, data=data)
        
        if response.status_code == 200:
            json_response = response.json()
            
            # Formater la réponse pour correspondre à notre format standard
            if json_response.get("query_status") == "ok":
                if len(json_response.get("data", [])) > 0:
                    malware_data = json_response["data"][0]
                    return {
                        "scan_id": file_hash,
                        "permalink": f"https://bazaar.abuse.ch/sample/{file_hash}/",
                        "exists_in_mb": True,
                        "file_info": {
                            "type": malware_data.get("file_type", "Unknown"),
                            "tags": malware_data.get("tags", []),
                            "signature": malware_data.get("signature", "Unknown")
                        },
                        "message": "Ce fichier est présent dans la base de données MalwareBazaar.",
                        "results": [
                            {"av_name": "MalwareBazaar", "detection": True, "detection_name": malware_data.get("signature", "Malware détecté"), "logo_path": "static/images/av_logos/default.png"}
                        ]
                    }
                else:
                    return {
                        "scan_id": file_hash,
                        "exists_in_mb": False,
                        "message": "Ce fichier n'est pas présent dans la base de données MalwareBazaar.",
                        "results": [
                            {"av_name": "MalwareBazaar", "detection": False, "detection_name": "Fichier non trouvé dans la base de données", "logo_path": "static/images/av_logos/default.png"}
                        ]
                    }
            else:
                return {
                    "error": f"Erreur MalwareBazaar: {json_response.get('query_status')}"
                }
        else:
            return {"error": f"Erreur MalwareBazaar: {response.status_code}"}
    except Exception as e:
        return {"error": f"Erreur lors de la vérification avec MalwareBazaar: {str(e)}"}

def check_with_threatfox(file_hash):
    """
    Vérifie un hash avec l'API gratuite ThreatFox
    
    Args:
        file_hash: Hash du fichier (MD5, SHA1 ou SHA256)
        
    Returns:
        dict: Rapport d'analyse
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    data = {
        "query": "search_hash",
        "hash": file_hash
    }
    
    try:
        response = requests.post(url, json=data)
        
        if response.status_code == 200:
            json_response = response.json()
            
            # Formater la réponse pour correspondre à notre format standard
            if json_response.get("query_status") == "ok":
                if len(json_response.get("data", [])) > 0:
                    threat_data = json_response["data"]
                    return {
                        "scan_id": file_hash,
                        "permalink": f"https://threatfox.abuse.ch/ioc/{file_hash}/",
                        "exists_in_tf": True,
                        "file_info": {
                            "threats": [item.get("malware_printable", "Unknown") for item in threat_data],
                            "tags": list(set(sum([item.get("tags", []) for item in threat_data], [])))
                        },
                        "message": "Ce fichier est présent dans la base de données ThreatFox.",
                        "results": [
                            {"av_name": "ThreatFox", "detection": True, "detection_name": "IOC détecté: " + ", ".join([item.get("malware_printable", "Unknown") for item in threat_data[:3]]), "logo_path": "static/images/av_logos/default.png"}
                        ]
                    }
                else:
                    return {
                        "scan_id": file_hash,
                        "exists_in_tf": False,
                        "message": "Ce fichier n'est pas présent dans la base de données ThreatFox.",
                        "results": [
                            {"av_name": "ThreatFox", "detection": False, "detection_name": "Fichier non trouvé dans la base de données", "logo_path": "static/images/av_logos/default.png"}
                        ]
                    }
            else:
                return {
                    "error": f"Erreur ThreatFox: {json_response.get('query_status')}"
                }
        else:
            return {"error": f"Erreur ThreatFox: {response.status_code}"}
    except Exception as e:
        return {"error": f"Erreur lors de la vérification avec ThreatFox: {str(e)}"}

def scan_file_with_free_apis(file_path):
    """
    Analyse un fichier avec plusieurs API gratuites
    
    Args:
        file_path: Chemin vers le fichier à analyser
        
    Returns:
        dict: Résultats combinés des différentes API
    """
    file_info = get_file_info(file_path)
    scan_id = str(uuid.uuid4())[:8]
    
    # Obtenir les résultats de chaque API
    vt_results = check_with_virustotal_public(file_info["hash"])
    mb_results = check_with_malwarebazaar(file_info["hash"])
    tf_results = check_with_threatfox(file_info["hash"])
    
    # Combiner les résultats
    results = []
    detection_count = 0
    total_sources = 0
    
    # Ajouter les résultats de VirusTotal
    if "error" not in vt_results:
        results.extend(vt_results.get("results", []))
        if vt_results.get("exists_in_vt", False):
            detection_count += 1
        total_sources += 1
    
    # Ajouter les résultats de MalwareBazaar
    if "error" not in mb_results:
        results.extend(mb_results.get("results", []))
        if mb_results.get("exists_in_mb", False):
            detection_count += 1
        total_sources += 1
    
    # Ajouter les résultats de ThreatFox
    if "error" not in tf_results:
        results.extend(tf_results.get("results", []))
        if tf_results.get("exists_in_tf", False):
            detection_count += 1
        total_sources += 1
    
    # Créer le rapport final
    scan_result = {
        "scan_id": scan_id,
        "file_info": file_info,
        "status": "Scan finished",
        "detection_rate": f"{detection_count}/{total_sources}",
        "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
        "results": results
    }
    
    # Sauvegarder le résultat dans un fichier
    result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    with open(result_path, "w") as f:
        json.dump(scan_result, f, indent=2)
    
    return scan_id

def get_scan_results(scan_id):
    """Récupère et formate les résultats d'un scan pour l'affichage"""
    result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    
    if not os.path.exists(result_path):
        return {"error": "Scan results not found"}
    
    with open(result_path, "r") as f:
        scan_result = json.load(f)
    
    return scan_result

if __name__ == "__main__":
    # Test du module
    test_file = __file__  # Utiliser ce script comme fichier de test
    scan_id = scan_file_with_free_apis(test_file)
    print(f"Scan completed. Scan ID: {scan_id}")
    
    results = get_scan_results(scan_id)
    print(f"Detection rate: {results['detection_rate']}")