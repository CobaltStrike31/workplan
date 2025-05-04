"""
Module pour les scanners d'antivirus utilisant des API (gratuites ou payantes)
Ce module gère l'analyse de fichiers en utilisant différentes API en fonction des clés disponibles
"""
import os
import json
import hashlib
import requests
import time
import uuid
import base64
from datetime import datetime

# Récupérer les clés API depuis les variables d'environnement
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
HA_API_KEY = os.environ.get('HYBRID_ANALYSIS_API_KEY', '')
FS_API_KEY = os.environ.get('FILESCAN_API_KEY', '')

# Configuration
RESULTS_DIR = "saved_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def get_available_scan_types():
    """
    Détermine quels types de scan sont disponibles en fonction des clés API configurées
    
    Returns:
        dict: Types de scan disponibles avec leur nom convivial
    """
    available_scans = {
        "simulated": "Analyse simulée (rapide)",
        "apis_gratuites": "Bases de données gratuites (VT, MalwareBazaar, ThreatFox)"
    }
    
    # Ajouter les services payants si les clés sont disponibles
    if VT_API_KEY:
        available_scans["virustotal"] = "VirusTotal (API officielle)"
    
    if HA_API_KEY:
        available_scans["hybrid_analysis"] = "Hybrid Analysis (Falcon Sandbox)"
        
    if FS_API_KEY:
        available_scans["filescan"] = "FileScan.io"
    
    return available_scans

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
    
    # Calculer SHA256
    file_hash = get_file_hash(file_path)
    
    # Calculer MD5
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    md5 = md5_hash.hexdigest()
    
    # Calculer SHA1
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

def check_with_virustotal(file_hash):
    """
    Vérifie un hash avec l'API officielle VirusTotal
    
    Args:
        file_hash: Hash SHA256 du fichier
        
    Returns:
        dict: Rapport d'analyse formaté
    """
    if not VT_API_KEY:
        return {"error": "Clé API VirusTotal non configurée"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extraire les résultats antivirus
            results = []
            detection_count = 0
            total_engines = 0
            
            if 'data' in data and 'attributes' in data['data'] and 'last_analysis_results' in data['data']['attributes']:
                av_results = data['data']['attributes']['last_analysis_results']
                total_engines = len(av_results)
                
                for av_name, av_result in av_results.items():
                    detected = av_result['category'] == 'malicious'
                    if detected:
                        detection_count += 1
                    
                    results.append({
                        "av_name": av_name,
                        "detection": detected,
                        "detection_name": av_result.get('result', '') if detected else '',
                        "logo_path": f"static/images/av_logos/{av_name.lower()}.png",
                        "timestamp": datetime.now().strftime("%b %d, %Y")
                    })
            
            # Formater la réponse
            scan_id = str(uuid.uuid4())[:8]
            scan_result = {
                "scan_id": scan_id,
                "file_info": {
                    "hash": file_hash,
                    "name": data['data']['attributes'].get('meaningful_name', 'Unknown'),
                    "size": f"{data['data']['attributes'].get('size', 0)} bytes",
                    "type": data['data']['attributes'].get('type_description', 'Unknown'),
                    "first_seen": datetime.fromtimestamp(data['data']['attributes'].get('first_submission_date', 0)).strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                    "md5": data['data']['attributes'].get('md5', ''),
                    "sha1": data['data']['attributes'].get('sha1', '')
                },
                "status": "Scan finished",
                "detection_rate": f"{detection_count}/{total_engines}",
                "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                "results": results
            }
            
            # Sauvegarder le résultat
            result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
            with open(result_path, "w") as f:
                json.dump(scan_result, f, indent=2)
            
            return scan_id
        elif response.status_code == 404:
            # Le fichier n'existe pas dans la base de données
            scan_id = str(uuid.uuid4())[:8]
            scan_result = {
                "scan_id": scan_id,
                "file_info": {
                    "hash": file_hash,
                    "name": "Unknown",
                    "size": "Unknown",
                    "type": "Unknown",
                    "first_seen": "N/A",
                    "md5": "",
                    "sha1": ""
                },
                "status": "File not found",
                "detection_rate": "0/0",
                "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                "results": [{
                    "av_name": "VirusTotal",
                    "detection": False,
                    "detection_name": "Fichier non trouvé dans la base de données",
                    "logo_path": "static/images/av_logos/default.png",
                    "timestamp": datetime.now().strftime("%b %d, %Y")
                }]
            }
            
            # Sauvegarder le résultat
            result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
            with open(result_path, "w") as f:
                json.dump(scan_result, f, indent=2)
            
            return scan_id
        else:
            return {"error": f"Erreur API VirusTotal: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": f"Erreur lors de la connexion à VirusTotal: {str(e)}"}

def check_with_hybrid_analysis(file_hash):
    """
    Vérifie un hash avec l'API Hybrid Analysis (Falcon Sandbox)
    
    Args:
        file_hash: Hash SHA256 du fichier
        
    Returns:
        dict: Rapport d'analyse formaté ou ID de scan
    """
    if not HA_API_KEY:
        return {"error": "Clé API Hybrid Analysis non configurée"}
    
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Hybrid Analysis API",
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "hash": file_hash
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extraire les résultats
            results = []
            detection_count = 0
            
            if isinstance(data, list) and len(data) > 0:
                # Il y a des résultats
                malicious_count = sum(1 for item in data if item.get('verdict', '').lower() == 'malicious')
                
                for item in data:
                    detected = item.get('verdict', '').lower() == 'malicious'
                    if detected:
                        detection_count += 1
                    
                    results.append({
                        "av_name": "Hybrid Analysis",
                        "detection": detected,
                        "detection_name": item.get('threat_name', 'Malicious') if detected else '',
                        "logo_path": "static/images/av_logos/falcon.png",
                        "timestamp": datetime.fromtimestamp(item.get('analysis_start_time', 0)/1000).strftime("%b %d, %Y")
                    })
                
                # Ajouter d'autres scanners mentionnés dans les résultats si disponibles
                if 'av_detect' in data[0]:
                    for av_name, detected in data[0]['av_detect'].items():
                        results.append({
                            "av_name": av_name,
                            "detection": detected > 0,
                            "detection_name": "Detected" if detected > 0 else "",
                            "logo_path": f"static/images/av_logos/{av_name.lower()}.png",
                            "timestamp": datetime.now().strftime("%b %d, %Y")
                        })
                
                # Formater la réponse
                scan_id = str(uuid.uuid4())[:8]
                scan_result = {
                    "scan_id": scan_id,
                    "file_info": {
                        "hash": file_hash,
                        "name": data[0].get('submit_name', 'Unknown'),
                        "size": f"{data[0].get('size', 0)} bytes",
                        "type": data[0].get('type', 'Unknown'),
                        "first_seen": datetime.fromtimestamp(data[0].get('analysis_start_time', 0)/1000).strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                        "md5": data[0].get('md5', ''),
                        "sha1": data[0].get('sha1', '')
                    },
                    "status": "Scan finished",
                    "detection_rate": f"{malicious_count}/{len(data)}",
                    "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                    "results": results
                }
                
                # Sauvegarder le résultat
                result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
                with open(result_path, "w") as f:
                    json.dump(scan_result, f, indent=2)
                
                return scan_id
            else:
                # Aucun résultat
                scan_id = str(uuid.uuid4())[:8]
                scan_result = {
                    "scan_id": scan_id,
                    "file_info": {
                        "hash": file_hash,
                        "name": "Unknown",
                        "size": "Unknown",
                        "type": "Unknown",
                        "first_seen": "N/A",
                        "md5": "",
                        "sha1": ""
                    },
                    "status": "File not found",
                    "detection_rate": "0/0",
                    "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                    "results": [{
                        "av_name": "Hybrid Analysis",
                        "detection": False,
                        "detection_name": "Fichier non trouvé dans la base de données",
                        "logo_path": "static/images/av_logos/falcon.png",
                        "timestamp": datetime.now().strftime("%b %d, %Y")
                    }]
                }
                
                # Sauvegarder le résultat
                result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
                with open(result_path, "w") as f:
                    json.dump(scan_result, f, indent=2)
                
                return scan_id
        else:
            return {"error": f"Erreur API Hybrid Analysis: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": f"Erreur lors de la connexion à Hybrid Analysis: {str(e)}"}

def check_with_filescan(file_hash):
    """
    Vérifie un hash avec l'API FileScan.io
    
    Args:
        file_hash: Hash SHA256 du fichier
        
    Returns:
        dict: Rapport d'analyse formaté ou ID de scan
    """
    if not FS_API_KEY:
        return {"error": "Clé API FileScan.io non configurée"}
    
    url = f"https://www.filescan.io/api/v1/report/{file_hash}"
    headers = {
        "Authorization": f"Bearer {FS_API_KEY}"
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extraire les résultats
            results = []
            detection_count = 0
            total_engines = 0
            
            if 'scan_results' in data:
                scan_data = data['scan_results']
                for scanner_name, scanner_results in scan_data.items():
                    if isinstance(scanner_results, dict) and 'result' in scanner_results:
                        total_engines += 1
                        detected = scanner_results['result'] != 'clean'
                        if detected:
                            detection_count += 1
                        
                        results.append({
                            "av_name": scanner_name,
                            "detection": detected,
                            "detection_name": scanner_results.get('result', '') if detected else '',
                            "logo_path": f"static/images/av_logos/{scanner_name.lower()}.png",
                            "timestamp": datetime.now().strftime("%b %d, %Y")
                        })
            
            # Formater la réponse
            scan_id = str(uuid.uuid4())[:8]
            scan_result = {
                "scan_id": scan_id,
                "file_info": {
                    "hash": file_hash,
                    "name": data.get('file_name', 'Unknown'),
                    "size": f"{data.get('file_size', 0)} bytes",
                    "type": data.get('file_type', 'Unknown'),
                    "first_seen": data.get('first_scan_date', 'N/A'),
                    "md5": data.get('md5', ''),
                    "sha1": data.get('sha1', '')
                },
                "status": "Scan finished",
                "detection_rate": f"{detection_count}/{total_engines}",
                "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                "results": results
            }
            
            # Sauvegarder le résultat
            result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
            with open(result_path, "w") as f:
                json.dump(scan_result, f, indent=2)
            
            return scan_id
        elif response.status_code == 404:
            # Le fichier n'existe pas dans la base de données
            scan_id = str(uuid.uuid4())[:8]
            scan_result = {
                "scan_id": scan_id,
                "file_info": {
                    "hash": file_hash,
                    "name": "Unknown",
                    "size": "Unknown",
                    "type": "Unknown",
                    "first_seen": "N/A",
                    "md5": "",
                    "sha1": ""
                },
                "status": "File not found",
                "detection_rate": "0/0",
                "scan_date": datetime.now().strftime("%b %d, %Y at %H:%M:%S GMT+2"),
                "results": [{
                    "av_name": "FileScan.io",
                    "detection": False,
                    "detection_name": "Fichier non trouvé dans la base de données",
                    "logo_path": "static/images/av_logos/default.png",
                    "timestamp": datetime.now().strftime("%b %d, %Y")
                }]
            }
            
            # Sauvegarder le résultat
            result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
            with open(result_path, "w") as f:
                json.dump(scan_result, f, indent=2)
            
            return scan_id
        else:
            return {"error": f"Erreur API FileScan.io: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": f"Erreur lors de la connexion à FileScan.io: {str(e)}"}

def check_with_free_databases(file_path):
    """
    Vérifie un fichier avec plusieurs bases de données gratuites
    Utilise les modules existants de free_av_scanner.py
    
    Args:
        file_path: Chemin vers le fichier à analyser
        
    Returns:
        str: ID du scan
    """
    from scanners.free_av_scanner import scan_file_with_free_apis
    return scan_file_with_free_apis(file_path)

def get_scan_results(scan_id):
    """
    Récupère et formate les résultats d'un scan pour l'affichage
    
    Args:
        scan_id: Identifiant du scan
        
    Returns:
        dict: Résultats du scan
    """
    result_path = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    
    if not os.path.exists(result_path):
        return {"error": "Scan results not found"}
    
    with open(result_path, "r") as f:
        scan_result = json.load(f)
    
    return scan_result

def analyze_file(file_path, scan_type):
    """
    Analyse un fichier avec la méthode spécifiée
    
    Args:
        file_path: Chemin vers le fichier à analyser
        scan_type: Type d'analyse à effectuer
        
    Returns:
        str or dict: ID du scan ou erreur
    """
    file_info = get_file_info(file_path)
    file_hash = file_info["hash"]
    
    if scan_type == "virustotal" and VT_API_KEY:
        return check_with_virustotal(file_hash)
    elif scan_type == "hybrid_analysis" and HA_API_KEY:
        return check_with_hybrid_analysis(file_hash)
    elif scan_type == "filescan" and FS_API_KEY:
        return check_with_filescan(file_hash)
    elif scan_type == "apis_gratuites":
        return check_with_free_databases(file_path)
    elif scan_type == "simulated":
        from scanners.av_scanner import simulate_av_scan
        return simulate_av_scan(file_info)
    else:
        return {"error": f"Type d'analyse non pris en charge ou clé API manquante: {scan_type}"}