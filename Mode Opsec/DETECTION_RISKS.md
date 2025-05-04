# Risques de détection et mitigations

## Pourquoi éviter les outils standards comme Donut

Les outils standards de conversion PE-to-Shellcode comme Donut posent plusieurs risques majeurs:

### 1. Signatures connues par les EDR

Les solutions EDR modernes intègrent des signatures spécifiques pour détecter:
- Les en-têtes et stubs générés par Donut
- Les routines d'allocation mémoire typiques
- Les patterns de reflective loading

### 2. Caractéristiques comportementales surveillées

Les EDR surveillent activement:
- Les allocations RWX en mémoire
- Les techniques d'auto-injection
- Les appels API suspects dans un ordre particulier

## Notre approche pour l'évasion

Le framework implémente plusieurs techniques avancées:

### 1. Convertisseur PE personnalisé

Notre script `havoc_to_shellcode.py` priorise:
- Votre propre convertisseur PE-to-shellcode
- Un mécanisme intégré de conversion avec encodage personnalisé
- L'utilisation de pe2shc comme alternative à Donut
- L'utilisation de Donut uniquement en dernier recours, avec post-traitement

### 2. Techniques d'obfuscation multi-couches

- **Mutation binaire**: Altération des octets non-critiques
- **XOR dynamique**: Encodage avec clés variables
- **Suppression de signatures**: Élimination des chaînes identifiables
- **Post-traitement**: Modification des patterns connus

### 3. Exécution à faible visibilité

- **Allocation mémoire en plusieurs étapes**
- **Effacement des traces intermédiaires**
- **Protection mémoire progressive** (RW → RX)

## Recommendations pour améliorer davantage l'OPSEC

1. **Développez votre propre convertisseur PE**: Idéalement en C/ASM natif
2. **Implémentez des appels système directs**: Évitez l'API Windows standard
3. **Utilisez des techniques d'injection distante**: Plutôt que l'auto-injection
4. **Appliquez une randomisation lors de chaque opération**: Templates, offsets, clés
5. **Testez contre les EDR modernes**: Dans un environnement sandbox

---

Pour plus d'informations sur les techniques avancées d'évasion, consultez la section "Aspects techniques" du README principal.