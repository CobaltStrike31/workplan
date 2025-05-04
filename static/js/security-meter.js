/**
 * Security Meter - Animation dynamique pour évaluation des risques
 * 
 * Ce script crée une jauge de sécurité animée pour afficher visuellement
 * le niveau de risque ou de sécurité d'une configuration.
 */

document.addEventListener("DOMContentLoaded", function() {
    // Initialiser tous les compteurs de sécurité sur la page
    initializeSecurityMeters();
    
    // Initialiser les compteurs spécifiques pour le système clé en main
    setupDynamicSecurityMeters();
});

/**
 * Initialise tous les compteurs de sécurité sur la page
 */
function initializeSecurityMeters() {
    const meters = document.querySelectorAll('.security-meter');
    
    meters.forEach(meter => {
        const value = parseFloat(meter.dataset.value || 50);
        const maxValue = parseFloat(meter.dataset.maxValue || 100);
        const minValue = parseFloat(meter.dataset.minValue || 0);
        const danger = meter.dataset.danger === 'true';
        
        // Animer le compteur à l'initialisation
        animateSecurityMeter(meter, value, minValue, maxValue, danger);
    });
}

/**
 * Configure les compteurs dynamiques pour le système clé en main
 */
function setupDynamicSecurityMeters() {
    // Écouteurs pour les changements dans le modal système clé en main
    const modal = document.getElementById('oneClickModal');
    if (!modal) return;
    
    // Récupération des éléments du formulaire qui impactent la sécurité
    const encryptionMethod = document.getElementById('encryption_method');
    const applyObfuscation = document.getElementById('apply_obfuscation');
    const verifyIntegrity = document.getElementById('verify_integrity');
    
    // Meter pour afficher le score global de sécurité
    const securityScoreMeter = document.getElementById('security-score-meter');
    
    // Mettre à jour le score quand un paramètre change
    const updateSecurityScore = () => {
        let score = 50; // Score de base
        
        // Ajustement selon la méthode de chiffrement
        if (encryptionMethod.value === 'aes-256-cbc') {
            score += 25;
        } else if (encryptionMethod.value === 'aes-128-cbc') {
            score += 15;
        } else if (encryptionMethod.value === 'xor') {
            score -= 15;
        }
        
        // Ajustement pour l'obfuscation
        if (applyObfuscation && applyObfuscation.checked) {
            score += 10;
        } else if (applyObfuscation) {
            score -= 10;
        }
        
        // Ajustement pour la vérification d'intégrité
        if (verifyIntegrity && verifyIntegrity.checked) {
            score += 15;
        } else if (verifyIntegrity) {
            score -= 15;
        }
        
        // Limiter le score entre 0 et 100
        score = Math.max(0, Math.min(100, score));
        
        // Mettre à jour le compteur si disponible
        if (securityScoreMeter) {
            animateSecurityMeter(securityScoreMeter, score, 0, 100, false);
            updateSecurityLabel(securityScoreMeter.nextElementSibling, score);
        }
    };
    
    // Ajouter les écouteurs d'événements aux éléments du formulaire
    if (encryptionMethod) {
        encryptionMethod.addEventListener('change', updateSecurityScore);
    }
    
    if (applyObfuscation) {
        applyObfuscation.addEventListener('change', updateSecurityScore);
    }
    
    if (verifyIntegrity) {
        verifyIntegrity.addEventListener('change', updateSecurityScore);
    }
    
    // Exécuter l'initialisation pour définir le score initial
    updateSecurityScore();
}

/**
 * Anime un compteur de sécurité vers une valeur spécifique
 * 
 * @param {HTMLElement} meterElement - L'élément DOM du compteur
 * @param {number} targetValue - Valeur cible pour l'animation
 * @param {number} minValue - Valeur minimum de l'échelle
 * @param {number} maxValue - Valeur maximum de l'échelle
 * @param {boolean} danger - Si true, les valeurs élevées sont dangereuses (rouge)
 */
function animateSecurityMeter(meterElement, targetValue, minValue, maxValue, danger) {
    // Calculer le pourcentage pour l'affichage de la barre
    const percentage = ((targetValue - minValue) / (maxValue - minValue)) * 100;
    
    // Définir la couleur en fonction du pourcentage et du mode (danger ou sécurité)
    let colorClass = '';
    
    if (danger) {
        // Mode danger (plus c'est élevé, plus c'est dangereux)
        if (percentage < 25) {
            colorClass = 'bg-success';
        } else if (percentage < 50) {
            colorClass = 'bg-info';
        } else if (percentage < 75) {
            colorClass = 'bg-warning';
        } else {
            colorClass = 'bg-danger';
        }
    } else {
        // Mode sécurité (plus c'est élevé, plus c'est sécurisé)
        if (percentage < 25) {
            colorClass = 'bg-danger';
        } else if (percentage < 50) {
            colorClass = 'bg-warning';
        } else if (percentage < 75) {
            colorClass = 'bg-info';
        } else {
            colorClass = 'bg-success';
        }
    }
    
    // Mettre à jour la classe de couleur
    meterElement.classList.remove('bg-danger', 'bg-warning', 'bg-info', 'bg-success');
    meterElement.classList.add(colorClass);
    
    // Créer l'animation en CSS
    meterElement.style.width = '0%';
    meterElement.style.transition = 'width 1s ease-in-out';
    
    // Déclencher l'animation
    setTimeout(() => {
        meterElement.style.width = percentage + '%';
    }, 100);
    
    // Mettre à jour l'attribut data pour future référence
    meterElement.dataset.value = targetValue;
    
    // Mettre à jour le texte de valeur si présent
    const valueDisplay = meterElement.querySelector('.meter-value');
    if (valueDisplay) {
        valueDisplay.textContent = Math.round(targetValue);
    }
}

/**
 * Met à jour le libellé textuel à côté du compteur de sécurité
 * 
 * @param {HTMLElement} labelElement - L'élément contenant le libellé
 * @param {number} score - Score de sécurité actuel
 */
function updateSecurityLabel(labelElement, score) {
    if (!labelElement) return;
    
    let label = '';
    let icon = '';
    
    if (score < 25) {
        label = 'Risqué';
        icon = '<i class="bi bi-exclamation-triangle-fill text-danger"></i>';
    } else if (score < 50) {
        label = 'Basique';
        icon = '<i class="bi bi-shield-fill text-warning"></i>';
    } else if (score < 75) {
        label = 'Sécurisé';
        icon = '<i class="bi bi-shield-check text-info"></i>';
    } else {
        label = 'Très sécurisé';
        icon = '<i class="bi bi-shield-lock-fill text-success"></i>';
    }
    
    labelElement.innerHTML = `${icon} <span>${label}</span>`;
}