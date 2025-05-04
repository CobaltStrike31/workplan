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
        let securityScore = 40; // Score de base plus faible pour rendre les choix plus impactants
        
        // Ajustement selon la méthode de chiffrement (impact majeur)
        if (encryptionMethod.value === 'aes-256-cbc') {
            securityScore += 30;  // Meilleure méthode = +30
        } else if (encryptionMethod.value === 'aes-128-cbc') {
            securityScore += 20;  // Méthode bonne mais moins sécurisée = +20
        } else if (encryptionMethod.value === 'xor') {
            securityScore -= 10;  // Méthode simple et vulnérable = -10
        }
        
        // Ajustement pour l'obfuscation (impact modéré)
        if (applyObfuscation && applyObfuscation.checked) {
            securityScore += 15;  // L'obfuscation augmente significativement la sécurité
        } else if (applyObfuscation) {
            securityScore -= 15;  // Ne pas appliquer l'obfuscation = risque accru
        }
        
        // Ajustement pour la vérification d'intégrité (impact significatif)
        if (verifyIntegrity && verifyIntegrity.checked) {
            securityScore += 25;  // La vérification HMAC est cruciale pour l'intégrité
        } else if (verifyIntegrity) {
            securityScore -= 25;  // Sans vérification d'intégrité, le risque est important
        }
        
        // Vérification du mot de passe (si visible et rempli)
        const passwordField = document.getElementById('password');
        if (passwordField && passwordField.value) {
            const passwordStrength = calculatePasswordStrength(passwordField.value);
            securityScore += passwordStrength;  // Ajoute entre -10 et +15 selon la force
        }
        
        // Limiter le score entre 0 et 100
        securityScore = Math.max(0, Math.min(100, securityScore));
        
        // Afficher le score dans la console pour déboguer
        console.log('Score de sécurité calculé:', securityScore);
        
        // Mettre à jour le compteur si disponible
        if (securityScoreMeter) {
            animateSecurityMeter(securityScoreMeter, securityScore, 0, 100, false);
            updateSecurityLabel(securityScoreMeter.nextElementSibling, securityScore);
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
    
    // Ajouter un écouteur pour le champ mot de passe
    const passwordField = document.getElementById('password');
    if (passwordField) {
        passwordField.addEventListener('input', updateSecurityScore);
        
        // Pour le bouton de génération de mot de passe
        const generatePasswordBtn = document.getElementById('generate-password');
        if (generatePasswordBtn) {
            generatePasswordBtn.addEventListener('click', () => {
                // Attendre un instant pour que le mot de passe soit généré
                setTimeout(updateSecurityScore, 50);
            });
        }
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
    
    // Créer une animation plus fluide avec requestAnimationFrame
    meterElement.style.width = '0%';
    meterElement.style.transition = 'none'; // Désactiver la transition CSS
    
    // Animation style React avec des transitions plus fluides
    
    // Récupérer la valeur actuelle (si disponible)
    const currentWidth = parseFloat(meterElement.style.width) || 0;
    const currentValue = parseInt(meterElement.dataset.value) || 0;
    
    // Calculer la différence pour l'animation progressive
    const widthDiff = percentage - currentWidth;
    const valueDiff = targetValue - currentValue;
    
    // Nombre de frames pour une animation ultra-fluide (60fps pendant 500ms)
    const frames = 30;
    let frame = 0;
    
    // Utiliser un spring effect comme dans React-Spring
    const springConfig = { tension: 0.25, friction: 0.9, velocity: 0.05 };
    
    function animate(timestamp) {
        // Spring physics pour une animation fluide très naturelle
        // Imite le comportement de React-Spring
        frame++;
        
        // Progression non-linéaire (accélère puis ralentit)
        const spring = (t) => {
            // Fonction qui imite une animation à ressort
            const tension = springConfig.tension;
            const friction = springConfig.friction;
            
            // Équation simplifiée de mouvement à ressort amorti
            return 1 - Math.cos(tension * t * Math.PI) * Math.exp(-friction * t);
        };
        
        const progress = Math.min(frame / frames, 1);
        const springProgress = spring(progress);
        
        // Appliquer la largeur avec l'effet spring
        const newWidth = currentWidth + (widthDiff * springProgress);
        meterElement.style.width = newWidth + '%';
        
        // Mettre à jour le texte avec l'effet spring aussi
        const valueDisplay = meterElement.querySelector('.meter-value');
        if (valueDisplay) {
            const newValue = Math.round(currentValue + (valueDiff * springProgress));
            valueDisplay.textContent = newValue;
            
            // Ajouter un effet de highlight sur le changement de valeur
            valueDisplay.classList.add('value-changing');
            setTimeout(() => valueDisplay.classList.remove('value-changing'), 150);
        }
        
        // Continuer l'animation jusqu'à complétion
        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }
    
    // Démarrer l'animation
    requestAnimationFrame(animate);
    
    // Mettre à jour l'attribut data pour future référence
    meterElement.dataset.value = targetValue;
    
    // Mettre à jour le texte de valeur si présent
    const valueDisplay = meterElement.querySelector('.meter-value');
    if (valueDisplay) {
        valueDisplay.textContent = Math.round(targetValue);
    }
}

/**
 * Calcule la force d'un mot de passe et renvoie un ajustement de score
 * 
 * @param {string} password - Le mot de passe à évaluer
 * @return {number} - Un score entre -10 et +15 à ajouter au score de sécurité
 */
function calculatePasswordStrength(password) {
    if (!password) return 0;
    
    let strength = 0;
    
    // Évaluer la longueur
    if (password.length < 8) {
        strength -= 5; // Trop court = risque majeur
    } else if (password.length >= 12) {
        strength += 5; // Bonne longueur
    } else if (password.length >= 16) {
        strength += 8; // Excellente longueur
    }
    
    // Vérifier la présence de différents types de caractères
    if (/[A-Z]/.test(password)) strength += 2; // Majuscules
    if (/[a-z]/.test(password)) strength += 2; // Minuscules
    if (/[0-9]/.test(password)) strength += 2; // Chiffres
    if (/[^A-Za-z0-9]/.test(password)) strength += 3; // Caractères spéciaux
    
    // Vérifier la variété de caractères
    const uniqueChars = new Set(password).size;
    if (uniqueChars < password.length * 0.5) {
        strength -= 2; // Beaucoup de répétitions
    }
    
    // Limiter le résultat entre -10 et +15
    return Math.max(-10, Math.min(15, strength));
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