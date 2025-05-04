// Script pour gérer le thème sombre/clair

// Fonction pour définir le thème
function setTheme(themeName) {
    // Stocker la préférence de thème
    localStorage.setItem('theme', themeName);
    
    // Appliquer le thème à l'élément HTML
    document.documentElement.setAttribute('data-bs-theme', themeName);
    
    // Mettre à jour l'état du switch
    const themeSwitch = document.getElementById('theme-switch');
    if (themeSwitch) {
        themeSwitch.checked = themeName === 'dark';
    }
    
    // Mettre à jour les icônes visibles
    updateThemeIcons(themeName);
}

// Fonction pour basculer entre les thèmes
function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

// Fonction pour mettre à jour les icônes
function updateThemeIcons(themeName) {
    const sunIcons = document.querySelectorAll('.theme-icon-sun');
    const moonIcons = document.querySelectorAll('.theme-icon-moon');
    
    if (themeName === 'dark') {
        // Mode sombre - afficher le soleil, cacher la lune
        sunIcons.forEach(icon => icon.style.display = 'inline-block');
        moonIcons.forEach(icon => icon.style.display = 'none');
    } else {
        // Mode clair - afficher la lune, cacher le soleil
        sunIcons.forEach(icon => icon.style.display = 'none');
        moonIcons.forEach(icon => icon.style.display = 'inline-block');
    }
}

// Initialiser le thème au chargement de la page
document.addEventListener('DOMContentLoaded', function() {
    // Vérifier si l'utilisateur a déjà défini un thème
    const savedTheme = localStorage.getItem('theme');
    
    // Appliquer le thème sauvegardé ou utiliser la préférence du système
    if (savedTheme) {
        setTheme(savedTheme);
    } else {
        // Vérifier si l'utilisateur préfère le mode sombre au niveau du système
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            setTheme('dark');
        } else {
            setTheme('light');
        }
    }
    
    // Ajouter un écouteur d'événement pour le changement de thème
    const themeSwitch = document.getElementById('theme-switch');
    if (themeSwitch) {
        themeSwitch.addEventListener('change', toggleTheme);
    }
    
    // Ajouter un écouteur pour les changements de préférence système
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        if (!localStorage.getItem('theme')) {
            setTheme(e.matches ? 'dark' : 'light');
        }
    });
});