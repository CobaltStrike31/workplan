// JavaScript pour l'application de vérification OPSEC Loader

document.addEventListener('DOMContentLoaded', function() {
    // Activer les tooltips Bootstrap
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Gestion du formulaire de vérification
    const verifyForm = document.getElementById('verify-form');
    if (verifyForm) {
        verifyForm.addEventListener('submit', function(e) {
            // Afficher un indicateur de chargement
            const submitBtn = verifyForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Vérification en cours...';
                submitBtn.disabled = true;
            }
        });
    }
    
    // Coloration syntaxique pour les blocs de code
    const codeBlocks = document.querySelectorAll('pre code');
    if (codeBlocks.length > 0 && typeof hljs !== 'undefined') {
        codeBlocks.forEach(block => {
            hljs.highlightBlock(block);
        });
    }
    
    // Gestion des notifications
    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show`;
        notification.setAttribute('role', 'alert');
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        const container = document.querySelector('.container');
        if (container) {
            container.insertBefore(notification, container.firstChild);
            
            // Auto-dismiss après 5 secondes
            setTimeout(() => {
                const alert = new bootstrap.Alert(notification);
                alert.close();
            }, 5000);
        }
    }
    
    // Exposer la fonction showNotification globalement
    window.showNotification = showNotification;
    
    // Fonction pour vérifier un composant spécifique via l'API
    window.verifyComponent = function(component, frameworkPath) {
        // Créer un modal de chargement
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'loadingModal';
        modal.setAttribute('tabindex', '-1');
        modal.setAttribute('aria-hidden', 'true');
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-body text-center py-4">
                        <div class="spinner-border text-primary mb-3" role="status">
                            <span class="visually-hidden">Chargement...</span>
                        </div>
                        <h5>Vérification du composant ${component}...</h5>
                        <p>Veuillez patienter pendant que nous analysons le composant.</p>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
        // Afficher le modal
        const loadingModal = new bootstrap.Modal(modal);
        loadingModal.show();
        
        // Appel API
        fetch('/api/verify-component', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                component: component,
                framework_path: frameworkPath
            }),
        })
        .then(response => response.json())
        .then(data => {
            // Fermer le modal
            loadingModal.hide();
            
            if (data.status === 'success') {
                // Afficher les résultats
                showComponentResults(component, data.data);
            } else {
                // Afficher l'erreur
                showNotification(`Erreur lors de la vérification du composant: ${data.message}`, 'danger');
            }
        })
        .catch(error => {
            // Fermer le modal
            loadingModal.hide();
            
            // Afficher l'erreur
            showNotification(`Erreur: ${error.message}`, 'danger');
        });
    };
    
    // Fonction pour afficher les résultats d'un composant
    function showComponentResults(component, results) {
        // Créer un modal pour afficher les résultats
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'resultsModal';
        modal.setAttribute('tabindex', '-1');
        modal.setAttribute('aria-hidden', 'true');
        
        // Contenu du modal (dépend du composant)
        let modalContent = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header ${results.success ? 'bg-success' : 'bg-danger'} text-white">
                        <h5 class="modal-title">Résultats: ${component.replace('_', ' ').toUpperCase()}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert ${results.success ? 'alert-success' : 'alert-danger'}">
                            <h5>Status: ${results.success ? 'SUCCÈS' : 'ÉCHEC'}</h5>
                            <p>${results.message}</p>
                        </div>
        `;
        
        // Ajouter des détails spécifiques en fonction du composant
        if (results.tools_found) {
            modalContent += `
                <div class="mb-3">
                    <h6>Outils trouvés:</h6>
                    <ul>
                        ${results.tools_found.map(tool => `<li>${tool}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        // Ajouter la recommandation si elle existe
        if (results.recommendation) {
            modalContent += `
                <div class="alert alert-info">
                    <strong>Recommandation:</strong> ${results.recommendation}
                </div>
            `;
        }
        
        // Fermer les balises
        modalContent += `
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Fermer</button>
                    </div>
                </div>
            </div>
        `;
        
        modal.innerHTML = modalContent;
        document.body.appendChild(modal);
        
        // Afficher le modal
        const resultsModal = new bootstrap.Modal(modal);
        resultsModal.show();
        
        // Supprimer le modal une fois fermé
        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
    }
});