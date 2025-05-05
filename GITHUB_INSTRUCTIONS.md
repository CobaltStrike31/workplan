# Instructions pour mettre le projet sur GitHub

## 1. Créer un dépôt GitHub privé
- Allez sur GitHub.com et connectez-vous
- Cliquez sur le bouton '+' en haut à droite, puis 'New repository'
- Donnez un nom au dépôt (par exemple 'opsec-loader-web')
- Sélectionnez 'Private'
- Cliquez sur 'Create repository'

## 2. Télécharger les fichiers de ce projet
- Téléchargez tous les fichiers de ce projet Replit sur votre ordinateur
- Vous pouvez utiliser l'option 'Download as zip' depuis le menu Files de Replit

## 3. Initialiser le dépôt Git et pousser vers GitHub
```bash
# Ouvrez un terminal dans le dossier où vous avez extrait les fichiers
git init
git add .
git commit -m "Initial commit"

# Remplacez l'URL ci-dessous par l'URL de votre dépôt GitHub
git remote add origin https://github.com/votreUsername/opsec-loader-web.git
git branch -M main
git push -u origin main
```

## 4. Mettre à jour le dépôt ultérieurement
```bash
git add .
git commit -m "Description des modifications"
git push
```

