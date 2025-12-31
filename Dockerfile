# Utiliser une image Node stable et légère
FROM node:18-slim

# Définir l'environnement en production
ENV NODE_ENV=production
# Force le port à 5000 pour correspondre à ton code server.js
ENV PORT=5000

# Créer le répertoire de travail
WORKDIR /app

# Copier uniquement les fichiers de dépendances pour optimiser le cache Docker
COPY package*.json ./

# Installer les dépendances (uniquement production)
RUN npm install --production

# Copier le reste du code source
COPY . .

# Créer le dossier uploads avec les bonnes permissions
RUN mkdir -p uploads && chmod 777 uploads

# Exposer le port configuré
EXPOSE 5000

# Lancer le serveur
CMD ["node", "server.js"]