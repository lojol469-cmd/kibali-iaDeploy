// --- CORRECTIF WEBCRYPTO POUR NODE.JS / DOCKER / RENDER (INDISPENSABLE) ---
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse 
} from '@simplewebauthn/server';
import base64url from 'base64url';

const app = express();

// --- CONFIGURATION DYNAMIQUE DES ORIGINES ---
const RP_ID = process.env.RP_ID || 'kibali-ui-deploy.onrender.com'; // Doit être le domaine du FRONTEND
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || 'https://kibali-ui-deploy.onrender.com';

console.log(`🌍 RP_ID utilisé : ${RP_ID}`);
console.log(`🔗 ORIGIN attendue : ${EXPECTED_ORIGIN}`);

// --- CONFIGURATION MIDDLEWARE ---
app.use(cors({
    origin: [
        'https://kibali-ui-deploy.onrender.com',
        'http://localhost:5173'  // Pour tes tests locaux
    ],
    credentials: true,
    methods: ['GET', 'POST']
}));
app.use(express.json());

// --- 1. CONNEXION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error("❌ ERREUR : MONGO_URI n'est pas définie");
    process.exit(1);
}

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ Connecté à MongoDB Atlas (Kibali Auth)"))
    .catch(err => console.error("❌ Erreur de connexion MongoDB:", err.message));

// --- 2. MODÈLE UTILISATEUR ---
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    devices: [{
        credentialID: String,
        publicKey: String,
        counter: Number,
        transports: [String]
    }],
    currentChallenge: String
});

const User = mongoose.model('User', UserSchema);

// --- 3. ROUTES AUTH BIOMÉTRIQUE ---
function stringToUint8Array(str) {
    return new TextEncoder().encode(str);
}

// Étape A : Générer les options d'enregistrement
app.post('/auth/register-options', async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: "Username requis" });

        let user = await User.findOne({ username });
        if (!user) {
            user = new User({ username, devices: [] });
        }

        const options = await generateRegistrationOptions({
            rpName: 'Kibali AI',
            rpID: RP_ID,
            userID: stringToUint8Array(username),
            userName: username,
            userDisplayName: username,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'required',
            },
        });

        user.currentChallenge = options.challenge;
        await user.save();

        res.json(options);
    } catch (error) {
        console.error("❌ Erreur register-options:", error);
        res.status(500).json({ error: error.message });
    }
});

// Étape B : Vérifier et enregistrer la credential (CORRECTION ROBUSTE)
app.post('/auth/register-verify', async (req, res) => {
    try {
        const { username, body } = req.body;

        // Recherche de l'utilisateur
        const user = await User.findOne({ username });

        if (!user) {
            console.error("❌ Utilisateur non trouvé:", username);
            return res.status(400).json({ error: "Utilisateur non trouvé" });
        }

        if (!user.currentChallenge) {
            console.error("❌ Challenge manquant ou expiré pour:", username);
            return res.status(400).json({ error: "Session expirée ou challenge manquant" });
        }

        // Vérification avec SimpleWebAuthn
        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: EXPECTED_ORIGIN,
            expectedRPID: RP_ID,
            requireUserVerification: true,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;

            // Sauvegarde sécurisée du nouvel appareil
            user.devices.push({
                credentialID: base64url.encode(registrationInfo.credentialID),
                publicKey: base64url.encode(registrationInfo.credentialPublicKey),
                counter: registrationInfo.counter,
                transports: body.transports || body.response?.transports || [],
            });

            user.currentChallenge = null; // Invalidation du challenge
            await user.save();

            console.log(`✅ Biométrie enregistrée avec succès pour ${username}`);
            return res.json({ verified: true });
        }

        console.warn("⚠️ Vérification biométrique échouée (signature invalide)");
        res.status(400).json({ verified: false, error: "Signature invalide" });
    } catch (error) {
        console.error("❌ Erreur critique dans register-verify:", error);
        res.status(500).json({ error: error.message || "Erreur interne du serveur" });
    }
});

// --- 4. LANCEMENT DU SERVEUR ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Serveur Kibali Auth actif sur le port ${PORT}`);
    console.log(`Attente de requêtes depuis : ${EXPECTED_ORIGIN}`);
});