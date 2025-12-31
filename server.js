// --- CORRECTIF WEBCRYPTO OBLIGATOIRE POUR RENDER/NODE ---
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

// --- CONFIGURATION CRITIQUE : DOMAINE DU FRONTEND ---
const RP_ID = process.env.RP_ID || 'kibali-ui-deploy.onrender.com'; // Domaine du FRONTEND uniquement
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || 'https://kibali-ui-deploy.onrender.com'; // URL complète FRONTEND, sans slash final

console.log(`🌍 RP_ID configuré : ${RP_ID}`);
console.log(`🔗 Origin attendue : ${EXPECTED_ORIGIN}`);

// --- MIDDLEWARE ---
app.use(cors({
    origin: [
        'https://kibali-ui-deploy.onrender.com',
        'http://localhost:5173'  // Pour développement local
    ],
    credentials: true,
    methods: ['GET', 'POST']
}));
app.use(express.json());

// --- CONNEXION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
    console.error("❌ ERREUR : MONGO_URI n'est pas définie");
    process.exit(1);
}
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ Connecté à MongoDB Atlas (Kibali Auth)"))
    .catch(err => console.error("❌ Erreur MongoDB:", err.message));

// --- MODÈLE UTILISATEUR ---
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

// --- UTILITAIRE ---
function stringToUint8Array(str) {
    return new TextEncoder().encode(str);
}

// --- ROUTE : GÉNÉRATION DES OPTIONS ---
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

// --- ROUTE : VÉRIFICATION ET ENREGISTREMENT ---
app.post('/auth/register-verify', async (req, res) => {
    try {
        const { username, body } = req.body;

        const user = await User.findOne({ username });
        if (!user || !user.currentChallenge) {
            return res.status(400).json({ error: "Challenge introuvable. Recommencez." });
        }

        console.log(`🔍 Vérification biométrique pour ${username}`);
        console.log(`Origin attendue : ${EXPECTED_ORIGIN}`);
        console.log(`RP_ID attendu : ${RP_ID}`);

        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: EXPECTED_ORIGIN,
            expectedRPID: RP_ID,
            requireUserVerification: true,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;

            user.devices.push({
                credentialID: base64url.encode(registrationInfo.credentialID),
                publicKey: base64url.encode(registrationInfo.credentialPublicKey),
                counter: registrationInfo.counter,
                transports: body.response?.transports || body.transports || [],
            });

            user.currentChallenge = null;
            await user.save();

            console.log(`✅ Appareil biométrique enregistré avec succès dans MongoDB pour ${username}`);
            return res.json({ verified: true });
        }

        console.warn("⚠️ Signature invalide");
        res.status(400).json({ verified: false, error: "Signature invalide" });
    } catch (error) {
        console.error("❌ ERREUR 500 dans register-verify :", error.message);
        console.error("Stack :", error.stack);
        res.status(500).json({ error: error.message || "Erreur interne du serveur" });
    }
});

// --- LANCEMENT ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Serveur Kibali Auth actif sur le port ${PORT}`);
    console.log(`Prêt pour les requêtes depuis ${EXPECTED_ORIGIN}`);
});// Update: Wed Dec 31 21:09:57 WAT 2025
// Update: Wed Dec 31 22:05:35 WAT 2025
