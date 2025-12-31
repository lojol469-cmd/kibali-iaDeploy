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
const RP_ID = process.env.RP_ID || 'kibali-ui-deploy.onrender.com';
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || 'https://kibali-ui-deploy.onrender.com';

console.log(`🌍 RP_ID configuré : ${RP_ID}`);
console.log(`🔗 Origin attendue : ${EXPECTED_ORIGIN}`);

// --- MIDDLEWARE ---
app.use(cors({
    origin: [
        'https://kibali-ui-deploy.onrender.com',
        'http://localhost:5173'
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

        console.log(`✅ Challenge généré pour ${username}: ${options.challenge.substring(0, 20)}...`);
        res.json(options);
    } catch (error) {
        console.error("❌ Erreur register-options:", error);
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTE : VÉRIFICATION ET ENREGISTREMENT (CORRIGÉE) ---
app.post('/auth/register-verify', async (req, res) => {
    try {
        const { username, attestation } = req.body;

        console.log(`🔍 Tentative de vérification pour: ${username}`);
        console.log(`📦 Données reçues:`, JSON.stringify(req.body, null, 2));

        if (!username || !attestation) {
            return res.status(400).json({ error: "Données manquantes (username ou attestation)" });
        }

        const user = await User.findOne({ username });
        if (!user || !user.currentChallenge) {
            return res.status(400).json({ error: "Challenge introuvable. Recommencez l'enregistrement." });
        }

        console.log(`✅ Challenge trouvé: ${user.currentChallenge.substring(0, 20)}...`);
        console.log(`🔐 Origin attendue: ${EXPECTED_ORIGIN}`);
        console.log(`🔐 RP_ID attendu: ${RP_ID}`);

        // CORRECTION CRITIQUE : Utiliser "attestation" au lieu de "body"
        const verification = await verifyRegistrationResponse({
            response: attestation,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: EXPECTED_ORIGIN,
            expectedRPID: RP_ID,
            requireUserVerification: true,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;

            console.log(`✅ Signature vérifiée pour ${username}`);

            user.devices.push({
                credentialID: base64url.encode(registrationInfo.credentialID),
                publicKey: base64url.encode(registrationInfo.credentialPublicKey),
                counter: registrationInfo.counter,
                transports: attestation.response?.transports || attestation.transports || [],
            });

            user.currentChallenge = null;
            await user.save();

            console.log(`✅ Appareil biométrique enregistré dans MongoDB pour ${username}`);
            console.log(`📊 Total d'appareils: ${user.devices.length}`);
            
            return res.json({ 
                verified: true,
                message: "Appareil enregistré avec succès",
                deviceCount: user.devices.length
            });
        }

        console.warn("⚠️ Signature invalide");
        res.status(400).json({ verified: false, error: "Signature invalide" });
    } catch (error) {
        console.error("❌ ERREUR CRITIQUE dans register-verify :", error.message);
        console.error("Stack complet :", error.stack);
        res.status(500).json({ 
            error: error.message || "Erreur interne du serveur",
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// --- ROUTE DE TEST ---
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        rpId: RP_ID,
        expectedOrigin: EXPECTED_ORIGIN,
        timestamp: new Date().toISOString()
    });
});

// --- LANCEMENT ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Serveur Kibali Auth actif sur le port ${PORT}`);
    console.log(`🌍 RP_ID: ${RP_ID}`);
    console.log(`🔗 Origin acceptée: ${EXPECTED_ORIGIN}`);
    console.log(`📡 Prêt pour les requêtes WebAuthn`);
});

// Update: Wed Dec 31 22:45:00 WAT 2025// Update: Wed Dec 31 22:30:54 WAT 2025
