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
    verifyRegistrationResponse,
    isoUint8Array // ← NOUVEAU : IMPORT CRITIQUE
} from '@simplewebauthn/server';
import base64url from 'base64url';

const app = express();

// --- CONFIGURATION ---
const RP_ID = process.env.RP_ID || 'kibali-ui-deploy.onrender.com';
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || 'https://kibali-ui-deploy.onrender.com';

console.log(`RP_ID configuré : ${RP_ID}`);
console.log(`Origin attendue : ${EXPECTED_ORIGIN}`);

// --- MIDDLEWARE ---
app.use(cors({
    origin: [
        'https://kibali-ui-deploy.onrender.com',
        'http://localhost:5173'
    ],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '10mb' }));

// --- CONNEXION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
    console.error("ERREUR : MONGO_URI manquante dans .env");
    process.exit(1);
}

mongoose.connect(MONGO_URI)
    .then(() => console.log("Connecté à MongoDB Atlas"))
    .catch(err => {
        console.error("Erreur MongoDB:", err.message);
        process.exit(1);
    });

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

// --- ROUTE : GÉNÉRATION DES OPTIONS (CORRIGÉE POUR v10+) ---
app.post('/auth/register-options', async (req, res) => {
    try {
        const { username } = req.body;
        if (!username || typeof username !== 'string') {
            return res.status(400).json({ error: "Username requis et doit être une string" });
        }

        let user = await User.findOne({ username });
        if (!user) {
            user = new User({ username, devices: [] });
        }

        // excludeCredentials seulement si des appareils existent
        const excludeCredentials = user.devices.length > 0
            ? user.devices.map(dev => ({
                  id: base64url.toBuffer(dev.credentialID),
                  type: 'public-key',
                  transports: dev.transports || [],
              }))
            : undefined;

        const options = await generateRegistrationOptions({
            rpName: 'Kibali AI',
            rpID: RP_ID,
            userID: isoUint8Array.fromUTF8String(username),  // CORRECTION CRITIQUE
            userName: username,
            userDisplayName: username,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'required',
            },
            excludeCredentials,
        });

        user.currentChallenge = options.challenge;
        await user.save();

        console.log(`Options générées avec succès pour ${username}`);
        res.json(options);
    } catch (error) {
        console.error("Erreur register-options:", error.message);
        console.error("Stack:", error.stack);
        res.status(500).json({ 
            error: "Erreur serveur lors de la génération des options",
            details: error.message 
        });
    }
});

// --- ROUTE : VÉRIFICATION DE L'ENREGISTREMENT ---
app.post('/auth/register-verify', async (req, res) => {
    try {
        const { username, response } = req.body;

        if (!username || !response) {
            return res.status(400).json({ error: "username et response requis" });
        }

        const user = await User.findOne({ username });
        if (!user || !user.currentChallenge) {
            return res.status(400).json({ error: "Challenge invalide ou expiré" });
        }

        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: EXPECTED_ORIGIN,
            expectedRPId: RP_ID,
            requireUserVerification: true,
        });

        if (!verification.verified) {
            return res.status(400).json({ verified: false, error: "Vérification échouée" });
        }

        const { registrationInfo } = verification;
        const { credentialPublicKey, credentialID, counter } = registrationInfo;

        user.devices.push({
            credentialID: base64url.encode(credentialID),
            publicKey: base64url.encode(credentialPublicKey),
            counter,
            transports: response.transports || [],
        });

        user.currentChallenge = null;
        await user.save();

        console.log(`Appareil enregistré pour ${username} (total: ${user.devices.length})`);

        res.json({
            verified: true,
            message: "Appareil enregistré avec succès",
            deviceCount: user.devices.length
        });

    } catch (error) {
        console.error("Erreur register-verify:", error.message);
        console.error(error.stack);
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTE DE SANTÉ ---
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        rpId: RP_ID,
        expectedOrigin: EXPECTED_ORIGIN,
        timestamp: new Date().toISOString(),
        mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// --- DÉMARRAGE ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Serveur Kibali Auth actif sur le port ${PORT}`);
    console.log(`Prêt pour WebAuthn biométrique`);
});// Update: Thu Jan  1 00:42:16 WAT 2026
// Update: Thu Jan  1 00:49:11 WAT 2026
