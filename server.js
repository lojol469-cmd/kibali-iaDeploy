import dotenv from 'dotenv';
dotenv.config(); // Charge les variables du .env immédiatement

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse 
} from '@simplewebauthn/server';
import base64url from 'base64url';

const app = express();

// --- CONFIGURATION MIDDLEWARE ---
app.use(cors({
    origin: '*', // En production, remplace par ton domaine frontend
    methods: ['GET', 'POST']
}));
app.use(express.json());

// --- 1. CONNEXION MONGODB ---
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error("❌ ERREUR : MONGO_URI n'est pas définie dans le fichier .env");
    process.exit(1); 
}

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ Connecté à MongoDB Atlas (Kibali Auth)"))
    .catch(err => console.error("❌ Erreur de connexion MongoDB:", err.message));

// --- 2. MODÈLE UTILISATEUR (BIOMÉTRIE) ---
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

// --- 3. ROUTES AUTH BIOMÉTRIQUE (WEBAUTHN) ---
const RP_ID = 'localhost'; 
const EXPECTED_ORIGIN = `http://${RP_ID}:3000`; // À adapter si ton frontend est sur un autre port (ex: 5173)

// Fonction utilitaire : convertir string → Uint8Array (obligatoire v9+)
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
                userVerification: 'required', // Force biométrie ou PIN
                // ← LIGNE SUPPRIMÉE INTENTIONNELLEMENT :
                // authenticatorAttachment: 'platform',
                // → Cela permet à Chrome Windows d'afficher Windows Hello directement
            },
        });

        user.currentChallenge = options.challenge;
        await user.save();

        res.json(options);
    } catch (error) {
        console.error("Erreur register-options:", error);
        res.status(500).json({ error: error.message });
    }
});

// Étape B : Vérifier et enregistrer la credential
app.post('/auth/register-verify', async (req, res) => {
    try {
        const { username, body } = req.body;
        const user = await User.findOne({ username });

        if (!user) return res.status(400).json({ error: "Utilisateur non trouvé" });
        if (!user.currentChallenge) return res.status(400).json({ error: "Aucun challenge en cours" });

        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: EXPECTED_ORIGIN,
            expectedRPID: RP_ID,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;

            user.devices.push({
                credentialID: base64url.encode(registrationInfo.credentialID),
                publicKey: base64url.encode(registrationInfo.credentialPublicKey),
                counter: registrationInfo.counter,
                transports: body.transports || [],
            });

            user.currentChallenge = null;
            await user.save();

            return res.json({ verified: true });
        }

        res.status(400).json({ verified: false, error: "Vérification échouée" });
    } catch (error) {
        console.error("Erreur register-verify:", error);
        res.status(500).json({ error: error.message });
    }
});

// --- 4. LANCEMENT DU SERVEUR ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Serveur Kibali Auth lancé sur http://localhost:${PORT}`);
});