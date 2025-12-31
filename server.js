// --- CORRECTIF WEBCRYPTO (facultatif, on le garde) ---
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';

// --- CRÉATION DE L'APP EXPRESS (OBLIGATOIRE EN PREMIER) ---
const app = express();

// --- MIDDLEWARE ---
app.use(cors({
    origin: [
        'https://kibali-ui-deploy.onrender.com',
        'http://localhost:5173'
    ],
    credentials: true
}));
app.use(express.json());

// --- CONFIG NODEMAILER (avec tes 2 variables .env) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // false pour port 587 (STARTTLS)
    auth: {
        user: process.env.SMTP_USER,   // tonemail@gmail.com
        pass: process.env.SMTP_PASS    // ton App Password
    }
});

// --- STOCKAGE OTP TEMPORAIRE (en mémoire) ---
const otpStore = new Map(); // email → { otp, expiresAt }

// --- ROUTE : ENVOI OTP PAR EMAIL ---
app.post('/auth/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email requis" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

        otpStore.set(email, { otp, expiresAt });

        await transporter.sendMail({
            from: `"Kibali AI" <${process.env.SMTP_USER}>`,
            to: email,
            subject: "🔒 Code d'accès Kibali AI",
            text: `Votre code OTP est : ${otp}\nValable 5 minutes.\n\nKIBALI-1 • IA SOUVERAINE GABONAISE`,
            html: `
                <div style="font-family:system-ui,sans-serif;text-align:center;padding:2rem;background:#020617;color:white;">
                    <h1 style="color:#10b981">Kibali AI</h1>
                    <p>Votre code d'accès :</p>
                    <h2 style="font-size:48px;letter-spacing:12px;color:#10b981">${otp}</h2>
                    <p>Valable 5 minutes</p>
                    <hr style="border-color:#334155">
                    <p style="font-size:12px;color:#64748b">
                        KIBALI-1 • IA SOUVERAINE GABONAISE • SETRAF-GABON
                    </p>
                </div>
            `
        });

        console.log(`✅ OTP envoyé à ${email} : ${otp}`);
        res.json({ sent: true });
    } catch (error) {
        console.error("❌ Erreur envoi email :", error.message);
        res.status(500).json({ error: "Impossible d'envoyer l'email" });
    }
});

// --- ROUTE : VÉRIFICATION OTP ---
app.post('/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        const stored = otpStore.get(email);

        if (!stored || Date.now() > stored.expiresAt || stored.otp !== otp) {
            return res.json({ valid: false });
        }

        otpStore.delete(email);
        console.log(`✅ OTP validé pour ${email}`);
        res.json({ valid: true });
    } catch (error) {
        console.error("❌ Erreur vérification OTP :", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// --- LANCEMENT DU SERVEUR ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Serveur Kibali Auth (OTP) actif sur le port ${PORT}`);
});// Update: Wed Dec 31 21:34:18 WAT 2025
// Update: Wed Dec 31 21:37:02 WAT 2025
