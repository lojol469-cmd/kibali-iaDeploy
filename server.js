// --- AU DÉBUT DU FICHIER, APRÈS LES IMPORTS ---
import nodemailer from 'nodemailer';

// --- CONFIG NODEMAILER (utilise tes deux variables .env) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true pour 465, false pour 587 (STARTTLS)
    auth: {
        user: process.env.SMTP_USER,   // tonemail@gmail.com
        pass: process.env.SMTP_PASS    // ton App Password
    }
});

// --- STOCKAGE OTP TEMPORAIRE (simple et efficace pour ton usage) ---
const otpStore = new Map(); // email → { otp, expiresAt }

// --- ROUTE : ENVOI DE L'OTP PAR EMAIL ---
app.post('/auth/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email requis" });

        // Génération OTP 6 chiffres
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

        otpStore.set(email, { otp, expiresAt });

        // Envoi de l'email
        await transporter.sendMail({
            from: `"Kibali AI" <${process.env.SMTP_USER}>`,
            to: email,
            subject: "🔒 Code d'accès Kibali AI",
            text: `Votre code OTP est : ${otp}\n\nValable 5 minutes.\n\nKIBALI-1 • IA SOUVERAINE GABONAISE`,
            html: `
                <div style="font-family: system-ui, sans-serif; text-align: center; padding: 2rem; background: #020617; color: white;">
                    <h1 style="color: #10b981;">Kibali AI</h1>
                    <p>Votre code d'accès :</p>
                    <h2 style="font-size: 48px; letter-spacing: 12px; color: #10b981;">${otp}</h2>
                    <p>Valable 5 minutes</p>
                    <hr style="border-color: #334155;">
                    <p style="font-size: 12px; color: #64748b;">
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

// --- ROUTE : VÉRIFICATION DE L'OTP ---
app.post('/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        const stored = otpStore.get(email);

        if (!stored || Date.now() > stored.expiresAt || stored.otp !== otp) {
            return res.json({ valid: false });
        }

        // OTP valide → on le supprime pour éviter réutilisation
        otpStore.delete(email);

        console.log(`✅ OTP validé avec succès pour ${email}`);
        res.json({ valid: true });
    } catch (error) {
        console.error("❌ Erreur vérification OTP :", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});// Update: Wed Dec 31 21:28:08 WAT 2025
