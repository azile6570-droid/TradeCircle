const router = require("express").Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const { requireAuth, requireTermsAccepted } = require("../middleware/auth");
const { CURRENT_TERMS_VERSION } = require("../config/terms");
const { encryptBusinessProfile } = require("../config/business-profile");

const authLimiter = rateLimit({
    windowMs: 30 * 1000,
    limit: 10,
    message: { error: "Too many attempts. Please try again later." }
});

const deleteAccountLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    message: { error: "Too many account deletion attempts. Please try again later." }
});

const passwordResetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    message: { error: "Too many password reset attempts. Please try again later." }
});

function passwordResetEmailConfig() {
    const apiKey = process.env.RESEND_API_KEY?.trim();
    const from = process.env.PASSWORD_RESET_EMAIL_FROM?.trim();
    const publicAppUrl = process.env.PUBLIC_APP_URL?.trim();
    if (!apiKey || !from || !publicAppUrl) return null;

    try {
        const url = new URL(publicAppUrl);
        const isLocalDevelopment = ["localhost", "127.0.0.1"].includes(url.hostname);
        if (
            !["http:", "https:"].includes(url.protocol) ||
            (url.protocol !== "https:" && !isLocalDevelopment) ||
            url.username ||
            url.password ||
            url.search ||
            url.hash
        ) {
            return null;
        }
    } catch {
        return null;
    }

    return { apiKey, from, publicAppUrl: publicAppUrl.replace(/\/+$/, "") };
}

function publicUser(user) {
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        supplier_verified: user.supplier_verified === true,
        supplier_application_status: user.supplier_application_status || "none",
        terms_accepted_version: user.terms_accepted_version || null
    };
}

router.post("/register", authLimiter, async (req, res, next) => {
    try {
        const {
            name,
            email,
            phone,
            password,
            role,
            business_profile: businessProfile,
            terms_accepted: termsAccepted
        } = req.body;

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            name.trim().length < 2 ||
            name.length > 120 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
            email.length > 255 ||
            password.length < 10 ||
            password.length > 128 ||
            typeof phone !== "string" || phone.trim().length < 7 || phone.length > 20 ||
            (role !== undefined && role !== "buyer")
        ) {
            return res.status(400).json({
                error: "Enter a valid contact name, work email, business number, and account type. Passwords must be at least 10 characters."
            });
        }

        const allowedStructures = new Set([
            "sole_proprietor", "partnership", "limited_company", "cooperative", "other"
        ]);
        const allowedIndustries = new Set([
            "groceries", "agriculture", "electronics", "home_cleaning",
            "packaging", "fashion", "other"
        ]);
        const allowedVolumes = new Set([
            "under_50000", "50000_250000", "250001_1000000", "over_1000000"
        ]);
        const allowedPayments = new Set(["mpesa", "bank_transfer", "card", "cash", "other"]);
        let validWebsite = true;
        if (typeof businessProfile?.company_website === "string" && businessProfile.company_website.trim()) {
            try {
                const website = new URL(businessProfile.company_website.trim());
                validWebsite = ["http:", "https:"].includes(website.protocol) &&
                    businessProfile.company_website.length <= 500;
            } catch {
                validWebsite = false;
            }
        }

        if (
            !businessProfile || typeof businessProfile !== "object" || Array.isArray(businessProfile) ||
            typeof businessProfile.legal_business_name !== "string" ||
            businessProfile.legal_business_name.trim().length < 2 ||
            businessProfile.legal_business_name.length > 180 ||
            typeof businessProfile.business_name !== "string" ||
            businessProfile.business_name.trim().length < 2 ||
            businessProfile.business_name.length > 180 ||
            typeof businessProfile.business_registration_number !== "string" ||
            businessProfile.business_registration_number.trim().length < 2 ||
            businessProfile.business_registration_number.length > 80 ||
            !allowedStructures.has(businessProfile.business_structure) ||
            !validWebsite ||
            typeof businessProfile.registered_office_address !== "string" ||
            businessProfile.registered_office_address.trim().length < 5 ||
            businessProfile.registered_office_address.length > 500 ||
            typeof businessProfile.shipping_address !== "string" ||
            businessProfile.shipping_address.trim().length < 5 ||
            businessProfile.shipping_address.length > 500 ||
            typeof businessProfile.tax_pin_number !== "string" ||
            businessProfile.tax_pin_number.trim().length < 5 ||
            businessProfile.tax_pin_number.length > 40 ||
            typeof businessProfile.signatory_id_number !== "string" ||
            businessProfile.signatory_id_number.trim().length < 5 ||
            businessProfile.signatory_id_number.length > 60 ||
            !allowedIndustries.has(businessProfile.industry_category) ||
            !allowedVolumes.has(businessProfile.monthly_purchase_volume) ||
            !allowedPayments.has(businessProfile.preferred_payment_method) ||
            typeof businessProfile.vat_registered !== "boolean" ||
            typeof businessProfile.trade_credit_requested !== "boolean"
        ) {
            return res.status(400).json({
                error: "Complete the required legal business, contact, address, tax, industry, and purchasing details."
            });
        }

        if (termsAccepted !== true) {
            return res.status(400).json({
                error: "You must accept the Terms and Conditions to create an account."
            });
        }

        const safeRole = "buyer";
        const normalizedEmail = email.trim().toLowerCase();
        const passwordHash = await bcrypt.hash(password, 12);
        const normalizedBusinessName = businessProfile.business_name.trim();
        const encryptedBusinessProfile = encryptBusinessProfile({
            legal_business_name: businessProfile.legal_business_name.trim(),
            business_name: normalizedBusinessName,
            business_registration_number: businessProfile.business_registration_number.trim(),
            business_structure: businessProfile.business_structure,
            company_website: businessProfile.company_website?.trim() || null,
            registered_office_address: businessProfile.registered_office_address.trim(),
            shipping_address: businessProfile.shipping_address.trim(),
            tax_pin_number: businessProfile.tax_pin_number.trim(),
            vat_registered: businessProfile.vat_registered,
            signatory_id_number: businessProfile.signatory_id_number.trim(),
            industry_category: businessProfile.industry_category,
            monthly_purchase_volume: businessProfile.monthly_purchase_volume,
            preferred_payment_method: businessProfile.preferred_payment_method,
            trade_credit_requested: businessProfile.trade_credit_requested
        });

        const result = await req.app.locals.pool.query(
            `INSERT INTO users (
                 name, email, phone, password_hash, role,
                 terms_accepted_version, terms_accepted_at,
                 business_name, business_profile
             )
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8::jsonb)
             RETURNING id, name, email, phone, role, supplier_verified,
                       supplier_application_status, terms_accepted_version`,
            [
                name.trim(),
                normalizedEmail,
                phone.trim().slice(0, 20),
                passwordHash,
                safeRole,
                CURRENT_TERMS_VERSION,
                normalizedBusinessName,
                JSON.stringify(encryptedBusinessProfile)
            ]
        );

        const user = publicUser(result.rows[0]);
        req.session.regenerate((sessionError) => {
            if (sessionError) return next(sessionError);

            req.session.user = user;
            req.session.save((saveError) => {
                if (saveError) return next(saveError);
                res.status(201).json({ user });
            });
        });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ error: "That email is already registered." });
        }
        next(error);
    }
});

router.post("/login", authLimiter, async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            email.length > 255 ||
            password.length > 128
        ) {
            return res.status(400).json({ error: "Enter your email and password." });
        }

        const result = await req.app.locals.pool.query(
            `SELECT id, name, email, phone, role, password_hash,
                    supplier_verified, supplier_application_status,
                    terms_accepted_version
             FROM users
             WHERE email = $1 AND deleted_at IS NULL`,
            [email.trim().toLowerCase()]
        );

        const user = result.rows[0];
        const valid = user && await bcrypt.compare(password, user.password_hash);

        if (!valid) {
            return res.status(401).json({ error: "Invalid email or password." });
        }

        const safeUser = publicUser(user);
        req.session.regenerate((sessionError) => {
            if (sessionError) return next(sessionError);

            req.session.user = safeUser;
            req.session.save((saveError) => {
                if (saveError) return next(saveError);
                res.json({ user: safeUser });
            });
        });
    } catch (error) {
        next(error);
    }
});

router.post("/forgot-password", passwordResetLimiter, async (req, res, next) => {
    const { email } = req.body;
    if (
        typeof email !== "string" ||
        email.length > 255 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
    ) {
        return res.status(400).json({ error: "Enter a valid email address." });
    }

    const emailConfig = passwordResetEmailConfig();
    if (!emailConfig) {
        return res.status(503).json({
            error: "Password reset email is not configured. Set RESEND_API_KEY, PASSWORD_RESET_EMAIL_FROM, and PUBLIC_APP_URL."
        });
    }

    let client;
    let tokenHash;
    try {
        const userResult = await req.app.locals.pool.query(
            "SELECT id, email FROM users WHERE email = $1 AND deleted_at IS NULL",
            [email.trim().toLowerCase()]
        );
        const user = userResult.rows[0];
        if (!user) {
            return res.status(202).json({
                message: "If an account exists for that email, a password reset link will be sent."
            });
        }

        const token = crypto.randomBytes(32).toString("hex");
        tokenHash = crypto.createHash("sha256").update(token).digest("hex");
        const resetUrl = new URL("/reset-password.html", `${emailConfig.publicAppUrl}/`);
        resetUrl.searchParams.set("token", token);

        client = await req.app.locals.pool.connect();
        await client.query("BEGIN");
        await client.query("DELETE FROM password_reset_tokens WHERE user_id = $1", [user.id]);
        await client.query(
            `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '30 minutes')`,
            [user.id, tokenHash]
        );
        await client.query("COMMIT");
        client.release();
        client = null;

        try {
            await axios.post(
                "https://api.resend.com/emails",
                {
                    from: emailConfig.from,
                    to: [user.email],
                    subject: "Reset your TradeCircle password",
                    text: `Use this link to reset your TradeCircle password. It expires in 30 minutes:\n\n${resetUrl.toString()}\n\nIf you did not request this, you can ignore this email.`,
                    html: `<p>Use the link below to reset your TradeCircle password. It expires in 30 minutes.</p><p><a href="${resetUrl.toString()}">Reset your password</a></p><p>If you did not request this, you can ignore this email.</p>`
                },
                {
                    headers: { Authorization: `Bearer ${emailConfig.apiKey}` },
                    timeout: 10000
                }
            );
        } catch (error) {
            await req.app.locals.pool.query(
                "DELETE FROM password_reset_tokens WHERE token_hash = $1",
                [tokenHash]
            );
            console.error(
                "Password reset email delivery failed:",
                error.response?.status || error.code || error.message
            );
            return res.status(502).json({
                error: "Unable to send a password reset email right now. Please try again later."
            });
        }

        res.status(202).json({
            message: "If an account exists for that email, a password reset link will be sent."
        });
    } catch (error) {
        if (client) {
            await client.query("ROLLBACK");
            client.release();
        }
        next(error);
    }
});

router.post("/reset-password", passwordResetLimiter, async (req, res, next) => {
    const { token, password } = req.body;
    if (
        typeof token !== "string" ||
        !/^[a-f0-9]{64}$/.test(token) ||
        typeof password !== "string" ||
        password.length < 10 ||
        password.length > 128
    ) {
        return res.status(400).json({
            error: "Use a valid reset link and a password between 10 and 128 characters."
        });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    let client;
    try {
        client = await req.app.locals.pool.connect();
        await client.query("BEGIN");
        const resetResult = await client.query(
            `SELECT tokens.user_id
             FROM password_reset_tokens AS tokens
             JOIN users ON users.id = tokens.user_id
             WHERE tokens.token_hash = $1
               AND tokens.expires_at > NOW()
               AND users.deleted_at IS NULL
             FOR UPDATE OF tokens`,
            [tokenHash]
        );
        const reset = resetResult.rows[0];
        if (!reset) {
            await client.query("ROLLBACK");
            client.release();
            return res.status(400).json({
                error: "This password reset link is invalid or has expired. Request a new one."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        await client.query(
            "UPDATE users SET password_hash = $1 WHERE id = $2 AND deleted_at IS NULL",
            [passwordHash, reset.user_id]
        );
        await client.query(
            "DELETE FROM password_reset_tokens WHERE user_id = $1",
            [reset.user_id]
        );
        await client.query(
            `DELETE FROM user_sessions
             WHERE sess->'user'->>'id' = $1`,
            [String(reset.user_id)]
        );
        await client.query("COMMIT");
        client.release();
        client = null;
        res.json({ message: "Your password has been reset. You can now sign in." });
    } catch (error) {
        if (client) {
            await client.query("ROLLBACK");
            client.release();
        }
        next(error);
    }
});

router.get("/me", requireAuth, (req, res) => {
    res.json({ user: req.session.user });
});

router.post(
    "/apply-supplier",
    requireAuth,
    requireTermsAccepted,
    async (req, res, next) => {
        if (req.session.user.role === "admin") {
            return res.status(403).json({
                error: "Admin accounts cannot apply for supplier access."
            });
        }

        const businessName = req.body.business_name;
        const applicationNote = req.body.application_note === undefined
            ? ""
            : req.body.application_note;
        if (
            typeof businessName !== "string" ||
            businessName.trim().length < 2 ||
            businessName.length > 180 ||
            typeof applicationNote !== "string" ||
            applicationNote.length > 1000
        ) {
            return res.status(400).json({
                error: "Enter a business name and keep your application note under 1,000 characters."
            });
        }

        try {
            const result = await req.app.locals.pool.query(
                `UPDATE users
                 SET supplier_application_status = 'pending',
                     business_name = $1,
                     supplier_application_note = $2
                 WHERE id = $3 AND deleted_at IS NULL
                   AND role = 'buyer' AND supplier_verified = FALSE
                   AND supplier_application_status IN ('none', 'rejected')
                 RETURNING id, name, email, phone, role, supplier_verified,
                           supplier_application_status, terms_accepted_version`,
                [businessName.trim(), applicationNote.trim(), req.session.user.id]
            );

            const user = result.rows[0];
            if (!user) {
                return res.status(409).json({
                    error: "Your account already has an active supplier application or approved supplier access."
                });
            }

            req.session.user = publicUser(user);
            req.session.save((saveError) => {
                if (saveError) return next(saveError);
                res.json({ user: req.session.user });
            });
        } catch (error) {
            next(error);
        }
    }
);

router.post("/accept-terms", requireAuth, async (req, res, next) => {
    try {
        if (req.body.terms_accepted !== true) {
            return res.status(400).json({
                error: "Confirm that you accept the current Terms and Conditions."
            });
        }

        const result = await req.app.locals.pool.query(
            `UPDATE users
             SET terms_accepted_version = $1, terms_accepted_at = NOW()
             WHERE id = $2 AND deleted_at IS NULL
             RETURNING terms_accepted_version`,
            [CURRENT_TERMS_VERSION, req.session.user.id]
        );
        if (!result.rows[0]) {
            return res.status(401).json({ error: "Please sign in first." });
        }

        req.session.user.terms_accepted_version =
            result.rows[0].terms_accepted_version;
        req.session.save((saveError) => {
            if (saveError) return next(saveError);
            res.json({ user: req.session.user });
        });
    } catch (error) {
        next(error);
    }
});

router.post("/logout", requireAuth, (req, res, next) => {
    req.session.destroy((error) => {
        if (error) return next(error);
        res.clearCookie("tradecircle.sid", {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production"
        });
        res.json({ message: "Signed out successfully." });
    });
});

router.post("/delete-account", deleteAccountLimiter, requireAuth, async (req, res, next) => {
    const { current_password: currentPassword, confirmation } = req.body;
    if (
        typeof currentPassword !== "string" ||
        currentPassword.length < 1 ||
        currentPassword.length > 128 ||
        typeof confirmation !== "string" ||
        confirmation !== "DELETE"
    ) {
        return res.status(400).json({
            error: 'Enter your current password and type "DELETE" to confirm.'
        });
    }

    const db = req.app.locals.pool;
    let client;
    try {
        client = await db.connect();
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(711923480)");

        const accountResult = await client.query(
            `SELECT id, role, password_hash
             FROM users
             WHERE id = $1 AND deleted_at IS NULL
             FOR UPDATE`,
            [req.session.user.id]
        );
        const account = accountResult.rows[0];
        if (!account || !await bcrypt.compare(currentPassword, account.password_hash)) {
            await client.query("ROLLBACK");
            return res.status(401).json({ error: "The current password is incorrect." });
        }

        if (account.role === "admin") {
            const adminsResult = await client.query(
                "SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin' AND deleted_at IS NULL"
            );
            if (adminsResult.rows[0].count <= 1) {
                await client.query("ROLLBACK");
                return res.status(409).json({
                    error: "The last active admin account cannot be deleted. Promote another admin first."
                });
            }
        }

        const replacementPasswordHash = await bcrypt.hash(
            crypto.randomBytes(64).toString("hex"),
            12
        );

        await client.query("DELETE FROM wishlists WHERE user_id = $1", [account.id]);
        await client.query("DELETE FROM product_reviews WHERE buyer_id = $1", [account.id]);
        await client.query(
            "DELETE FROM messages WHERE sender_id = $1 OR recipient_id = $1",
            [account.id]
        );
        await client.query(
            `UPDATE products
             SET status = 'rejected'
             WHERE supplier_id = $1`,
            [account.id]
        );
        await client.query(
            `UPDATE group_deals
             SET status = 'cancelled'
             WHERE product_id IN (
                 SELECT id FROM products WHERE supplier_id = $1
             ) AND status = 'active'`,
            [account.id]
        );
        await client.query(
            "DELETE FROM group_deal_requests WHERE supplier_id = $1",
            [account.id]
        );
        await client.query(
            `UPDATE users
             SET name = 'Deleted account',
                 email = 'deleted-' || id || '@deleted.invalid',
                 phone = NULL,
                 password_hash = $1,
                 role = 'buyer',
                 supplier_verified = FALSE,
                 supplier_application_status = 'none',
                 business_name = NULL,
                 supplier_application_note = NULL,
                 business_profile = '{}'::jsonb,
                 terms_accepted_version = NULL,
                 terms_accepted_at = NULL,
                 deleted_at = NOW()
             WHERE id = $2`,
            [replacementPasswordHash, account.id]
        );
        await client.query(
            `DELETE FROM user_sessions
             WHERE sess->'user'->>'id' = $1`,
            [String(account.id)]
        );
        await client.query("COMMIT");

        req.session.destroy((sessionError) => {
            if (sessionError) return next(sessionError);
            res.clearCookie("tradecircle.sid", {
                httpOnly: true,
                sameSite: "lax",
                secure: process.env.NODE_ENV === "production"
            });
            res.json({
                message: "Your account has been permanently deleted. Financial and order history has been retained without your personal details."
            });
        });
    } catch (error) {
        if (client) await client.query("ROLLBACK");
        next(error);
    } finally {
        if (client) client.release();
    }
});

module.exports = router;
