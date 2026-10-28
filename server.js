require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const path = require("path");

const app = express();
const bcrypt = require("bcryptjs");
const session = require("express-session");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || "dreamdecor-local-dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Localhost HTTP development only
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
    }
}));


// Serve HTML, CSS, JavaScript and images from public/
app.use(express.static(path.join(__dirname, "public")));

const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "dream_decor_db",
    port: Number(process.env.DB_PORT || 3306),
    waitForConnections: true,
    connectionLimit: 10
}).promise();

// Test the database connection
app.get("/api/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");
        res.json({ server: "running", database: "connected" });
    } catch (error) {
        console.error("Database connection failed:", error.message);
        res.status(500).json({ error: "Database connection failed" });
    }
});

// Save a booking/order
app.post("/api/order", async (req, res) => {
    try {
        const data = req.body || {};

        const name = String(
            data.customer_name || data.name || data.fullName || ""
        ).trim();

        const email = String(data.email || "").trim().toLowerCase();
        const phone = String(data.phone || "").trim();

        const designKey =
            data.design_key || data.designKey || data.design || null;

        const designName =
            data.design_name || data.designName || null;

        const price = Number(data.price || 0);

        const appointmentDate =
            data.appointment_date ||
            data.appointmentDate ||
            data.date ||
            null;

        const address = String(data.address || "").trim();

        const budget = String(data.budget || "Not specified");

        const requirements = String(
            data.requirements || data.notes || ""
        );

        const paymentPreference =
            data.payment_preference ||
            data.paymentPreference ||
            data.paymentMethod ||
            "Not selected";

        if (
            !name ||
            !email ||
            !phone ||
            !designKey ||
            !designName ||
            !appointmentDate ||
            !address
        ) {
            return res.status(400).json({
                success: false,
                error: "Please fill in all required booking fields."
            });
        }

        if (!Number.isFinite(price) || price < 0) {
            return res.status(400).json({
                success: false,
                error: "Invalid design price."
            });
        }

        const sql = `
            INSERT INTO bookings (
                customer_name,
                email,
                phone,
                design_key,
                design_name,
                price,
                appointment_date,
                address,
                budget,
                requirements,
                payment_preference,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            name,
            email,
            phone,
            designKey,
            designName,
            price,
            appointmentDate,
            address,
            budget,
            requirements,
            paymentPreference,
            "Pending"
        ];

        const [result] = await pool.execute(sql, values);

        return res.status(201).json({
            success: true,
            message: "Booking saved successfully.",
            bookingId: result.insertId
        });

    } catch (error) {
        console.error("Booking save failed:", error);

        return res.status(500).json({
            success: false,
            error: "Could not save booking to the database."
        });
    }
});

/* Register a new account */
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name?.trim() || !email?.trim() || !password) {
            return res.status(400).json({
                message: "Please fill in all required fields."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const [existing] = await pool.execute(
            "SELECT id FROM users WHERE email = ?",
            [normalizedEmail]
        );

        if (existing.length > 0) {
            return res.status(409).json({
                message: "An account already exists. Please log in."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        await pool.execute(
            `INSERT INTO users (name, email, password_hash)
             VALUES (?, ?, ?)`,
            [name.trim(), normalizedEmail, passwordHash]
        );

        res.status(201).json({
            message: "Account created! Please log in."
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({
            message: "Could not create your account."
        });
    }
});


/* Log in an existing account */
app.post("/api/login", async (req, res) => {
    try {
        const email = req.body?.email;
        const password = req.body?.password;

        // Validate incoming data before using string methods
        if (typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password) {
            return res.status(400).json({
                message: "Invalid login data. Enter your email and password."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const [users] = await pool.execute(
            `SELECT id, name, email, password_hash
             FROM users
             WHERE email = ?`,
            [normalizedEmail]
        );

        if (users.length === 0) {
            return res.status(404).json({
                message: "Account not found. Please sign up first."
            });
        }

        const user = users[0];

        const valid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!valid) {
            return res.status(401).json({
                message: "Incorrect email or password."
            });
        }

        req.session.userId = user.id;

        req.session.save((error) => {
            if (error) {
                console.error("Session error:", error);
                return res.status(500).json({
                    message: "Could not start your session."
                });
            }

            return res.json({
                message: "Login successful.",
                user: {
                    name: user.name,
                    email: user.email
                }
            });
        });
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({
            message: "Login failed. Please try again."
        });
    }
});


/* Get the currently logged-in account */
app.get("/api/me", async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({
                message: "Not logged in."
            });
        }

        const [users] = await pool.execute(
            "SELECT id, name, email FROM users WHERE id = ?",
            [req.session.userId]
        );

        if (users.length === 0) {
            return res.status(401).json({
                message: "Account not found. Please log in again."
            });
        }

        res.json({ user: users[0] });
    } catch (error) {
        console.error("Account lookup error:", error);
        res.status(500).json({
            message: "Could not load account information."
        });
    }
});


/* Log out */
app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({
                message: "Could not log out."
            });
        }

        res.clearCookie("connect.sid");
        res.json({ message: "Logged out successfully." });
    });
});

const PORT = process.env.PORT || 3000;

app.post("/api/contact", async (req, res) => {
    try {
        const {
            name,
            email,
            phone,
            category,
            bookingReference,
            message
        } = req.body || {};

        // Validate required fields.
        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof phone !== "string" ||
            typeof category !== "string" ||
            typeof message !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "Please provide all required contact details."
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();
        const cleanPhone = phone.trim();
        const cleanCategory = category.trim();
        const cleanReference =
            typeof bookingReference === "string"
                ? bookingReference.trim()
                : "";
        const cleanMessage = message.trim();

        if (
            !cleanName ||
            cleanName.length > 100 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
            cleanEmail.length > 254 ||
            !cleanPhone ||
            cleanPhone.length > 20 ||
            !cleanCategory ||
            cleanCategory.length > 100 ||
            cleanReference.length > 100 ||
            cleanMessage.length < 5 ||
            cleanMessage.length > 3000
        ) {
            return res.status(400).json({
                success: false,
                message: "Please check your details and try again."
            });
        }

        const allowedCategories = [
            "Booking Support",
            "Design Enquiry",
            "Payment Enquiry",
            "Website Problem",
            "Suggestion",
            "Other"
        ];

        if (!allowedCategories.includes(cleanCategory)) {
            return res.status(400).json({
                success: false,
                message: "Please select a valid help category."
            });
        }

        const [result] = await pool.execute(
            `INSERT INTO contact_messages
            (
                name,
                email,
                phone,
                category,
                booking_reference,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
                cleanName,
                cleanEmail,
                cleanPhone,
                cleanCategory,
                cleanReference || null,
                cleanMessage
            ]
        );

        return res.status(201).json({
            success: true,
            message: "Your message has been submitted.",
            contactId: result.insertId
        });

    } catch (error) {
        console.error("Contact submission error:", error);

        return res.status(500).json({
            success: false,
            message: "We could not save your message. Please try again."
        });
    }
});


app.post("/api/payment", async (req, res) => {
    try {
        const bookingId = Number(req.body.bookingId);
        const email = String(req.body.email || "").trim().toLowerCase();
        const paymentMethod = String(req.body.paymentMethod || "");

        const allowedMethods = [
            "UPI (demo)",
            "Card (demo)",
            "Pay later"
        ];

        if (
            !Number.isInteger(bookingId) ||
            bookingId <= 0 ||
            !email ||
            !allowedMethods.includes(paymentMethod)
        ) {
            return res.status(400).json({
                success: false,
                error: "Please enter a valid email and payment method."
            });
        }

        const [bookings] = await pool.execute(
            `SELECT id, email, price
             FROM bookings
             WHERE id = ? AND LOWER(email) = ?`,
            [bookingId, email]
        );

        if (bookings.length === 0) {
            return res.status(404).json({
                success: false,
                error: "Booking not found for this email."
            });
        }

        const booking = bookings[0];

        const [result] = await pool.execute(
            `INSERT INTO payments
             (booking_id, customer_email, amount, payment_method, payment_status)
             VALUES (?, ?, ?, ?, ?)`,
            [
                booking.id,
                email,
                booking.price,
                paymentMethod,
                "Pending"
            ]
        );

        return res.status(201).json({
            success: true,
            message: "Payment selection saved successfully.",
            bookingId: booking.id,
            paymentId: result.insertId
        });

    } catch (error) {
        console.error("Payment save failed:", error);

        return res.status(500).json({
            success: false,
            error: "Could not save payment details to the database."
        });
    }
});


app.get("/api/orders", async (req, res) => {
    try {
        // Use the same session property as your existing /api/me route.
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                error: "Please log in to view your orders."
            });
        }

        const email = req.session.user.email;

        const [orders] = await pool.execute(
            `SELECT id, customer_name, email, design_key,
                    design_name, price, appointment_date,
                    status, created_at
             FROM bookings
             WHERE LOWER(email) = LOWER(?)
             ORDER BY created_at DESC`,
            [email]
        );

        res.json({ success: true, orders });
    } catch (error) {
        console.error("GET /api/orders error:", error);

        res.status(500).json({
            success: false,
            error: "Failed to load orders."
        });
    }
});

app.listen(PORT, () => {
    console.log(`DreamDecor running at http://localhost:${PORT}`);
});
