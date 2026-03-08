// ─────────────────────────────────────────────────────────────────────────────
// NO RULES NUTRITION — Backend Server
// Phase 1: Authentication & User Management
// ─────────────────────────────────────────────────────────────────────────────

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { pool } = require("./db");

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: [
    "https://gerardqueen.github.io",  // your live GitHub Pages site
    "http://localhost:5173",           // Vite dev server when testing locally
    "http://localhost:3000",
  ],
  credentials: true,
}));

// ── Auth middleware — protects routes that need a login ───────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Not logged in" });
  }
  try {
    const token   = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user      = decoded; // { id, email, role, name }
    next();
  } catch {
    return res.status(401).json({ error: "Session expired — please log in again" });
  }
}

// Coach-only middleware
function requireCoach(req, res, next) {
  if (req.user?.role !== "coach") {
    return res.status(403).json({ error: "Coach access required" });
  }
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// POST /auth/login
// Body: { email, password }
// Returns: { token, user }
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Find user in database
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    // Create JWT token (expires in 24 hours)
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Return token and safe user data (never return password_hash)
    res.json({
      token,
      user: {
        id:           user.id,
        email:        user.email,
        name:         user.name,
        role:         user.role,
        sport:        user.sport,
        mfpUsername:  user.mfp_username,
        coachId:      user.coach_id,
        avatarUrl:    user.avatar_url,
      }
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Something went wrong — please try again" });
  }
});


// GET /auth/me
// Returns the logged-in user's profile (used on app load to restore session)
app.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, name, role, sport, mfp_username, coach_id, avatar_url FROM users WHERE id = $1",
      [req.user.id]
    );

    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({
      id:          user.id,
      email:       user.email,
      name:        user.name,
      role:        user.role,
      sport:       user.sport,
      mfpUsername: user.mfp_username,
      coachId:     user.coach_id,
      avatarUrl:   user.avatar_url,
    });

  } catch (err) {
    console.error("Auth/me error:", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});


// POST /auth/logout
// (JWT is stateless — client just deletes the token.
//  This endpoint exists so the frontend has something to call.)
app.post("/auth/logout", requireAuth, (req, res) => {
  res.json({ message: "Logged out successfully" });
});


// ─────────────────────────────────────────────────────────────────────────────
// ATHLETE ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// GET /athletes
// Coach only — returns all their athletes
app.get("/athletes", requireAuth, requireCoach, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, sport, mfp_username, avatar_url, created_at
       FROM users
       WHERE coach_id = $1 AND role = 'athlete'
       ORDER BY name ASC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Get athletes error:", err);
    res.status(500).json({ error: "Could not fetch athletes" });
  }
});


// GET /athletes/:id
// Coach only — full profile for one athlete
app.get("/athletes/:id", requireAuth, requireCoach, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, sport, mfp_username, avatar_url, created_at
       FROM users
       WHERE id = $1 AND coach_id = $2 AND role = 'athlete'`,
      [req.params.id, req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Athlete not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Get athlete error:", err);
    res.status(500).json({ error: "Could not fetch athlete" });
  }
});


// POST /athletes
// Coach only — create a new athlete account
app.post("/athletes", requireAuth, requireCoach, async (req, res) => {
  try {
    const { email, name, password, sport, mfpUsername } = req.body;

    if (!email || !name || !password) {
      return res.status(400).json({ error: "Email, name and password are required" });
    }

    // Check email isn't already taken
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );
    if (existing.rows[0]) {
      return res.status(409).json({ error: "An account with that email already exists" });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create athlete
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, role, sport, mfp_username, coach_id)
       VALUES ($1, $2, $3, 'athlete', $4, $5, $6)
       RETURNING id, email, name, sport, mfp_username, created_at`,
      [email.toLowerCase().trim(), passwordHash, name, sport || null, mfpUsername || null, req.user.id]
    );

    res.status(201).json(result.rows[0]);

  } catch (err) {
    console.error("Create athlete error:", err);
    res.status(500).json({ error: "Could not create athlete" });
  }
});


// PUT /athletes/:id
// Coach only — update an athlete's details
app.put("/athletes/:id", requireAuth, requireCoach, async (req, res) => {
  try {
    const { name, sport, mfpUsername } = req.body;

    const result = await pool.query(
      `UPDATE users
       SET name = COALESCE($1, name),
           sport = COALESCE($2, sport),
           mfp_username = COALESCE($3, mfp_username)
       WHERE id = $4 AND coach_id = $5 AND role = 'athlete'
       RETURNING id, email, name, sport, mfp_username`,
      [name, sport, mfpUsername, req.params.id, req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Athlete not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update athlete error:", err);
    res.status(500).json({ error: "Could not update athlete" });
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────────────────────────────────────

// GET /health
// Used by Railway to check the server is running
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});


// ─────────────────────────────────────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`✅ No Rules Nutrition API running on port ${PORT}`);
  const bcrypt = require("bcryptjs");
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'athlete', sport TEXT, mfp_username TEXT, coach_id INTEGER, avatar_url TEXT, created_at TIMESTAMPTZ DEFAULT NOW());`);
    await pool.query(`CREATE TABLE IF NOT EXISTS macro_plans (id SERIAL PRIMARY KEY, athlete_id INTEGER NOT NULL, day_of_week TEXT NOT NULL, calories INTEGER NOT NULL DEFAULT 2000, protein_g INTEGER NOT NULL DEFAULT 150, carbs_g INTEGER NOT NULL DEFAULT 200, fat_g INTEGER NOT NULL DEFAULT 70, meals JSONB, updated_by INTEGER, updated_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE (athlete_id, day_of_week));`);
    await pool.query(`CREATE TABLE IF NOT EXISTS mfp_entries (id SERIAL PRIMARY KEY, athlete_id INTEGER NOT NULL, date DATE NOT NULL, calories INTEGER DEFAULT 0, protein_g INTEGER DEFAULT 0, carbs_g INTEGER DEFAULT 0, fat_g INTEGER DEFAULT 0, fibre_g INTEGER DEFAULT 0, exercise_cals INTEGER DEFAULT 0, meals_json JSONB, source TEXT DEFAULT 'mfp_live', synced_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE (athlete_id, date));`);
    await pool.query(`CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, thread_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL, body TEXT NOT NULL, read BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());`);
    await pool.query(`CREATE TABLE IF NOT EXISTS checkins (id SERIAL PRIMARY KEY, athlete_id INTEGER NOT NULL, date DATE NOT NULL, weight_kg DECIMAL(5,2), mood INTEGER, energy INTEGER, sleep_hrs DECIMAL(3,1), notes TEXT, photo_url TEXT, coach_reply TEXT, created_at TIMESTAMPTZ DEFAULT NOW());`);
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", ["gerard@norules.com"]);
    if (!existing.rows[0]) {
      const h1 = await bcrypt.hash("gerard1", 12); await pool.query(`INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,'Gerard Queen','coach')`, ["gerard@norules.com", h1]);
      const h2 = await bcrypt.hash("luke1", 12); await pool.query(`INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,'Luke Bastick','coach')`, ["luke@norules.com", h2]);
      const h3 = await bcrypt.hash("esme1", 12); await pool.query(`INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,'Esme','coach')`, ["esme@norules.com", h3]);
      const h4 = await bcrypt.hash("athlete1", 12); await pool.query(`INSERT INTO users (email,password_hash,name,role,sport) VALUES ($1,$2,'Alex Morgan','athlete','Triathlon')`, ["alex@norules.com", h4]);
      const h5 = await bcrypt.hash("athlete2", 12); await pool.query(`INSERT INTO users (email,password_hash,name,role,sport) VALUES ($1,$2,'Jamie Clarke','athlete','Powerlifting')`, ["jamie@norules.com", h5]);
    }
    console.log("✅ Database tables ready");
  } catch (err) {
    console.error("❌ Auto-migration error:", err.message);
  }
});