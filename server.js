// ─────────────────────────────────────────────────────────────────────────────
// NO RULES NUTRITION — Backend Server
// Auth + Athletes + Macro Plans
// ─────────────────────────────────────────────────────────────────────────────
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { pool } = require("./db");

const app = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());

app.use(
  cors({
    origin: [
      "https://gerardqueen.github.io",
      "http://localhost:5173",
      "http://localhost:3000",
    ],
    credentials: true,
  })
);

// ── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Not logged in" });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email, role, name }
    return next();
  } catch (e) {
    return res
      .status(401)
      .json({ error: "Session expired — please log in again" });
  }
}

function requireCoach(req, res, next) {
  if (req.user?.role !== "coach") {
    return res.status(403).json({ error: "Coach access required" });
  }
  return next();
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// POST /auth/login  Body: { email, password }  -> { token, user }
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      String(email).toLowerCase().trim(),
    ]);

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        sport: user.sport,
        mfpUsername: user.mfp_username,
        coachId: user.coach_id,
        avatarUrl: user.avatar_url,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Something went wrong — try again" });
  }
});

// GET /auth/me
app.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, role, sport, mfp_username, coach_id, avatar_url
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    return res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      sport: user.sport,
      mfpUsername: user.mfp_username,
      coachId: user.coach_id,
      avatarUrl: user.avatar_url,
    });
  } catch (err) {
    console.error("Auth/me error:", err);
    return res.status(500).json({ error: "Something went wrong" });
  }
});

// POST /auth/logout (client deletes token; endpoint exists for symmetry)
app.post("/auth/logout", requireAuth, (req, res) => {
  return res.json({ message: "Logged out successfully" });
});

// ─────────────────────────────────────────────────────────────────────────────
// ATHLETE ROUTES (coach-only)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/athletes", requireAuth, requireCoach, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, sport, mfp_username, avatar_url, created_at
       FROM users
       WHERE coach_id = $1 AND role = 'athlete'
       ORDER BY name ASC`,
      [req.user.id]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get athletes error:", err);
    return res.status(500).json({ error: "Could not fetch athletes" });
  }
});

app.get("/athletes/:id", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.id);

    const result = await pool.query(
      `SELECT id, email, name, sport, mfp_username, avatar_url, created_at
       FROM users
       WHERE id = $1 AND coach_id = $2 AND role = 'athlete'`,
      [athleteId, req.user.id]
    );

    if (!result.rows[0]) return res.status(404).json({ error: "Athlete not found" });
    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Get athlete error:", err);
    return res.status(500).json({ error: "Could not fetch athlete" });
  }
});

app.post("/athletes", requireAuth, requireCoach, async (req, res) => {
  try {
    const { email, name, password, sport, mfpUsername } = req.body || {};
    if (!email || !name || !password) {
      return res.status(400).json({ error: "Email, name and password are required" });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [
      String(email).toLowerCase().trim(),
    ]);
    if (existing.rows[0]) {
      return res.status(409).json({ error: "An account with that email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, role, sport, mfp_username, coach_id)
       VALUES ($1, $2, $3, 'athlete', $4, $5, $6)
       RETURNING id, email, name, sport, mfp_username, avatar_url, created_at`,
      [
        String(email).toLowerCase().trim(),
        passwordHash,
        name,
        sport || null,
        mfpUsername || null,
        req.user.id,
      ]
    );

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create athlete error:", err);
    return res.status(500).json({ error: "Could not create athlete" });
  }
});

app.put("/athletes/:id", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.id);
    const { name, sport, mfpUsername } = req.body || {};

    const result = await pool.query(
      `UPDATE users
       SET name = COALESCE($1, name),
           sport = COALESCE($2, sport),
           mfp_username = COALESCE($3, mfp_username)
       WHERE id = $4 AND coach_id = $5 AND role = 'athlete'
       RETURNING id, email, name, sport, mfp_username, avatar_url`,
      [name, sport, mfpUsername, athleteId, req.user.id]
    );

    if (!result.rows[0]) return res.status(404).json({ error: "Athlete not found" });
    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Update athlete error:", err);
    return res.status(500).json({ error: "Could not update athlete" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// MACRO PLAN ROUTES (coach-only)  ✅ NEW
// ─────────────────────────────────────────────────────────────────────────────

const VALID_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

async function coachOwnsAthlete(coachId, athleteId) {
  const r = await pool.query(
    `SELECT id FROM users WHERE id = $1 AND coach_id = $2 AND role = 'athlete'`,
    [athleteId, coachId]
  );
  return !!r.rows[0];
}

// GET /athletes/:id/macro-plans
app.get("/athletes/:id/macro-plans", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.id);
    if (!Number.isInteger(athleteId) || athleteId <= 0) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }

    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    // Ensure 7 day rows exist
    for (const day of VALID_DAYS) {
      await pool.query(
        `INSERT INTO macro_plans (athlete_id, day_of_week)
         VALUES ($1, $2)
         ON CONFLICT (athlete_id, day_of_week) DO NOTHING`,
        [athleteId, day]
      );
    }

    const result = await pool.query(
      `SELECT athlete_id, day_of_week, calories, protein_g, carbs_g, fat_g, meals, updated_by, updated_at
       FROM macro_plans
       WHERE athlete_id = $1
       ORDER BY CASE day_of_week
         WHEN 'MON' THEN 1 WHEN 'TUE' THEN 2 WHEN 'WED' THEN 3 WHEN 'THU' THEN 4
         WHEN 'FRI' THEN 5 WHEN 'SAT' THEN 6 WHEN 'SUN' THEN 7 ELSE 8 END`,
      [athleteId]
    );

    return res.json(result.rows);
  } catch (err) {
    console.error("Get macro plans error:", err);
    return res.status(500).json({ error: "Could not fetch macro plans" });
  }
});

// PUT /athletes/:id/macro-plans/:day
app.put("/athletes/:id/macro-plans/:day", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.id);
    const day = String(req.params.day || "").toUpperCase();

    if (!Number.isInteger(athleteId) || athleteId <= 0) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }
    if (!VALID_DAYS.includes(day)) {
      return res.status(400).json({ error: "Invalid day. Use MON..SUN" });
    }

    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    const calories = Number(req.body?.calories);
    const protein_g = Number(req.body?.protein_g);
    const carbs_g = Number(req.body?.carbs_g);
    const fat_g = Number(req.body?.fat_g);

    if ([calories, protein_g, carbs_g, fat_g].some((n) => Number.isNaN(n))) {
      return res.status(400).json({ error: "Macros must be numbers" });
    }

    const result = await pool.query(
      `INSERT INTO macro_plans (athlete_id, day_of_week, calories, protein_g, carbs_g, fat_g, updated_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (athlete_id, day_of_week)
       DO UPDATE SET
         calories = EXCLUDED.calories,
         protein_g = EXCLUDED.protein_g,
         carbs_g = EXCLUDED.carbs_g,
         fat_g = EXCLUDED.fat_g,
         updated_by = EXCLUDED.updated_by,
         updated_at = NOW()
       RETURNING athlete_id, day_of_week, calories, protein_g, carbs_g, fat_g, updated_by, updated_at`,
      [athleteId, day, calories, protein_g, carbs_g, fat_g, req.user.id]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Update macro plan error:", err);
    return res.status(500).json({ error: "Could not update macro plan" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────────────────────────────────────

app.get("/health", (req, res) => {
  return res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────────────────────────────────────
// START SERVER + AUTO-MIGRATIONS / SEED
// ─────────────────────────────────────────────────────────────────────────────

app.listen(PORT, async () => {
  console.log(`✅ No Rules Nutrition API running on port ${PORT}`);

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'athlete',
        sport TEXT,
        mfp_username TEXT,
        coach_id INTEGER,
        avatar_url TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS macro_plans (
        id SERIAL PRIMARY KEY,
        athlete_id INTEGER NOT NULL,
        day_of_week TEXT NOT NULL,
        calories INTEGER NOT NULL DEFAULT 2000,
        protein_g INTEGER NOT NULL DEFAULT 150,
        carbs_g INTEGER NOT NULL DEFAULT 200,
        fat_g INTEGER NOT NULL DEFAULT 70,
        meals JSONB,
        updated_by INTEGER,
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (athlete_id, day_of_week)
      );
    `);

    // Seed coaches once
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [
      "gerard@norules.com",
    ]);

    if (!existing.rows[0]) {
      const h1 = await bcrypt.hash("gerard1", 12);
      await pool.query(
        `INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,$3,$4)`,
        ["gerard@norules.com", h1, "Gerard Queen", "coach"]
      );

      const h2 = await bcrypt.hash("luke1", 12);
      await pool.query(
        `INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,$3,$4)`,
        ["luke@norules.com", h2, "Luke Bastick", "coach"]
      );

      const h3 = await bcrypt.hash("esme1", 12);
      await pool.query(
        `INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,$3,$4)`,
        ["esme@norules.com", h3, "Esme", "coach"]
      );
    }

    console.log("✅ DB ready");
  } catch (err) {
    console.error("❌ Auto-migration error:", err.message);
  }
});
