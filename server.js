// ─────────────────────────────────────────────────────────────────────────────
// NO RULES NUTRITION — Backend Server
// Auth + Athletes + Macro Plans + Profiles + Weights + Meal Plans
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
    return res.status(401).json({ error: "Session expired — please log in again" });
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

// POST /auth/login  Body: { email, password } -> { token, user }
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      String(email).toLowerCase().trim(),
    ]);

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Incorrect email or password" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect email or password" });

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
// MACRO PLANS
// ─────────────────────────────────────────────────────────────────────────────

const VALID_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

async function coachOwnsAthlete(coachId, athleteId) {
  const r = await pool.query(
    `SELECT id FROM users WHERE id = $1 AND coach_id = $2 AND role = 'athlete'`,
    [athleteId, coachId]
  );
  return !!r.rows[0];
}

// Athlete self OR coach of athlete
async function requireSelfOrCoachOfAthlete(req, res, next) {
  try {
    const athleteId = Number(req.params.athleteId);
    if (!Number.isInteger(athleteId) || athleteId <= 0) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }

    // Athlete can access self
    if (req.user?.role === "athlete" && req.user?.id === athleteId) return next();

    // Coach can access their athletes
    if (req.user?.role === "coach") {
      const ok = await coachOwnsAthlete(req.user.id, athleteId);
      if (!ok) return res.status(404).json({ error: "Athlete not found" });
      return next();
    }

    return res.status(403).json({ error: "Forbidden" });
  } catch (e) {
    console.error("Access check error:", e);
    return res.status(500).json({ error: "Something went wrong" });
  }
}

// ✅ Client (athlete) reads their macro targets
app.get("/macro-plans/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);

    // Ensure 7 rows exist
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
    console.error("Get macro plans (client) error:", err);
    return res.status(500).json({ error: "Could not fetch macro plans" });
  }
});

// ✅ CoachCMS bulk save (used by your CoachCMS WeeklyMacroPlan)
app.put("/macro-plans/:athleteId", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const plans = req.body?.plans;

    if (!Number.isInteger(athleteId) || athleteId <= 0) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }
    if (!Array.isArray(plans)) {
      return res.status(400).json({ error: "plans must be an array" });
    }

    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    for (const p of plans) {
      const day = String(p.dayOfWeek || "").toUpperCase();
      if (!VALID_DAYS.includes(day)) continue;

      const calories = Number(p.calories);
      const protein_g = Number(p.protein_g);
      const carbs_g = Number(p.carbs_g);
      const fat_g = Number(p.fat_g);

      if ([calories, protein_g, carbs_g, fat_g].some((n) => Number.isNaN(n))) continue;

      await pool.query(
        `INSERT INTO macro_plans (athlete_id, day_of_week, calories, protein_g, carbs_g, fat_g, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT (athlete_id, day_of_week)
         DO UPDATE SET
           calories = EXCLUDED.calories,
           protein_g = EXCLUDED.protein_g,
           carbs_g = EXCLUDED.carbs_g,
           fat_g = EXCLUDED.fat_g,
           updated_by = EXCLUDED.updated_by,
           updated_at = NOW()`,
        [athleteId, day, calories, protein_g, carbs_g, fat_g, req.user.id]
      );
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Bulk update macro plans error:", err);
    return res.status(500).json({ error: "Could not update macro plans" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CLIENT DATA ROUTES (athlete self OR coach of athlete)
// Profiles + Weights + Meal Plans
// ─────────────────────────────────────────────────────────────────────────────

// GET /profiles/:athleteId
app.get("/profiles/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);

    const result = await pool.query(
      `SELECT athlete_id, goal, height_cm, current_weight_kg, mfp_username, updated_at
       FROM profiles
       WHERE athlete_id = $1`,
      [athleteId]
    );

    if (!result.rows[0]) {
      return res.json({ athleteId, goal: "", heightCm: null, currentWeightKg: null, mfpUsername: null });
    }

    const row = result.rows[0];
    return res.json({
      athleteId: row.athlete_id,
      goal: row.goal,
      heightCm: row.height_cm,
      currentWeightKg: row.current_weight_kg,
      mfpUsername: row.mfp_username,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    console.error("Get profile error:", err);
    return res.status(500).json({ error: "Could not fetch profile" });
  }
});

// PUT /profiles/:athleteId
app.put("/profiles/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { goal, heightCm, currentWeightKg, mfpUsername } = req.body || {};

    const result = await pool.query(
      `INSERT INTO profiles (athlete_id, goal, height_cm, current_weight_kg, mfp_username, updated_at)
       VALUES ($1, COALESCE($2,''), $3, $4, $5, NOW())
       ON CONFLICT (athlete_id)
       DO UPDATE SET
         goal = COALESCE(EXCLUDED.goal,''),
         height_cm = EXCLUDED.height_cm,
         current_weight_kg = EXCLUDED.current_weight_kg,
         mfp_username = EXCLUDED.mfp_username,
         updated_at = NOW()
       RETURNING athlete_id, goal, height_cm, current_weight_kg, mfp_username, updated_at`,
      [
        athleteId,
        goal ?? "",
        heightCm === "" ? null : heightCm ?? null,
        currentWeightKg === "" ? null : currentWeightKg ?? null,
        mfpUsername ?? null,
      ]
    );

    // keep users.mfp_username in sync
    if (mfpUsername !== undefined) {
      await pool.query(
        `UPDATE users SET mfp_username = COALESCE($1, mfp_username) WHERE id = $2`,
        [mfpUsername || null, athleteId]
      );
    }

    const row = result.rows[0];
    return res.json({
      athleteId: row.athlete_id,
      goal: row.goal,
      heightCm: row.height_cm,
      currentWeightKg: row.current_weight_kg,
      mfpUsername: row.mfp_username,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    console.error("Save profile error:", err);
    return res.status(500).json({ error: "Could not save profile" });
  }
});

// GET /weights/:athleteId
app.get("/weights/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const result = await pool.query(
      `SELECT date::text AS date, kg
       FROM weights
       WHERE athlete_id = $1
       ORDER BY date DESC`,
      [athleteId]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get weights error:", err);
    return res.status(500).json({ error: "Could not fetch weights" });
  }
});

// POST /weights/:athleteId
app.post("/weights/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { date, kg } = req.body || {};

    if (!date || typeof date !== "string") {
      return res.status(400).json({ error: "Date is required (YYYY-MM-DD)" });
    }

    const kgNum = Number(kg);
    if (!Number.isFinite(kgNum) || kgNum <= 0) {
      return res.status(400).json({ error: "kg must be a positive number" });
    }

    await pool.query(
      `INSERT INTO weights (athlete_id, date, kg, created_at)
       VALUES ($1, $2::date, $3, NOW())
       ON CONFLICT (athlete_id, date)
       DO UPDATE SET kg = EXCLUDED.kg`,
      [athleteId, date, kgNum]
    );

    // update profile current weight
    await pool.query(
      `INSERT INTO profiles (athlete_id, current_weight_kg, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (athlete_id)
       DO UPDATE SET current_weight_kg = EXCLUDED.current_weight_kg, updated_at = NOW()`,
      [athleteId, kgNum]
    );

    const updated = await pool.query(
      `SELECT date::text AS date, kg
       FROM weights
       WHERE athlete_id = $1
       ORDER BY date DESC`,
      [athleteId]
    );

    return res.json(updated.rows);
  } catch (err) {
    console.error("Add weight error:", err);
    return res.status(500).json({ error: "Could not save weight" });
  }
});

// GET /meal-plans/:athleteId
app.get("/meal-plans/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const result = await pool.query(
      `SELECT plan
       FROM meal_plans
       WHERE athlete_id = $1`,
      [athleteId]
    );
    if (!result.rows[0]) return res.json({ plan: null });
    return res.json({ plan: result.rows[0].plan });
  } catch (err) {
    console.error("Get meal plan error:", err);
    return res.status(500).json({ error: "Could not fetch meal plan" });
  }
});

// PUT /meal-plans/:athleteId
app.put("/meal-plans/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const plan = req.body?.plan;

    if (!plan || typeof plan !== "object") {
      return res.status(400).json({ error: "Plan object is required" });
    }

    const result = await pool.query(
      `INSERT INTO meal_plans (athlete_id, plan, updated_by, updated_at)
       VALUES ($1, $2::jsonb, $3, NOW())
       ON CONFLICT (athlete_id)
       DO UPDATE SET plan = EXCLUDED.plan, updated_by = EXCLUDED.updated_by, updated_at = NOW()
       RETURNING updated_by, updated_at`,
      [athleteId, JSON.stringify(plan), req.user.id]
    );

    return res.json({ ok: true, updatedBy: result.rows[0].updated_by, updatedAt: result.rows[0].updated_at });
  } catch (err) {
    console.error("Save meal plan error:", err);
    return res.status(500).json({ error: "Could not save meal plan" });
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS profiles (
        athlete_id INTEGER PRIMARY KEY,
        goal TEXT DEFAULT '',
        height_cm INTEGER,
        current_weight_kg NUMERIC(6,2),
        mfp_username TEXT,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS weights (
        athlete_id INTEGER NOT NULL,
        date DATE NOT NULL,
        kg NUMERIC(6,2) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (athlete_id, date)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS meal_plans (
        athlete_id INTEGER PRIMARY KEY,
        plan JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_by INTEGER,
        updated_at TIMESTAMPTZ DEFAULT NOW()
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