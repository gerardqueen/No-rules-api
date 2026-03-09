// ─────────────────────────────────────────────────────────────────────────────
// NO RULES NUTRITION — Backend Server
// Auth + Athletes + Macro Plans + Profiles + Weights + Meal Plans + Moods
// v3: fixes 404s by including all endpoints and fixes 403 by allowing self regardless of role
//     coach access allowed for any user with coach_id = coach and role != 'coach'
// ─────────────────────────────────────────────────────────────────────────────
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { pool } = require("./db");

const app = express();
const PORT = process.env.PORT || 3001;

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
// AUTH
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// AUTHZ helper: allow self regardless of role + allow coach for their users (role != coach)
// ─────────────────────────────────────────────────────────────────────────────
const VALID_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

async function coachOwnsAthlete(coachId, athleteId) {
  const r = await pool.query(
    `SELECT id FROM users WHERE id = $1 AND coach_id = $2 AND role <> 'coach'`,
    [athleteId, coachId]
  );
  return !!r.rows[0];
}

async function requireSelfOrCoachOfAthlete(req, res, next) {
  try {
    const athleteId = Number(req.params.athleteId);
    if (!Number.isInteger(athleteId) || athleteId <= 0) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }

    // ✅ any logged-in user can access their own records
    if (req.user?.id === athleteId) return next();

    // ✅ coaches can access users assigned to them
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

// ─────────────────────────────────────────────────────────────────────────────
// ATHLETES (coach)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/athletes", requireAuth, requireCoach, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, role, sport, mfp_username, avatar_url, created_at
       FROM users
       WHERE coach_id = $1 AND role <> 'coach'
       ORDER BY name ASC`,
      [req.user.id]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get athletes error:", err);
    return res.status(500).json({ error: "Could not fetch athletes" });
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
       RETURNING id, email, name, role, sport, mfp_username, avatar_url, created_at`,
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

// ─────────────────────────────────────────────────────────────────────────────
// MACRO PLANS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/macro-plans/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);

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

app.put("/macro-plans/:athleteId", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const plans = req.body?.plans;

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
// PROFILES
// ─────────────────────────────────────────────────────────────────────────────
app.get("/profiles/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const result = await pool.query(
      `SELECT athlete_id, goal, height_cm, current_weight_kg, mfp_username, updated_at
       FROM profiles WHERE athlete_id = $1`,
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

app.put("/profiles/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { goal, heightCm, currentWeightKg, mfpUsername } = req.body || {};

    const result = await pool.query(
      `INSERT INTO profiles (athlete_id, goal, height_cm, current_weight_kg, mfp_username, updated_at)
       VALUES ($1, COALESCE($2,''), $3, $4, $5, NOW())
       ON CONFLICT (athlete_id)
       DO UPDATE SET goal = COALESCE(EXCLUDED.goal,''),
                    height_cm = EXCLUDED.height_cm,
                    current_weight_kg = EXCLUDED.current_weight_kg,
                    mfp_username = EXCLUDED.mfp_username,
                    updated_at = NOW()
       RETURNING athlete_id, goal, height_cm, current_weight_kg, mfp_username, updated_at`,
      [athleteId, goal ?? "", heightCm ?? null, currentWeightKg ?? null, mfpUsername ?? null]
    );

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

// ─────────────────────────────────────────────────────────────────────────────
// WEIGHTS
// ─────────────────────────────────────────────────────────────────────────────
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

app.post("/weights/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { date, kg } = req.body || {};

    const kgNum = Number(kg);
    if (!date || typeof date !== "string" || !Number.isFinite(kgNum) || kgNum <= 0) {
      return res.status(400).json({ error: "Invalid payload" });
    }

    await pool.query(
      `INSERT INTO weights (athlete_id, date, kg, created_at)
       VALUES ($1, $2::date, $3, NOW())
       ON CONFLICT (athlete_id, date)
       DO UPDATE SET kg = EXCLUDED.kg`,
      [athleteId, date, kgNum]
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

// ─────────────────────────────────────────────────────────────────────────────
// MOODS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/moods/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const result = await pool.query(
      `SELECT date::text AS date, mood_id, emoji, label, color, note
       FROM mood_logs
       WHERE athlete_id = $1
       ORDER BY date DESC`,
      [athleteId]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get moods error:", err);
    return res.status(500).json({ error: "Could not fetch moods" });
  }
});

app.post("/moods/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { date, id, emoji, label, color, note } = req.body || {};

    const moodId = Number(id);
    if (!date || typeof date !== "string" || !Number.isFinite(moodId) || moodId <= 0) {
      return res.status(400).json({ error: "Invalid payload" });
    }

    await pool.query(
      `INSERT INTO mood_logs (athlete_id, date, mood_id, emoji, label, color, note, created_at)
       VALUES ($1, $2::date, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (athlete_id, date)
       DO UPDATE SET mood_id = EXCLUDED.mood_id, emoji = EXCLUDED.emoji, label = EXCLUDED.label, color = EXCLUDED.color, note = EXCLUDED.note`,
      [athleteId, date, moodId, emoji || null, label || null, color || null, note || null]
    );

    const updated = await pool.query(
      `SELECT date::text AS date, mood_id, emoji, label, color, note
       FROM mood_logs
       WHERE athlete_id = $1
       ORDER BY date DESC`,
      [athleteId]
    );

    return res.json(updated.rows);
  } catch (err) {
    console.error("Save mood error:", err);
    return res.status(500).json({ error: "Could not save mood" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// MEAL PLANS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/meal-plans/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const result = await pool.query(
      `SELECT plan FROM meal_plans WHERE athlete_id = $1`,
      [athleteId]
    );
    if (!result.rows[0]) return res.json({ plan: null });
    return res.json({ plan: result.rows[0].plan });
  } catch (err) {
    console.error("Get meal plan error:", err);
    return res.status(500).json({ error: "Could not fetch meal plan" });
  }
});

app.put("/meal-plans/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const plan = req.body?.plan;
    if (!plan || typeof plan !== "object") {
      return res.status(400).json({ error: "Plan object is required" });
    }

    await pool.query(
      `INSERT INTO meal_plans (athlete_id, plan, updated_by, updated_at)
       VALUES ($1, $2::jsonb, $3, NOW())
       ON CONFLICT (athlete_id)
       DO UPDATE SET plan = EXCLUDED.plan, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [athleteId, JSON.stringify(plan), req.user.id]
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error("Save meal plan error:", err);
    return res.status(500).json({ error: "Could not save meal plan" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  return res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────────────────────────────────────
// START + AUTO TABLES
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
      CREATE TABLE IF NOT EXISTS mood_logs (
        athlete_id INTEGER NOT NULL,
        date DATE NOT NULL,
        mood_id INTEGER NOT NULL,
        emoji TEXT,
        label TEXT,
        color TEXT,
        note TEXT,
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

    console.log("✅ DB ready");
  } catch (err) {
    console.error("❌ Auto-migration error:", err.message);
  }
});
