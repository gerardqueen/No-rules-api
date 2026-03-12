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
  if (req.user?.role !== "coach" && req.user?.role !== "admin") {
    return res.status(403).json({ error: "Coach access required" });
  }
  return next();
}

async function requireAdmin(req, res, next) {
  // Check JWT role first; fall back to DB for freshness after role migrations
  if (req.user?.role === "admin") return next();
  try {
    const r = await pool.query("SELECT role FROM users WHERE id = $1", [req.user?.id]);
    if (r.rows[0]?.role === "admin") return next();
  } catch {}
  return res.status(403).json({ error: "Admin access required" });
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
    `SELECT id FROM users WHERE id = $1 AND coach_id = $2 AND role NOT IN ('coach','admin')`,
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

    // ✅ coaches/admins can access users assigned to them
    if (req.user?.role === "coach" || req.user?.role === "admin") {
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
       WHERE coach_id = $1 AND role NOT IN ('coach','admin')
       ORDER BY name ASC`,
      [req.user.id]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get athletes error:", err);
    return res.status(500).json({ error: "Could not fetch athletes" });
  }
});

app.get("/coach/overview", requireAuth, requireCoach, async (req, res) => {
  try {
    const days = Math.max(7, Math.min(180, Number(req.query.days || 30)));
    const end = new Date();
    end.setHours(0, 0, 0, 0);
    const start = new Date(end);
    start.setDate(end.getDate() - (days - 1));

    const startISO = start.toISOString().slice(0, 10);
    const endISO = end.toISOString().slice(0, 10);

    const athletes = await pool.query(
      `SELECT id, name, email, sport
       FROM users
       WHERE coach_id = $1 AND role <> 'coach'
       ORDER BY name ASC`,
      [req.user.id]
    );

    const out = [];
    for (const a of athletes.rows) {
      const aid = a.id;
      const wLatest = await pool.query(`SELECT date::text AS date, kg FROM weights WHERE athlete_id=$1 ORDER BY date DESC LIMIT 1`, [aid]);
      const wStart = await pool.query(`SELECT date::text AS date, kg FROM weights WHERE athlete_id=$1 AND date >= $2::date AND date <= $3::date ORDER BY date ASC LIMIT 1`, [aid, startISO, endISO]);

      const latestKg = wLatest.rows[0]?.kg ?? null;
      const startKg = wStart.rows[0]?.kg ?? null;
      const weightChangePct = (startKg && latestKg && Number(startKg) > 0) ? ((Number(latestKg) - Number(startKg)) / Number(startKg)) * 100 : null;

      const moodAvgQ = await pool.query(`SELECT AVG(mood_id)::float AS avg FROM mood_logs WHERE athlete_id=$1 AND date >= $2::date AND date <= $3::date`, [aid, startISO, endISO]);
      const moodAvg = moodAvgQ.rows[0]?.avg ?? null;

      const adherQ = await pool.query(
        `WITH dt AS (
           SELECT date, calories
           FROM daily_totals
           WHERE athlete_id = $1 AND date >= $2::date AND date <= $3::date
         ),
         base AS (
           SELECT dt.date,
                  dt.calories AS consumed,
                  COALESCE(mt.calories, mp.calories) AS target
           FROM dt
           LEFT JOIN macro_targets mt ON mt.athlete_id = $1 AND mt.date = dt.date
           LEFT JOIN macro_plans mp ON mp.athlete_id = $1 AND mp.day_of_week = (
             CASE EXTRACT(DOW FROM dt.date)
               WHEN 0 THEN 'SUN'
               WHEN 1 THEN 'MON'
               WHEN 2 THEN 'TUE'
               WHEN 3 THEN 'WED'
               WHEN 4 THEN 'THU'
               WHEN 5 THEN 'FRI'
               WHEN 6 THEN 'SAT'
             END
           )
         )
         SELECT COUNT(*)::int AS total_days,
                SUM(CASE WHEN target IS NOT NULL AND target > 0 AND ABS(consumed - target) / target <= 0.10 THEN 1 ELSE 0 END)::int AS adhered_days
         FROM base
         WHERE target IS NOT NULL AND target > 0`,
        [aid, startISO, endISO]
      );

      const totalDays = adherQ.rows[0]?.total_days ?? 0;
      const adheredDays = adherQ.rows[0]?.adhered_days ?? 0;
      const adherencePct = totalDays > 0 ? (adheredDays / totalDays) * 100 : null;

      out.push({ id: aid, name: a.name, email: a.email, sport: a.sport, latestKg, weightChangePct, moodAvg, adherencePct });
    }

    return res.json({ start: startISO, end: endISO, days, athletes: out });
  } catch (err) {
    console.error("Coach overview error:", err);
    return res.status(500).json({ error: "Could not compute overview" });
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

app.delete("/athletes/:athleteId", requireAuth, requireCoach, async (req, res) => {
  const athleteId = Number(req.params.athleteId);
  if (!Number.isInteger(athleteId) || athleteId <= 0) return res.status(400).json({ error: "Invalid athlete id" });

  try {
    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM coach_checkins WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM daily_totals WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM macro_targets WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM weights WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM mood_logs WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM meal_plans WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM profiles WHERE athlete_id = $1', [athleteId]);
      await client.query('DELETE FROM macro_plans WHERE athlete_id = $1', [athleteId]);
      await client.query("DELETE FROM users WHERE id = $1 AND coach_id = $2 AND role NOT IN ('coach','admin')", [athleteId, req.user.id]);
      await client.query('COMMIT');
      return res.json({ ok: true });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Delete athlete transaction error:', err);
      return res.status(500).json({ error: 'Could not delete athlete' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Delete athlete error:', err);
    return res.status(500).json({ error: 'Could not delete athlete' });
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
// DAILY TOTALS (Macros Consumed) — calendar/date based
app.get("/daily-totals/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const start = req.query.start ? String(req.query.start) : null;
    const end = req.query.end ? String(req.query.end) : null;

    let q = `SELECT date::text AS date, calories, protein_g, carbs_g, fat_g, note, source, updated_at
             FROM daily_totals
             WHERE athlete_id = $1`;
    const params = [athleteId];
    if (start) { params.push(start); q += ` AND date >= $${params.length}::date`; }
    if (end) { params.push(end); q += ` AND date <= $${params.length}::date`; }
    q += ` ORDER BY date DESC`;

    const result = await pool.query(q, params);
    return res.json(result.rows);
  } catch (err) {
    console.error("Get daily totals error:", err);
    return res.status(500).json({ error: "Could not fetch daily totals" });
  }
});

app.post("/daily-totals/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { date, calories, protein_g, carbs_g, fat_g, note, source } = req.body || {};
    if (!date || typeof date !== "string") return res.status(400).json({ error: "date (YYYY-MM-DD) is required" });

    const cals = Number(calories);
    const p = Number(protein_g);
    const c = Number(carbs_g);
    const f = Number(fat_g);
    if ([cals, p, c, f].some((n) => !Number.isFinite(n) || n < 0)) {
      return res.status(400).json({ error: "Invalid macro numbers" });
    }

    await pool.query(
      `INSERT INTO daily_totals (athlete_id, date, calories, protein_g, carbs_g, fat_g, note, source, updated_at)
       VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, NOW())
       ON CONFLICT (athlete_id, date)
       DO UPDATE SET calories = EXCLUDED.calories,
                     protein_g = EXCLUDED.protein_g,
                     carbs_g = EXCLUDED.carbs_g,
                     fat_g = EXCLUDED.fat_g,
                     note = EXCLUDED.note,
                     source = EXCLUDED.source,
                     updated_at = NOW()`,
      [athleteId, date, cals, p, c, f, note || null, source || "manual"]
    );

    const result = await pool.query(
      `SELECT date::text AS date, calories, protein_g, carbs_g, fat_g, note, source, updated_at
       FROM daily_totals
       WHERE athlete_id = $1 AND date = $2::date`,
      [athleteId, date]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Save daily totals error:", err);
    return res.status(500).json({ error: "Could not save daily totals" });
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// MACRO TARGETS — calendar/date based (coach -> client)
function dayKeyFromISO(iso) {
  const d = new Date(`${iso}T00:00:00Z`);
  const js = d.getUTCDay();
  const idx = js === 0 ? 6 : js - 1;
  return VALID_DAYS[idx];
}

app.get("/macro-targets/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const start = req.query.start ? String(req.query.start) : null;
    const end = req.query.end ? String(req.query.end) : null;
    if (!start || !end) return res.status(400).json({ error: "start and end (YYYY-MM-DD) are required" });

    const startD = new Date(`${start}T00:00:00Z`);
    const endD = new Date(`${end}T00:00:00Z`);
    const days = Math.floor((endD - startD) / 86400000) + 1;
    if (!Number.isFinite(days) || days <= 0 || days > 370) return res.status(400).json({ error: "Range too large (max 370 days)" });

    const overrides = await pool.query(
      `SELECT date::text AS date, calories, protein_g, carbs_g, fat_g, updated_at
       FROM macro_targets
       WHERE athlete_id = $1 AND date >= $2::date AND date <= $3::date`,
      [athleteId, start, end]
    );
    const ovMap = {};
    overrides.rows.forEach((r) => (ovMap[r.date] = r));

    const plan = await pool.query(
      `SELECT day_of_week, calories, protein_g, carbs_g, fat_g
       FROM macro_plans
       WHERE athlete_id = $1`,
      [athleteId]
    );
    const planMap = {};
    plan.rows.forEach((r) => (planMap[r.day_of_week] = r));

    const out = [];
    for (let i = 0; i < days; i++) {
      const cur = new Date(startD.getTime() + i * 86400000);
      const iso = cur.toISOString().slice(0, 10);
      if (ovMap[iso]) {
        out.push({ date: iso, calories: ovMap[iso].calories, protein_g: ovMap[iso].protein_g, carbs_g: ovMap[iso].carbs_g, fat_g: ovMap[iso].fat_g, source: "override", updated_at: ovMap[iso].updated_at });
      } else {
        const key = dayKeyFromISO(iso);
        const base = planMap[key];
        if (base) out.push({ date: iso, calories: base.calories, protein_g: base.protein_g, carbs_g: base.carbs_g, fat_g: base.fat_g, source: "plan" });
      }
    }

    return res.json(out);
  } catch (err) {
    console.error("Get macro targets error:", err);
    return res.status(500).json({ error: "Could not fetch macro targets" });
  }
});

app.put("/macro-targets/:athleteId", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const entries = req.body?.entries;
    if (!Array.isArray(entries) || entries.length === 0) return res.status(400).json({ error: "entries must be a non-empty array" });

    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    for (const e of entries) {
      const date = String(e.date || "");
      const calories = Number(e.calories);
      const protein_g = Number(e.protein_g);
      const carbs_g = Number(e.carbs_g);
      const fat_g = Number(e.fat_g);
      if (!date || [calories, protein_g, carbs_g, fat_g].some((n) => !Number.isFinite(n) || n < 0)) continue;

      await pool.query(
        `INSERT INTO macro_targets (athlete_id, date, calories, protein_g, carbs_g, fat_g, updated_by, updated_at)
         VALUES ($1, $2::date, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT (athlete_id, date)
         DO UPDATE SET calories = EXCLUDED.calories,
                       protein_g = EXCLUDED.protein_g,
                       carbs_g = EXCLUDED.carbs_g,
                       fat_g = EXCLUDED.fat_g,
                       updated_by = EXCLUDED.updated_by,
                       updated_at = NOW()`,
        [athleteId, date, calories, protein_g, carbs_g, fat_g, req.user.id]
      );
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Save macro targets error:", err);
    return res.status(500).json({ error: "Could not save macro targets" });
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
// COACH CHECK-IN CALENDAR (links + notes by date)
app.get("/checkins/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const start = req.query.start ? String(req.query.start) : null;
    const end = req.query.end ? String(req.query.end) : null;

    let q = `SELECT id, date::text AS date, title, link_url AS \"linkUrl\", notes, created_at
             FROM coach_checkins
             WHERE athlete_id = $1`;
    const params = [athleteId];
    if (start) { params.push(start); q += ` AND date >= $${params.length}::date`; }
    if (end) { params.push(end); q += ` AND date <= $${params.length}::date`; }
    q += ` ORDER BY date ASC, id ASC`;

    const result = await pool.query(q, params);
    return res.json(result.rows);
  } catch (err) {
    console.error("Get checkins error:", err);
    return res.status(500).json({ error: "Could not fetch check-ins" });
  }
});

app.post("/checkins/:athleteId", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    const { date, title, linkUrl, notes } = req.body || {};
    if (!date || typeof date !== "string") return res.status(400).json({ error: "date is required" });

    const t = String(title || "Check-in").slice(0, 120);
    const l = linkUrl ? String(linkUrl).slice(0, 500) : null;
    const n = notes ? String(notes).slice(0, 2000) : null;

    const result = await pool.query(
      `INSERT INTO coach_checkins (athlete_id, date, title, link_url, notes, created_by, created_at)
       VALUES ($1, $2::date, $3, $4, $5, $6, NOW())
       RETURNING id, date::text AS date, title, link_url AS \"linkUrl\", notes, created_at`,
      [athleteId, date, t, l, n, req.user.id]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Create checkin error:", err);
    return res.status(500).json({ error: "Could not create check-in" });
  }
});

app.delete("/checkins/:athleteId/:id", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const id = Number(req.params.id);
    const ok = await coachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    await pool.query('DELETE FROM coach_checkins WHERE id = $1 AND athlete_id = $2', [id, athleteId]);
    return res.json({ ok: true });
  } catch (err) {
    console.error("Delete checkin error:", err);
    return res.status(500).json({ error: "Could not delete check-in" });
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

// ─────────────────────────────────────────────────────────────────────────────
// FOOD LOGS (Manual foods + per-item macros) — date based
// Stores the list of foods logged for a day so the UI can rebuild the diary on re-login.
//
// Shape: { date:'YYYY-MM-DD', foods:[{ id, name, grams, calories, protein_g, carbs_g, fat_g, source, created_at }] }
// ─────────────────────────────────────────────────────────────────────────────
app.get("/food-logs/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const start = req.query.start ? String(req.query.start) : null;
    const end = req.query.end ? String(req.query.end) : null;

    let q = `SELECT date::text AS date, foods, updated_at
             FROM food_logs
             WHERE athlete_id = $1`;
    const params = [athleteId];
    if (start) { params.push(start); q += ` AND date >= $${params.length}::date`; }
    if (end) { params.push(end); q += ` AND date <= $${params.length}::date`; }
    q += ` ORDER BY date DESC`;

    const result = await pool.query(q, params);
    return res.json(result.rows.map(r => ({ ...r, foods: r.foods || [] })));
  } catch (err) {
    console.error("Get food logs error:", err);
    return res.status(500).json({ error: "Could not fetch food logs" });
  }
});

app.put("/food-logs/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { date, foods } = req.body || {};
    if (!date || typeof date !== "string") return res.status(400).json({ error: "date (YYYY-MM-DD) is required" });
    if (!Array.isArray(foods)) return res.status(400).json({ error: "foods must be an array" });

    // Normalize items a bit
    const norm = foods.map((f) => ({
      id: f.id || null,
      name: String(f.name || "").slice(0, 120),
      grams: Number(f.grams || 0),
      calories: Number(f.calories || 0),
      protein_g: Number(f.protein_g ?? f.protein ?? 0),
      carbs_g: Number(f.carbs_g ?? f.carbs ?? 0),
      fat_g: Number(f.fat_g ?? f.fat ?? 0),
      source: String(f.source || "manual").slice(0, 24),
      created_at: f.created_at || null,
    }));

    await pool.query(
      `INSERT INTO food_logs (athlete_id, date, foods, updated_by, updated_at)
       VALUES ($1, $2::date, $3::jsonb, $4, NOW())
       ON CONFLICT (athlete_id, date)
       DO UPDATE SET foods = EXCLUDED.foods, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [athleteId, date, JSON.stringify(norm), req.user.id]
    );

    const result = await pool.query(
      `SELECT date::text AS date, foods, updated_at
       FROM food_logs
       WHERE athlete_id=$1 AND date=$2::date`,
      [athleteId, date]
    );

    return res.json({ ...result.rows[0], foods: result.rows[0]?.foods || [] });
  } catch (err) {
    console.error("Save food logs error:", err);
    return res.status(500).json({ error: "Could not save food logs" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CALENDAR EVENTS (Athlete-created + coach-created) — date/time based
// ─────────────────────────────────────────────────────────────────────────────
app.get("/calendar-events/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const start = req.query.start ? String(req.query.start) : null;
    const end = req.query.end ? String(req.query.end) : null;

    let q = `SELECT id, date::text AS date, title, start_iso AS "startISO", end_iso AS "endISO", notes, created_by AS "createdBy", created_at
             FROM calendar_events
             WHERE athlete_id = $1`;
    const params = [athleteId];
    if (start) { params.push(start); q += ` AND date >= $${params.length}::date`; }
    if (end) { params.push(end); q += ` AND date <= $${params.length}::date`; }
    q += ` ORDER BY date ASC, start_iso ASC, id ASC`;

    const result = await pool.query(q, params);
    return res.json(result.rows);
  } catch (err) {
    console.error("Get calendar events error:", err);
    return res.status(500).json({ error: "Could not fetch calendar events" });
  }
});

app.post("/calendar-events/:athleteId", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const { date, title, startISO, endISO, notes } = req.body || {};
    if (!date || typeof date !== "string") return res.status(400).json({ error: "date (YYYY-MM-DD) is required" });
    if (!title) return res.status(400).json({ error: "title is required" });

    const t = String(title).slice(0, 120);
    const s = startISO ? String(startISO).slice(0, 32) : null;
    const e = endISO ? String(endISO).slice(0, 32) : null;
    const n = notes ? String(notes).slice(0, 2000) : null;

    const result = await pool.query(
      `INSERT INTO calendar_events (athlete_id, date, title, start_iso, end_iso, notes, created_by, created_at)
       VALUES ($1, $2::date, $3, $4, $5, $6, $7, NOW())
       RETURNING id, date::text AS date, title, start_iso AS "startISO", end_iso AS "endISO", notes, created_by AS "createdBy", created_at`,
      [athleteId, date, t, s, e, n, req.user.id]
    );
    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Create calendar event error:", err);
    return res.status(500).json({ error: "Could not create calendar event" });
  }
});

app.delete("/calendar-events/:athleteId/:id", requireAuth, requireSelfOrCoachOfAthlete, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "Invalid event id" });

    // allow deletion if self or coach of athlete (already checked)
    await pool.query(`DELETE FROM calendar_events WHERE athlete_id=$1 AND id=$2`, [athleteId, id]);
    return res.json({ ok: true });
  } catch (err) {
    console.error("Delete calendar event error:", err);
    return res.status(500).json({ error: "Could not delete calendar event" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN — Coach management (admin only)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/admin/coaches", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, role, sport, avatar_url, created_at
       FROM users
       WHERE role IN ('coach','admin')
       ORDER BY name ASC`
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get coaches error:", err);
    return res.status(500).json({ error: "Could not fetch coaches" });
  }
});

app.post("/admin/coaches", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { email, name, password, role } = req.body || {};
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
    const coachRole = role === "admin" ? "admin" : "coach";
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, role, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id, email, name, role, created_at`,
      [String(email).toLowerCase().trim(), passwordHash, name, coachRole]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create coach error:", err);
    return res.status(500).json({ error: "Could not create coach" });
  }
});

app.delete("/admin/coaches/:coachId", requireAuth, requireAdmin, async (req, res) => {
  try {
    const coachId = Number(req.params.coachId);
    if (!Number.isInteger(coachId) || coachId <= 0) return res.status(400).json({ error: "Invalid coach id" });
    // Don't let admin delete themselves
    if (coachId === req.user.id) return res.status(400).json({ error: "Cannot delete your own account" });
    // Check the target is actually a coach/admin
    const check = await pool.query("SELECT role FROM users WHERE id = $1", [coachId]);
    if (!check.rows[0] || !['coach','admin'].includes(check.rows[0].role)) {
      return res.status(404).json({ error: "Coach not found" });
    }
    // Unassign athletes (set coach_id to null) rather than deleting them
    await pool.query("UPDATE users SET coach_id = NULL WHERE coach_id = $1", [coachId]);
    await pool.query("DELETE FROM users WHERE id = $1", [coachId]);
    return res.json({ ok: true });
  } catch (err) {
    console.error("Delete coach error:", err);
    return res.status(500).json({ error: "Could not delete coach" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGES (coach <-> athlete)
// ─────────────────────────────────────────────────────────────────────────────

// Broadcast from coach to all their athletes (MUST be before :toId route)
app.post("/messages/broadcast", requireAuth, requireCoach, async (req, res) => {
  try {
    const coachId = req.user.id;
    const { content } = req.body || {};
    if (!content || typeof content !== "string" || !content.trim()) {
      return res.status(400).json({ error: "Message content is required" });
    }
    const athletes = await pool.query(
      `SELECT id FROM users WHERE coach_id=$1 AND role NOT IN ('coach','admin')`,
      [coachId]
    );
    const msg = content.trim().slice(0, 5000);
    let sent = 0;
    for (const a of athletes.rows) {
      await pool.query(
        `INSERT INTO messages (from_id, to_id, content, created_at) VALUES ($1,$2,$3,NOW())`,
        [coachId, a.id, msg]
      );
      sent++;
    }
    return res.json({ ok: true, sent });
  } catch (err) {
    console.error("Broadcast error:", err);
    return res.status(500).json({ error: "Could not broadcast" });
  }
});

// Admin broadcast to ALL athletes across all coaches
app.post("/messages/broadcast-all", requireAuth, requireAdmin, async (req, res) => {
  try {
    const adminId = req.user.id;
    const { content } = req.body || {};
    if (!content || typeof content !== "string" || !content.trim()) {
      return res.status(400).json({ error: "Message content is required" });
    }
    const athletes = await pool.query(
      `SELECT id FROM users WHERE role NOT IN ('coach','admin')`
    );
    const msg = content.trim().slice(0, 5000);
    let sent = 0;
    for (const a of athletes.rows) {
      await pool.query(
        `INSERT INTO messages (from_id, to_id, content, created_at) VALUES ($1,$2,$3,NOW())`,
        [adminId, a.id, msg]
      );
      sent++;
    }
    return res.json({ ok: true, sent });
  } catch (err) {
    console.error("Broadcast-all error:", err);
    return res.status(500).json({ error: "Could not broadcast to all" });
  }
});

// Unread count for current user
app.get("/messages-unread", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT from_id AS "fromId", COUNT(*)::int AS count
       FROM messages WHERE to_id=$1 AND is_read=FALSE
       GROUP BY from_id`,
      [req.user.id]
    );
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: "Could not fetch unread counts" });
  }
});

app.get("/messages/:otherId", requireAuth, async (req, res) => {
  try {
    const me = req.user.id;
    const other = Number(req.params.otherId);
    const result = await pool.query(
      `SELECT id, from_id AS "fromId", to_id AS "toId", content, is_read AS "read", created_at
       FROM messages
       WHERE (from_id=$1 AND to_id=$2) OR (from_id=$2 AND to_id=$1)
       ORDER BY created_at ASC`,
      [me, other]
    );
    // Mark messages TO me as read
    await pool.query(
      `UPDATE messages SET is_read=TRUE WHERE from_id=$1 AND to_id=$2 AND is_read=FALSE`,
      [other, me]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Get messages error:", err);
    return res.status(500).json({ error: "Could not fetch messages" });
  }
});

app.post("/messages/:toId", requireAuth, async (req, res) => {
  try {
    const fromId = req.user.id;
    const toId = Number(req.params.toId);
    const { content } = req.body || {};
    if (!content || typeof content !== "string" || !content.trim()) {
      return res.status(400).json({ error: "Message content is required" });
    }
    const result = await pool.query(
      `INSERT INTO messages (from_id, to_id, content, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING id, from_id AS "fromId", to_id AS "toId", content, is_read AS "read", created_at`,
      [fromId, toId, content.trim().slice(0, 5000)]
    );
    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Send message error:", err);
    return res.status(500).json({ error: "Could not send message" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN — Coach overview with stats + reassign athletes
// ─────────────────────────────────────────────────────────────────────────────
app.get("/admin/coach-overview", requireAuth, requireAdmin, async (req, res) => {
  try {
    const coaches = await pool.query(
      `SELECT id, email, name, role FROM users WHERE role IN ('coach','admin') ORDER BY name`
    );
    const out = [];
    for (const c of coaches.rows) {
      const athleteCount = await pool.query(
        `SELECT COUNT(*)::int AS count FROM users WHERE coach_id=$1 AND role NOT IN ('coach','admin')`,
        [c.id]
      );
      // Average adherence for last 14 days
      const adherQ = await pool.query(
        `WITH dt AS (
           SELECT dt.athlete_id, dt.date, dt.calories AS consumed,
                  COALESCE(mp.calories, 2000) AS target
           FROM daily_totals dt
           JOIN users u ON u.id = dt.athlete_id AND u.coach_id = $1
           LEFT JOIN macro_plans mp ON mp.athlete_id = dt.athlete_id AND mp.day_of_week = (
             CASE EXTRACT(DOW FROM dt.date)
               WHEN 0 THEN 'SUN' WHEN 1 THEN 'MON' WHEN 2 THEN 'TUE' WHEN 3 THEN 'WED'
               WHEN 4 THEN 'THU' WHEN 5 THEN 'FRI' WHEN 6 THEN 'SAT' END)
           WHERE dt.date >= CURRENT_DATE - INTERVAL '14 days'
         )
         SELECT COUNT(*)::int AS total,
                SUM(CASE WHEN target>0 AND ABS(consumed-target)/target<=0.15 THEN 1 ELSE 0 END)::int AS adhered
         FROM dt WHERE target>0`,
        [c.id]
      );
      const total = adherQ.rows[0]?.total ?? 0;
      const adhered = adherQ.rows[0]?.adhered ?? 0;
      const adherencePct = total > 0 ? Math.round((adhered / total) * 100) : null;

      out.push({
        id: c.id, name: c.name, email: c.email, role: c.role,
        athleteCount: athleteCount.rows[0]?.count ?? 0,
        adherencePct,
      });
    }
    return res.json(out);
  } catch (err) {
    console.error("Coach overview error:", err);
    return res.status(500).json({ error: "Could not fetch overview" });
  }
});

// Get athletes for a specific coach (admin view)
app.get("/admin/coach/:coachId/athletes", requireAuth, requireAdmin, async (req, res) => {
  try {
    const coachId = Number(req.params.coachId);
    const result = await pool.query(
      `SELECT id, email, name, sport FROM users WHERE coach_id=$1 AND role NOT IN ('coach','admin') ORDER BY name`,
      [coachId]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Coach athletes error:", err);
    return res.status(500).json({ error: "Could not fetch athletes" });
  }
});

// Reassign athlete to different coach
app.put("/admin/reassign", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { athleteId, newCoachId } = req.body || {};
    if (!athleteId || !newCoachId) return res.status(400).json({ error: "athleteId and newCoachId required" });
    // Verify target is a coach/admin
    const coach = await pool.query("SELECT id, role FROM users WHERE id=$1", [newCoachId]);
    if (!coach.rows[0] || !['coach','admin'].includes(coach.rows[0].role)) {
      return res.status(404).json({ error: "Target coach not found" });
    }
    await pool.query("UPDATE users SET coach_id=$1 WHERE id=$2", [newCoachId, athleteId]);
    return res.json({ ok: true });
  } catch (err) {
    console.error("Reassign error:", err);
    return res.status(500).json({ error: "Could not reassign athlete" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ATHLETE SUMMARY — combined macro goals + week plan (athlete-facing)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/athlete/:athleteId/macro-targets", requireAuth, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    if (req.user?.id !== athleteId) return res.status(403).json({ error: "Forbidden" });

    const plan = await pool.query(
      `SELECT day_of_week, calories, protein_g, carbs_g, fat_g
       FROM macro_plans WHERE athlete_id = $1`, [athleteId]);

    if (!plan.rows.length) return res.json({});

    const sum = plan.rows.reduce((a, r) => ({
      calories: a.calories + Number(r.calories || 0),
      protein: a.protein + Number(r.protein_g || 0),
      carbs: a.carbs + Number(r.carbs_g || 0),
      fat: a.fat + Number(r.fat_g || 0),
    }), { calories: 0, protein: 0, carbs: 0, fat: 0 });
    const n = Math.max(1, plan.rows.length);
    const macroGoals = {
      calories: Math.round(sum.calories / n),
      protein: Math.round(sum.protein / n),
      carbs: Math.round(sum.carbs / n),
      fat: Math.round(sum.fat / n),
    };
    return res.json({ macroGoals });
  } catch (err) {
    console.error("Athlete macro targets error:", err);
    return res.status(500).json({ error: "Could not fetch macro targets" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ATHLETE CALENDAR EVENTS (athlete-facing, legacy path)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/athlete/:athleteId/calendar-events", requireAuth, async (req, res) => {
  try {
    const athleteId = Number(req.params.athleteId);
    if (req.user?.id !== athleteId) return res.status(403).json({ error: "Forbidden" });
    const result = await pool.query(
      `SELECT id, date::text AS date, title, start_iso AS "startISO", end_iso AS "endISO", notes, created_by AS "createdBy"
       FROM calendar_events WHERE athlete_id = $1 ORDER BY date ASC, id ASC`, [athleteId]);
    return res.json({ events: result.rows });
  } catch (err) {
    console.error("Athlete calendar events error:", err);
    return res.status(500).json({ error: "Could not fetch events" });
  }
});

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

    

    await pool.query(`
      CREATE TABLE IF NOT EXISTS daily_totals (
        athlete_id INTEGER NOT NULL,
        date DATE NOT NULL,
        calories INTEGER NOT NULL DEFAULT 0,
        protein_g INTEGER NOT NULL DEFAULT 0,
        carbs_g INTEGER NOT NULL DEFAULT 0,
        fat_g INTEGER NOT NULL DEFAULT 0,
        note TEXT,
        source TEXT DEFAULT 'manual',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (athlete_id, date)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS macro_targets (
        athlete_id INTEGER NOT NULL,
        date DATE NOT NULL,
        calories INTEGER NOT NULL DEFAULT 0,
        protein_g INTEGER NOT NULL DEFAULT 0,
        carbs_g INTEGER NOT NULL DEFAULT 0,
        fat_g INTEGER NOT NULL DEFAULT 0,
        updated_by INTEGER,
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (athlete_id, date)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS coach_checkins (
        id BIGSERIAL PRIMARY KEY,
        athlete_id INTEGER NOT NULL,
        date DATE NOT NULL,
        title TEXT NOT NULL,
        link_url TEXT,
        notes TEXT,
        created_by INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

 await pool.query(`
 CREATE TABLE IF NOT EXISTS food_logs (
   athlete_id INTEGER NOT NULL,
   date DATE NOT NULL,
   foods JSONB NOT NULL DEFAULT '[]'::jsonb,
   updated_by INTEGER,
   updated_at TIMESTAMPTZ DEFAULT NOW(),
   PRIMARY KEY (athlete_id, date)
 );
 `);
 await pool.query(`
 CREATE TABLE IF NOT EXISTS calendar_events (
   id BIGSERIAL PRIMARY KEY,
   athlete_id INTEGER NOT NULL,
   date DATE NOT NULL,
   title TEXT NOT NULL,
   start_iso TEXT,
   end_iso TEXT,
   notes TEXT,
   created_by INTEGER,
   created_at TIMESTAMPTZ DEFAULT NOW()
 );
 `);
 // Messages table — drop old version if column schema is wrong, then create fresh
 try {
   const colCheck = await pool.query(
     `SELECT column_name FROM information_schema.columns WHERE table_name='messages' AND column_name='read'`
   );
   if (colCheck.rows.length > 0) {
     // Old schema with reserved-word column — drop and recreate
     await pool.query(`DROP TABLE messages`);
     console.log("⚠️  Dropped old messages table (had reserved 'read' column)");
   }
 } catch (e) { /* table might not exist yet, that's fine */ }
 await pool.query(`
 CREATE TABLE IF NOT EXISTS messages (
   id BIGSERIAL PRIMARY KEY,
   from_id INTEGER NOT NULL,
   to_id INTEGER NOT NULL,
   content TEXT NOT NULL,
   is_read BOOLEAN DEFAULT FALSE,
   created_at TIMESTAMPTZ DEFAULT NOW()
 );
 `);
console.log("✅ DB ready");

    // Promote known coach accounts to admin
    await pool.query(
      `UPDATE users SET role = 'admin' WHERE email IN ('gerard@norules.com','luke@norules.com','esme@norules.com') AND role = 'coach'`
    );
    console.log("✅ Admin accounts set");
  } catch (err) {
    console.error("❌ Auto-migration error:", err.message);
  }
});
