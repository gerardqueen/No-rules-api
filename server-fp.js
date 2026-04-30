// ─────────────────────────────────────────────────────────────────────────────
// Fitness Pacific routes
// ─────────────────────────────────────────────────────────────────────────────
//
// USAGE — in server.js, after you've defined `app`, `pool`, `requireAuth`,
// `requireCoach` and `requireAdmin`, add these two lines:
//
//   const registerFpRoutes = require("./server-fp.js");
//   registerFpRoutes(app, { pool, requireAuth, requireCoach, requireAdmin });
//
// All FP endpoints live under /fp/* so they don't collide with No Rules.
//
// SECURITY MODEL:
//   - Coaches see only the athletes they own (via fp_coach_athletes table)
//   - Athletes see only their own data (req.user.id === athlete_id)
//   - Admins can see all coaches and promote/demote them
//   - The shared /foods/* endpoints in your main server.js stay unchanged —
//     this module doesn't touch them
//
// PASSWORDS:
//   - Coaches set a temporary password when adding athletes
//   - Athletes can ONLY change their own password if password_reset_allowed=true
//     (coach toggle controls this)
//   - Coaches can directly reset any of their athletes' passwords
// ─────────────────────────────────────────────────────────────────────────────

const bcrypt = require("bcryptjs");

module.exports = function registerFpRoutes(app, { pool, requireAuth, requireCoach, requireAdmin }) {

  // ───────────────────────────────────────────────────────────────────────────
  // Helper: ensure the requesting coach owns this athlete (or is admin)
  // ───────────────────────────────────────────────────────────────────────────
  async function requireCoachOwnsAthlete(req, res, next) {
    const athleteId = parseInt(req.params.athleteId || req.params.id, 10);
    if (!Number.isInteger(athleteId)) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }
    // Admins bypass ownership check
    if (req.user?.role === "admin") {
      req.athleteId = athleteId;
      return next();
    }
    // Athletes can only access their own data
    if (req.user?.role === "athlete" && req.user.id === athleteId) {
      req.athleteId = athleteId;
      return next();
    }
    // Coaches must own the athlete
    if (req.user?.role === "coach") {
      try {
        const r = await pool.query(
          "SELECT 1 FROM fp_coach_athletes WHERE coach_id = $1 AND athlete_id = $2",
          [req.user.id, athleteId]
        );
        if (r.rowCount > 0) {
          req.athleteId = athleteId;
          return next();
        }
      } catch (err) {
        console.error("Coach ownership check failed:", err);
      }
    }
    return res.status(403).json({ error: "You don't have access to this athlete" });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // COACH: athlete management
  // ───────────────────────────────────────────────────────────────────────────

  // List all athletes the coach owns (admins see everything)
  app.get("/fp/coach/athletes", requireAuth, requireCoach, async (req, res) => {
    try {
      let rows;
      if (req.user.role === "admin") {
        // Admin sees every FP-managed athlete (across all coaches),
        // but NOT athletes from other apps that share this users table.
        // Membership in fp_coach_athletes is what makes someone an FP athlete.
        const r = await pool.query(
          `SELECT DISTINCT u.id, u.email, u.name, u.role, u.password_reset_allowed,
                  u.created_at,
                  (SELECT MAX(date) FROM fp_workouts WHERE athlete_id = u.id) AS last_workout_date
           FROM users u
           JOIN fp_coach_athletes ca ON ca.athlete_id = u.id
           WHERE u.role = 'athlete'
           ORDER BY u.name ASC`
        );
        rows = r.rows;
      } else {
        const r = await pool.query(
          `SELECT u.id, u.email, u.name, u.role, u.password_reset_allowed,
                  u.created_at,
                  (SELECT MAX(date) FROM fp_workouts WHERE athlete_id = u.id) AS last_workout_date
           FROM users u
           JOIN fp_coach_athletes ca ON ca.athlete_id = u.id
           WHERE ca.coach_id = $1 AND u.role = 'athlete'
           ORDER BY u.name ASC`,
          [req.user.id]
        );
        rows = r.rows;
      }

      // Adapt to the shape the FP frontend expects
      const out = rows.map(r => ({
        id: r.id,
        email: r.email,
        name: r.name,
        avatar: (r.name || r.email || "?")
          .split(" ").map(s => s[0]).join("").slice(0, 2).toUpperCase(),
        password_reset_allowed: r.password_reset_allowed,
        weight: 0,                    // populated by the per-athlete fetch later
        targets: { calories: 2000, protein: 150, carbs: 200, fat: 65 },
        lastCheckIn: r.last_workout_date
          ? Math.max(0, Math.round((Date.now() - new Date(r.last_workout_date).getTime()) / 86400000))
          : 999,
      }));
      return res.json(out);
    } catch (err) {
      console.error("List athletes error:", err);
      return res.status(500).json({ error: "Could not list athletes" });
    }
  });

  // Create a new athlete (coach action)
  app.post("/fp/coach/athletes", requireAuth, requireCoach, async (req, res) => {
    const client = await pool.connect();
    try {
      const { email, name, password, weight, targets } = req.body || {};
      if (!email || !name || !password) {
        return res.status(400).json({ error: "Email, name and password are required" });
      }
      if (String(password).length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
      }

      const cleanEmail = String(email).toLowerCase().trim();

      await client.query("BEGIN");

      // Check email isn't already taken
      const existing = await client.query("SELECT id FROM users WHERE email = $1", [cleanEmail]);
      if (existing.rowCount > 0) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "An account with that email already exists" });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const insertUser = await client.query(
        `INSERT INTO users (email, password_hash, name, role, password_reset_allowed, created_at)
         VALUES ($1, $2, $3, 'athlete', false, NOW())
         RETURNING id, email, name, role`,
        [cleanEmail, passwordHash, String(name).trim()]
      );
      const newUser = insertUser.rows[0];

      // Link athlete to this coach (admins also get the link so they own them too)
      await client.query(
        `INSERT INTO fp_coach_athletes (coach_id, athlete_id, created_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT DO NOTHING`,
        [req.user.id, newUser.id]
      );

      await client.query("COMMIT");

      return res.status(201).json({
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Create athlete error:", err);
      return res.status(500).json({ error: "Could not create athlete" });
    } finally {
      client.release();
    }
  });

  // Toggle whether an athlete can change their own password
  app.put("/fp/coach/athletes/:id/password-reset-allowed",
    requireAuth, requireCoach, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const { allowed } = req.body || {};
        await pool.query(
          "UPDATE users SET password_reset_allowed = $1 WHERE id = $2",
          [!!allowed, req.athleteId]
        );
        return res.json({ ok: true, password_reset_allowed: !!allowed });
      } catch (err) {
        console.error("Toggle password reset error:", err);
        return res.status(500).json({ error: "Could not update setting" });
      }
    }
  );

  // Coach directly resets athlete's password
  app.put("/fp/coach/athletes/:id/password",
    requireAuth, requireCoach, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const { password } = req.body || {};
        if (!password || String(password).length < 6) {
          return res.status(400).json({ error: "Password must be at least 6 characters" });
        }
        const hash = await bcrypt.hash(String(password), 12);
        await pool.query(
          "UPDATE users SET password_hash = $1 WHERE id = $2",
          [hash, req.athleteId]
        );
        return res.json({ ok: true });
      } catch (err) {
        console.error("Reset athlete password error:", err);
        return res.status(500).json({ error: "Could not reset password" });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // ADMIN: coach management
  // ───────────────────────────────────────────────────────────────────────────

  app.get("/fp/admin/coaches", requireAuth, requireAdmin, async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT id, email, name, role, is_admin, created_at
         FROM users
         WHERE role = 'coach' OR role = 'admin'
         ORDER BY name ASC`
      );
      return res.json(r.rows);
    } catch (err) {
      console.error("List coaches error:", err);
      return res.status(500).json({ error: "Could not list coaches" });
    }
  });

  app.post("/fp/admin/coaches", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { email, name, password, is_admin } = req.body || {};
      if (!email || !name || !password) {
        return res.status(400).json({ error: "Email, name and password are required" });
      }
      if (String(password).length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
      }
      const cleanEmail = String(email).toLowerCase().trim();
      const existing = await pool.query("SELECT id FROM users WHERE email = $1", [cleanEmail]);
      if (existing.rowCount > 0) {
        return res.status(409).json({ error: "An account with that email already exists" });
      }
      const passwordHash = await bcrypt.hash(password, 12);
      const r = await pool.query(
        `INSERT INTO users (email, password_hash, name, role, is_admin, created_at)
         VALUES ($1, $2, $3, 'coach', $4, NOW())
         RETURNING id, email, name, role, is_admin`,
        [cleanEmail, passwordHash, String(name).trim(), !!is_admin]
      );
      return res.status(201).json(r.rows[0]);
    } catch (err) {
      console.error("Create coach error:", err);
      return res.status(500).json({ error: "Could not create coach" });
    }
  });

  app.put("/fp/admin/coaches/:id/admin", requireAuth, requireAdmin, async (req, res) => {
    try {
      const coachId = parseInt(req.params.id, 10);
      if (!Number.isInteger(coachId)) {
        return res.status(400).json({ error: "Invalid coach id" });
      }
      // Don't let an admin demote themselves and lock everyone out
      if (coachId === req.user.id && !req.body.is_admin) {
        const adminCount = await pool.query(
          "SELECT COUNT(*) FROM users WHERE is_admin = true AND (role = 'coach' OR role = 'admin')"
        );
        if (parseInt(adminCount.rows[0].count, 10) <= 1) {
          return res.status(400).json({ error: "Cannot remove the last admin" });
        }
      }
      await pool.query(
        "UPDATE users SET is_admin = $1 WHERE id = $2 AND (role = 'coach' OR role = 'admin')",
        [!!req.body.is_admin, coachId]
      );
      return res.json({ ok: true, is_admin: !!req.body.is_admin });
    } catch (err) {
      console.error("Update coach admin error:", err);
      return res.status(500).json({ error: "Could not update coach" });
    }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // WORKOUTS
  // ───────────────────────────────────────────────────────────────────────────

  app.get("/fp/athletes/:athleteId/workouts",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const r = await pool.query(
          `SELECT id, athlete_id, date::text AS date, title, type, duration, intensity,
                  notes, release_mode AS "releaseMode", exercises, created_at
           FROM fp_workouts
           WHERE athlete_id = $1
           ORDER BY date ASC`,
          [req.athleteId]
        );
        return res.json(r.rows);
      } catch (err) {
        console.error("List workouts error:", err);
        return res.status(500).json({ error: "Could not load workouts" });
      }
    }
  );

  // Upsert (create or update on the (athlete_id, date) unique key)
  app.post("/fp/athletes/:athleteId/workouts",
    requireAuth, requireCoach, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const w = req.body || {};
        if (!w.date || !w.title || !w.type) {
          return res.status(400).json({ error: "date, title and type are required" });
        }
        const r = await pool.query(
          `INSERT INTO fp_workouts (
             athlete_id, date, title, type, duration, intensity, notes,
             release_mode, exercises
           )
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
           ON CONFLICT (athlete_id, date) DO UPDATE SET
             title = EXCLUDED.title,
             type = EXCLUDED.type,
             duration = EXCLUDED.duration,
             intensity = EXCLUDED.intensity,
             notes = EXCLUDED.notes,
             release_mode = EXCLUDED.release_mode,
             exercises = EXCLUDED.exercises
           RETURNING id, date::text AS date, title, type, duration, intensity, notes,
                     release_mode AS "releaseMode", exercises`,
          [
            req.athleteId, w.date,
            String(w.title).slice(0, 200), String(w.type).slice(0, 40),
            w.duration ? parseInt(w.duration, 10) : null,
            w.intensity ? String(w.intensity).slice(0, 80) : null,
            w.notes ? String(w.notes).slice(0, 2000) : null,
            String(w.releaseMode || "reveal-on-day").slice(0, 40),
            JSON.stringify(w.exercises || []),
          ]
        );
        return res.status(200).json(r.rows[0]);
      } catch (err) {
        console.error("Upsert workout error:", err);
        return res.status(500).json({ error: "Could not save workout" });
      }
    }
  );

  app.delete("/fp/athletes/:athleteId/workouts/:date",
    requireAuth, requireCoach, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        await pool.query(
          "DELETE FROM fp_workouts WHERE athlete_id = $1 AND date = $2",
          [req.athleteId, req.params.date]
        );
        return res.status(204).end();
      } catch (err) {
        console.error("Delete workout error:", err);
        return res.status(500).json({ error: "Could not delete workout" });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // TRACKING (steps / weight / mood / water / sleep)
  // ───────────────────────────────────────────────────────────────────────────

  const VALID_KINDS = new Set(["weight", "mood", "steps", "water", "sleep"]);

  app.get("/fp/athletes/:athleteId/tracking/:kind",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      const kind = req.params.kind;
      if (!VALID_KINDS.has(kind)) {
        return res.status(400).json({ error: "Invalid tracking kind" });
      }
      try {
        const r = await pool.query(
          `SELECT date::text AS date, value, extra
           FROM fp_tracking
           WHERE athlete_id = $1 AND kind = $2
           ORDER BY date ASC`,
          [req.athleteId, kind]
        );
        // Adapt to the shape each tracking type expects on the frontend
        const out = r.rows.map(row => {
          const base = { date: row.date };
          const extra = row.extra || {};
          switch (kind) {
            case "weight": return { ...base, weight: Number(row.value) };
            case "mood":   return { ...base, score: Number(row.value), note: extra.note || "" };
            case "steps":  return { ...base, steps: Number(row.value) };
            case "water":  return { ...base, ml: Number(row.value) };
            case "sleep":  return { ...base, hours: Number(row.value), quality: extra.quality || 3 };
          }
        });
        return res.json(out);
      } catch (err) {
        console.error("List tracking error:", err);
        return res.status(500).json({ error: "Could not load tracking data" });
      }
    }
  );

  app.post("/fp/athletes/:athleteId/tracking/:kind",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      const kind = req.params.kind;
      if (!VALID_KINDS.has(kind)) {
        return res.status(400).json({ error: "Invalid tracking kind" });
      }
      try {
        const entry = req.body || {};
        if (!entry.date) return res.status(400).json({ error: "date is required" });

        // Map frontend shape -> (value, extra)
        let value, extra;
        switch (kind) {
          case "weight": value = entry.weight; break;
          case "mood":   value = entry.score; extra = { note: entry.note || "" }; break;
          case "steps":  value = entry.steps; break;
          case "water":  value = entry.ml; break;
          case "sleep":  value = entry.hours; extra = { quality: entry.quality || 3 }; break;
        }
        if (value == null || isNaN(Number(value))) {
          return res.status(400).json({ error: "Invalid value" });
        }
        await pool.query(
          `INSERT INTO fp_tracking (athlete_id, kind, date, value, extra)
           VALUES ($1, $2, $3, $4, $5::jsonb)
           ON CONFLICT (athlete_id, kind, date) DO UPDATE SET
             value = EXCLUDED.value,
             extra = EXCLUDED.extra`,
          [req.athleteId, kind, entry.date, Number(value),
           extra ? JSON.stringify(extra) : null]
        );
        return res.status(200).json({ ok: true });
      } catch (err) {
        console.error("Log tracking error:", err);
        return res.status(500).json({ error: "Could not save entry" });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // LIFTS
  // ───────────────────────────────────────────────────────────────────────────

  app.get("/fp/athletes/:athleteId/lifts",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const r = await pool.query(
          `SELECT exercise_name AS "exerciseName", date::text AS date, sets
           FROM fp_lifts
           WHERE athlete_id = $1
           ORDER BY date ASC`,
          [req.athleteId]
        );
        // Group by exercise name (frontend expects { "Back Squat": [...sessions] })
        const grouped = {};
        for (const row of r.rows) {
          if (!grouped[row.exerciseName]) grouped[row.exerciseName] = [];
          grouped[row.exerciseName].push({
            date: row.date,
            sets: row.sets || [],
          });
        }
        return res.json(grouped);
      } catch (err) {
        console.error("List lifts error:", err);
        return res.status(500).json({ error: "Could not load lifts" });
      }
    }
  );

  app.post("/fp/athletes/:athleteId/lifts",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const { exercise_name, date, sets } = req.body || {};
        if (!exercise_name || !date || !Array.isArray(sets)) {
          return res.status(400).json({ error: "exercise_name, date and sets are required" });
        }
        await pool.query(
          `INSERT INTO fp_lifts (athlete_id, exercise_name, date, sets)
           VALUES ($1, $2, $3, $4::jsonb)
           ON CONFLICT (athlete_id, exercise_name, date) DO UPDATE SET
             sets = EXCLUDED.sets`,
          [req.athleteId, String(exercise_name).slice(0, 200), date, JSON.stringify(sets)]
        );
        return res.status(200).json({ ok: true });
      } catch (err) {
        console.error("Log lift error:", err);
        return res.status(500).json({ error: "Could not save lift" });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // FOOD LOG
  // ───────────────────────────────────────────────────────────────────────────

  app.get("/fp/athletes/:athleteId/food-log",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const date = req.query.date;
        const params = [req.athleteId];
        let where = "athlete_id = $1";
        if (date) { params.push(date); where += " AND date = $2"; }
        const r = await pool.query(
          `SELECT id, date::text AS date, meal, name, calories, protein_g AS protein,
                  carbs_g AS carbs, fat_g AS fat, created_at
           FROM fp_food_log WHERE ${where}
           ORDER BY created_at ASC`,
          params
        );
        return res.json(r.rows);
      } catch (err) {
        console.error("List food log error:", err);
        return res.status(500).json({ error: "Could not load food log" });
      }
    }
  );

  app.post("/fp/athletes/:athleteId/food-log",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const e = req.body || {};
        if (!e.name) return res.status(400).json({ error: "name is required" });
        const today = new Date().toISOString().slice(0, 10);
        const r = await pool.query(
          `INSERT INTO fp_food_log
             (athlete_id, date, meal, name, calories, protein_g, carbs_g, fat_g)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, date::text AS date, meal, name,
                     calories, protein_g AS protein, carbs_g AS carbs, fat_g AS fat`,
          [
            req.athleteId,
            e.date || today,
            e.meal ? String(e.meal).slice(0, 40) : null,
            String(e.name).slice(0, 200),
            e.calories != null ? Math.round(Number(e.calories)) : null,
            e.protein != null ? Number(e.protein) : null,
            e.carbs != null ? Number(e.carbs) : null,
            e.fat != null ? Number(e.fat) : null,
          ]
        );
        return res.status(201).json(r.rows[0]);
      } catch (err) {
        console.error("Log food error:", err);
        return res.status(500).json({ error: "Could not save food entry" });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // CALENDAR EVENTS (non-workout)
  // ───────────────────────────────────────────────────────────────────────────

  app.get("/fp/athletes/:athleteId/events",
    requireAuth, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const r = await pool.query(
          `SELECT id, date::text AS date, title, notes, created_at
           FROM fp_events WHERE athlete_id = $1
           ORDER BY date ASC`,
          [req.athleteId]
        );
        return res.json(r.rows);
      } catch (err) {
        console.error("List events error:", err);
        return res.status(500).json({ error: "Could not load events" });
      }
    }
  );

  app.post("/fp/athletes/:athleteId/events",
    requireAuth, requireCoach, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        const e = req.body || {};
        if (!e.date || !e.title) {
          return res.status(400).json({ error: "date and title are required" });
        }
        const r = await pool.query(
          `INSERT INTO fp_events (athlete_id, date, title, notes)
           VALUES ($1, $2, $3, $4)
           RETURNING id, date::text AS date, title, notes`,
          [req.athleteId, e.date, String(e.title).slice(0, 200),
           e.notes ? String(e.notes).slice(0, 2000) : null]
        );
        return res.status(201).json(r.rows[0]);
      } catch (err) {
        console.error("Create event error:", err);
        return res.status(500).json({ error: "Could not create event" });
      }
    }
  );

  app.delete("/fp/athletes/:athleteId/events/:id",
    requireAuth, requireCoach, requireCoachOwnsAthlete,
    async (req, res) => {
      try {
        await pool.query(
          "DELETE FROM fp_events WHERE id = $1 AND athlete_id = $2",
          [parseInt(req.params.id, 10), req.athleteId]
        );
        return res.status(204).end();
      } catch (err) {
        console.error("Delete event error:", err);
        return res.status(500).json({ error: "Could not delete event" });
      }
    }
  );

  // ───────────────────────────────────────────────────────────────────────────
  // MESSAGES — uses your existing messages table, scoped via app_id
  // ───────────────────────────────────────────────────────────────────────────
  // Frontend sends "coach" as the otherUserId for athletes — we resolve that
  // to whichever coach owns this athlete.

  async function resolveOtherId(req) {
    const raw = req.params.otherId;
    if (raw !== "coach") return parseInt(raw, 10);
    // Athlete asking for "their coach" — find via fp_coach_athletes
    const r = await pool.query(
      "SELECT coach_id FROM fp_coach_athletes WHERE athlete_id = $1 LIMIT 1",
      [req.user.id]
    );
    return r.rows[0]?.coach_id || null;
  }

  app.get("/fp/messages/:otherId", requireAuth, async (req, res) => {
    try {
      const otherId = await resolveOtherId(req);
      if (!otherId) return res.json([]);
      const r = await pool.query(
        `SELECT id, from_id AS from_id, to_id, text, created_at
         FROM messages
         WHERE app_id = 'fitness-pacific'
           AND ((from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1))
         ORDER BY created_at ASC`,
        [req.user.id, otherId]
      );
      const out = r.rows.map(m => ({
        id: m.id,
        from: m.from_id === req.user.id ? "me" : (req.user.role === "athlete" ? "coach" : "athlete"),
        text: m.text,
        time: new Date(m.created_at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }),
      }));
      return res.json(out);
    } catch (err) {
      console.error("List messages error:", err);
      return res.status(500).json({ error: "Could not load messages" });
    }
  });

  app.post("/fp/messages/:otherId", requireAuth, async (req, res) => {
    try {
      const { text } = req.body || {};
      if (!text || !String(text).trim()) {
        return res.status(400).json({ error: "Message text required" });
      }
      const otherId = await resolveOtherId(req);
      if (!otherId) return res.status(404).json({ error: "No coach found for this athlete" });

      const r = await pool.query(
        `INSERT INTO messages (from_id, to_id, text, app_id, created_at)
         VALUES ($1, $2, $3, 'fitness-pacific', NOW())
         RETURNING id, created_at`,
        [req.user.id, otherId, String(text).slice(0, 4000)]
      );
      return res.status(201).json({ id: r.rows[0].id, ok: true });
    } catch (err) {
      console.error("Send message error:", err);
      return res.status(500).json({ error: "Could not send message" });
    }
  });
};
