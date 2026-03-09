// ─────────────────────────────────────────────────────────────────────────────
// MACRO PLAN ROUTES
// ─────────────────────────────────────────────────────────────────────────────

const VALID_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

// Helper: confirm this coach owns this athlete
async function assertCoachOwnsAthlete(coachId, athleteId) {
  const r = await pool.query(
    `SELECT id FROM users
     WHERE id = $1 AND coach_id = $2 AND role = 'athlete'`,
    [athleteId, coachId]
  );
  return !!r.rows[0];
}

// GET /athletes/:id/macro-plans
// Coach only — returns 7 rows (MON..SUN). Ensures rows exist using defaults.
app.get("/athletes/:id/macro-plans", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.id);
    if (!Number.isInteger(athleteId) || athleteId <= 0) {
      return res.status(400).json({ error: "Invalid athlete id" });
    }

    const ok = await assertCoachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    // Ensure each day row exists so UI always gets a full week
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
// Coach only — upserts a single day
// Body: { calories, protein_g, carbs_g, fat_g }
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

    const ok = await assertCoachOwnsAthlete(req.user.id, athleteId);
    if (!ok) return res.status(404).json({ error: "Athlete not found" });

    const calories = Number(req.body.calories);
    const protein_g = Number(req.body.protein_g);
    const carbs_g = Number(req.body.carbs_g);
    const fat_g = Number(req.body.fat_g);

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
