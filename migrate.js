// migrate.js — Creates your database tables
// Run this ONCE with:  node migrate.js
// It is safe to run again — it won't delete existing data.

require("dotenv").config();
const { pool } = require("./db");

async function migrate() {
  console.log("🔄 Running database migration...");

  try {
    // ── Users table ───────────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name          TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'athlete' CHECK (role IN ('athlete', 'coach')),
        sport         TEXT,
        mfp_username  TEXT,
        coach_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        avatar_url    TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log("  ✅ users table ready");

    // ── Macro plans table ─────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS macro_plans (
        id          SERIAL PRIMARY KEY,
        athlete_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        day_of_week TEXT NOT NULL CHECK (day_of_week IN ('MON','TUE','WED','THU','FRI','SAT','SUN')),
        calories    INTEGER NOT NULL DEFAULT 2000,
        protein_g   INTEGER NOT NULL DEFAULT 150,
        carbs_g     INTEGER NOT NULL DEFAULT 200,
        fat_g       INTEGER NOT NULL DEFAULT 70,
        meals       JSONB,
        updated_by  INTEGER REFERENCES users(id),
        updated_at  TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (athlete_id, day_of_week)
      );
    `);
    console.log("  ✅ macro_plans table ready");

    // ── MFP diary entries ─────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mfp_entries (
        id            SERIAL PRIMARY KEY,
        athlete_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        date          DATE NOT NULL,
        calories      INTEGER DEFAULT 0,
        protein_g     INTEGER DEFAULT 0,
        carbs_g       INTEGER DEFAULT 0,
        fat_g         INTEGER DEFAULT 0,
        fibre_g       INTEGER DEFAULT 0,
        exercise_cals INTEGER DEFAULT 0,
        meals_json    JSONB,
        source        TEXT DEFAULT 'mfp_live' CHECK (source IN ('mfp_live','manual','estimate')),
        synced_at     TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (athlete_id, date)
      );
    `);
    console.log("  ✅ mfp_entries table ready");

    // ── Messages ──────────────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id           SERIAL PRIMARY KEY,
        thread_id    INTEGER NOT NULL,
        sender_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        body         TEXT NOT NULL,
        read         BOOLEAN DEFAULT FALSE,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log("  ✅ messages table ready");

    // ── Check-ins ─────────────────────────────────────────────────────────────
    await pool.query(`
      CREATE TABLE IF NOT EXISTS checkins (
        id          SERIAL PRIMARY KEY,
        athlete_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        date        DATE NOT NULL,
        weight_kg   DECIMAL(5,2),
        mood        INTEGER CHECK (mood BETWEEN 1 AND 5),
        energy      INTEGER CHECK (energy BETWEEN 1 AND 5),
        sleep_hrs   DECIMAL(3,1),
        notes       TEXT,
        photo_url   TEXT,
        coach_reply TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log("  ✅ checkins table ready");

    // ── Seed demo data ────────────────────────────────────────────────────────
    // Creates your coach account + 2 demo athletes so you can test immediately.
    // Passwords are hashed — change them after first login!

    const bcrypt = require("bcryptjs");

    // Create coach account (you)
    const coachExists = await pool.query("SELECT id FROM users WHERE email = $1", ["gerard@norules.com"]);
    if (!coachExists.rows[0]) {
      const coachHash = await bcrypt.hash("gerard1", 12);
      await pool.query(
        `INSERT INTO users (email, password_hash, name, role)
         VALUES ($1, $2, 'Gerard Queen', 'coach')`,
        ["gerard@norules.com", coachHash]
      );
      console.log("  ✅ Coach account created: gerard@norules.com / gerard1");
    } else {
      console.log("  ℹ️  Coach account already exists");
    }

    // Get coach ID
    const coach = await pool.query("SELECT id FROM users WHERE email = $1", ["gerard@norules.com"]);
    const coachId = coach.rows[0].id;

    // Create demo athlete — Alex
    const alexExists = await pool.query("SELECT id FROM users WHERE email = $1", ["alex@norules.com"]);
    if (!alexExists.rows[0]) {
      const alexHash = await bcrypt.hash("athlete1", 12);
      await pool.query(
        `INSERT INTO users (email, password_hash, name, role, sport, mfp_username, coach_id)
         VALUES ($1, $2, 'Alex Morgan', 'athlete', 'Triathlon', 'alexmorgan_mfp', $3)`,
        ["alex@norules.com", alexHash, coachId]
      );
      console.log("  ✅ Athlete created: alex@norules.com / athlete1");
    }

    // Create demo athlete — Jamie
    const jamieExists = await pool.query("SELECT id FROM users WHERE email = $1", ["jamie@norules.com"]);
    if (!jamieExists.rows[0]) {
      const jamieHash = await bcrypt.hash("athlete2", 12);
      await pool.query(
        `INSERT INTO users (email, password_hash, name, role, sport, coach_id)
         VALUES ($1, $2, 'Jamie Clarke', 'athlete', 'Powerlifting', $3)`,
        ["jamie@norules.com", jamieHash, coachId]
      );
      console.log("  ✅ Athlete created: jamie@norules.com / athlete2");
    }

    console.log("\n🎉 Migration complete! Your database is ready.");
    console.log("\nDemo accounts:");
    console.log("  Coach:   gerard@norules.com  /  gerard1");
    console.log("  Athlete: alex@norules.com    /  athlete1");
    console.log("  Athlete: jamie@norules.com   /  athlete2");

  } catch (err) {
    console.error("❌ Migration failed:", err.message);
  } finally {
    await pool.end();
  }
}

migrate();
