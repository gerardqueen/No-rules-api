// add-coaches.js — Run once to add Luke and Esme as coach accounts
// Usage: node add-coaches.js

require("dotenv").config();
const { pool } = require("./db");
const bcrypt = require("bcryptjs");

async function addCoaches() {
  console.log("Adding coach accounts...");

  try {
    // Luke
    const lukeExists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      ["luke@norules.com"]
    );
    if (!lukeExists.rows[0]) {
      const hash = await bcrypt.hash("luke1", 12);
      await pool.query(
        `INSERT INTO users (email, password_hash, name, role)
         VALUES ($1, $2, 'Luke Bastick', 'coach')`,
        ["luke@norules.com", hash]
      );
      console.log("✅ Coach created: luke@norules.com / luke1");
    } else {
      console.log("ℹ️  Luke already exists");
    }

    // Esme
    const esmeExists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      ["esme@norules.com"]
    );
    if (!esmeExists.rows[0]) {
      const hash = await bcrypt.hash("esme1", 12);
      await pool.query(
        `INSERT INTO users (email, password_hash, name, role)
         VALUES ($1, $2, 'Esme', 'coach')`,
        ["esme@norules.com", hash]
      );
      console.log("✅ Coach created: esme@norules.com / esme1");
    } else {
      console.log("ℹ️  Esme already exists");
    }

    console.log("\n🎉 Done! All coach accounts ready.");
    console.log("  luke@norules.com / luke1");
    console.log("  esme@norules.com / esme1");

  } catch (err) {
    console.error("❌ Error:", err.message);
  } finally {
    await pool.end();
  }
}

addCoaches();
