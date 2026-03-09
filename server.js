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

// IMPORTANT: CORS origin is only domain (no path). GitHub Pages uses the same origin.
// Add any additional production domains here if you later use a custom domain.
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

// ── Auth middleware — protects routes that need a login ───────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Not logged in" });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email, role, name }
    next();
  } catch {
    return res
      .status(401)
      .json({ error: "Session expired — please log in again" });
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
      return res
        .status(400)
        .json({ error: "Email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email.toLowerCase().trim(),
    ]);

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Never return password_hash
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
    return res.status(500).json({ error: "Something went wrong — please try again" });
  }
});

// GET /auth/me
app.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, name, role, sport, mfp_username, coach_id, avatar_url
       FROM users
       WHERE id = $1`,
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

// POST /auth/logout (JWT is stateless; client deletes token)
app.post("/auth/logout", requireAuth, (req, res) => {
  return res.json({ message: "Logged out successfully" });
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

    return res.json(result.rows);
  } catch (err) {
    console.error("Get athletes error:", err);
    return res.status(500).json({ error: "Could not fetch athletes" });
  }
});

// GET /athletes/:id
app.get("/athletes/:id", requireAuth, requireCoach, async (req, res) => {
  try {
    const athleteId = Number(req.params.id);

    const result = await pool.query(
      `SELECT id, email, name, sport, mfp_username, avatar_url, created_at
       FROM users
       WHERE id = $1 AND coach_id = $2 AND role = 'athlete'`,
      [athleteId, req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Athlete not found" });
    }

