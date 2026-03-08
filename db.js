
// db.js — Database connection
const { Pool } = require("pg");
const url = require("url");

const connectionString = process.env.DATABASE_URL;
const parsed = url.parse(connectionString);
const [user, password] = (parsed.auth || "").split(":");

const pool = new Pool({
  host:     parsed.hostname,
  port:     parseInt(parsed.port),
  database: (parsed.pathname || "").replace("/", ""),
  user:     user,
  password: password,
  ssl:      { rejectUnauthorized: false },
});

pool.connect((err, client, release) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
  } else {
    console.log("✅ Database connected successfully");
    release();
  }
});

module.exports = { pool };
