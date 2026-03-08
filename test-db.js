require("dotenv").config();
const { Pool } = require("pg");

console.log("Testing connection to:", process.env.DATABASE_URL?.replace(/:([^:@]+)@/, ":****@"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
});

pool.connect()
  .then(client => {
    console.log("✅ Connected!");
    client.release();
    pool.end();
  })
  .catch(err => {
    console.log("❌ Full error details:");
    console.log("   Message:", err.message);
    console.log("   Code:", err.code);
    console.log("   Detail:", err.detail);
    pool.end();
  });
