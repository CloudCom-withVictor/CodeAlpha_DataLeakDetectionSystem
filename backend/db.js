const { Pool } = require('pg');
require('dotenv').config();

const db = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false // for self-signed RDS certs (safe for dev)
  }
});

db.connect()
  .then(() => console.log('✅ Connected to PostgreSQL!'))
  .catch((err) => console.error('❌ PostgreSQL connection failed:', err.message));

module.exports = db;
// This module sets up a connection pool to a PostgreSQL database using the 'pg' library.
// It reads configuration from environment variables defined in a .env file.