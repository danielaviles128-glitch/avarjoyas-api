const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('✅ Conexión exitosa a Neon:', res.rows[0]);
    await pool.end();
  } catch (err) {
    console.error('❌ Error de conexión:', err);
  }
})();