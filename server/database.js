const { Pool } = require('pg');

// Настройки подключения к базе данных
const pool = new Pool({
  user: '**',
  host: '**',
  database: '**',
  password: '**',
  port: 5432,
});

module.exports = pool;
