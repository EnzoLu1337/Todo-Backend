const { Pool } = require('pg');

const connectionString = process.env.NODE_ENV === 'test' 
    ? process.env.TEST_DATABASE_URL // URL для тестовой базы
    : process.env.DATABASE_URL;     // URL для основной базы

const pool = new Pool({
  connectionString,
});

console.log("Connecting to database with:", connectionString);


module.exports = pool;
