const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const pool = require('./database');

const app = express();
app.use(bodyParser.json());
const allowedOrigins = ['http://127.0.0.1:3000'];

app.use(cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
}));

//Регистрация пользователя
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
  
    //Шифрование пароля
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
      const newUser = await pool.query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
        [username, hashedPassword]
      );
      res.status(201).send('User registered');
    } catch (err) {
      console.error(err.message);
      res.status(400).send('Error registering user');
    }
});

// Авторизация пользователя
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
  
    try {
      const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  
      if (user.rows.length === 0) {
        return res.status(401).send('User not found');
      }
  
      const validPassword = await bcrypt.compare(password, user.rows[0].password);
  
      if (!validPassword) {
        return res.status(401).send('Invalid credentials');
      }
  
      const token = jwt.sign({ id: user.rows[0].id }, 'secret_key', { expiresIn: '1h' });
      res.json({ token });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  });

// Запуск сервера
app.listen(5000, () => {
    console.log('Server is running on http://127.0.0.1:5000');
  });
  