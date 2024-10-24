const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
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

