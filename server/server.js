const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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



// Регистрация пользователя
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Проверка на существующего пользователя
    const userExists = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).send('User already exists');
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Сохранение нового пользователя в базе данных
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

//Удаление аккаунта пользователя
app.delete('/api/deleteacc', async(req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).send('Token is missing');
  }
  try {
    const decoded = jwt.verify(token, 'secret_key');
    
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [decoded]);
    if (user.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    await pool.query('DELETE FROM tasks WHERE user_id = $1', [decoded.id])
    await pool.query('DELETE FROM users WHERE id = $1', [decoded.id]);
    
    res.status(204).send('User and associated tasks deleted');
  }
  catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

//Изменение пароля
app.put('/api/editpasswd', async (req, res) => {
  const { oldPasswd, newPasswd } = req.body;
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(403).send('Token is missing');
  }

  try {   
    const decoded = jwt.verify(token, 'secret_key');

    const user = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (user.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    const validPassword = await bcrypt.compare(oldPasswd, user.rows[0].password);
    if (!validPassword) {
      return res.status(401).send('Invalid credentials');
    }
    
    const hashedNewPassword = await bcrypt.hash(newPasswd, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, decoded.id]);

    res.status(204).send('Password updated');
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Получение списка задач
app.get('/api/tasks', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).send('Token is missing');
  }

  try {
    const decoded = jwt.verify(token, 'secret_key');
    const tasks = await pool.query(
      'SELECT id, name, completed, to_char(end_date, \'DD-MM-YYYY\') AS end_date FROM tasks WHERE user_id = $1',
      [decoded.id]
    );
    res.json(tasks.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Добавление новой задачи
app.post('/api/tasks', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).send('Token is missing');
  }

  try {
    const decoded = jwt.verify(token, 'secret_key');
    const { name, endDate} = req.body;

    const newTask = await pool.query(
      'INSERT INTO tasks (name, completed, user_id, end_date) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, false, decoded.id, endDate]
    );
    console.log(endDate);
    res.json(newTask.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Удаление задачи
app.delete('/api/tasks/:id', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).send('Token is missing');
  }

  try {
    const decoded = jwt.verify(token, 'secret_key');
    const taskId = req.params.id;

    // Удаляем задачу только если она принадлежит текущему пользователю
    await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [taskId, decoded.id]);

    res.status(204).send(); // Успешно, но ничего не возвращаем
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Изменение статуса задачи
app.put('/api/tasks/:id', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).send('Token is missing');
  }

  try {
    const decoded = jwt.verify(token, 'secret_key');
    const taskId = req.params.id;
    const { completed } = req.body;

    // Обновляем задачу только если она принадлежит текущему пользователю
    const updatedTask = await pool.query(
      'UPDATE tasks SET completed = $1 WHERE id = $2 AND user_id = $3 RETURNING *',
      [completed, taskId, decoded.id]
    );

    res.json(updatedTask.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});


// Запуск сервера
app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000');
});

module.exports = app;