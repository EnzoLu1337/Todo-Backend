const request = require('supertest');
const app = require('../server/server');
const pool = require('../server/db')

describe('API Tests', () => {
  // Тест регистрации пользователя
  it('POST /api/register - должно регистрировать пользователя', async () => {
    const response = await request(app).post('/api/register').send({
      username: 'testuser',
      password: 'testpassword',
    });

    expect(response.status).toBe(201);
    expect(response.text).toBe('User registered');
  });

  // Тест авторизации пользователя
  it('POST /api/login - должно авторизовать пользователя', async () => {
    const response = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'testpassword',
    });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('token');
  });

  // Тест на получение задач (GET /api/tasks)
  it('GET /api/tasks - должно вернуть список задач', async () => {
    const loginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'testpassword',
    });

    const token = loginResponse.body.token;
    const response = await request(app)
      .get('/api/tasks')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body).toBeInstanceOf(Array);
  });

  // Тест на добавление задачи
  it('POST /api/tasks - должно добавлять новую задачу', async () => {
    const loginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'testpassword',
    });

    const token = loginResponse.body.token;
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Test Task', endDate: '2024-12-31' });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('id');
    expect(response.body.name).toBe('Test Task');
  });

  // Тест на удаление задачи
  it('DELETE /api/tasks/:id - должно удалять задачу', async () => {
    const loginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'testpassword',
    });

    const token = loginResponse.body.token;
    const newTaskResponse = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Task to Delete', endDate: '2024-12-31' });

    const taskId = newTaskResponse.body.id;
    const deleteResponse = await request(app)
      .delete(`/api/tasks/${taskId}`)
      .set('Authorization', `Bearer ${token}`);

    expect(deleteResponse.status).toBe(204);
  });

  // Тест на изменение пароля
  it('PUT /api/editpasswd - должно изменять пароль пользователя', async () => {
    const loginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'testpassword',
    });

    const token = loginResponse.body.token;
    const response = await request(app)
      .put('/api/editpasswd')
      .set('Authorization', `Bearer ${token}`)
      .send({ oldPasswd: 'testpassword', newPasswd: 'newtestpassword' });

    expect(response.status).toBe(204);

    // Проверка нового пароля
    const reloginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'newtestpassword',
    });
    expect(reloginResponse.status).toBe(200);
    expect(reloginResponse.body).toHaveProperty('token');
  });

  // Тест на удаление аккаунта
  it('DELETE /api/deleteacc - должно удалять аккаунт пользователя', async () => {
    const loginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'newtestpassword',
    });

    const token = loginResponse.body.token;
    const response = await request(app)
      .delete('/api/deleteacc')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(204);

    // Проверка отсутствия пользователя
    const reloginResponse = await request(app).post('/api/login').send({
      username: 'testuser',
      password: 'newtestpassword',
    });
    expect(reloginResponse.status).toBe(401);
    expect(reloginResponse.text).toBe('User not found');
  });

});
