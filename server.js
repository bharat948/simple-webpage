const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const users = [];
let nextUserId = 1;

const sanitizeUser = (user) => {
  const { password, ...safeUser } = user;
  return safeUser;
};

app.get('/', (req, res) => {
  res.send('Auth and user service is running!');
});

app.post('/auth/signup', (req, res) => {
  const { username, password, name } = req.body || {};

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required.' });
  }

  const existingUser = users.find((user) => user.username === username);

  if (existingUser) {
    return res.status(409).json({ error: 'User already exists.' });
  }

  const newUser = {
    id: nextUserId++,
    username,
    password,
    name: name || null,
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);

  return res.status(201).json({ user: sanitizeUser(newUser) });
});

app.post('/auth/signin', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required.' });
  }

  const user = users.find(
    (candidate) =>
      candidate.username === username && candidate.password === password,
  );

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  return res.json({ user: sanitizeUser(user) });
});

app.get('/users', (req, res) => {
  const sanitizedUsers = users.map(sanitizeUser);
  return res.json({ users: sanitizedUsers });
});

app.get('/users/:id', (req, res) => {
  const id = Number.parseInt(req.params.id, 10);

  if (Number.isNaN(id)) {
    return res.status(400).json({ error: 'User id must be a number.' });
  }

  const user = users.find((candidate) => candidate.id === id);

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  return res.json({ user: sanitizeUser(user) });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
