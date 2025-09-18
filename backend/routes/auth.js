// routes/auth.js
import express from 'express';
import bcrypt from 'bcryptjs';
import { queries } from '../db.js';

const router = express.Router();

// Basic input validation
function isValidUsername(s) {
  return typeof s === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(s);
}
function isValidEmail(s) {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}
function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 8;
}

// POST /api/auth/register
router.post('/register', (req, res) => {
  const { username, email, password } = req.body || {};

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Username must be 3–32 chars, letters/numbers/underscore.' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email.' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const existsUser = queries.getUserByUsername.get(username);
  const existsEmail = queries.getUserByEmail.get(email);
  if (existsUser || existsEmail) {
    return res.status(409).json({ error: 'Username or email already in use.' });
  }

  const password_hash = bcrypt.hashSync(password, 12);
  try {
    const info = queries.createUser.run({ username, email, password_hash });
    req.session.userId = info.lastInsertRowid;
    req.session.username = username;
    return res.status(201).json({ message: 'Registered', user: { id: info.lastInsertRowid, username, email } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to register.' });
  }
});

// POST /api/auth/login
router.post('/login', (req, res) => {
  const { usernameOrEmail, password } = req.body || {};
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: 'usernameOrEmail and password required.' });
  }

  let user = queries.getUserByUsername.get(usernameOrEmail);
  if (!user) user = queries.getUserByEmail.get(usernameOrEmail);
  if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });

  req.session.userId = user.id;
  req.session.username = user.username;
  return res.json({ message: 'Logged in', user: { id: user.id, username: user.username, email: user.email } });
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    return res.json({ message: 'Logged out' });
  });
});

// GET /api/auth/me
router.get('/me', (req, res) => {
  if (!req.session?.userId) return res.status(200).json({ user: null });
  return res.json({ user: { id: req.session.userId, username: req.session.username } });
});

export default router;
