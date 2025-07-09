const express = require('express');
const router = express.Router();
const db = require('../db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const encrypt = require('../utils/encrypt');
const decrypt = require('../utils/decrypt');
const authenticateToken = require('../middleware/auth');

// 🆕 Register a new user
router.post('/register', async (req, res) => {
  const { email, password, capabilities = ['read', 'store'] } = req.body;
console.log('📦 Register route hit');
console.log('🔍 req.body:', req.body);

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      'INSERT INTO users (email, password, capabilities) VALUES ($1, $2, $3) RETURNING id, email, capabilities',
      [email, hashedPassword, capabilities]
    );

    const user = result.rows[0];
    res.status(201).json({ message: 'User registered', user });
  } catch (err) {
    console.error('❌ Registration failed:', err.message);
    res.status(500).json({ error: 'Could not register user' });
  }
});


// 🔐 Login and issue a capability-based token

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        capabilities: user.capabilities
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Login successful!',
      token,
      capabilities: user.capabilities
    });
  } catch (err) {
    console.error('❌ Login error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 📦 Store a secret — requires 'store' capability
router.post('/store', authenticateToken, async (req, res) => {
  if (!Array.isArray(req.user.capabilities) || !req.user.capabilities.includes('store')) {
    return res.status(403).json({ error: 'Insufficient capability to store secrets' });
  }

  try {
    const { sensitive } = req.body;
    if (!sensitive) return res.status(400).json({ error: 'Missing sensitive field' });

    const encrypted = encrypt(sensitive);

    await db.query(
      'INSERT INTO secrets (user_id, data) VALUES ($1, $2)',
      [req.user.id, encrypted]
    );

    res.json({ message: 'Encrypted data stored securely!' });
  } catch (err) {
    console.error('❌ Store route failed:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 🧾 Read user's secrets — requires 'read' capability
router.get('/read', authenticateToken, async (req, res) => {
  if (!Array.isArray(req.user.capabilities) || !req.user.capabilities.includes('read')) {
    return res.status(403).json({ error: 'Insufficient capability to read secrets' });
  }

  try {
    const result = await db.query(
      'SELECT * FROM secrets WHERE user_id = $1',
      [req.user.id]
    );

    const decrypted = result.rows.map(row => ({
      id: row.id,
      data: decrypt(row.data),
      created_at: row.created_at
    }));

    res.json({
      message: 'Secrets decrypted successfully!',
      data: decrypted
    });
  } catch (err) {
    console.error('❌ Read route failed:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 🔍 Health check
router.get('/ping', (req, res) => {
  res.send('👋 Router is alive');
});

module.exports = router;
