const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');

const app = express(); // ✅ Now app exists

app.use(cors());       // ✅ Now this works as expected
app.use(express.json());
app.use((req, res, next) => {
  if (Buffer.isBuffer(req.body)) {
    try {
      req.body = JSON.parse(req.body.toString('utf8'));
    } catch (e) {
      console.error('🧨 JSON parse failed:', e.message);
      req.body = {};
    }
  }
  next();
});

app.get('/', (req, res) => res.send('🔐 SecureVault API is live!'));

const usersRouter = require('./routes/users');
app.use('/api/users', usersRouter);

module.exports.server = serverless(app);
