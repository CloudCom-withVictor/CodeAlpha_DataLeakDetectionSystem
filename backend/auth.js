const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // gets the part after 'Bearer'

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('❌ JWT verification failed:', err.message); // debug output
      return res.status(403).json({ error: 'Token verification failed' });
    }
    req.user = user;
    next();
  });
}

module.exports = authenticateToken;
