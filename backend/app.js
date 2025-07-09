require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();


app.get('/', (req, res) => {
  res.send('✅ SecureVault API is up and running!');
});
// Database connection

// Middleware to parse JSON
app.use(cors({
  origin: ['http://127.0.0.1:5500', 'https://data-leak.vercel.app'],
  methods: ['GET', 'POST'],
  credentials: true
}));

// Middleware to handle JSON requests
app.use(express.json());

// Routes
const usersRouter = require('./routes/users');
app.use('/api/users', usersRouter);

// Start server
const PORT = process.env.PORT || 8081;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
