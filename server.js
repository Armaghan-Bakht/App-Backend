const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const User = require('./models/User');
const authMiddleware = require('./middleware/auth');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// Login route


app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  const adminEmail = process.env.ADMIN_EMAIL;
  const hashedPassword = process.env.ADMIN_PASSWORD;

  // Check email
  if (email !== adminEmail) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Make sure both password and hash are defined
  if (!password || !hashedPassword) {
    return res.status(500).json({ message: 'Server error: Missing password or hash' });
  }

  // Compare
  const isMatch = await bcrypt.compare(password, hashedPassword);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});



// Protected route
app.get('/api/protected', authMiddleware, (req, res) => {
  res.json({ message: 'Welcome to the private landing page, Armaghan!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
