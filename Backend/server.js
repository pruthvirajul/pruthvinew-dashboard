require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const port = process.env.PORT || 3048;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'postgres',
  database: process.env.DB_DATABASE || 'login',
  password: process.env.DB_PASSWORD || 'admin123',
  port: parseInt(process.env.DB_PORT) || 5432,
});

// ✅ Updated CORS config
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://16.170.237.51:8154'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS: ' + origin));
    }
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  exposedHeaders: ['set-cookie']
}));

app.use((req, res, next) => {
  console.log('Incoming request:', req.method, req.url);
  console.log('Headers:', req.headers);
  console.log('Cookies:', req.cookies);
  next();
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../')));

const storage = multer.memoryStorage();
const upload = multer({ storage });

const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(30) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        profile_picture TEXT
      )
    `);
    console.log('Database initialized');
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
};

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token ||
                req.headers['authorization']?.split(' ')[1] ||
                req.query.token;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      res.clearCookie('token');
      return res.status(403).json({ error: 'Forbidden - Invalid token' });
    }
    req.user = user;
    next();
  });
};

const validateEmail = (email) => {
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return re.test(email);
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../Login/index.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../Sign_up/index.html'));
});

app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, '../Forgot/index.html'));
});

app.get('/dashboard', authenticateToken, (req, res) => {
  const filePath = path.join(__dirname, '../Dashboard/dashboard.html');
  console.log('Attempting to serve:', filePath);
  res.sendFile(filePath);
});

app.post('/api/signup', upload.single('profilePicture'), async (req, res) => {
  try {
    console.log('Received signup request with body:', req.body);
    console.log('Received file:', req.file);

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      console.log('Missing required fields');
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    if (!validateEmail(email)) {
      console.log('Invalid email format:', email);
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (emailCheck.rows.length > 0) {
      console.log('Email already exists:', email);
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed successfully');

    const profilePicture = req.file ? req.file.buffer.toString('base64') : null;

    const result = await pool.query(
      'INSERT INTO users (name, email, password, profile_picture) VALUES ($1, $2, $3, $4) RETURNING id, name, email, profile_picture',
      [name, email, hashedPassword, profilePicture]
    );

    const newUser = result.rows[0];

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // ✅ Updated cookie settings for local dev; adjust for prod
    res.cookie('token', token, {
      httpOnly: true,
      secure: false,           // change to true in production with HTTPS
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000
    });

    console.log('Signup completed successfully for:', email);
    res.status(201).json({
      message: 'Signup successful',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        profilePicture: newUser.profile_picture ? `data:image/jpeg;base64,${newUser.profile_picture}` : null
      }
    });
  } catch (error) {
    console.error('SIGNUP ERROR DETAILS:', {
      message: error.message,
      stack: error.stack,
      body: req.body,
      file: req.file
    });
    res.status(500).json({
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// The rest of your routes stay unchanged (login, forgot-password, etc.)
// [I kept them unchanged to keep this short; copy from your original code.]

initDatabase().then(() => {
  app.listen(port, () => {
    console.log(`Server running on http://16.170.237.51:${port}`);
    console.log('Available routes:');
    console.log('GET  /                 -> Login page');
    console.log('GET  /signup           -> Signup page');
    console.log('GET  /forgot-password  -> Forgot password page');
    console.log('GET  /dashboard        -> Dashboard (protected)');
    console.log('POST /api/signup       -> User registration');
    console.log('POST /api/login        -> User login');
    console.log('POST /api/forgot-password -> Password reset');
    console.log('GET  /api/user         -> Get user data');
    console.log('POST /api/logout       -> User logout');
    console.log('GET  /api/protected    -> Test protected route');
  });
});
