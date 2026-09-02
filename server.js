require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.set('trust proxy', 1);

app.use(express.json({ limit: '2mb' }));

// ============================================================
// CORS
// ============================================================

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests without Origin header
      if (!origin) {
        return callback(null, true);
      }

      // If no origins are configured, allow all
      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error('CORS not allowed'));
    },
    credentials: true
  })
);

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
});

pool.on('error', err => {
  console.error('Postgres pool error:', err);
});

// ============================================================
// RATE LIMITERS
// ============================================================

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please try again later.'
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts.'
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'psbaitool-backend'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'psbaitool-backend'
  });
});

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title TEXT,
        messages JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        item JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS files (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('Database initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// ============================================================
// AUTH HELPERS
// ============================================================

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({
      error: 'Invalid or expired token'
    });
  }
}

// ============================================================
// REGISTER
// ============================================================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password must be at least 6 characters'
      });
    }

    const normalizedEmail = String(email)
      .trim()
      .toLowerCase();

    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: 'User already exists'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email, created_at
      `,
      [normalizedEmail, passwordHash]
    );

    const user = result.rows[0];

    const token = signToken(user);

    res.json({
      token,
      user
    });
  } catch (err) {
    console.error('Register error:', err);

    res.status(500).json({
      error: 'Registration failed'
    });
  }
});

// ============================================================
// LOGIN
// ============================================================

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required'
      });
    }

    const normalizedEmail = String(email)
      .trim()
      .toLowerCase();

    const result = await pool.query(
      `
      SELECT id, email, password_hash, created_at
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const token = signToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Login failed'
    });
  }
});

// ============================================================
// CURRENT USER
// ============================================================

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, email, created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Auth me error:', err);

    res.status(500).json({
      error: 'Unable to load user'
    });
  }
});

// ============================================================
// AI CHAT PROXY - GEMINI
// ============================================================

app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const { messages, system } = req.body || {};

    console.log('Received /api/chat request');

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: 'messages array is required'
      });
    }

    if (!process.env.GEMINI_API_KEY) {
      console.error('GEMINI_API_KEY is missing');

      return res.status(500).json({
        error: 'Gemini API key is not configured'
      });
    }

    // --------------------------------------------------------
    // Convert frontend messages to Gemini format
    // --------------------------------------------------------

    const contents = messages
      .filter(message => message && message.content != null)
      .map(message => ({
        role:
          message.role === 'assistant'
            ? 'model'
            : 'user',
        parts: [
          {
            text: String(message.content)
          }
        ]
      }));

    if (contents.length === 0) {
      return res.status(400).json({
        error: 'No valid messages provided'
      });
    }

    // --------------------------------------------------------
    // Gemini request body
    // --------------------------------------------------------

    const body = {
      contents,
      generationConfig: {
        maxOutputTokens: 1000,
        temperature: 0.7
      }
    };

    // --------------------------------------------------------
    // System instruction
    // --------------------------------------------------------

    if (system) {
      body.systemInstruction = {
        parts: [
          {
            text: String(system)
          }
        ]
      };
    }

    console.log('Calling Gemini API...');

    // --------------------------------------------------------
    // Gemini API
    // --------------------------------------------------------

    const response = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': process.env.GEMINI_API_KEY
        },
        body: JSON.stringify(body)
      }
    );

    const data = await response.json();

    // --------------------------------------------------------
    // Gemini error
    // --------------------------------------------------------

    if (!response.ok) {
      console.error(
        'Gemini API error:',
        response.status,
        JSON.stringify(data)
      );

      return res.status(502).json({
        error: 'Gemini API error',
        details:
          data?.error?.message ||
          'Unknown Gemini API error'
      });
    }

    // --------------------------------------------------------
    // Extract Gemini text
    // --------------------------------------------------------

    const text =
      data?.candidates?.[0]?.content?.parts
        ?.map(part => part.text || '')
        .join('') || '';

    if (!text) {
      console.error(
        'Gemini returned empty response:',
        JSON.stringify(data)
      );

      return res.status(502).json({
        error: 'Gemini returned an empty response'
      });
    }

    console.log('Gemini response received successfully');

    // --------------------------------------------------------
    // IMPORTANT:
    // Existing PSBAITool frontend expects data.content
    // --------------------------------------------------------

    return res.json({
      content: [
        {
          type: 'text',
          text
        }
      ]
    });

  } catch (err) {
    console.error(
      'Chat proxy error:',
      err
    );

    return res.status(500).json({
      error: 'Something went wrong talking to Gemini'
    });
  }
});

// ============================================================
// CONVERSATIONS / HISTORY
// ============================================================

app.get(
  '/api/conversations',
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT id, title, messages, created_at, updated_at
        FROM conversations
        WHERE user_id = $1
        ORDER BY updated_at DESC
        `,
        [req.user.id]
      );

      res.json({
        conversations: result.rows
      });
    } catch (err) {
      console.error('Get conversations error:', err);

      res.status(500).json({
        error: 'Unable to load conversations'
      });
    }
  }
);

app.post(
  '/api/conversations',
  requireAuth,
  async (req, res) => {
    try {
      const {
        title,
        messages
      } = req.body || {};

      const result = await pool.query(
        `
        INSERT INTO conversations
          (user_id, title, messages)
        VALUES
          ($1, $2, $3)
        RETURNING *
        `,
        [
          req.user.id,
          title || 'New conversation',
          JSON.stringify(messages || [])
        ]
      );

      res.json({
        conversation: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Create conversation error:',
        err
      );

      res.status(500).json({
        error: 'Unable to save conversation'
      });
    }
  }
);

app.put(
  '/api/conversations/:id',
  requireAuth,
  async (req, res) => {
    try {
      const {
        title,
        messages
      } = req.body || {};

      const result = await pool.query(
        `
        UPDATE conversations
        SET
          title = COALESCE($1, title),
          messages = COALESCE($2, messages),
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
          AND user_id = $4
        RETURNING *
        `,
        [
          title || null,
          messages
            ? JSON.stringify(messages)
            : null,
          req.params.id,
          req.user.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Conversation not found'
        });
      }

      res.json({
        conversation: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Update conversation error:',
        err
      );

      res.status(500).json({
        error: 'Unable to update conversation'
      });
    }
  }
);

app.delete(
  '/api/conversations/:id',
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        DELETE FROM conversations
        WHERE id = $1
          AND user_id = $2
        RETURNING id
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Conversation not found'
        });
      }

      res.json({
        success: true
      });
    } catch (err) {
      console.error(
        'Delete conversation error:',
        err
      );

      res.status(500).json({
        error: 'Unable to delete conversation'
      });
    }
  }
);

// ============================================================
// FAVORITES
// ============================================================

app.get(
  '/api/favorites',
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT id, item, created_at
        FROM favorites
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        favorites: result.rows
      });
    } catch (err) {
      console.error(
        'Get favorites error:',
        err
      );

      res.status(500).json({
        error: 'Unable to load favorites'
      });
    }
  }
);

app.post(
  '/api/favorites',
  requireAuth,
  async (req, res) => {
    try {
      const { item } = req.body || {};

      if (!item) {
        return res.status(400).json({
          error: 'item is required'
        });
      }

      const result = await pool.query(
        `
        INSERT INTO favorites
          (user_id, item)
        VALUES
          ($1, $2)
        RETURNING *
        `,
        [
          req.user.id,
          JSON.stringify(item)
        ]
      );

      res.json({
        favorite: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Create favorite error:',
        err
      );

      res.status(500).json({
        error: 'Unable to save favorite'
      });
    }
  }
);

app.delete(
  '/api/favorites/:id',
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM favorites
        WHERE id = $1
          AND user_id = $2
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      res.json({
        success: true
      });
    } catch (err) {
      console.error(
        'Delete favorite error:',
        err
      );

      res.status(500).json({
        error: 'Unable to delete favorite'
      });
    }
  }
);

// ============================================================
// FILES
// ============================================================

app.get(
  '/api/files',
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT id, name, content, created_at
        FROM files
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        files: result.rows
      });
    } catch (err) {
      console.error(
        'Get files error:',
        err
      );

      res.status(500).json({
        error: 'Unable to load files'
      });
    }
  }
);

app.post(
  '/api/files',
  requireAuth,
  async (req, res) => {
    try {
      const {
        name,
        content
      } = req.body || {};

      if (!name) {
        return res.status(400).json({
          error: 'File name is required'
        });
      }

      const result = await pool.query(
        `
        INSERT INTO files
          (user_id, name, content)
        VALUES
          ($1, $2, $3)
        RETURNING *
        `,
        [
          req.user.id,
          String(name),
          content || ''
        ]
      );

      res.json({
        file: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Create file error:',
        err
      );

      res.status(500).json({
        error: 'Unable to save file'
      });
    }
  }
);

app.delete(
  '/api/files/:id',
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM files
        WHERE id = $1
          AND user_id = $2
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      res.json({
        success: true
      });
    } catch (err) {
      console.error(
        'Delete file error:',
        err
      );

      res.status(500).json({
        error: 'Unable to delete file'
      });
    }
  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (err.message === 'CORS not allowed') {
    return res.status(403).json({
      error: 'CORS not allowed'
    });
  }

  res.status(500).json({
    error: 'Internal server error'
  });
});

// ============================================================
// START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `PSBAITool backend listening on port ${PORT}`
  );
});

// ============================================================
// START DATABASE
// ============================================================

initDatabase();
