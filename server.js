require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const { pool } = require('./db');
const {
  hashPassword,
  verifyPassword,
  signToken,
  requireAuth
} = require('./auth');

const app = express();

app.set('trust proxy', 1);

app.use(express.json({ limit: '10mb' }));

// ============================================================
// CORS
// ============================================================

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (curl/server-to-server)
      // and explicitly allowed website origins.
      if (
        !origin ||
        allowedOrigins.length === 0 ||
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    }
  })
);

// ============================================================
// RATE LIMITING
// ============================================================

// Generic limiter for all routes
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300
  })
);

// Stricter limiter for AI chat
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: {
    error: 'Too many chat requests — please slow down.'
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

// ============================================================
// AUTH
// ============================================================

// ---------- REGISTER ----------

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({
        error: 'name, email, and password are required'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters'
      });
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: 'An account with this email already exists'
      });
    }

    const passwordHash = await hashPassword(password);

    const result = await pool.query(
      `INSERT INTO users
       (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, is_pro, created_at`,
      [
        name,
        email.toLowerCase(),
        passwordHash
      ]
    );

    const user = result.rows[0];

    const token = signToken(user);

    res.status(201).json({
      token,
      user
    });

  } catch (err) {
    console.error('register error:', err);

    res.status(500).json({
      error: 'Something went wrong creating your account'
    });
  }
});

// ---------- LOGIN ----------

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        error: 'email and password are required'
      });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const valid = await verifyPassword(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const token = signToken(user);

    delete user.password_hash;

    res.json({
      token,
      user
    });

  } catch (err) {
    console.error('login error:', err);

    res.status(500).json({
      error: 'Something went wrong logging in'
    });
  }
});

// ---------- CURRENT USER ----------

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, is_pro, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (err) {
    console.error('auth/me error:', err);

    res.status(500).json({
      error: 'Something went wrong'
    });
  }
});

// ============================================================
// HISTORY
// ============================================================

// ---------- GET HISTORY ----------

app.get('/api/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, tool_name, created_at
       FROM history
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 200`,
      [req.user.id]
    );

    res.json({
      history: result.rows
    });

  } catch (err) {
    console.error('get history error:', err);

    res.status(500).json({
      error: 'Something went wrong loading history'
    });
  }
});

// ---------- ADD HISTORY ----------

app.post('/api/history', requireAuth, async (req, res) => {
  try {
    const { tool_name } = req.body || {};

    if (!tool_name) {
      return res.status(400).json({
        error: 'tool_name is required'
      });
    }

    const result = await pool.query(
      `INSERT INTO history
       (user_id, tool_name)
       VALUES ($1, $2)
       RETURNING id, tool_name, created_at`,
      [
        req.user.id,
        tool_name
      ]
    );

    res.status(201).json({
      entry: result.rows[0]
    });

  } catch (err) {
    console.error('add history error:', err);

    res.status(500).json({
      error: 'Something went wrong saving history'
    });
  }
});

// ---------- DELETE HISTORY ----------

app.delete('/api/history', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM history WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      success: true
    });

  } catch (err) {
    console.error('delete history error:', err);

    res.status(500).json({
      error: 'Something went wrong deleting history'
    });
  }
});

// ============================================================
// FAVORITES
// ============================================================

// ---------- GET FAVORITES ----------

app.get('/api/favorites', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT tool_name
       FROM favorites
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      favorites: result.rows.map((r) => r.tool_name)
    });

  } catch (err) {
    console.error('get favorites error:', err);

    res.status(500).json({
      error: 'Something went wrong loading favorites'
    });
  }
});

// ---------- ADD FAVORITE ----------

app.post('/api/favorites', requireAuth, async (req, res) => {
  try {
    const { tool_name } = req.body || {};

    if (!tool_name) {
      return res.status(400).json({
        error: 'tool_name is required'
      });
    }

    await pool.query(
      `INSERT INTO favorites
       (user_id, tool_name)
       VALUES ($1, $2)
       ON CONFLICT (user_id, tool_name)
       DO NOTHING`,
      [
        req.user.id,
        tool_name
      ]
    );

    res.status(201).json({
      success: true
    });

  } catch (err) {
    console.error('add favorite error:', err);

    res.status(500).json({
      error: 'Something went wrong saving favorite'
    });
  }
});

// ---------- DELETE FAVORITE ----------

app.delete(
  '/api/favorites/:toolName',
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        `DELETE FROM favorites
         WHERE user_id = $1
         AND tool_name = $2`,
        [
          req.user.id,
          req.params.toolName
        ]
      );

      res.json({
        success: true
      });

    } catch (err) {
      console.error('delete favorite error:', err);

      res.status(500).json({
        error: 'Something went wrong deleting favorite'
      });
    }
  }
);

// ============================================================
// FILES
// ============================================================

// ---------- GET FILES ----------

app.get('/api/files', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, created_at
       FROM files
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    res.json({
      files: result.rows
    });

  } catch (err) {
    console.error('get files error:', err);

    res.status(500).json({
      error: 'Something went wrong loading files'
    });
  }
});

// ---------- GET SINGLE FILE ----------

app.get('/api/files/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM files
       WHERE id = $1
       AND user_id = $2`,
      [
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'File not found'
      });
    }

    res.json({
      file: result.rows[0]
    });

  } catch (err) {
    console.error('get file error:', err);

    res.status(500).json({
      error: 'Something went wrong loading file'
    });
  }
});

// ---------- ADD FILE ----------

app.post('/api/files', requireAuth, async (req, res) => {
  try {
    const { name, data_url } = req.body || {};

    if (!name || !data_url) {
      return res.status(400).json({
        error: 'name and data_url are required'
      });
    }

    const result = await pool.query(
      `INSERT INTO files
       (user_id, name, data_url)
       VALUES ($1, $2, $3)
       RETURNING id, name, created_at`,
      [
        req.user.id,
        name,
        data_url
      ]
    );

    res.status(201).json({
      file: result.rows[0]
    });

  } catch (err) {
    console.error('add file error:', err);

    res.status(500).json({
      error: 'Something went wrong saving file'
    });
  }
});

// ---------- DELETE FILE ----------

app.delete('/api/files/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM files
       WHERE id = $1
       AND user_id = $2`,
      [
        req.params.id,
        req.user.id
      ]
    );

    res.json({
      success: true
    });

  } catch (err) {
    console.error('delete file error:', err);

    res.status(500).json({
      error: 'Something went wrong deleting file'
    });
  }
});

// ============================================================
// AI CHAT PROXY — GEMINI
// ============================================================

app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const { messages, system } = req.body || {};

    // Validate messages
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: 'messages array is required'
      });
    }

    // Check Gemini API key
    if (!process.env.GEMINI_API_KEY) {
      console.error('GEMINI_API_KEY is missing');

      return res.status(500).json({
        error: 'Gemini API key is not configured'
      });
    }

    // Convert frontend messages to Gemini format
    const contents = messages.map((message) => ({
      role: message.role === 'assistant'
        ? 'model'
        : 'user',

      parts: [
        {
          text: String(message.content || '')
        }
      ]
    }));

    // Gemini request body
    const body = {
      contents,

      generationConfig: {
        maxOutputTokens: 1000
      }
    };

    // Add system instruction
    if (system) {
      body.systemInstruction = {
        parts: [
          {
            text: String(system)
          }
        ]
      };
    }

    // Call Gemini API
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

    // Gemini API error
    if (!response.ok) {
      console.error(
        'Gemini API error:',
        response.status,
        data
      );

      return res.status(502).json({
        error: 'Gemini API error',
        details:
          data?.error?.message ||
          'Unknown Gemini error'
      });
    }

    // Extract Gemini response text
    const text =
      data?.candidates?.[0]?.content?.parts
        ?.map((part) => part.text || '')
        .join('') || '';

    // Empty response protection
    if (!text) {
      console.error(
        'Gemini returned an empty response:',
        data
      );

      return res.status(502).json({
        error: 'Gemini returned an empty response'
      });
    }

    // IMPORTANT:
    // Existing PSBAITool frontend expects data.content
    res.json({
      content: [
        {
          type: 'text',
          text
        }
      ]
    });

  } catch (err) {
    console.error(
      'chat proxy error:',
      err
    );

    res.status(500).json({
      error: 'Something went wrong talking to Gemini'
    });
  }
});

// ============================================================
// SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `PSBAITool backend listening on port ${PORT}`
  );
});
