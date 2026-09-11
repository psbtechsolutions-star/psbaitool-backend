require("dotenv").config();

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));

// ============================================================
// CORS
// ============================================================

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS not allowed"));
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
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

pool.on("error", err => {
  console.error("Postgres pool error:", err);
});

// ============================================================
// RATE LIMITING
// ============================================================

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests. Please try again later."
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts."
  }
});

// ============================================================
// BASIC ROUTES
// ============================================================

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "psbaitool-backend"
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "psbaitool-backend"
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

    console.log("Database initialized");
  } catch (err) {
    console.error("Database initialization error:", err);
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
      expiresIn: "7d"
    }
  );
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
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
      error: "Invalid or expired token"
    });
  }
}

// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  authLimiter,
  async (req, res) => {
    try {
      const { email, password } = req.body || {};

      if (!email || !password) {
        return res.status(400).json({
          error: "Email and password are required"
        });
      }

      if (String(password).length < 6) {
        return res.status(400).json({
          error: "Password must be at least 6 characters"
        });
      }

      const normalizedEmail = String(email)
        .trim()
        .toLowerCase();

      const existing = await pool.query(
        "SELECT id FROM users WHERE email = $1",
        [normalizedEmail]
      );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          error: "User already exists"
        });
      }

      const passwordHash = await bcrypt.hash(
        String(password),
        12
      );

      const result = await pool.query(
        `
        INSERT INTO users
          (email, password_hash)
        VALUES
          ($1, $2)
        RETURNING id, email, created_at
        `,
        [normalizedEmail, passwordHash]
      );

      const user = result.rows[0];

      return res.json({
        token: signToken(user),
        user
      });
    } catch (err) {
      console.error("Register error:", err);

      return res.status(500).json({
        error: "Registration failed"
      });
    }
  }
);

// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res) => {
    try {
      const { email, password } = req.body || {};

      if (!email || !password) {
        return res.status(400).json({
          error: "Email and password are required"
        });
      }

      const normalizedEmail = String(email)
        .trim()
        .toLowerCase();

      const result = await pool.query(
        `
        SELECT
          id,
          email,
          password_hash,
          created_at
        FROM users
        WHERE email = $1
        `,
        [normalizedEmail]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          error: "Invalid email or password"
        });
      }

      const user = result.rows[0];

      const valid = await bcrypt.compare(
        String(password),
        user.password_hash
      );

      if (!valid) {
        return res.status(401).json({
          error: "Invalid email or password"
        });
      }

      return res.json({
        token: signToken(user),
        user: {
          id: user.id,
          email: user.email,
          created_at: user.created_at
        }
      });
    } catch (err) {
      console.error("Login error:", err);

      return res.status(500).json({
        error: "Login failed"
      });
    }
  }
);

// ============================================================
// CURRENT USER
// ============================================================

app.get(
  "/api/auth/me",
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          email,
          created_at
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found"
        });
      }

      return res.json({
        user: result.rows[0]
      });
    } catch (err) {
      console.error("Auth me error:", err);

      return res.status(500).json({
        error: "Unable to load user"
      });
    }
  }
);

// ============================================================
// AI CHAT - OPENROUTER FREE
// ============================================================

app.post(
  "/api/chat",
  chatLimiter,
  async (req, res) => {
    try {
      const {
        messages,
        system,
        max_tokens,
        temperature
      } = req.body || {};

      console.log("Received /api/chat request");

      if (
        !Array.isArray(messages) ||
        messages.length === 0
      ) {
        return res.status(400).json({
          error: "messages array is required"
        });
      }

      if (!process.env.OPENROUTER_API_KEY) {
        console.error("OPENROUTER_API_KEY is missing");

        return res.status(500).json({
          error: "OpenRouter API key is not configured"
        });
      }

      const cleanMessages = messages
        .filter(
          message =>
            message &&
            message.content != null
        )
        .map(message => ({
          role:
            message.role === "assistant"
              ? "assistant"
              : "user",

          content:
            Array.isArray(message.content)
              ? message.content
              : String(message.content)
        }));

      if (cleanMessages.length === 0) {
        return res.status(400).json({
          error: "No valid messages provided"
        });
      }

      const body = {
        model:
          process.env.OPENROUTER_MODEL ||
          "openrouter/free",

        messages: [
          ...(system
            ? [
                {
                  role: "system",
                  content: String(system)
                }
              ]
            : []),

          ...cleanMessages
        ],

        max_tokens: Math.min(
          Math.max(
            Number(max_tokens) || 1000,
            1
          ),
          4000
        )
      };

      if (
        typeof temperature === "number" &&
        Number.isFinite(temperature)
      ) {
        body.temperature = Math.max(
          0,
          Math.min(temperature, 2)
        );
      }

      console.log(
        `Calling OpenRouter: ${body.model}`
      );

      const response = await fetch(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          method: "POST",

          headers: {
            Authorization:
              `Bearer ${process.env.OPENROUTER_API_KEY}`,

            "Content-Type":
              "application/json",

            "HTTP-Referer":
              process.env.SITE_URL ||
              "https://psbtechsolutions.in",

            "X-Title":
              process.env.SITE_NAME ||
              "PSBTechSolutions"
          },

          body: JSON.stringify(body)
        }
      );

      const raw = await response.text();

      let data;

      try {
        data = JSON.parse(raw);
      } catch {
        data = {
          error: {
            message:
              raw ||
              "Invalid response from OpenRouter"
          }
        };
      }

      if (!response.ok) {
        console.error(
          "OpenRouter API error:",
          response.status,
          JSON.stringify(data)
        );

        return res.status(502).json({
          error: "OpenRouter API error",
          details:
            data?.error?.message ||
            "Unknown OpenRouter API error"
        });
      }

      const content =
        data?.choices?.[0]?.message?.content;

      const text =
        typeof content === "string"
          ? content
          : Array.isArray(content)
            ? content
                .map(part => part?.text || "")
                .join("")
            : "";

      if (!text) {
        console.error(
          "OpenRouter returned empty response:",
          JSON.stringify(data)
        );

        return res.status(502).json({
          error:
            "OpenRouter returned an empty response"
        });
      }

      console.log(
        "OpenRouter response received successfully"
      );

      return res.json({
        content: [
          {
            type: "text",
            text
          }
        ]
      });
    } catch (err) {
      console.error(
        "Chat proxy error:",
        err
      );

      return res.status(500).json({
        error:
          "Something went wrong talking to OpenRouter"
      });
    }
  }
);

// ============================================================
// CONVERSATIONS - GET
// ============================================================

app.get(
  "/api/conversations",
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          title,
          messages,
          created_at,
          updated_at
        FROM conversations
        WHERE user_id = $1
        ORDER BY updated_at DESC
        `,
        [req.user.id]
      );

      return res.json({
        conversations: result.rows
      });
    } catch (err) {
      console.error(
        "Get conversations error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to load conversations"
      });
    }
  }
);

// ============================================================
// CONVERSATIONS - CREATE
// ============================================================

app.post(
  "/api/conversations",
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
          title || "New conversation",
          JSON.stringify(messages || [])
        ]
      );

      return res.json({
        conversation: result.rows[0]
      });
    } catch (err) {
      console.error(
        "Create conversation error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to save conversation"
      });
    }
  }
);

// ============================================================
// CONVERSATIONS - UPDATE
// ============================================================

app.put(
  "/api/conversations/:id",
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
          error:
            "Conversation not found"
        });
      }

      return res.json({
        conversation: result.rows[0]
      });
    } catch (err) {
      console.error(
        "Update conversation error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to update conversation"
      });
    }
  }
);

// ============================================================
// CONVERSATIONS - DELETE
// ============================================================

app.delete(
  "/api/conversations/:id",
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
          error:
            "Conversation not found"
        });
      }

      return res.json({
        success: true
      });
    } catch (err) {
      console.error(
        "Delete conversation error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to delete conversation"
      });
    }
  }
);

// ============================================================
// FAVORITES - GET
// ============================================================

app.get(
  "/api/favorites",
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          item,
          created_at
        FROM favorites
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.user.id]
      );

      return res.json({
        favorites: result.rows
      });
    } catch (err) {
      console.error(
        "Get favorites error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to load favorites"
      });
    }
  }
);

// ============================================================
// FAVORITES - CREATE
// ============================================================

app.post(
  "/api/favorites",
  requireAuth,
  async (req, res) => {
    try {
      const { item } = req.body || {};

      if (!item) {
        return res.status(400).json({
          error: "item is required"
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

      return res.json({
        favorite: result.rows[0]
      });
    } catch (err) {
      console.error(
        "Create favorite error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to save favorite"
      });
    }
  }
);

// ============================================================
// FAVORITES - DELETE
// ============================================================

app.delete(
  "/api/favorites/:id",
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

      return res.json({
        success: true
      });
    } catch (err) {
      console.error(
        "Delete favorite error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to delete favorite"
      });
    }
  }
);

// ============================================================
// FILES - GET
// ============================================================

app.get(
  "/api/files",
  requireAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          name,
          content,
          created_at
        FROM files
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.user.id]
      );

      return res.json({
        files: result.rows
      });
    } catch (err) {
      console.error(
        "Get files error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to load files"
      });
    }
  }
);

// ============================================================
// FILES - CREATE
// ============================================================

app.post(
  "/api/files",
  requireAuth,
  async (req, res) => {
    try {
      const {
        name,
        content
      } = req.body || {};

      if (!name) {
        return res.status(400).json({
          error:
            "File name is required"
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
          content || ""
        ]
      );

      return res.json({
        file: result.rows[0]
      });
    } catch (err) {
      console.error(
        "Create file error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to save file"
      });
    }
  }
);

// ============================================================
// FILES - DELETE
// ============================================================

app.delete(
  "/api/files/:id",
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

      return res.json({
        success: true
      });
    } catch (err) {
      console.error(
        "Delete file error:",
        err
      );

      return res.status(500).json({
        error:
          "Unable to delete file"
      });
    }
  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (err, req, res, next) => {
    console.error(
      "Unhandled error:",
      err
    );

    if (
      err.message ===
      "CORS not allowed"
    ) {
      return res.status(403).json({
        error:
          "CORS not allowed"
      });
    }

    return res.status(500).json({
      error:
        "Internal server error"
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `PSBAITool backend listening on port ${PORT}`
    );
  }
);

// ============================================================
// START DATABASE
// ============================================================

initDatabase();
