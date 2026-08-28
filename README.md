# PSBAITool Backend

A small Node.js + Express + PostgreSQL API that adds real accounts, cross-device
history/favorites/files, and a secure AI chat proxy to PSBAITool.

This matches the "Backend & Database" layer from the architecture diagrams —
everything above this (frontend, login UI, tools, chat UI) already exists in
`index.html`. This backend is what makes accounts real (instead of
browser-only) and keeps your Anthropic API key safe.

## What this fixes

Right now, `index.html` calls `https://api.anthropic.com/v1/messages` directly
from the browser with no API key — that only works inside Claude.ai's sandbox.
Once deployed as a real site, those calls will fail, and you should never put
a real API key in client-side JavaScript anyway (anyone can view-source and
steal it). This backend adds a `/api/chat` endpoint that keeps your key on the
server and proxies requests safely.

## 1. Deploy to Railway

1. Create a free account at [railway.app](https://railway.app)
2. **New Project → Deploy from GitHub repo** (push this `backend/` folder to
   its own GitHub repo first), or **Empty Project** and drag/upload the files
3. In the same project, click **+ New → Database → Add PostgreSQL**. Railway
   automatically creates a `DATABASE_URL` variable and makes it available to
   your app service.
4. Click into your app service → **Variables** tab, and add:
   - `JWT_SECRET` — generate one locally with:
     `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
   - `ANTHROPIC_API_KEY` — your real Anthropic API key
   - `ALLOWED_ORIGINS` — your deployed frontend URL, e.g. `https://psbaitool.netlify.app`
   - (`DATABASE_URL` and `PORT` are already set automatically by Railway)
5. Under **Settings**, set the **Start Command** to `npm start`
6. Once deployed, open the Railway **Shell** for your service (or run
   locally against the same `DATABASE_URL`) and run:
   ```
   npm run migrate
   ```
   This creates the `users`, `history`, `favorites`, and `files` tables.
7. Railway gives you a public URL like `https://psbaitool-backend.up.railway.app`
   — that's your API base URL for the next step.

## 2. Run it locally first (recommended before deploying)

```bash
cd backend
npm install
cp .env.example .env
# edit .env with a local Postgres URL, a JWT secret, and your Anthropic key
npm run migrate
npm run dev
```

The API will be running at `http://localhost:3000`.

## 3. Update the frontend to use this backend

In `index.html`, every `fetch("https://api.anthropic.com/v1/messages", ...)`
call needs to change to point at your new `/api/chat` endpoint instead. There
are several of these (main chat, Document Assistant, ATS Checker, etc.) —
each one currently looks like this:

```js
const response = await fetch("https://api.anthropic.com/v1/messages", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    model: "claude-sonnet-4-6",
    max_tokens: 1000,
    system: "...",
    messages: [...]
  })
});
```

Change the URL and drop the model/max_tokens (the backend sets those now):

```js
const response = await fetch("https://your-backend.up.railway.app/api/chat", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    system: "...",
    messages: [...]
  })
});
```

The response shape from `/api/chat` is identical to the Anthropic API's
response, so the rest of your existing code (`data.content.find(...)`, etc.)
doesn't need to change.

**I can make this exact swap across every chat call in `index.html` for you
once your backend is deployed and you have a real URL to point at — just
share the URL and say "swap in my backend URL".**

## 4. Optional next step: real accounts instead of localStorage

Right now `index.html`'s login system just saves a name/email to
`localStorage` — it's not connected to this backend yet. To make accounts
real (synced across devices), the frontend's `getUser`, `setUser`,
`getHistory`, `logActivity`, `getFavorites`, `setFavorites`, `getFiles`, and
`saveFileToDashboard` functions would need to call these new API endpoints
(`/api/auth/*`, `/api/history`, `/api/favorites`, `/api/files`) instead of
reading/writing `localStorage` directly, using the JWT token from login for
authenticated requests. This is a meaningful rewrite of that part of the
frontend — happy to do it as a dedicated next step once the backend above is
live and tested.

## API reference

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | — | `{name, email, password}` → `{token, user}` |
| POST | `/api/auth/login` | — | `{email, password}` → `{token, user}` |
| GET | `/api/auth/me` | ✅ | Current user info |
| GET | `/api/history` | ✅ | Last 200 history entries |
| POST | `/api/history` | ✅ | `{tool_name}` |
| DELETE | `/api/history` | ✅ | Clears all history |
| GET | `/api/favorites` | ✅ | List of favorited tool names |
| POST | `/api/favorites` | ✅ | `{tool_name}` |
| DELETE | `/api/favorites/:toolName` | ✅ | Un-favorite a tool |
| GET | `/api/files` | ✅ | List of saved files (metadata only) |
| GET | `/api/files/:id` | ✅ | One file including its data |
| POST | `/api/files` | ✅ | `{name, data_url}` |
| DELETE | `/api/files/:id` | ✅ | Delete a saved file |
| POST | `/api/chat` | — | `{system, messages}` → proxies to Claude |

Authenticated routes expect `Authorization: Bearer <token>` from login/register.

## A note on scale

Files are stored as base64 text directly in Postgres for simplicity — fine
for an MVP, but not ideal once you have real users uploading many PDFs/images.
When that becomes a real cost/performance concern, swap the `files` table's
`data_url` column for a URL pointing at object storage (S3, Cloudflare R2, or
Supabase Storage) instead of storing the raw bytes in the database.
