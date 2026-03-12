// ============================================
//   AutoFarm Key System — API Server
//   Stack : Node.js + Express + SQLite
//   Deploy : Railway / Render / any VPS
// ============================================

const express  = require("express");
const Database = require("better-sqlite3");
const crypto   = require("crypto");
const cors     = require("cors");
const path     = require("path");

const app  = express();
const db   = new Database("keys.db");
const PORT = process.env.PORT || 3000;

// ── Config ──────────────────────────────────
const ADMIN_SECRET     = process.env.ADMIN_SECRET || "change_this_admin_password";
const KEY_DURATION     = 24 * 60 * 60 * 1000; // 24h in ms
const MAX_KEYS_IP      = 1;  // 1 key per IP per day

// ── DB init ──────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL UNIQUE,
    hwid       TEXT,
    ip         TEXT,
    created_at INTEGER NOT NULL,
    bound_at   INTEGER,
    expires_at INTEGER,
    used       INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS ip_ratelimit (
    ip    TEXT    NOT NULL,
    date  TEXT    NOT NULL,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (ip, date)
  );
  CREATE TABLE IF NOT EXISTS used_tokens (
    token      TEXT    NOT NULL PRIMARY KEY,
    used_at    INTEGER NOT NULL
  );
`);

// ── Middleware ──────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Helpers ─────────────────────────────────
function genKey() {
  // Format: AFv5-XXXX-XXXX-XXXX-XXXX
  const seg = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `AFv5-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

// ── Workink token verification ───────────────
async function verifyWorkinkToken(token) {
  try {
    const url = `https://work.ink/_api/v2/token/isValid/${encodeURIComponent(token)}`;
    const res  = await fetch(url);
    const data = await res.json();
    // Workink returns { valid: true } on valid token
    return data.valid === true;
  } catch (e) {
    console.error("[Workink] Verification failed:", e.message);
    return false;
  }
}

// ── Routes ──────────────────────────────────

// POST /api/generate — verify Workink token + generate key (1/IP/day)
app.post("/api/generate", async (req, res) => {
  const { token } = req.body;
  const ip        = getClientIp(req);
  const today     = todayStr();

  if (!token) {
    return res.status(400).json({ success: false, error: "Missing Workink token. Please complete the verification." });
  }

  // Check token already used (replay attack prevention)
  const usedToken = db.prepare("SELECT token FROM used_tokens WHERE token=?").get(token);
  if (usedToken) {
    return res.status(400).json({ success: false, error: "This verification token has already been used." });
  }

  // Verify Workink token
  const valid = await verifyWorkinkToken(token);
  if (!valid) {
    return res.status(403).json({ success: false, error: "Workink verification failed. Please complete the full verification." });
  }

  // Mark token as used immediately (prevents concurrent requests with same token)
  db.prepare("INSERT OR IGNORE INTO used_tokens (token, used_at) VALUES (?,?)").run(token, Date.now());

  // Rate limit: 1 key per IP per day
  const row   = db.prepare("SELECT count FROM ip_ratelimit WHERE ip=? AND date=?").get(ip, today);
  const count = row ? row.count : 0;
  if (count >= MAX_KEYS_IP) {
    return res.status(429).json({
      success: false,
      error: "You have already generated a key today. Keys reset every 24 hours — come back tomorrow."
    });
  }

  const key = genKey();
  const now = Date.now();

  db.prepare("INSERT INTO keys (key, ip, created_at) VALUES (?,?,?)").run(key, ip, now);
  db.prepare(`
    INSERT INTO ip_ratelimit (ip, date, count) VALUES (?,?,1)
    ON CONFLICT(ip, date) DO UPDATE SET count=count+1
  `).run(ip, today);

  res.json({ success: true, key });
});

// POST /api/verify — verify key + HWID from the Lua script
app.post("/api/verify", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ success: false, error: "Missing parameters." });

  const row = db.prepare("SELECT * FROM keys WHERE key=?").get(key);
  if (!row) return res.json({ success: false, error: "Invalid key." });

  const now = Date.now();

  // First use: bind HWID + start 24h expiry
  if (!row.hwid) {
    db.prepare("UPDATE keys SET hwid=?, bound_at=?, expires_at=?, used=1 WHERE key=?")
      .run(hwid, now, now + KEY_DURATION, key);
    return res.json({ success: true, message: "Key activated!", expires_in: KEY_DURATION });
  }

  // Different HWID = sharing attempt
  if (row.hwid !== hwid) {
    return res.json({ success: false, error: "This key is bound to a different PC." });
  }

  // Expired
  if (now > row.expires_at) {
    db.prepare("UPDATE keys SET hwid=NULL, bound_at=NULL, expires_at=NULL, used=0 WHERE key=?").run(key);
    return res.json({ success: false, error: "Key expired. Generate a new one on the website." });
  }

  const remaining = row.expires_at - now;
  res.json({ success: true, message: "Premium active!", expires_in: remaining });
});

// POST /api/admin/revoke — revoke a key (admin)
app.post("/api/admin/revoke", (req, res) => {
  const { secret, key } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ success: false, error: "Unauthorized." });
  db.prepare("DELETE FROM keys WHERE key=?").run(key);
  res.json({ success: true, message: "Key revoked." });
});

// GET /api/admin/keys — list all keys (admin)
app.get("/api/admin/keys", (req, res) => {
  const { secret } = req.query;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ success: false, error: "Unauthorized." });
  const keys = db.prepare("SELECT * FROM keys ORDER BY created_at DESC LIMIT 100").all();
  res.json({ success: true, keys });
});

// Cleanup old tokens every hour (keep DB small)
setInterval(() => {
  const cutoff = Date.now() - 48 * 60 * 60 * 1000; // 48h
  db.prepare("DELETE FROM used_tokens WHERE used_at < ?").run(cutoff);
}, 60 * 60 * 1000);

// Fallback → site
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.listen(PORT, () => {
  console.log(`[AutoFarm KeyServer] Running on port ${PORT}`);
});
