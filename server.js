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
const ADMIN_SECRET  = process.env.ADMIN_SECRET  || "change_this_admin_password";
const KEY_DURATION  = 24 * 60 * 60 * 1000; // 24h en ms
const MAX_KEYS_IP   = 3;  // max générations par IP par jour

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
`);

// ── Middleware ──────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

// ── Helpers ─────────────────────────────────
function genKey() {
  // Format : AFv5-XXXX-XXXX-XXXX-XXXX
  const seg = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `AFv5-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

// ── Routes ──────────────────────────────────

// GET /api/generate — génère une clé (rate-limited par IP)
app.post("/api/generate", (req, res) => {
  const ip   = getClientIp(req);
  const today = todayStr();

  // Rate limit
  const row = db.prepare("SELECT count FROM ip_ratelimit WHERE ip=? AND date=?").get(ip, today);
  const count = row ? row.count : 0;
  if (count >= MAX_KEYS_IP) {
    return res.status(429).json({ success: false, error: "Limite de génération atteinte pour aujourd'hui (3/jour)." });
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

// POST /api/verify — vérifie clé + HWID depuis le script Lua
app.post("/api/verify", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ success: false, error: "Paramètres manquants." });

  const row = db.prepare("SELECT * FROM keys WHERE key=?").get(key);
  if (!row) return res.json({ success: false, error: "Clé invalide." });

  const now = Date.now();

  // Première utilisation : bind HWID + démarrer expiration 24h
  if (!row.hwid) {
    db.prepare("UPDATE keys SET hwid=?, bound_at=?, expires_at=?, used=1 WHERE key=?")
      .run(hwid, now, now + KEY_DURATION, key);
    return res.json({ success: true, message: "Clé activée !", expires_in: KEY_DURATION });
  }

  // HWID différent = tentative de partage
  if (row.hwid !== hwid) {
    return res.json({ success: false, error: "Cette clé est liée à un autre PC." });
  }

  // Expirée
  if (now > row.expires_at) {
    db.prepare("UPDATE keys SET hwid=NULL, bound_at=NULL, expires_at=NULL, used=0 WHERE key=?").run(key);
    return res.json({ success: false, error: "Clé expirée. Génère-en une nouvelle sur le site." });
  }

  const remaining = row.expires_at - now;
  res.json({ success: true, message: "Premium actif !", expires_in: remaining });
});

// POST /api/admin/revoke — révoque une clé (admin)
app.post("/api/admin/revoke", (req, res) => {
  const { secret, key } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ success: false, error: "Non autorisé." });
  db.prepare("DELETE FROM keys WHERE key=?").run(key);
  res.json({ success: true, message: "Clé révoquée." });
});

// GET /api/admin/keys — liste toutes les clés (admin)
app.get("/api/admin/keys", (req, res) => {
  const { secret } = req.query;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ success: false, error: "Non autorisé." });
  const keys = db.prepare("SELECT * FROM keys ORDER BY created_at DESC LIMIT 100").all();
  res.json({ success: true, keys });
});

// Fallback → site
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.listen(PORT, () => {
  console.log(`[AutoFarm KeyServer] Running on port ${PORT}`);
});
