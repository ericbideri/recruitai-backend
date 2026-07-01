// ── Database Layer (SQLite) ────────────────────────
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH || './data/recruitai.db';

const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ── Schema ────────────────────────────────────────
// Lemon Squeezy is the merchant of record. It handles checkout,
// taxes, cards, subscriptions, dunning, and cancellations. We only
// store the user's plan status (updated via webhook) and track usage.
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    company TEXT,
    plan TEXT DEFAULT 'free',
    ls_subscription_id TEXT,
    ls_customer_id TEXT,
    plan_renews_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_usage_user_date ON usage_log(user_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_ls_sub ON users(ls_subscription_id);
`);

// ── Prepared Statements ───────────────────────────
const stmts = {
  createUser: db.prepare(`INSERT INTO users (email, password_hash, name, company) VALUES (?, ?, ?, ?)`),
  getUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  getUserById: db.prepare(`SELECT * FROM users WHERE id = ?`),

  // Plan updates come from Lemon Squeezy webhooks
  setPlanByEmail: db.prepare(`
    UPDATE users SET plan = ?, ls_subscription_id = ?, ls_customer_id = ?, plan_renews_at = ?, updated_at = datetime('now')
    WHERE email = ?
  `),
  setPlanBySubscriptionId: db.prepare(`
    UPDATE users SET plan = ?, plan_renews_at = ?, updated_at = datetime('now')
    WHERE ls_subscription_id = ?
  `),

  logUsage: db.prepare(`INSERT INTO usage_log (user_id, action) VALUES (?, ?)`),
  getTodayUsage: db.prepare(`SELECT COUNT(*) as count FROM usage_log WHERE user_id = ? AND created_at >= date('now')`),
};

module.exports = { db, stmts };
