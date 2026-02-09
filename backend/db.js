const path = require("path");
const Database = require("better-sqlite3");

const dbPath = path.join(__dirname, "app.db");
const db = new Database(dbPath);

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    passwordHash TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );
`);

// Create posts table (linked to users)
db.exec(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    userId INTEGER NOT NULL,
    productName TEXT NOT NULL,
    imageUrl TEXT NOT NULL,
    caption TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    createdAt TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
  );
`);

// --- Instagram OAuth storage columns (safe migration) ---
try { db.prepare(`ALTER TABLE users ADD COLUMN pageId TEXT`).run(); } catch(e) {}
try { db.prepare(`ALTER TABLE users ADD COLUMN igUserId TEXT`).run(); } catch(e) {}
try { db.prepare(`ALTER TABLE users ADD COLUMN igAccessToken TEXT`).run(); } catch(e) {}
try { db.prepare(`ALTER TABLE users ADD COLUMN igTokenExpiresAt TEXT`).run(); } catch(e) {}

// --- OAuth state table ---
db.exec(`
  CREATE TABLE IF NOT EXISTS ig_states (
    state TEXT PRIMARY KEY,
    userId INTEGER NOT NULL,
    createdAt TEXT NOT NULL
  );
`);

module.exports = db;


