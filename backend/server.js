const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Backend running clean (Self-posting mode)");
});

/**
 * Helper: get logged-in userId from request headers
 * Client sends header: token: "<userId>"
 */
function requireUser(req, res) {
  const token = req.headers.token;
  if (!token) {
    res.status(401).json({ error: "Not logged in (missing token header)" });
    return null;
  }
  const userId = Number(token);
  if (!Number.isInteger(userId) || userId <= 0) {
    res.status(401).json({ error: "Invalid token" });
    return null;
  }
  return userId;
}

/* ============================
   AUTH
============================ */

// SIGNUP
app.post("/signup", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email);
  if (existing) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const createdAt = new Date().toISOString();

  const info = db
    .prepare(`INSERT INTO users (email, passwordHash, createdAt) VALUES (?, ?, ?)`)

    .run(email, passwordHash, createdAt);

  res.json({ success: true, userId: info.lastInsertRowid });
});

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // MVP token = userId
  res.json({ success: true, token: String(user.id), userId: user.id });
});

/* ============================
   POSTS (SELF-POSTING)
============================ */

// CREATE POST → status = ready
app.post("/post", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const { productName, imageUrl, caption } = req.body;

  if (!productName || !imageUrl || !caption) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const createdAt = new Date().toISOString();

  const info = db.prepare(`
    INSERT INTO posts (userId, productName, imageUrl, caption, status, createdAt)
    VALUES (?, ?, ?, ?, 'ready', ?)
  `).run(userId, productName, imageUrl, caption, createdAt);

  res.json({ success: true, id: info.lastInsertRowid });
});

// GET USER POSTS
app.get("/posts", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const rows = db
    .prepare(`SELECT * FROM posts WHERE userId = ? ORDER BY id DESC`)
    .all(userId);

  res.json(rows);
});

// OPTIONAL STATUS UPDATE (kept safe, not required)
app.post("/update-status", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const { id, status } = req.body;
  if (!id || !status) {
    return res.status(400).json({ error: "Missing id or status" });
  }

  const info = db
    .prepare(`UPDATE posts SET status = ? WHERE id = ? AND userId = ?`)
    .run(status, id, userId);

  if (info.changes === 0) {
    return res.status(404).json({ error: "Post not found" });
  }

  res.json({ success: true });
});

// PUBLISH → ready → posted
app.post("/publish", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ error: "Missing id" });
  }

  const post = db
    .prepare(`SELECT * FROM posts WHERE id = ? AND userId = ?`)
    .get(id, userId);

  if (!post) {
    return res.status(404).json({ error: "Post not found" });
  }

  if (post.status !== "ready") {
    return res.status(400).json({ error: "Post not ready yet" });
  }

  // 🔮 NEXT STEP: Real Instagram Graph API call here
  db.prepare(`
    UPDATE posts SET status = 'posted'
    WHERE id = ? AND userId = ?
  `).run(id, userId);

  console.log("📸 Posted to Instagram (simulated):", post.productName);

  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
