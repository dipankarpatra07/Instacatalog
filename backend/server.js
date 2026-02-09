const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_RENDER";

const allowedOrigins = [
  "https://gramixy.com",
  "http://localhost:3000",
  "http://localhost:5500"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS blocked: " + origin));
  }
}));

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Backend running clean (JWT + IG Ready)");
});

/* ============================
   JWT AUTH HELPER
============================ */

function requireUser(req, res) {
  const token = req.headers.token;
  if (!token) {
    res.status(401).json({ error: "Not logged in" });
    return null;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.userId;
  } catch (err) {
    res.status(401).json({ error: "Token expired or invalid" });
    return null;
  }
}

/* ============================
   AUTH ROUTES
============================ */

app.post("/signup", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email);
  if (existing) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const createdAt = new Date().toISOString();

  const info = db.prepare(`
    INSERT INTO users (email, passwordHash, createdAt)
    VALUES (?, ?, ?)
  `).run(email, passwordHash, createdAt);

  res.json({ success: true });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(
    { userId: user.id },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({ success: true, token });
});

/* ============================
   POSTS
============================ */

app.post("/post", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const { productName, imageUrl, caption } = req.body;
  if (!productName || !imageUrl || !caption)
    return res.status(400).json({ error: "Missing fields" });

  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO posts (userId, productName, imageUrl, caption, status, createdAt)
    VALUES (?, ?, ?, ?, 'ready', ?)
  `).run(userId, productName, imageUrl, caption, createdAt);

  res.json({ success: true });
});

app.get("/posts", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const rows = db.prepare(`
    SELECT * FROM posts WHERE userId = ? ORDER BY id DESC
  `).all(userId);

  res.json(rows);
});

app.post("/publish", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const { id } = req.body;
  const post = db.prepare(`
    SELECT * FROM posts WHERE id = ? AND userId = ?
  `).get(id, userId);

  if (!post) return res.status(404).json({ error: "Post not found" });

  db.prepare(`
    UPDATE posts SET status = 'posted' WHERE id = ?
  `).run(id);

  res.json({ success: true });
});

/* ============================
   INSTAGRAM OAUTH PREP
============================ */

// Check connection status
app.get("/ig/status", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const user = db.prepare(`
    SELECT igUserId FROM users WHERE id = ?
  `).get(userId);

  res.json({ connected: !!user?.igUserId });
});

// Disconnect
app.post("/ig/disconnect", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  db.prepare(`
    UPDATE users
    SET pageId = NULL,
        igUserId = NULL,
        igAccessToken = NULL,
        igTokenExpiresAt = NULL
    WHERE id = ?
  `).run(userId);

  res.json({ success: true });
});

// Start OAuth (will activate after Meta app is created)
app.get("/auth/instagram/start", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const META_APP_ID = process.env.META_APP_ID;
  const META_REDIRECT_URI = process.env.META_REDIRECT_URI;

  if (!META_APP_ID || !META_REDIRECT_URI) {
    return res.status(400).json({ error: "Meta app not configured yet" });
  }

  const state = crypto.randomBytes(16).toString("hex");

  db.prepare(`
    INSERT INTO ig_states (state, userId, createdAt)
    VALUES (?, ?, ?)
  `).run(state, userId, new Date().toISOString());

  const scopes = "instagram_basic,instagram_content_publish,pages_show_list";

  const authUrl =
    `https://www.facebook.com/v19.0/dialog/oauth` +
    `?client_id=${META_APP_ID}` +
    `&redirect_uri=${encodeURIComponent(META_REDIRECT_URI)}` +
    `&state=${state}` +
    `&response_type=code` +
    `&scope=${scopes}`;

  res.redirect(authUrl);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
