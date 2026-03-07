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
  "https://www.gramixy.com",
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
  res.send("Backend running clean (JWT + Instagram OAuth + Real Publish)");
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
   HELPERS
============================ */

function getEnv(name) {
  const value = process.env[name];
  if (!value || value === "TEMP") {
    throw new Error(`Missing env var: ${name}`);
  }
  return value;
}

function saveIgState(state, userId) {
  db.prepare(`
    INSERT INTO ig_states (state, userId, createdAt)
    VALUES (?, ?, ?)
  `).run(state, userId, new Date().toISOString());
}

function consumeIgState(state) {
  const row = db.prepare(`
    SELECT * FROM ig_states WHERE state = ?
  `).get(state);

  if (!row) return null;

  db.prepare(`DELETE FROM ig_states WHERE state = ?`).run(state);
  return row;
}

async function createInstagramMediaContainer({ igUserId, imageUrl, caption, accessToken }) {
  const body = new URLSearchParams({
    image_url: imageUrl,
    caption: caption,
    access_token: accessToken
  });

  const response = await fetch(`https://graph.facebook.com/v25.0/${igUserId}/media`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const data = await response.json();

  if (!response.ok || !data.id) {
    throw new Error(`Media container failed: ${JSON.stringify(data)}`);
  }

  return data.id;
}

async function publishInstagramMedia({ igUserId, creationId, accessToken }) {
  const body = new URLSearchParams({
    creation_id: creationId,
    access_token: accessToken
  });

  const response = await fetch(`https://graph.facebook.com/v25.0/${igUserId}/media_publish`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const data = await response.json();

  if (!response.ok || !data.id) {
    throw new Error(`Media publish failed: ${JSON.stringify(data)}`);
  }

  return data.id;
}

/* ============================
   AUTH ROUTES
============================ */

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

  db.prepare(`
    INSERT INTO users (email, passwordHash, createdAt)
    VALUES (?, ?, ?)
  `).run(email, passwordHash, createdAt);

  res.json({ success: true });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { userId: user.id },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({ success: true, token });
});

/* ============================
   INSTAGRAM OAUTH
============================ */

app.get("/ig/status", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const user = db.prepare(`
    SELECT igUserId, pageId
    FROM users
    WHERE id = ?
  `).get(userId);

  res.json({
    connected: !!user?.igUserId,
    igUserId: user?.igUserId || null,
    pageId: user?.pageId || null
  });
});

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

app.get("/auth/instagram/start", (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(401).json({ error: "Not logged in" });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }

  const userId = decoded.userId;

  let META_APP_ID, META_REDIRECT_URI;
  try {
    META_APP_ID = getEnv("META_APP_ID");
    META_REDIRECT_URI = getEnv("META_REDIRECT_URI");
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const state = crypto.randomBytes(16).toString("hex");
  saveIgState(state, userId);

  const scope = [
    "pages_show_list",
    "pages_read_engagement",
    "instagram_basic",
    "instagram_content_publish"
  ].join(",");

  const authUrl =
    `https://www.facebook.com/v25.0/dialog/oauth` +
    `?client_id=${encodeURIComponent(META_APP_ID)}` +
    `&redirect_uri=${encodeURIComponent(META_REDIRECT_URI)}` +
    `&state=${encodeURIComponent(state)}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent(scope)}`;

  res.redirect(authUrl);
});

app.get("/auth/instagram/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) {
      return res.status(400).send("Missing code or state");
    }

    const link = consumeIgState(state);
    if (!link) {
      return res.status(400).send("Invalid or expired state");
    }

    const userId = link.userId;

    const META_APP_ID = getEnv("META_APP_ID");
    const META_APP_SECRET = getEnv("META_APP_SECRET");
    const META_REDIRECT_URI = getEnv("META_REDIRECT_URI");
    const FRONTEND_URL = process.env.FRONTEND_URL || "https://gramixy.com";

    const tokenRes = await fetch(
      `https://graph.facebook.com/v25.0/oauth/access_token` +
      `?client_id=${encodeURIComponent(META_APP_ID)}` +
      `&redirect_uri=${encodeURIComponent(META_REDIRECT_URI)}` +
      `&client_secret=${encodeURIComponent(META_APP_SECRET)}` +
      `&code=${encodeURIComponent(code)}`
    );
    const tokenData = await tokenRes.json();

    if (!tokenRes.ok || !tokenData.access_token) {
      return res.status(400).send(`Token exchange failed: ${JSON.stringify(tokenData)}`);
    }

    const accessToken = tokenData.access_token;

    const pagesRes = await fetch(
      `https://graph.facebook.com/v25.0/me/accounts?access_token=${encodeURIComponent(accessToken)}`
    );
    const pagesData = await pagesRes.json();

    if (!pagesRes.ok || !pagesData.data || pagesData.data.length === 0) {
      return res.status(400).send(`No Page found for this user: ${JSON.stringify(pagesData)}`);
    }

    const page = pagesData.data[0];
    const pageId = page.id;

    const igRes = await fetch(
      `https://graph.facebook.com/v25.0/${pageId}` +
      `?fields=instagram_business_account&access_token=${encodeURIComponent(accessToken)}`
    );
    const igData = await igRes.json();

    const igUserId = igData?.instagram_business_account?.id;
    if (!igRes.ok || !igUserId) {
      return res.status(400).send(`No Instagram business account linked: ${JSON.stringify(igData)}`);
    }

    db.prepare(`
      UPDATE users
      SET pageId = ?, igUserId = ?, igAccessToken = ?, igTokenExpiresAt = NULL
      WHERE id = ?
    `).run(pageId, igUserId, accessToken, userId);

    return res.redirect(`${FRONTEND_URL}/admin.html?ig=connected`);
  } catch (err) {
    console.error(err);
    return res.status(500).send(`Callback error: ${err.message}`);
  }
});

/* ============================
   POSTS
============================ */

app.post("/post", (req, res) => {
  const userId = requireUser(req, res);
  if (!userId) return;

  const { productName, imageUrl, caption } = req.body;
  if (!productName || !imageUrl || !caption) {
    return res.status(400).json({ error: "Missing fields" });
  }

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
    SELECT * FROM posts
    WHERE userId = ?
    ORDER BY id DESC
  `).all(userId);

  res.json(rows);
});

app.post("/publish", async (req, res) => {
  try {
    const userId = requireUser(req, res);
    if (!userId) return;

    const { id } = req.body;
    if (!id) {
      return res.status(400).json({ error: "Missing post id" });
    }

    const post = db.prepare(`
      SELECT * FROM posts
      WHERE id = ? AND userId = ?
    `).get(id, userId);

    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    if (post.status !== "ready") {
      return res.status(400).json({ error: "Post not ready yet" });
    }

    const user = db.prepare(`
      SELECT igUserId, igAccessToken
      FROM users
      WHERE id = ?
    `).get(userId);

    if (!user?.igUserId || !user?.igAccessToken) {
      return res.status(400).json({ error: "Instagram not connected" });
    }

    const creationId = await createInstagramMediaContainer({
      igUserId: user.igUserId,
      imageUrl: post.imageUrl,
      caption: post.caption,
      accessToken: user.igAccessToken
    });

    const mediaId = await publishInstagramMedia({
      igUserId: user.igUserId,
      creationId,
      accessToken: user.igAccessToken
    });

    db.prepare(`
      UPDATE posts
      SET status = 'posted'
      WHERE id = ? AND userId = ?
    `).run(id, userId);

    return res.json({
      success: true,
      message: "Posted to Instagram successfully",
      mediaId
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: err.message || "Instagram publish failed"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});