import express from "express";
import fetch from "node-fetch";
import Database from "better-sqlite3";
import {
  createFederation,
  MemoryKvStore,
  generateCryptoKeyPair,
  exportJwk,
  importJwk
} from "@fedify/fedify";
import { 
  Follow, 
  Accept, 
  Undo,
  Person,
  Create, // FIX: Ditambahkan untuk Outbox
  Note,    // FIX: Ditambahkan untuk Outbox
  CryptographicKey
} from "@fedify/vocab";
import { integrateFederation } from "@fedify/express";
import dotenv from "dotenv";
import compression from "compression";
import helmet from "helmet";
import crypto from "node:crypto";

dotenv.config();

const DOMAIN = process.env.DOMAIN;
const PORT = process.env.PORT || 3000;
const SYNC_TTL = Number(process.env.SYNC_TTL_MS || 300000);

if (!DOMAIN) {
  console.error("DOMAIN env required");
  process.exit(1);
}

const app = express();
app.set("trust proxy", true);
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "1mb" }));

/* ================= DATABASE ================= */

const db = new Database("./data/bridge.db");

db.exec(`
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  userId TEXT,
  description TEXT,
  avatar TEXT,
  createdAt INTEGER,
  lastPostSync INTEGER DEFAULT 0,
  lastCommentSync INTEGER DEFAULT 0,
  publicKey TEXT,      
  privateKey TEXT      
);

CREATE TABLE IF NOT EXISTS posts (
  postId TEXT PRIMARY KEY,
  username TEXT,
  title TEXT,
  rawContent TEXT,
  sensitive INTEGER,
  createdAt INTEGER
);

CREATE TABLE IF NOT EXISTS comments (
  commentId TEXT PRIMARY KEY,
  postId TEXT,
  username TEXT,
  content TEXT,
  createdAt INTEGER
);

CREATE TABLE IF NOT EXISTS followers (
  username TEXT,
  actor TEXT,
  PRIMARY KEY(username, actor)
);
`);

/* ================= UTIL ================= */

function iso(ms) {
  return new Date(ms).toISOString();
}

function hasFollowers(username) {
  const row = db.prepare(
    "SELECT COUNT(*) as c FROM followers WHERE username=?"
  ).get(username);
  return row.c > 0;
}

/* ================= USER FETCH ================= */

async function ensureUser(username) {
  let user = db.prepare(
    "SELECT * FROM users WHERE username=?"
  ).get(username);

  if (user) return user;

  const r = await fetch(
    `https://lahelu.com/api/user/get-username?username=${username}`
  );
  if (!r.ok) return null;

  const data = await r.json();
  const u = data.userInfo;
  if (!u) return null;

  db.prepare(`
    INSERT INTO users (username, userId, description, avatar, createdAt, lastPostSync, lastCommentSync)
    VALUES (?, ?, ?, ?, ?, 0, 0)
  `).run(
    u.username,
    u.userId,
    u.description || "",
    u.avatar || "",
    u.createTime
  );

  return db.prepare(
    "SELECT * FROM users WHERE username=?"
  ).get(username);
}

/* ================= SYNC POSTS ================= */

async function syncPosts(username) {
  const user = await ensureUser(username);
  if (!user) return;
  if (!hasFollowers(username)) return;
  if (Date.now() - user.lastPostSync < SYNC_TTL) return;

  const r = await fetch(
    `https://lahelu.com/api/post/get-user-posts?userId=${user.userId}&isNewest=true&cursor=1`
  );

  if (!r.ok) return;

  const data = await r.json();

  for (const p of data.postInfos || []) {
    db.prepare(`
      INSERT OR REPLACE INTO posts
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      p.postId,
      username,
      p.title,
      JSON.stringify(p.content || []),
      p.isSensitive ? 1 : 0,
      p.createTime
    );
  }

  db.prepare(
    "UPDATE users SET lastPostSync=? WHERE username=?"
  ).run(Date.now(), username);
}

/* ================= FEDIFY ================= */

/* ================ FEDIFY (routing) ================ */

const federation = createFederation({
  origin: DOMAIN,
  kv: new MemoryKvStore()
});

/* Actor */
federation.setActorDispatcher(
  "/users/{identifier}",
  async (ctx, identifier) => { 
    const username = typeof identifier === "object" ? identifier.identifier : identifier;
    
    const user = await ensureUser(username);
    if (!user) return null;

    const keyPairs = await ctx.getActorKeyPairs(username);
    const actorUri = ctx.getActorUri(username);

    // Export ke PEM

    return new Person({
          id: ctx.getActorUri(username).toString(),
          preferredUsername: username,
          summary: user.description || "", 
          inbox: ctx.getInboxUri(username),
          outbox: ctx.getOutboxUri(username),
          publicKey: new CryptographicKey({
            id: new URL(`${ctx.getActorUri(username)}#main-key`),
            owner: actorUri,
            publicKey: keyPairs[0].publicKey
          })
    });
  }
)
/* KeyPairs */
.setKeyPairsDispatcher(async (ctx, identifier) => {
  const username = typeof identifier === "object" ? identifier.identifier : identifier;
  
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user) return [];

  if (user.publicKey && user.privateKey) {
    return [{
      publicKey: await importJwk(JSON.parse(user.publicKey), "public"),
      privateKey: await importJwk(JSON.parse(user.privateKey), "private")
    }];
  }

  const { publicKey, privateKey } = await generateCryptoKeyPair();
  
  const pubJwk = await exportJwk(publicKey);
  const privJwk = await exportJwk(privateKey);

  db.prepare("UPDATE users SET publicKey=?, privateKey=? WHERE username=?")
    .run(JSON.stringify(pubJwk), JSON.stringify(privJwk), username);

  return [{ publicKey, privateKey }];
});

/* Outbox - FIX: Menggunakan Class dari vocab dan penanganan identifier */
federation.setOutboxDispatcher(
  "/users/{identifier}/outbox",
  async (ctx, identifier) => {
    const username = typeof identifier === "object" ? identifier.identifier : identifier;

    if (!hasFollowers(username)) return [];

    await syncPosts(username);

    const rows = db.prepare(`
      SELECT * FROM posts
      WHERE username=?
      ORDER BY createdAt DESC
    `).all(username);

    return rows.map(p => new Create({
      actor: ctx.getActorUri(username).href,
      to: new URL("https://www.w3.org/ns/activitystreams#Public"),
      object: new Note({
        id: `${DOMAIN}/users/${username}/posts/${p.postId}`,
        attributedTo: ctx.getActorUri(username).href,
        content: p.title,
        published: new Date(p.createdAt), // Date object
        sensitive: !!p.sensitive
      })
    }));
  }
);

/* Inbox - FIX: Safely extracting parameter username */
federation.setInboxListeners("/users/{identifier}/inbox", "/inbox")
  .on(Follow, async (ctx, follow) => {
  try {
    const username = ctx.parameters?.identifier 
      || (ctx.url ? new URL(ctx.url).pathname.split("/")[2] : null);
    if (!username) return;

    const actorId = follow.actorId?.href;
    if (!actorId) return;

    console.log("FOLLOW from:", actorId);

    db.prepare(`
      INSERT OR IGNORE INTO followers (username, actor)
      VALUES (?, ?)
    `).run(username, actorId);

    // Explicitly stringify every field — Mastodon rejects URL objects
    const followId = follow.id instanceof URL 
      ? follow.id.href 
      : (typeof follow.id === "string" ? follow.id : null);

    if (!followId) {
      console.error("Follow has no id, cannot send Accept");
      return;
    }

    const actorUri = ctx.getActorUri(username);
    const actorUriStr = actorUri instanceof URL ? actorUri.href : String(actorUri);

    const accept = new Accept({
      id: new URL(`${DOMAIN}/users/${username}/accepts/${crypto.randomUUID()}`),
      actor: new URL(actorUriStr),
      object: new URL(followId),
    });

    await ctx.sendActivity(
      { identifier: username },
      follow.actorId,
      accept
    );

    console.log("ACCEPT sent successfully for", username);
  } catch (err) {
    console.error("ERROR sending ACCEPT:", err);
  }
})
  .on(Undo, async (ctx, undo) => {
    const username = ctx.parameters?.identifier || (ctx.url ? new URL(ctx.url).pathname.split("/")[2] : null);
    if (!username) return;
    
    const object = await undo.getObject();
    
    if (object instanceof Follow) {
      const actorId = undo.actorId?.href;
      if (!actorId) return;

      db.prepare(`
        DELETE FROM followers
        WHERE username=? AND actor=?
      `).run(username, actorId);
    }
  });

/* ================= NODEINFO ================= */

app.get("/.well-known/nodeinfo", (req, res) => {
  res.json({
    links: [{
      rel: "http://nodeinfo.diaspora.software/ns/schema/2.0",
      href: `${DOMAIN}/nodeinfo/2.0`
    }]
  });
});

app.get("/nodeinfo/2.0", (req, res) => {
  const userCount = db.prepare(
    "SELECT COUNT(*) as c FROM users"
  ).get().c;

  res.json({
    version: "2.0",
    software: {
      name: "lahelu-bridge",
      version: "2.0.0"
    },
    protocols: ["activitypub"],
    usage: {
      users: { total: userCount }
    },
    openRegistrations: false
  });
});

/* ================= HEARTBEAT ================= */

app.get("/heartbeat", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime()
  });
});

/* ================= REGISTER ================= */

app.use(integrateFederation(federation, (req) => undefined));

/* ================= START ================= */

app.listen(PORT, () => {
  console.log(`Lahelu → Fediverse bridge running on port ${PORT} (Fedify)`);
});