import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
app.use(cookieParser());

const PORT = process.env.PORT || 3000;


const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SHOPIFY_SCOPES,
  SHOPIFY_APP_URL,
} = process.env;

function buildInstallUrl(shop, state) {
  const redirectUri = `${SHOPIFY_APP_URL}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${encodeURIComponent(SHOPIFY_SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;
  return installUrl;
}

function verifyHmac(query) {
  const { hmac, ...rest } = query;

  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${Array.isArray(rest[key]) ? rest[key].join(",") : rest[key]}`)
    .join("&");

  const generated = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(generated, "utf8"), Buffer.from(hmac, "utf8"));
}

// simple in-memory store (for now). In production use DB.
const TOKENS = new Map();

app.get("/", (req, res) => {
  res.send("AI Customer Agent is running ✅");
});

// Step 1: redirect to Shopify permission page
app.get("/auth", (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing shop param. Example: /auth?shop=xxx.myshopify.com");

  const state = crypto.randomBytes(16).toString("hex");

  // store state in cookie (simple)
  res.cookie("shopify_oauth_state", state, { httpOnly: true });

  const installUrl = buildInstallUrl(shop, state);
  return res.redirect(installUrl);
});

// Step 2: Shopify redirects back here with code
app.get("/auth/callback", express.urlencoded({ extended: true }), async (req, res) => {
  const { shop, code, state } = req.query;

  if (!shop || !code || !state) return res.status(400).send("Missing shop/code/state");

  const cookieState = req.cookies?.shopify_oauth_state;
  if (!cookieState || cookieState !== state) {
    return res.status(400).send("Invalid state. Try /auth again.");
  }

  if (!verifyHmac(req.query)) {
    return res.status(400).send("HMAC verification failed.");
  }

  // exchange code for access token
  const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: SHOPIFY_API_KEY,
      client_secret: SHOPIFY_API_SECRET,
      code,
    }),
  });

  const tokenJson = await tokenRes.json();

  if (!tokenRes.ok) {
    return res.status(500).send(`Token exchange failed: ${JSON.stringify(tokenJson)}`);
  }

  const accessToken = tokenJson.access_token;

  // store token (demo)
  TOKENS.set(shop, accessToken);

  res.send(`Installed ✅ Token saved for ${shop}. You can now call /customers?shop=${shop}`);
});

// Step 3: test endpoint — fetch customers using stored token
app.get("/customers", async (req, res) => {
  const shop = req.query.shop;
  const first = req.query.first || 5;

  if (!shop) return res.status(400).json({ error: "Missing shop param" });

  const token = TOKENS.get(shop);
  if (!token) return res.status(401).json({ error: "No token found for this shop. Go to /auth?shop=..." });

  const apiVersion = "2026-01";
  const url = `https://${shop}/admin/api/${apiVersion}/customers.json?limit=${first}`;

  const r = await fetch(url, {
    headers: {
      "X-Shopify-Access-Token": token,
      "Content-Type": "application/json",
    },
  });

  const data = await r.json();
  res.status(r.status).json(data);
});

app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
