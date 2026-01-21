import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();

// ✅ IMPORTANT for Render/Reverse Proxy (secure cookies + req.protocol)
app.set("trust proxy", 1);

app.use(cookieParser());
app.use(express.json());

const PORT = process.env.PORT || 3001;

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SHOPIFY_SCOPES,
  SHOPIFY_APP_URL,
} = process.env;

// ---------- env checks ----------
function assertEnv() {
  const missing = [];
  if (!SHOPIFY_API_KEY) missing.push("SHOPIFY_API_KEY");
  if (!SHOPIFY_API_SECRET) missing.push("SHOPIFY_API_SECRET");
  if (!SHOPIFY_SCOPES) missing.push("SHOPIFY_SCOPES");
  if (!SHOPIFY_APP_URL) missing.push("SHOPIFY_APP_URL");
  return missing;
}

const missing = assertEnv();
if (missing.length) {
  console.log("❌ Missing env vars:", missing.join(", "));
}

// ✅ remove trailing slash
const APP_URL = (SHOPIFY_APP_URL || "").replace(/\/$/, "");
const IS_HTTPS = APP_URL.startsWith("https://");

// ✅ In-memory token store (use DB in production)
const TOKENS = new Map();

// ---------- helpers ----------
function isValidShop(shop) {
  return (
    typeof shop === "string" &&
    /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)
  );
}

/**
 * ✅ Shopify HMAC verify (hex compare)
 * NOTE: Shopify query is "hex string" => compare buffers as hex.
 */
function verifyHmac(query) {
  const { hmac, signature, ...rest } = query;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((key) => {
      const val = rest[key];
      if (Array.isArray(val)) return `${key}=${val.join(",")}`;
      return `${key}=${val}`;
    })
    .join("&");

  const generated = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  const a = Buffer.from(generated, "hex");
  const b = Buffer.from(String(hmac), "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * ✅ IMPORTANT FIX for redirect_uri not whitelisted
 * We MUST send EXACT redirect_uri that is whitelisted in Shopify Dev Dashboard.
 *
 * If running local:   http://localhost:3001/auth/callback
 * If running Render:  https://ai-customer-agent.onrender.com/auth/callback
 *
 * So: whitelist BOTH in Dev Dashboard Redirect URLs.
 */
function getRedirectUri(req) {
  // use env APP_URL always (most stable)
  // return `${APP_URL}/auth/callback`;

  // optional: auto-detect host if you want (but env is safer):
  // const proto = req.protocol; // needs trust proxy
  // return `${proto}://${req.get("host")}/auth/callback`;

  return `${APP_URL}/auth/callback`;
}

// ✅ EXACT redirect_uri that must be whitelisted in Shopify Dev Dashboard
function buildInstallUrl(req, shop, state) {
  const redirectUri = getRedirectUri(req);

  return (
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${encodeURIComponent(SHOPIFY_SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`
  );
}

// ✅ format addresses
function formatAddresses(addresses = []) {
  return (addresses || [])
    .map((a) => {
      const parts = [
        a?.address1,
        a?.address2,
        a?.city,
        a?.province,
        a?.zip,
        a?.country,
      ].filter(Boolean);
      return parts.join(", ");
    })
    .join(" | ");
}

// ✅ CSV generator
function toCSV(rows = []) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);

  const escape = (val) => {
    if (val === null || val === undefined) return "";
    const s = String(val);
    if (s.includes(",") || s.includes('"') || s.includes("\n")) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const lines = [
    headers.join(","),
    ...rows.map((row) => headers.map((h) => escape(row[h])).join(",")),
  ];
  return lines.join("\n");
}

// ---------- debug ----------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    port: PORT,
    appUrl: APP_URL,
    scopes: SHOPIFY_SCOPES,
    redirectUri: getRedirectUri(req),
    tokensCount: TOKENS.size,
    missingEnv: missing,
    serverHost: req.get("host"),
    serverProto: req.protocol,
  });
});

/**
 * ✅ IMPORTANT FIX: Escape iframe before OAuth
 * Shopify admin loads your app in an iframe.
 * OAuth/login pages can't be iframed -> accounts.shopify.com refused to connect
 */
app.get("/exitiframe", (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  if (!shop) return res.status(400).send("Missing shop");

  res.setHeader("Content-Type", "text/html");
  res.send(`
    <script>
      var target = "/auth?shop=${encodeURIComponent(shop)}";
      if (window.top === window.self) {
        window.location.href = target;
      } else {
        window.top.location.href = target;
      }
    </script>
  `);
});

// ---------- UI ----------
function uiHTML(shopDefault = "") {
  const safeShop = String(shopDefault).replace(/"/g, "&quot;");

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>AI Customer Agent</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; background:#f7f7f7; }
    h2 { margin-bottom: 10px; }
    .box { background:white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
    input { padding: 10px; width: 350px; margin: 5px 0; }
    button { padding: 10px 16px; margin-top: 10px; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #222; color: white; position: sticky; top: 0; }
    .row { display:flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    .note { color: #555; margin-top: 10px; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; background:#eee; font-size:12px; margin-left:8px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>📌 AI Customer Agent - Customer Information List <span class="pill">UI</span></h2>

    <div class="row">
      <div>
        <label><b>Shop domain</b></label><br/>
        <input id="shop" placeholder="example: qh6riz-kj.myshopify.com" value="${safeShop}" />
      </div>

      <div>
        <label><b>Limit (first)</b></label><br/>
        <input id="first" value="5" />
      </div>
    </div>

    <div class="row">
      <button onclick="install()">🔑 Install / Auth</button>
      <button onclick="loadCustomers()">📥 Load Customers</button>
      <button onclick="downloadCSV()">⬇️ Download CSV</button>
      <button onclick="openHealth()">🩺 Health</button>
    </div>

    <p class="note">
      ✅ Step 1: Click <b>Install/Auth</b><br/>
      ✅ Step 2: Click <b>Load Customers</b><br/>
      ✅ Step 3: Click <b>Download CSV</b>
    </p>

    <div id="status"></div>

    <div style="overflow:auto; max-height: 500px;">
      <table id="table" style="display:none;">
        <thead>
          <tr>
            <th>ID</th>
            <th>created_at</th>
            <th>updated_at</th>
            <th>first_name</th>
            <th>last_name</th>
            <th>orders_count</th>
            <th>state</th>
            <th>total_spent</th>
            <th>last_order_id</th>
            <th>note</th>
            <th>tags</th>
            <th>email</th>
            <th>phone</th>
            <th>currency</th>
            <th>addresses</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

<script>
  function getShop() {
    return document.getElementById("shop").value.trim();
  }

  // ✅ IMPORTANT: use /exitiframe
  function install() {
    const shop = getShop();
    if(!shop) return alert("Please Put Shop Domain.");
    window.location.href = "/exitiframe?shop=" + encodeURIComponent(shop);
  }

  async function loadCustomers() {
    const shop = getShop();
    const first = document.getElementById("first").value.trim() || "5";
    if(!shop) return alert("Please Put Shop Domain.");

    document.getElementById("status").innerHTML = "<p>Loading...</p>";

    const r = await fetch("/customers?shop=" + encodeURIComponent(shop) + "&first=" + encodeURIComponent(first));
    const data = await r.json().catch(() => ({}));

    if(!r.ok) {
      document.getElementById("status").innerHTML =
        "<p style='color:red'><b>Error:</b> " + (data.error || JSON.stringify(data) || "Failed") + "</p>";
      return;
    }

    const customers = data.customers || [];
    document.getElementById("status").innerHTML =
      "<p style='color:green'>✅ Loaded " + customers.length + " customer(s)</p>";

    const tbody = document.getElementById("tbody");
    tbody.innerHTML = "";

    customers.forEach(c => {
      const tr = document.createElement("tr");
      tr.innerHTML = \`
        <td>\${c.id || ""}</td>
        <td>\${c.created_at || ""}</td>
        <td>\${c.updated_at || ""}</td>
        <td>\${c.first_name || ""}</td>
        <td>\${c.last_name || ""}</td>
        <td>\${c.orders_count || 0}</td>
        <td>\${c.state || ""}</td>
        <td>\${c.total_spent || ""}</td>
        <td>\${c.last_order_id || ""}</td>
        <td>\${(c.note || "").replace(/</g,"&lt;")}</td>
        <td>\${c.tags || ""}</td>
        <td>\${c.email || ""}</td>
        <td>\${c.phone || ""}</td>
        <td>\${c.currency || ""}</td>
        <td>\${c.addresses || ""}</td>
      \`;
      tbody.appendChild(tr);
    });

    document.getElementById("table").style.display = "table";
  }

  function downloadCSV() {
    const shop = getShop();
    const first = document.getElementById("first").value.trim() || "5";
    if(!shop) return alert("Please Put Shop Domain.");
    window.location.href = "/customers.csv?shop=" + encodeURIComponent(shop) + "&first=" + encodeURIComponent(first);
  }

  function openHealth() {
    window.open("/health", "_blank");
  }
</script>

</body>
</html>
`;
}

// ✅ "/" = UI
app.get("/", (req, res) => {
  const shopDefault = (req.query.shop || "").toString();
  res.setHeader("Content-Type", "text/html");
  res.send(uiHTML(shopDefault));
});

// ✅ "/app" = alias
app.get("/app", (req, res) => {
  const shopDefault = (req.query.shop || "").toString();
  res.setHeader("Content-Type", "text/html");
  res.send(uiHTML(shopDefault));
});

// ---------- OAuth ----------
app.get("/auth", (req, res) => {
  const shop = (req.query.shop || "").toString().trim();

  if (!shop) return res.status(400).send("Missing shop param. Example: /auth?shop=xxx.myshopify.com");
  if (!isValidShop(shop)) return res.status(400).send("Invalid shop domain. Must end with .myshopify.com");

  const state = crypto.randomBytes(16).toString("hex");

  // ✅ cookie for state
  // - HTTPS: sameSite none + secure true
  // - Local: lax + secure false
  res.cookie("shopify_oauth_state", state, {
    httpOnly: true,
    secure: IS_HTTPS,
    sameSite: IS_HTTPS ? "none" : "lax",
  });

  return res.redirect(buildInstallUrl(req, shop, state));
});

app.get("/auth/callback", async (req, res) => {
  const { shop, code, state } = req.query;

  if (!shop || !code || !state) {
    return res
      .status(400)
      .send("Missing shop/code/state (Don't open /auth/callback manually. Use Install/Auth.)");
  }

  const cookieState = req.cookies?.shopify_oauth_state;
  if (!cookieState || cookieState !== state) {
    return res.status(400).send("Invalid state. Try /auth again.");
  }

  if (!verifyHmac(req.query)) {
    return res.status(400).send("HMAC verification failed.");
  }

  try {
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

    TOKENS.set(shop, tokenJson.access_token);

    // ✅ back to UI
    return res.redirect(`/?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    return res.status(500).send("Callback error: " + (err?.message || String(err)));
  }
});

// ---------- Data ----------
app.get("/customers", async (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  const first = req.query.first || 5;

  if (!shop) return res.status(400).json({ error: "Missing shop param" });

  const token = TOKENS.get(shop);
  if (!token) return res.status(401).json({ error: "No token found for this shop. Click Install/Auth first." });

  const apiVersion = "2026-01";
  const url = `https://${shop}/admin/api/${apiVersion}/customers.json?limit=${first}`;

  const r = await fetch(url, {
    headers: {
      "X-Shopify-Access-Token": token,
      "Content-Type": "application/json",
    },
  });

  const data = await r.json().catch(() => ({}));

  if (!r.ok) {
    return res.status(r.status).json({ error: data?.errors || "Shopify API error", raw: data });
  }

  const customers = (data.customers || []).map((c) => ({
    id: c.id,
    created_at: c.created_at,
    updated_at: c.updated_at,
    first_name: c.first_name,
    last_name: c.last_name,
    orders_count: c.orders_count,
    state: c.state,
    total_spent: c.total_spent,
    last_order_id: c.last_order_id,
    note: c.note,
    tags: c.tags,
    email: c.email,
    phone: c.phone,
    currency: c.currency,
    addresses: formatAddresses(c.addresses),
  }));

  res.status(200).json({ customers });
});

app.get("/customers.csv", async (req, res) => {
  const shop = (req.query.shop || "").toString().trim();
  const first = req.query.first || 5;

  if (!shop) return res.status(400).send("Missing shop param");

  const token = TOKENS.get(shop);
  if (!token) return res.status(401).send("No token found. Click Install/Auth first.");

  const apiVersion = "2026-01";
  const url = `https://${shop}/admin/api/${apiVersion}/customers.json?limit=${first}`;

  const r = await fetch(url, {
    headers: {
      "X-Shopify-Access-Token": token,
      "Content-Type": "application/json",
    },
  });

  const data = await r.json().catch(() => ({}));

  if (!r.ok) {
    return res.status(r.status).send("Shopify API error: " + JSON.stringify(data));
  }

  const customers = (data.customers || []).map((c) => ({
    id: c.id,
    created_at: c.created_at,
    updated_at: c.updated_at,
    first_name: c.first_name,
    last_name: c.last_name,
    orders_count: c.orders_count,
    state: c.state,
    total_spent: c.total_spent,
    last_order_id: c.last_order_id,
    note: c.note,
    tags: c.tags,
    email: c.email,
    phone: c.phone,
    currency: c.currency,
    addresses: formatAddresses(c.addresses),
  }));

  const csv = toCSV(customers);

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="customers-${shop}.csv"`);
  res.send(csv);
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`✅ APP_URL: ${APP_URL}`);
  console.log(`✅ Redirect URI: ${APP_URL}/auth/callback`);
  console.log("✅ DEPLOY CHECK:", new Date().toISOString());
});
