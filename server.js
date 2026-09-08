const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');
const config = require('./config');

const PORT = 3000;

// ─── Token cache ───
let cachedToken = null;
let tokenExpiry = 0;

/**
 * Call Coohom SSO API to get an authentication token.
 * Caches the token and reuses it until TOKEN_TTL expires.
 */
async function getToken(name, email) {
  // Use cached token if still valid
  if (cachedToken && Date.now() < tokenExpiry) {
    return cachedToken;
  }

  const timestamp = String(Date.now());
  const sign = crypto
    .createHash('md5')
    .update(config.APPSECRET + config.APPKEY + config.APPUID + timestamp)
    .digest('hex');

  const params = new URLSearchParams({
    appuid: config.APPUID,
    appkey: config.APPKEY,
    timestamp,
    sign,
  });
  const body = JSON.stringify({ name, email });

  const result = await new Promise((resolve, reject) => {
    const url = `https://api.coohom.com/global/i18n-user/login?${params}`;
    const parsed = new URL(url);

    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ raw: data });
          }
        });
      },
    );

    req.on('error', reject);
    req.write(body);
    req.end();
  });

  const token = result.d?.token;
  if (token) {
    cachedToken = token;
    tokenExpiry = Date.now() + config.TOKEN_TTL;
    console.log(`[SSO] Token acquired, expires at ${new Date(tokenExpiry).toLocaleString()}`);
  }

  return token;
}

// ─── Express app ───

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

/**
 * GET /config
 * Returns the launch ID needed by the demo page.
 * The real credentials (APPUID, APPKEY, APPSECRET) are never exposed to the client.
 */
app.get('/config', (req, res) => {
  res.json({ launchId: config.LANUCH_ID });
});

/**
 * POST /login
 *
 * Body (optional):
 *   { name: "User Name", email: "user@example.com" }
 *
 * If name/email are omitted, defaults from config.js are used.
 *
 * Response (success):
 *   { c: "0", token: "..." }
 *
 * Response (failure):
 *   { c: "1", m: "Error message" }
 */
app.post('/login', async (req, res) => {
  try {
    const name = req.body?.name || config.USER_NAME;
    const email = req.body?.email || config.USER_EMAIL;
    const token = await getToken(name, email);

    if (token) {
      res.json({ c: '0', token });
    } else {
      res.status(500).json({ c: '1', m: 'No token returned from Coohom' });
    }
  } catch (err) {
    console.error('[SSO] Login error:', err);
    res.status(500).json({ c: '1', m: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`SSO server running at http://localhost:${PORT}`);
  console.log(`Token cache TTL: ${config.TOKEN_TTL / 1000 / 60 / 60} hours`);
});