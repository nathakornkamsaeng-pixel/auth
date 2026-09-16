/*
 * TIME AUTHENTICATOR
 * Cloudflare Worker + KV
 *
 * KV binding required:
 *   kv
 *
 * Features:
 * - First-time setup
 * - Password authentication
 * - PBKDF2-SHA-256 password hashing
 * - Random session cookie
 * - SHA-256 session token stored in KV
 * - Configurable session expiration
 * - Logout
 * - No WebAuthn
 * - No Face ID
 */

const CONFIG_KEY = "auth:config";
const SESSION_COOKIE = "auth_session";

const DEFAULT_SESSION_MINUTES = 30;
const MAX_SESSION_MINUTES = 10080; // 7 days

const PASSWORD_ITERATIONS = 120000;

const encoder = new TextEncoder();


/* =========================================================
   MAIN
   ========================================================= */

export default {
  async fetch(request, env) {
    try {
      if (!env.kv) {
        return json(
          {
            ok: false,
            error: "KV binding 'kv' is missing."
          },
          500
        );
      }

      const url = new URL(request.url);

      // -------------------------
      // API
      // -------------------------

      if (
        url.pathname === "/api/status" &&
        request.method === "GET"
      ) {
        return await apiStatus(request, env);
      }

      if (
        url.pathname === "/api/setup" &&
        request.method === "POST"
      ) {
        return await apiSetup(request, env);
      }

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return await apiLogin(request, env);
      }

      if (
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        return await apiLogout(request, env);
      }

      if (
        url.pathname === "/api/session" &&
        request.method === "GET"
      ) {
        return await apiSession(request, env);
      }

      // -------------------------
      // Web page
      // -------------------------

      if (
        url.pathname === "/" ||
        url.pathname === "/setup"
      ) {
        return html(await mainPage(request, env));
      }

      return new Response("Not Found", {
        status: 404,
        headers: {
          "content-type":
            "text/plain; charset=utf-8"
        }
      });

    } catch (error) {
      console.error("AUTHENTICATOR ERROR:", error);

      return json(
        {
          ok: false,
          error: "Internal authenticator error",
          detail:
            String(error?.message || error)
        },
        500
      );
    }
  }
};


/* =========================================================
   RESPONSE HELPERS
   ========================================================= */

function json(
  data,
  status = 200,
  headers = {}
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=utf-8",
        "cache-control":
          "no-store",
        ...headers
      }
    }
  );
}


function html(content) {
  return new Response(
    content,
    {
      status: 200,
      headers: {
        "content-type":
          "text/html; charset=utf-8",

        "cache-control":
          "no-store",

        "x-content-type-options":
          "nosniff",

        "referrer-policy":
          "no-referrer",

        "content-security-policy":
          "default-src 'self'; " +
          "script-src 'self' 'unsafe-inline'; " +
          "style-src 'self' 'unsafe-inline'; " +
          "connect-src 'self'; " +
          "frame-ancestors 'none';"
      }
    }
  );
}


/* =========================================================
   BASE64URL
   ========================================================= */

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


function base64UrlToBytes(value) {
  const padded =
    value
      .replace(/-/g, "+")
      .replace(/_/g, "/") +
    "=".repeat(
      (4 - (value.length % 4)) % 4
    );

  const binary = atob(padded);

  const bytes =
    new Uint8Array(binary.length);

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}


/* =========================================================
   RANDOM
   ========================================================= */

function randomBytes(length) {
  const bytes =
    new Uint8Array(length);

  crypto.getRandomValues(bytes);

  return bytes;
}


function randomToken() {
  return bytesToBase64Url(
    randomBytes(32)
  );
}


/* =========================================================
   SHA-256
   ========================================================= */

async function sha256(data) {
  const bytes =
    data instanceof Uint8Array
      ? data
      : encoder.encode(String(data));

  return new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      bytes
    )
  );
}


async function sha256Base64Url(data) {
  return bytesToBase64Url(
    await sha256(data)
  );
}


/* =========================================================
   CONSTANT-TIME COMPARISON
   ========================================================= */

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}


/* =========================================================
   PASSWORD HASHING
   ========================================================= */

async function hashPassword(
  password,
  salt = randomBytes(16)
) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const derived =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations:
          PASSWORD_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      256
    );

  return {
    algorithm:
      "PBKDF2-SHA-256",

    iterations:
      PASSWORD_ITERATIONS,

    salt:
      bytesToBase64Url(salt),

    hash:
      bytesToBase64Url(
        new Uint8Array(derived)
      )
  };
}


async function verifyPassword(
  password,
  stored
) {
  const salt =
    base64UrlToBytes(
      stored.salt
    );

  const result =
    await hashPassword(
      password,
      salt
    );

  return constantTimeEqual(
    base64UrlToBytes(
      result.hash
    ),
    base64UrlToBytes(
      stored.hash
    )
  );
}


/* =========================================================
   CONFIG
   ========================================================= */

async function getConfig(env) {
  return await env.kv.get(
    CONFIG_KEY,
    "json"
  );
}


async function saveConfig(
  env,
  config
) {
  await env.kv.put(
    CONFIG_KEY,
    JSON.stringify(config)
  );
}


/* =========================================================
   SETUP
   ========================================================= */

async function apiSetup(
  request,
  env
) {
  const existing =
    await getConfig(env);

  if (existing) {
    return json(
      {
        ok: false,
        error:
          "Authenticator has already been configured."
      },
      409
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        ok: false,
        error: "Invalid request."
      },
      400
    );
  }

  const password =
    String(body.password || "");

  let sessionMinutes =
    Number(body.sessionMinutes);

  if (password.length < 8) {
    return json(
      {
        ok: false,
        error:
          "Password must be at least 8 characters."
      },
      400
    );
  }

  if (
    !Number.isFinite(sessionMinutes)
  ) {
    sessionMinutes =
      DEFAULT_SESSION_MINUTES;
  }

  sessionMinutes =
    Math.floor(sessionMinutes);

  if (
    sessionMinutes < 1 ||
    sessionMinutes >
      MAX_SESSION_MINUTES
  ) {
    return json(
      {
        ok: false,
        error:
          `Session duration must be between 1 and ${MAX_SESSION_MINUTES} minutes.`
      },
      400
    );
  }

  const passwordHash =
    await hashPassword(password);

  const config = {
    version: 1,

    password:
      passwordHash,

    sessionMinutes,

    createdAt:
      Date.now()
  };

  await saveConfig(
    env,
    config
  );

  return await createSessionResponse(
    env,
    sessionMinutes
  );
}


/* =========================================================
   PASSWORD LOGIN
   ========================================================= */

async function apiLogin(
  request,
  env
) {
  const config =
    await getConfig(env);

  if (!config) {
    return json(
      {
        ok: false,
        error:
          "Authenticator has not been configured."
      },
      400
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        ok: false,
        error: "Invalid request."
      },
      400
    );
  }

  const password =
    String(body.password || "");

  if (!password) {
    return json(
      {
        ok: false,
        error: "Password is required."
      },
      400
    );
  }

  const valid =
    await verifyPassword(
      password,
      config.password
    );

  if (!valid) {
    return json(
      {
        ok: false,
        error: "Incorrect password."
      },
      401
    );
  }

  return await createSessionResponse(
    env,
    config.sessionMinutes
  );
}


/* =========================================================
   SESSION CREATION
   ========================================================= */

async function createSessionResponse(
  env,
  minutes
) {
  const token =
    randomToken();

  /*
   * IMPORTANT:
   *
   * The plaintext token is NOT stored
   * in KV.
   *
   * Only its SHA-256 hash is stored.
   */

  const tokenHash =
    await sha256Base64Url(
      token
    );

  const expiresAt =
    Date.now() +
    minutes * 60 * 1000;

  const session = {
    createdAt:
      Date.now(),

    expiresAt
  };

  await env.kv.put(
    `auth:session:${tokenHash}`,
    JSON.stringify(session),
    {
      expirationTtl:
        Math.max(
          60,
          minutes * 60
        )
    }
  );

  return json(
    {
      ok: true,
      authenticated: true,
      expiresAt
    },
    200,
    {
      "set-cookie":
        makeSessionCookie(
          token,
          minutes * 60
        )
    }
  );
}


/* =========================================================
   COOKIE
   ========================================================= */

function makeSessionCookie(
  token,
  maxAge
) {
  return [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${Math.floor(maxAge)}`
  ].join("; ");
}


function makeDeleteCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0"
  ].join("; ");
}


/* =========================================================
   READ COOKIE
   ========================================================= */

function getCookie(
  request,
  name
) {
  const header =
    request.headers.get(
      "Cookie"
    );

  if (!header) {
    return null;
  }

  for (
    const part of header.split(";")
  ) {
    const index =
      part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      part
        .slice(0, index)
        .trim();

    const value =
      part
        .slice(index + 1)
        .trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}


/* =========================================================
   SESSION VALIDATION
   ========================================================= */

async function getSession(
  request,
  env
) {
  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (!token) {
    return null;
  }

  const tokenHash =
    await sha256Base64Url(
      token
    );

  const key =
    `auth:session:${tokenHash}`;

  const session =
    await env.kv.get(
      key,
      "json"
    );

  if (!session) {
    return null;
  }

  if (
    !session.expiresAt ||
    Date.now() >=
      session.expiresAt
  ) {
    await env.kv.delete(key);

    return null;
  }

  return {
    ...session,
    key
  };
}


/* =========================================================
   STATUS
   ========================================================= */

async function apiStatus(
  request,
  env
) {
  const config =
    await getConfig(env);

  if (!config) {
    return json({
      ok: true,
      setupRequired: true,
      authenticated: false
    });
  }

  const session =
    await getSession(
      request,
      env
    );

  return json({
    ok: true,
    setupRequired: false,
    authenticated:
      !!session,

    expiresAt:
      session
        ? session.expiresAt
        : null,

    sessionMinutes:
      config.sessionMinutes
  });
}


/* =========================================================
   SESSION API
   ========================================================= */

async function apiSession(
  request,
  env
) {
  const session =
    await getSession(
      request,
      env
    );

  if (!session) {
    return json({
      ok: true,
      authenticated: false
    });
  }

  return json({
    ok: true,
    authenticated: true,
    expiresAt:
      session.expiresAt
  });
}


/* =========================================================
   LOGOUT
   ========================================================= */

async function apiLogout(
  request,
  env
) {
  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (token) {
    const tokenHash =
      await sha256Base64Url(
        token
      );

    await env.kv.delete(
      `auth:session:${tokenHash}`
    );
  }

  return json(
    {
      ok: true,
      authenticated: false
    },
    200,
    {
      "set-cookie":
        makeDeleteCookie()
    }
  );
}


/* =========================================================
   WEB PAGE
   ========================================================= */

async function mainPage(
  request,
  env
) {
  const config =
    await getConfig(env);

  const session =
    await getSession(
      request,
      env
    );

  let page;

  if (!config) {
    page =
      setupPage();
  } else if (session) {
    page =
      unlockedPage(
        session.expiresAt
      );
  } else {
    page =
      loginPage();
  }

  return `
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,
           initial-scale=1.0,
           viewport-fit=cover"
>

<meta
  name="color-scheme"
  content="dark"
>

<title>
  Time Authenticator
</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;

  min-height: 100vh;

  padding: 20px;

  display: flex;

  align-items: center;

  justify-content: center;

  background:
    linear-gradient(
      135deg,
      #020617,
      #111827
    );

  color: white;

  font-family:
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}

.card {
  width: 100%;

  max-width: 460px;

  padding: 30px;

  border-radius: 24px;

  background:
    rgba(30, 41, 59, 0.96);

  border:
    1px solid
    rgba(255,255,255,0.08);

  box-shadow:
    0 25px 80px
    rgba(0,0,0,0.45);
}

.icon {
  width: 64px;

  height: 64px;

  border-radius: 18px;

  display: flex;

  align-items: center;

  justify-content: center;

  background:
    linear-gradient(
      135deg,
      #2563eb,
      #7c3aed
    );

  font-size: 30px;

  margin-bottom: 20px;
}

h1 {
  margin:
    0 0 8px;

  font-size: 28px;
}

h2 {
  margin-top: 0;
}

.description {
  color: #94a3b8;

  line-height: 1.5;

  margin-bottom: 25px;
}

label {
  display: block;

  color: #cbd5e1;

  font-size: 14px;

  margin-bottom: 7px;
}

input {
  width: 100%;

  padding: 14px;

  margin-bottom: 16px;

  border-radius: 12px;

  border:
    1px solid
    #475569;

  background:
    #0f172a;

  color: white;

  font-size: 16px;

  outline: none;
}

input:focus {
  border-color:
    #60a5fa;
}

button {
  width: 100%;

  padding: 14px;

  margin-top: 7px;

  border: 0;

  border-radius: 12px;

  background:
    #2563eb;

  color: white;

  font-size: 16px;

  font-weight: 600;

  cursor: pointer;
}

button:hover {
  background:
    #1d4ed8;
}

button.secondary {
  background:
    #334155;
}

button.secondary:hover {
  background:
    #475569;
}

button.danger {
  background:
    #dc2626;
}

button.danger:hover {
  background:
    #b91c1c;
}

.status {
  margin-top: 16px;

  padding: 14px;

  border-radius: 12px;

  background:
    #0f172a;

  color: #cbd5e1;

  line-height: 1.5;
}

.error {
  color:
    #fca5a5;
}

.success {
  color:
    #86efac;
}

.small {
  color:
    #94a3b8;

  font-size: 13px;

  line-height: 1.5;
}

.timer {
  text-align: center;

  font-size: 42px;

  font-weight: 700;

  margin:
    25px 0;
}

.section {
  margin-top: 25px;

  padding-top: 25px;

  border-top:
    1px solid
    rgba(255,255,255,0.08);
}

</style>

</head>

<body>

<div class="card">

<div class="icon">
  🔐
</div>

<h1>
  Time Authenticator
</h1>

<div class="description">
  Password-protected access with
  automatic session expiration.
</div>

${page}

</div>


<script>

async function api(
  url,
  options = {}
) {
  const response =
    await fetch(
      url,
      {
        ...options,

        headers: {
          "content-type":
            "application/json",

          ...(options.headers || {})
        }
      }
    );

  let data;

  try {
    data =
      await response.json();
  } catch {
    data = {
      ok: false,
      error:
        "Invalid server response."
    };
  }

  if (!response.ok) {
    throw new Error(
      data.error ||
      "Request failed."
    );
  }

  return data;
}


/* =====================================================
   SETUP
   ===================================================== */

async function setup() {

  const password =
    document.getElementById(
      "password"
    ).value;

  const confirm =
    document.getElementById(
      "confirm"
    ).value;

  const minutes =
    Number(
      document.getElementById(
        "minutes"
      ).value
    );

  const status =
    document.getElementById(
      "status"
    );

  if (password.length < 8) {
    status.innerHTML =
      '<span class="error">' +
      'Password must be at least 8 characters.' +
      '</span>';

    return;
  }

  if (password !== confirm) {
    status.innerHTML =
      '<span class="error">' +
      'Passwords do not match.' +
      '</span>';

    return;
  }

  if (
    !Number.isFinite(minutes) ||
    minutes < 1 ||
    minutes > 10080
  ) {
    status.innerHTML =
      '<span class="error">' +
      'Session duration must be between 1 and 10080 minutes.' +
      '</span>';

    return;
  }

  status.textContent =
    "Creating authenticator...";

  try {

    const result =
      await api(
        "/api/setup",
        {
          method: "POST",

          body:
            JSON.stringify({
              password,
              sessionMinutes:
                minutes
            })
        }
      );

    window.location =
      "/";

  } catch (error) {

    status.innerHTML =
      '<span class="error">' +
      escapeHtml(
        error.message
      ) +
      '</span>';
  }
}


/* =====================================================
   LOGIN
   ===================================================== */

async function login() {

  const password =
    document.getElementById(
      "password"
    ).value;

  const status =
    document.getElementById(
      "status"
    );

  status.textContent =
    "Checking password...";

  try {

    await api(
      "/api/login",
      {
        method: "POST",

        body:
          JSON.stringify({
            password
          })
      }
    );

    window.location =
      "/";

  } catch (error) {

    status.innerHTML =
      '<span class="error">' +
      escapeHtml(
        error.message
      ) +
      '</span>';
  }
}


/* =====================================================
   LOGOUT
   ===================================================== */

async function logout() {

  try {

    await api(
      "/api/logout",
      {
        method: "POST",

        body: "{}"
      }
    );

  } finally {

    window.location =
      "/";
  }
}


/* =====================================================
   TIMER
   ===================================================== */

const expiration =
  ${session?.expiresAt || 0};

function updateTimer() {

  const timer =
    document.getElementById(
      "timer"
    );

  if (!timer) {
    return;
  }

  const remaining =
    Math.max(
      0,
      expiration -
      Date.now()
    );

  if (remaining <= 0) {

    timer.textContent =
      "Expired";

    setTimeout(
      () => {
        window.location =
          "/";
      },
      500
    );

    return;
  }

  const totalSeconds =
    Math.floor(
      remaining / 1000
    );

  const minutes =
    Math.floor(
      totalSeconds / 60
    );

  const seconds =
    totalSeconds % 60;

  const hours =
    Math.floor(
      minutes / 60
    );

  const remainingMinutes =
    minutes % 60;

  if (hours > 0) {

    timer.textContent =
      String(hours)
        .padStart(2, "0") +
      ":" +
      String(
        remainingMinutes
      ).padStart(2, "0") +
      ":" +
      String(seconds)
        .padStart(2, "0");

  } else {

    timer.textContent =
      String(
        remainingMinutes
      ).padStart(2, "0") +
      ":" +
      String(seconds)
        .padStart(2, "0");
  }
}

if (expiration) {

  updateTimer();

  setInterval(
    updateTimer,
    1000
  );
}


/* =====================================================
   ENTER KEY
   ===================================================== */

document.addEventListener(
  "keydown",
  event => {

    if (
      event.key === "Enter"
    ) {

      const password =
        document.getElementById(
          "password"
        );

      if (password) {

        const setup =
          document.getElementById(
            "confirm"
          );

        if (setup) {
          setup();
        } else {
          login();
        }
      }
    }
  }
);


/* =====================================================
   ESCAPE HTML
   ===================================================== */

function escapeHtml(value) {

  return String(value)
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}

</script>

</body>

</html>
`;
}


/* =========================================================
   SETUP PAGE HTML
   ========================================================= */

function setupPage() {
  return `
<h2>
  First-time setup
</h2>

<p class="small">
  Create the password that will unlock
  this authenticator.
</p>

<label>
  Password
</label>

<input
  id="password"
  type="password"
  autocomplete="new-password"
  placeholder="At least 8 characters"
>

<label>
  Confirm password
</label>

<input
  id="confirm"
  type="password"
  autocomplete="new-password"
  placeholder="Enter the password again"
>

<label>
  Session duration
</label>

<input
  id="minutes"
  type="number"
  min="1"
  max="10080"
  value="30"
>

<p class="small">
  After this time, you will have to unlock
  the authenticator again.
</p>

<button onclick="setup()">
  Create Authenticator
</button>

<div
  id="status"
  class="status"
>
</div>
`;
}


/* =========================================================
   LOGIN PAGE HTML
   ========================================================= */

function loginPage() {
  return `
<h2>
  Unlock
</h2>

<p class="small">
  Enter your authenticator password.
</p>

<label>
  Password
</label>

<input
  id="password"
  type="password"
  autocomplete="current-password"
  placeholder="Password"
>

<button onclick="login()">
  Unlock
</button>

<div
  id="status"
  class="status"
>
</div>
`;
}


/* =========================================================
   UNLOCKED PAGE HTML
   ========================================================= */

function unlockedPage(
  expiresAt
) {
  return `
<h2>
  Unlocked
</h2>

<div class="status">
  <span class="success">
    ✓ Authenticator unlocked
  </span>
</div>

<div
  id="timer"
  class="timer"
>
  --
</div>

<div class="small">
  Remaining session time
</div>

<div class="section">

  <button
    class="danger"
    onclick="logout()"
  >
    Log Out
  </button>

</div>
`;
}
