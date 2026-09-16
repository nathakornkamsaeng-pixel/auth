/*
 * Time-Based Authenticator
 * Cloudflare Workers + KV + WebAuthn / Passkeys
 *
 * KV binding required:
 *   kv
 *
 * Features:
 *   - First-run setup page
 *   - Password setup
 *   - PBKDF2 password hashing
 *   - Face ID / Touch ID / Windows Hello / passkey
 *   - WebAuthn registration
 *   - WebAuthn login
 *   - 30-minute default sessions
 *   - Configurable session lifetime
 *   - Secure HttpOnly session cookie
 *   - Only SHA-256(session token) is stored in KV
 *   - Logout / session revocation
 */

const CONFIG_KEY = "auth:config";
const CREDENTIALS_KEY = "auth:credentials";

const SESSION_COOKIE = "auth_session";

const DEFAULT_SESSION_MINUTES = 30;
const MAX_SESSION_MINUTES = 7 * 24 * 60;

const PASSWORD_ITERATIONS = 120000;

const CHALLENGE_TTL_SECONDS = 120;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

      /*
       * API ROUTES
       */

      if (url.pathname === "/api/status" && request.method === "GET") {
        return await apiStatus(request, env);
      }

      if (url.pathname === "/api/setup" && request.method === "POST") {
        return await apiSetup(request, env);
      }

      if (url.pathname === "/api/login" && request.method === "POST") {
        return await apiPasswordLogin(request, env);
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        return await apiLogout(request, env);
      }

      /*
       * PASSKEY REGISTRATION
       */

      if (
        url.pathname === "/api/passkey/register/options" &&
        request.method === "POST"
      ) {
        return await passkeyRegisterOptions(request, env);
      }

      if (
        url.pathname === "/api/passkey/register/verify" &&
        request.method === "POST"
      ) {
        return await passkeyRegisterVerify(request, env);
      }

      /*
       * PASSKEY LOGIN
       */

      if (
        url.pathname === "/api/passkey/login/options" &&
        request.method === "POST"
      ) {
        return await passkeyLoginOptions(request, env);
      }

      if (
        url.pathname === "/api/passkey/login/verify" &&
        request.method === "POST"
      ) {
        return await passkeyLoginVerify(request, env);
      }

      /*
       * SESSION CHECK
       */

      if (url.pathname === "/api/session" && request.method === "GET") {
        const session = await getSession(request, env);

        if (!session) {
          return json({
            ok: false,
            authenticated: false
          });
        }

        return json({
          ok: true,
          authenticated: true,
          expiresAt: session.expiresAt
        });
      }

      /*
       * FRONTEND
       */

      if (url.pathname === "/" || url.pathname === "/setup") {
        return html(await mainPage(request, env));
      }

      /*
       * Everything else
       */

      return new Response("Not Found", {
        status: 404,
        headers: {
          "content-type": "text/plain; charset=utf-8"
        }
      });
    } catch (error) {
      console.error(error);

      return json(
        {
          ok: false,
          error: "Internal authenticator error",
          detail: String(error?.message || error)
        },
        500
      );
    }
  }
};


/* =========================================================
   BASIC RESPONSE HELPERS
   ========================================================= */

function json(data, status = 200, extraHeaders = {}) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...extraHeaders
  };

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function html(content, status = 200) {
  return new Response(content, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy":
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer"
    }
  });
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
  if (!value || typeof value !== "string") {
    throw new Error("Invalid base64url value");
  }

  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);

  const binary = atob(padded);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}


/* =========================================================
   RANDOM DATA
   ========================================================= */

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomToken(length = 32) {
  return bytesToBase64Url(randomBytes(length));
}


/* =========================================================
   HASHING
   ========================================================= */

async function sha256Bytes(data) {
  const buffer =
    data instanceof Uint8Array
      ? data
      : encoder.encode(String(data));

  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", buffer)
  );
}

async function sha256Base64Url(data) {
  return bytesToBase64Url(await sha256Bytes(data));
}


/* =========================================================
   PASSWORD HASH
   ========================================================= */

async function hashPassword(password, saltBytes = randomBytes(16)) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    salt: bytesToBase64Url(saltBytes),
    hash: bytesToBase64Url(new Uint8Array(bits)),
    iterations: PASSWORD_ITERATIONS
  };
}

async function verifyPassword(password, stored) {
  const salt = base64UrlToBytes(stored.salt);

  const result = await hashPassword(password, salt);

  return constantTimeEqual(
    base64UrlToBytes(result.hash),
    base64UrlToBytes(stored.hash)
  );
}


/* =========================================================
   CONSTANT-TIME COMPARISON
   ========================================================= */

function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array)) {
    a = new Uint8Array(a);
  }

  if (!(b instanceof Uint8Array)) {
    b = new Uint8Array(b);
  }

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
   CONFIG
   ========================================================= */

async function getConfig(env) {
  return await env.kv.get(CONFIG_KEY, "json");
}

async function saveConfig(env, config) {
  await env.kv.put(
    CONFIG_KEY,
    JSON.stringify(config)
  );
}


/* =========================================================
   CREDENTIALS
   ========================================================= */

async function getCredentials(env) {
  return (
    (await env.kv.get(CREDENTIALS_KEY, "json")) || []
  );
}

async function saveCredentials(env, credentials) {
  await env.kv.put(
    CREDENTIALS_KEY,
    JSON.stringify(credentials)
  );
}


/* =========================================================
   HOST / RP ID
   ========================================================= */

function getRpId(request) {
  const url = new URL(request.url);

  /*
   * WebAuthn RP ID is the hostname, not the full URL.
   *
   * Example:
   * https://auth.example.com/setup
   *
   * RP ID:
   * auth.example.com
   */

  return url.hostname;
}

function getExpectedOrigin(request) {
  const url = new URL(request.url);

  return url.origin;
}


/* =========================================================
   SETUP STATUS
   ========================================================= */

async function apiStatus(request, env) {
  const config = await getConfig(env);

  if (!config) {
    return json({
      ok: true,
      setupRequired: true,
      authenticated: false
    });
  }

  const session = await getSession(request, env);

  return json({
    ok: true,
    setupRequired: false,
    authenticated: !!session,
    expiresAt: session?.expiresAt || null,
    passkeyConfigured: !!config.passkeyConfigured
  });
}


/* =========================================================
   INITIAL SETUP
   ========================================================= */

async function apiSetup(request, env) {
  const existing = await getConfig(env);

  if (existing) {
    return json(
      {
        ok: false,
        error: "Authenticator has already been configured."
      },
      409
    );
  }

  const body = await request.json();

  const password = String(body.password || "");
  let sessionMinutes = Number(body.sessionMinutes);

  if (password.length < 8) {
    return json(
      {
        ok: false,
        error: "Password must be at least 8 characters."
      },
      400
    );
  }

  if (!Number.isFinite(sessionMinutes)) {
    sessionMinutes = DEFAULT_SESSION_MINUTES;
  }

  sessionMinutes = Math.floor(sessionMinutes);

  if (
    sessionMinutes < 1 ||
    sessionMinutes > MAX_SESSION_MINUTES
  ) {
    return json(
      {
        ok: false,
        error: `Session duration must be between 1 and ${MAX_SESSION_MINUTES} minutes.`
      },
      400
    );
  }

  const passwordData = await hashPassword(password);

  const config = {
    version: 1,

    password: passwordData,

    sessionMinutes,

    passkeyConfigured: false,

    createdAt: Date.now()
  };

  await saveConfig(env, config);

  /*
   * Automatically log the user in after setup.
   */

  const sessionResponse = await createSession(
    request,
    env,
    sessionMinutes
  );

  return json(
    {
      ok: true,
      message: "Authenticator configured.",
      passkeyConfigured: false
    },
    200,
    sessionResponse.headers
  );
}


/* =========================================================
   PASSWORD LOGIN
   ========================================================= */

async function apiPasswordLogin(request, env) {
  const config = await getConfig(env);

  if (!config) {
    return json(
      {
        ok: false,
        error: "Setup is required first."
      },
      400
    );
  }

  const body = await request.json();

  const password = String(body.password || "");

  if (!password) {
    return json(
      {
        ok: false,
        error: "Password required."
      },
      400
    );
  }

  const valid = await verifyPassword(
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
    request,
    env,
    config.sessionMinutes
  );
}


/* =========================================================
   SESSION CREATION
   ========================================================= */

async function createSessionResponse(
  request,
  env,
  minutes
) {
  const token = randomToken(32);

  const tokenHash = await sha256Base64Url(token);

  const expiresAt =
    Date.now() + minutes * 60 * 1000;

  const session = {
    createdAt: Date.now(),
    expiresAt
  };

  /*
   * IMPORTANT:
   *
   * KV receives only the SHA-256 hash.
   *
   * The actual random token exists only in the browser cookie.
   */

  await env.kv.put(
    `auth:session:${tokenHash}`,
    JSON.stringify(session),
    {
      expirationTtl: Math.max(
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
      "set-cookie": makeSessionCookie(
        token,
        minutes * 60
      )
    }
  );
}

async function createSession(
  request,
  env,
  minutes
) {
  const response = await createSessionResponse(
    request,
    env,
    minutes
  );

  return response;
}


/* =========================================================
   SESSION COOKIE
   ========================================================= */

function makeSessionCookie(token, maxAge) {
  return [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${Math.max(1, Math.floor(maxAge))}`
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

function getCookie(request, name) {
  const header = request.headers.get("Cookie");

  if (!header) {
    return null;
  }

  const parts = header.split(";");

  for (const part of parts) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}


/* =========================================================
   SESSION VALIDATION
   ========================================================= */

async function getSession(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE
  );

  if (!token) {
    return null;
  }

  /*
   * Hash the browser token.
   */

  const tokenHash = await sha256Base64Url(token);

  const key = `auth:session:${tokenHash}`;

  const session = await env.kv.get(
    key,
    "json"
  );

  if (!session) {
    return null;
  }

  if (
    !session.expiresAt ||
    Date.now() >= session.expiresAt
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
   LOGOUT
   ========================================================= */

async function apiLogout(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE
  );

  if (token) {
    const tokenHash = await sha256Base64Url(token);

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
      "set-cookie": makeDeleteCookie()
    }
  );
}


/* =========================================================
   WEBAUTHN CHALLENGES
   ========================================================= */

async function createChallenge(env, type) {
  const challenge = randomBytes(32);

  const challengeString =
    bytesToBase64Url(challenge);

  const id = randomToken(18);

  await env.kv.put(
    `auth:challenge:${type}:${id}`,
    JSON.stringify({
      challenge: challengeString,
      createdAt: Date.now()
    }),
    {
      expirationTtl: CHALLENGE_TTL_SECONDS
    }
  );

  return {
    id,
    challenge: challengeString
  };
}

async function consumeChallenge(
  env,
  type,
  id
) {
  if (!id) {
    return null;
  }

  const key =
    `auth:challenge:${type}:${id}`;

  const data = await env.kv.get(
    key,
    "json"
  );

  if (!data) {
    return null;
  }

  /*
   * Delete before returning.
   *
   * This prevents replay.
   */

  await env.kv.delete(key);

  if (
    Date.now() - data.createdAt >
    CHALLENGE_TTL_SECONDS * 1000
  ) {
    return null;
  }

  return data.challenge;
}


/* =========================================================
   PASSKEY REGISTRATION OPTIONS
   ========================================================= */

async function passkeyRegisterOptions(
  request,
  env
) {
  const session = await getSession(
    request,
    env
  );

  if (!session) {
    return json(
      {
        ok: false,
        error: "You must unlock the authenticator first."
      },
      401
    );
  }

  const config = await getConfig(env);

  if (!config) {
    return json(
      {
        ok: false,
        error: "Setup is required."
      },
      400
    );
  }

  const rpId = getRpId(request);

  const challenge =
    await createChallenge(
      env,
      "register"
    );

  const credentials =
    await getCredentials(env);

  /*
   * A random user ID is used.
   */

  let userId;

  if (config.userId) {
    userId = base64UrlToBytes(
      config.userId
    );
  } else {
    userId = randomBytes(32);

    config.userId =
      bytesToBase64Url(userId);

    await saveConfig(env, config);
  }

  const options = {
    challenge: challenge.challenge,

    rp: {
      name: "Time Authenticator",
      id: rpId
    },

    user: {
      id: bytesToBase64Url(userId),
      name: "authenticator-user",
      displayName: "Authenticator User"
    },

    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7
      }
    ],

    timeout: 60000,

    /*
     * This is important for Face ID.
     *
     * The platform authenticator must perform
     * user verification.
     */

    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required"
    },

    attestation: "none",

    excludeCredentials: credentials.map(
      credential => ({
        type: "public-key",
        id: credential.id,
        transports: ["internal", "hybrid"]
      })
    )
  };

  return json({
    ok: true,
    challengeId: challenge.id,
    publicKey: options
  });
}


/* =========================================================
   PASSKEY REGISTRATION VERIFY
   ========================================================= */

async function passkeyRegisterVerify(
  request,
  env
) {
  const session = await getSession(
    request,
    env
  );

  if (!session) {
    return json(
      {
        ok: false,
        error: "You must unlock the authenticator first."
      },
      401
    );
  }

  const body = await request.json();

  const challenge = await consumeChallenge(
    env,
    "register",
    body.challengeId
  );

  if (!challenge) {
    return json(
      {
        ok: false,
        error: "Registration challenge expired or invalid."
      },
      400
    );
  }

  const credential = body.credential;

  if (!credential) {
    return json(
      {
        ok: false,
        error: "Missing credential."
      },
      400
    );
  }

  if (
    credential.type !== "public-key" ||
    !credential.id ||
    !credential.rawId ||
    !credential.response
  ) {
    return json(
      {
        ok: false,
        error: "Invalid WebAuthn credential."
      },
      400
    );
  }

  const response = credential.response;

  const clientDataJSON =
    base64UrlToBytes(
      response.clientDataJSON
    );

  const clientData =
    JSON.parse(
      decoder.decode(clientDataJSON)
    );

  /*
   * Check operation type.
   */

  if (clientData.type !== "webauthn.create") {
    return json(
      {
        ok: false,
        error: "Invalid WebAuthn operation."
      },
      400
    );
  }

  /*
   * Check challenge.
   */

  if (
    clientData.challenge !== challenge
  ) {
    return json(
      {
        ok: false,
        error: "WebAuthn challenge mismatch."
      },
      400
    );
  }

  /*
   * Check origin.
   */

  const expectedOrigin =
    getExpectedOrigin(request);

  if (
    clientData.origin !== expectedOrigin
  ) {
    return json(
      {
        ok: false,
        error: "WebAuthn origin mismatch."
      },
      400
    );
  }

  /*
   * The browser gives us authenticatorData.
   */

  const authenticatorData =
    base64UrlToBytes(
      response.authenticatorData
    );

  if (authenticatorData.length < 37) {
    return json(
      {
        ok: false,
        error: "Invalid authenticator data."
      },
      400
    );
  }

  /*
   * Verify RP ID hash.
   */

  const rpId = getRpId(request);

  const expectedRpIdHash =
    await sha256Bytes(rpId);

  const actualRpIdHash =
    authenticatorData.slice(0, 32);

  if (
    !constantTimeEqual(
      expectedRpIdHash,
      actualRpIdHash
    )
  ) {
    return json(
      {
        ok: false,
        error: "WebAuthn RP ID mismatch."
      },
      400
    );
  }

  /*
   * Flags:
   *
   * bit 0 = User Present
   * bit 2 = User Verified
   */

  const flags = authenticatorData[32];

  const userPresent =
    (flags & 0x01) !== 0;

  const userVerified =
    (flags & 0x04) !== 0;

  if (!userPresent) {
    return json(
      {
        ok: false,
        error: "User presence was not verified."
      },
      400
    );
  }

  if (!userVerified) {
    return json(
      {
        ok: false,
        error: "Face ID / user verification was not performed."
      },
      400
    );
  }

  /*
   * Get the public key from the browser.
   *
   * Modern WebAuthn exposes getPublicKey()
   * which returns an SPKI public key.
   */

  if (!response.publicKey) {
    return json(
      {
        ok: false,
        error:
          "This browser did not provide the WebAuthn public key."
      },
      400
    );
  }

  const publicKey =
    base64UrlToBytes(
      response.publicKey
    );

  /*
   * WebAuthn's response.getPublicKeyAlgorithm()
   * should be -7 for ES256.
   *
   * We only allow ES256 here.
   */

  if (
    response.publicKeyAlgorithm !== -7
  ) {
    return json(
      {
        ok: false,
        error:
          "Unsupported passkey algorithm. ES256 is required."
      },
      400
    );
  }

  /*
   * Credential ID comes from rawId.
   */

  const credentialId =
    base64UrlToBytes(
      credential.rawId
    );

  if (credential.id !== credential.rawId) {
    return json(
      {
        ok: false,
        error: "Credential ID mismatch."
      },
      400
    );
  }

  /*
   * Don't allow the exact same credential twice.
   */

  const credentials =
    await getCredentials(env);

  if (
    credentials.some(
      item =>
        item.id === credential.rawId
    )
  ) {
    return json(
      {
        ok: false,
        error: "This passkey is already registered."
      },
      409
    );
  }

  /*
   * Store the public key.
   *
   * The private key never comes here.
   */

  credentials.push({
    id: bytesToBase64Url(credentialId),
    publicKey: bytesToBase64Url(publicKey),
    algorithm: -7,
    createdAt: Date.now()
  });

  await saveCredentials(
    env,
    credentials
  );

  const config =
    await getConfig(env);

  config.passkeyConfigured = true;

  await saveConfig(env, config);

  return json({
    ok: true,
    message: "Face ID / passkey registered successfully."
  });
}


/* =========================================================
   PASSKEY LOGIN OPTIONS
   ========================================================= */

async function passkeyLoginOptions(
  request,
  env
) {
  const config = await getConfig(env);

  if (!config) {
    return json(
      {
        ok: false,
        error: "Setup is required."
      },
      400
    );
  }

  const credentials =
    await getCredentials(env);

  if (credentials.length === 0) {
    return json(
      {
        ok: false,
        error: "No passkey has been registered."
      },
      400
    );
  }

  const challenge =
    await createChallenge(
      env,
      "login"
    );

  const options = {
    challenge: challenge.challenge,

    rpId: getRpId(request),

    timeout: 60000,

    userVerification: "required",

    allowCredentials:
      credentials.map(
        credential => ({
          type: "public-key",
          id: credential.id,
          transports: [
            "internal",
            "hybrid"
          ]
        })
      )
  };

  return json({
    ok: true,
    challengeId: challenge.id,
    publicKey: options
  });
}


/* =========================================================
   PASSKEY LOGIN VERIFY
   ========================================================= */

async function passkeyLoginVerify(
  request,
  env
) {
  const config = await getConfig(env);

  if (!config) {
    return json(
      {
        ok: false,
        error: "Setup is required."
      },
      400
    );
  }

  const body = await request.json();

  const challenge =
    await consumeChallenge(
      env,
      "login",
      body.challengeId
    );

  if (!challenge) {
    return json(
      {
        ok: false,
        error: "Login challenge expired or invalid."
      },
      400
    );
  }

  const credential =
    body.credential;

  if (
    !credential ||
    credential.type !== "public-key" ||
    !credential.id ||
    !credential.rawId ||
    !credential.response
  ) {
    return json(
      {
        ok: false,
        error: "Invalid passkey response."
      },
      400
    );
  }

  /*
   * Credential ID must match rawId.
   */

  if (
    credential.id !== credential.rawId
  ) {
    return json(
      {
        ok: false,
        error: "Credential ID mismatch."
      },
      400
    );
  }

  const credentials =
    await getCredentials(env);

  const stored =
    credentials.find(
      item =>
        item.id === credential.rawId
    );

  if (!stored) {
    return json(
      {
        ok: false,
        error: "Passkey is not registered."
      },
      401
    );
  }

  const response =
    credential.response;

  const clientDataJSON =
    base64UrlToBytes(
      response.clientDataJSON
    );

  const clientData =
    JSON.parse(
      decoder.decode(clientDataJSON)
    );

  /*
   * Operation type.
   */

  if (clientData.type !== "webauthn.get") {
    return json(
      {
        ok: false,
        error: "Invalid WebAuthn authentication type."
      },
      400
    );
  }

  /*
   * Challenge.
   */

  if (
    clientData.challenge !== challenge
  ) {
    return json(
      {
        ok: false,
        error: "WebAuthn challenge mismatch."
      },
      400
    );
  }

  /*
   * Origin.
   */

  const expectedOrigin =
    getExpectedOrigin(request);

  if (
    clientData.origin !== expectedOrigin
  ) {
    return json(
      {
        ok: false,
        error: "WebAuthn origin mismatch."
      },
      400
    );
  }

  /*
   * Authenticator data.
   */

  const authenticatorData =
    base64UrlToBytes(
      response.authenticatorData
    );

  if (
    authenticatorData.length < 37
  ) {
    return json(
      {
        ok: false,
        error: "Invalid authenticator data."
      },
      400
    );
  }

  /*
   * RP ID hash.
   */

  const expectedRpIdHash =
    await sha256Bytes(
      getRpId(request)
    );

  const actualRpIdHash =
    authenticatorData.slice(0, 32);

  if (
    !constantTimeEqual(
      expectedRpIdHash,
      actualRpIdHash
    )
  ) {
    return json(
      {
        ok: false,
        error: "WebAuthn RP ID mismatch."
      },
      400
    );
  }

  /*
   * Flags.
   */

  const flags =
    authenticatorData[32];

  const userPresent =
    (flags & 0x01) !== 0;

  const userVerified =
    (flags & 0x04) !== 0;

  if (!userPresent) {
    return json(
      {
        ok: false,
        error: "User presence was not verified."
      },
      401
    );
  }

  if (!userVerified) {
    return json(
      {
        ok: false,
        error:
          "Face ID / user verification was not performed."
      },
      401
    );
  }

  /*
   * Build the WebAuthn signed data:
   *
   * authenticatorData ||
   * SHA256(clientDataJSON)
   */

  const clientDataHash =
    await sha256Bytes(
      clientDataJSON
    );

  const signedData =
    concatBytes(
      authenticatorData,
      clientDataHash
    );

  /*
   * Import stored SPKI public key.
   */

  const publicKeyBytes =
    base64UrlToBytes(
      stored.publicKey
    );

  const publicKey =
    await crypto.subtle.importKey(
      "spki",
      publicKeyBytes,
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      false,
      ["verify"]
    );

  /*
   * WebAuthn ECDSA signatures are DER encoded.
   *
   * WebCrypto expects raw r || s.
   */

  const signatureDer =
    base64UrlToBytes(
      response.signature
    );

  const signatureRaw =
    derToRawEcdsa(
      signatureDer,
      32
    );

  const valid =
    await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: "SHA-256"
      },
      publicKey,
      signatureRaw,
      signedData
    );

  if (!valid) {
    return json(
      {
        ok: false,
        error: "Invalid passkey signature."
      },
      401
    );
  }

  /*
   * SUCCESS
   *
   * Create a normal time-limited session.
   */

  return await createSessionResponse(
    request,
    env,
    config.sessionMinutes
  );
}


/* =========================================================
   BYTE HELPERS
   ========================================================= */

function concatBytes(...arrays) {
  let total = 0;

  for (const array of arrays) {
    total += array.length;
  }

  const result =
    new Uint8Array(total);

  let offset = 0;

  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }

  return result;
}


/* =========================================================
   DER ECDSA -> RAW R||S
   ========================================================= */

function derToRawEcdsa(
  der,
  size = 32
) {
  const data =
    der instanceof Uint8Array
      ? der
      : new Uint8Array(der);

  if (data.length < 8) {
    throw new Error(
      "Invalid ECDSA signature."
    );
  }

  if (data[0] !== 0x30) {
    throw new Error(
      "ECDSA signature is not DER encoded."
    );
  }

  let offset = 1;

  /*
   * Read DER sequence length.
   */

  let sequenceLength;

  if ((data[offset] & 0x80) === 0) {
    sequenceLength =
      data[offset];
    offset++;
  } else {
    const lengthBytes =
      data[offset] & 0x7f;

    offset++;

    if (
      lengthBytes === 0 ||
      lengthBytes > 4 ||
      offset + lengthBytes > data.length
    ) {
      throw new Error(
        "Invalid DER length."
      );
    }

    sequenceLength = 0;

    for (
      let i = 0;
      i < lengthBytes;
      i++
    ) {
      sequenceLength =
        (sequenceLength << 8) |
        data[offset++];
    }
  }

  if (
    sequenceLength >
    data.length - offset
  ) {
    throw new Error(
      "Invalid DER sequence."
    );
  }

  function readInteger() {
    if (
      offset >= data.length ||
      data[offset++] !== 0x02
    ) {
      throw new Error(
        "Invalid DER integer."
      );
    }

    if (offset >= data.length) {
      throw new Error(
        "Invalid DER integer length."
      );
    }

    let length = data[offset++];

    if ((length & 0x80) !== 0) {
      const lengthBytes =
        length & 0x7f;

      if (
        lengthBytes === 0 ||
        lengthBytes > 4 ||
        offset + lengthBytes > data.length
      ) {
        throw new Error(
          "Invalid DER integer length."
        );
      }

      length = 0;

      for (
        let i = 0;
        i < lengthBytes;
        i++
      ) {
        length =
          (length << 8) |
          data[offset++];
      }
    }

    if (
      length <= 0 ||
      offset + length > data.length
    ) {
      throw new Error(
        "Invalid DER integer."
      );
    }

    let value =
      data.slice(
        offset,
        offset + length
      );

    offset += length;

    /*
     * Remove DER sign padding.
     */

    while (
      value.length > size &&
      value[0] === 0
    ) {
      value = value.slice(1);
    }

    if (value.length > size) {
      throw new Error(
        "ECDSA integer too large."
      );
    }

    const output =
      new Uint8Array(size);

    output.set(
      value,
      size - value.length
    );

    return output;
  }

  const r = readInteger();
  const s = readInteger();

  return concatBytes(r, s);
}


/* =========================================================
   FRONTEND
   ========================================================= */

async function mainPage(
  request,
  env
) {
  const config =
    await getConfig(env);

  const session =
    await getSession(request, env);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0,
               viewport-fit=cover">

<title>Time Authenticator</title>

<meta name="color-scheme"
      content="dark light">

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;

  font-family:
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;

  background:
    linear-gradient(
      135deg,
      #111827,
      #020617
    );

  color: white;

  display: flex;
  align-items: center;
  justify-content: center;

  padding: 20px;
}

.card {
  width: 100%;
  max-width: 460px;

  background: rgba(30, 41, 59, 0.94);

  border: 1px solid
    rgba(255,255,255,0.1);

  border-radius: 24px;

  padding: 30px;

  box-shadow:
    0 25px 80px
    rgba(0,0,0,0.4);
}

.logo {
  width: 64px;
  height: 64px;

  border-radius: 18px;

  background:
    linear-gradient(
      135deg,
      #3b82f6,
      #8b5cf6
    );

  display: flex;
  align-items: center;
  justify-content: center;

  font-size: 30px;

  margin-bottom: 20px;
}

h1 {
  margin: 0 0 8px;
  font-size: 28px;
}

.subtitle {
  color: #94a3b8;
  line-height: 1.5;
  margin-bottom: 25px;
}

label {
  display: block;
  margin-bottom: 7px;

  font-size: 14px;
  color: #cbd5e1;
}

input {
  width: 100%;

  padding: 14px 15px;

  border-radius: 12px;

  border: 1px solid
    #475569;

  background: #0f172a;

  color: white;

  font-size: 16px;

  outline: none;

  margin-bottom: 15px;
}

input:focus {
  border-color: #60a5fa;
}

button {
  width: 100%;

  padding: 14px;

  border: 0;

  border-radius: 12px;

  background: #2563eb;

  color: white;

  font-size: 16px;

  font-weight: 600;

  cursor: pointer;

  margin-top: 8px;
}

button:hover {
  background: #1d4ed8;
}

button.secondary {
  background: #334155;
}

button.secondary:hover {
  background: #475569;
}

button.danger {
  background: #dc2626;
}

button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.section {
  margin-top: 25px;

  padding-top: 25px;

  border-top:
    1px solid
    rgba(255,255,255,0.08);
}

.status {
  padding: 14px;

  border-radius: 12px;

  background:
    rgba(15,23,42,0.8);

  color: #cbd5e1;

  margin: 15px 0;

  line-height: 1.5;
}

.success {
  color: #86efac;
}

.error {
  color: #fca5a5;
}

.small {
  font-size: 13px;
  color: #94a3b8;
  line-height: 1.5;
}

.hidden {
  display: none;
}

.timer {
  font-size: 36px;
  font-weight: 700;

  text-align: center;

  margin: 20px 0;
}

.passkey {
  background:
    linear-gradient(
      135deg,
      #7c3aed,
      #2563eb
    );
}

.passkey:hover {
  background:
    linear-gradient(
      135deg,
      #6d28d9,
      #1d4ed8
    );
}

</style>
</head>

<body>

<div class="card">

  <div class="logo">
    🔐
  </div>

  <h1>Time Authenticator</h1>

  <div class="subtitle">
    Secure access with a password or
    Face ID / passkey.
  </div>

  <div id="app"></div>

</div>

<script>

const app =
  document.getElementById("app");


/* =====================================================
   BASE64URL HELPERS
   ===================================================== */

function base64UrlToBytes(value) {

  const padded =
    value
      .replace(/-/g, "+")
      .replace(/_/g, "/") +
    "=".repeat(
      (4 - (value.length % 4)) % 4
    );

  const binary =
    atob(padded);

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


function bytesToBase64Url(buffer) {

  const bytes =
    new Uint8Array(buffer);

  let binary = "";

  for (const byte of bytes) {
    binary +=
      String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\\+/g, "-")
    .replace(/\\//g, "_")
    .replace(/=+$/g, "");
}


/* =====================================================
   API
   ===================================================== */

async function api(
  url,
  options = {}
) {

  const response =
    await fetch(url, {
      ...options,

      headers: {
        "content-type":
          "application/json",
        ...(options.headers || {})
      }
    });

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
   INITIAL STATUS
   ===================================================== */

async function load() {

  try {

    const status =
      await api("/api/status");

    if (status.setupRequired) {
      showSetup();
      return;
    }

    if (status.authenticated) {
      showUnlocked(status);
      return;
    }

    showLogin(status);

  } catch (error) {

    app.innerHTML = \`
      <div class="status error">
        Failed to load authenticator:
        \${escapeHtml(error.message)}
      </div>
    \`;

  }
}


/* =====================================================
   SETUP PAGE
   ===================================================== */

function showSetup() {

  app.innerHTML = \`
    <h2>First-time setup</h2>

    <p class="small">
      Create the password used to unlock this
      authenticator.
    </p>

    <label>Password</label>

    <input
      id="setupPassword"
      type="password"
      autocomplete="new-password"
      placeholder="At least 8 characters"
    >

    <label>Confirm password</label>

    <input
      id="setupConfirm"
      type="password"
      autocomplete="new-password"
      placeholder="Enter it again"
    >

    <label>
      Session duration
      <span class="small">
        (default: 30 minutes)
      </span>
    </label>

    <input
      id="sessionMinutes"
      type="number"
      min="1"
      max="10080"
      value="30"
    >

    <button
      onclick="setup()"
    >
      Create Authenticator
    </button>

    <div
      id="setupStatus"
      class="status hidden"
    ></div>
  \`;
}


/* =====================================================
   SETUP
   ===================================================== */

async function setup() {

  const password =
    document.getElementById(
      "setupPassword"
    ).value;

  const confirm =
    document.getElementById(
      "setupConfirm"
    ).value;

  const minutes =
    Number(
      document.getElementById(
        "sessionMinutes"
      ).value
    );

  const status =
    document.getElementById(
      "setupStatus"
    );

  status.classList.remove(
    "hidden",
    "error"
  );

  if (password.length < 8) {

    status.classList.add("error");

    status.textContent =
      "Password must be at least 8 characters.";

    return;
  }

  if (password !== confirm) {

    status.classList.add("error");

    status.textContent =
      "Passwords do not match.";

    return;
  }

  if (
    !Number.isFinite(minutes) ||
    minutes < 1 ||
    minutes > 10080
  ) {

    status.classList.add("error");

    status.textContent =
      "Session duration must be between 1 and 10080 minutes.";

    return;
  }

  try {

    status.textContent =
      "Creating authenticator...";

    await api(
      "/api/setup",
      {
        method: "POST",

        body: JSON.stringify({
          password,
          sessionMinutes: minutes
        })
      }
    );

    showUnlocked({
      passkeyConfigured: false,
      expiresAt:
        Date.now() +
        minutes * 60000
    });

  } catch (error) {

    status.classList.add("error");

    status.textContent =
      error.message;
  }
}


/* =====================================================
   LOGIN PAGE
   ===================================================== */

function showLogin(status) {

  app.innerHTML = \`
    <h2>Unlock</h2>

    <p class="small">
      Enter your password or use your
      registered passkey.
    </p>

    <label>Password</label>

    <input
      id="loginPassword"
      type="password"
      autocomplete="current-password"
      placeholder="Password"
      onkeydown="if(event.key==='Enter') login()"
    >

    <button
      onclick="login()"
    >
      Unlock with Password
    </button>

    \${
      status.passkeyConfigured
      ? \`
        <button
          class="passkey"
          onclick="loginPasskey()"
        >
          🔐 Unlock with Face ID / Passkey
        </button>
      \`
      : ""
    }

    <div
      id="loginStatus"
      class="status hidden"
    ></div>
  \`;
}


/* =====================================================
   PASSWORD LOGIN
   ===================================================== */

async function login() {

  const password =
    document.getElementById(
      "loginPassword"
    ).value;

  const status =
    document.getElementById(
      "loginStatus"
    );

  status.classList.remove(
    "hidden",
    "error"
  );

  status.textContent =
    "Checking password...";

  try {

    const result =
      await api(
        "/api/login",
        {
          method: "POST",

          body: JSON.stringify({
            password
          })
        }
      );

    showUnlocked(result);

  } catch (error) {

    status.classList.add("error");

    status.textContent =
      error.message;
  }
}


/* =====================================================
   PASSKEY REGISTRATION
   ===================================================== */

async function registerPasskey() {

  const status =
    document.getElementById(
      "passkeyStatus"
    );

  try {

    status.classList.remove(
      "hidden",
      "error"
    );

    status.textContent =
      "Preparing Face ID...";

    const options =
      await api(
        "/api/passkey/register/options",
        {
          method: "POST"
        }
      );

    /*
     * Convert base64url strings into
     * ArrayBuffers as required by WebAuthn.
     */

    const publicKey =
      options.publicKey;

    publicKey.challenge =
      base64UrlToBytes(
        publicKey.challenge
      );

    publicKey.user.id =
      base64UrlToBytes(
        publicKey.user.id
      );

    if (
      publicKey.excludeCredentials
    ) {

      publicKey.excludeCredentials =
        publicKey.excludeCredentials.map(
          item => ({
            ...item,
            id:
              base64UrlToBytes(
                item.id
              )
          })
        );
    }

    /*
     * This MUST happen directly from
     * the button click.
     *
     * iPhone can now display Face ID.
     */

    const credential =
      await navigator.credentials.create({
        publicKey
      });

    if (!credential) {
      throw new Error(
        "No passkey was created."
      );
    }

    const response =
      credential.response;

    /*
     * getPublicKey() returns the
     * public key in SPKI format.
     */

    const publicKeyBuffer =
      response.getPublicKey();

    const publicKeyAlgorithm =
      response.getPublicKeyAlgorithm();

    if (!publicKeyBuffer) {
      throw new Error(
        "The browser did not provide a public key."
      );
    }

    /*
     * Send only public WebAuthn data.
     */

    const credentialData = {

      type:
        credential.type,

      id:
        credential.id,

      rawId:
        bytesToBase64Url(
          credential.rawId
        ),

      response: {

        clientDataJSON:
          bytesToBase64Url(
            response.clientDataJSON
          ),

        authenticatorData:
          bytesToBase64Url(
            response.getAuthenticatorData()
          ),

        publicKey:
          bytesToBase64Url(
            publicKeyBuffer
          ),

        publicKeyAlgorithm
      }
    };

    status.textContent =
      "Saving passkey...";

    const result =
      await api(
        "/api/passkey/register/verify",
        {
          method: "POST",

          body: JSON.stringify({
            challengeId:
              options.challengeId,

            credential:
              credentialData
          })
        }
      );

    status.classList.remove(
      "error"
    );

    status.innerHTML =
      '<span class="success">' +
      escapeHtml(result.message) +
      "</span>";

    setTimeout(
      load,
      1000
    );

  } catch (error) {

    console.error(error);

    status.classList.add(
      "error"
    );

    status.textContent =
      "Face ID setup failed: " +
      error.message;
  }
}


/* =====================================================
   PASSKEY LOGIN
   ===================================================== */

async function loginPasskey() {

  const status =
    document.getElementById(
      "loginStatus"
    );

  try {

    status.classList.remove(
      "hidden",
      "error"
    );

    status.textContent =
      "Waiting for Face ID...";

    const options =
      await api(
        "/api/passkey/login/options",
        {
          method: "POST"
        }
      );

    const publicKey =
      options.publicKey;

    publicKey.challenge =
      base64UrlToBytes(
        publicKey.challenge
      );

    if (
      publicKey.allowCredentials
    ) {

      publicKey.allowCredentials =
        publicKey.allowCredentials.map(
          item => ({
            ...item,
            id:
              base64UrlToBytes(
                item.id
              )
          })
        );
    }

    const credential =
      await navigator.credentials.get({
        publicKey
      });

    if (!credential) {
      throw new Error(
        "No passkey response."
      );
    }

    const response =
      credential.response;

    const credentialData = {

      type:
        credential.type,

      id:
        credential.id,

      rawId:
        bytesToBase64Url(
          credential.rawId
        ),

      response: {

        clientDataJSON:
          bytesToBase64Url(
            response.clientDataJSON
          ),

        authenticatorData:
          bytesToBase64Url(
            response.authenticatorData
          ),

        signature:
          bytesToBase64Url(
            response.signature
          ),

        userHandle:
          response.userHandle
            ? bytesToBase64Url(
                response.userHandle
              )
            : null
      }
    };

    status.textContent =
      "Verifying Face ID...";

    const result =
      await api(
        "/api/passkey/login/verify",
        {
          method: "POST",

          body: JSON.stringify({
            challengeId:
              options.challengeId,

            credential:
              credentialData
          })
        }
      );

    showUnlocked(result);

  } catch (error) {

    console.error(error);

    status.classList.add(
      "error"
    );

    status.textContent =
      "Face ID login failed: " +
      error.message;
  }
}


/* =====================================================
   UNLOCKED PAGE
   ===================================================== */

function showUnlocked(data) {

  const expiresAt =
    Number(data.expiresAt || 0);

  app.innerHTML = \`
    <h2>Unlocked</h2>

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
      Your session will automatically expire
      when the timer reaches zero.
    </div>

    <div class="section">

      <button
        class="passkey"
        onclick="registerPasskey()"
      >
        🔐 Set Up / Add Face ID Passkey
      </button>

      <div
        id="passkeyStatus"
        class="status hidden"
      ></div>

    </div>

    <div class="section">

      <button
        class="danger"
        onclick="logout()"
      >
        Log Out
      </button>

    </div>
  \`;

  updateTimer(expiresAt);

  window.authTimer =
    setInterval(
      () => updateTimer(expiresAt),
      1000
    );
}


/* =====================================================
   SESSION TIMER
   ===================================================== */

function updateTimer(expiresAt) {

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
      expiresAt - Date.now()
    );

  if (remaining <= 0) {

    clearInterval(
      window.authTimer
    );

    timer.textContent =
      "Expired";

    setTimeout(
      load,
      500
    );

    return;
  }

  const totalSeconds =
    Math.floor(
      remaining / 1000
    );

  const hours =
    Math.floor(
      totalSeconds / 3600
    );

  const minutes =
    Math.floor(
      (totalSeconds % 3600) / 60
    );

  const seconds =
    totalSeconds % 60;

  timer.textContent =
    hours > 0
      ? \`\${String(hours).padStart(2,"0")}:\${String(minutes).padStart(2,"0")}:\${String(seconds).padStart(2,"0")}\`
      : \`\${String(minutes).padStart(2,"0")}:\${String(seconds).padStart(2,"0")}\`;
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

    clearInterval(
      window.authTimer
    );

    load();
  }
}


/* =====================================================
   HTML ESCAPE
   ===================================================== */

function escapeHtml(value) {

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


/* =====================================================
   START
   ===================================================== */

load();

</script>

</body>
</html>`;
}
