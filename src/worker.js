// Time-based Authenticator with TOTP validation
// Simple 2FA implementation using cookies

const APP_NAME = "2FA Authenticator";
const WINDOW_SIZE = 1; // Allow ±1 time window for time skew tolerance

// Generate random base32 secret
function generateSecret(length = 32) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let secret = "";
  for (let i = 0; i < length; i++) {
    secret += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return secret;
}

// Base32 decode
function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let value = 0;

  for (let i = 0; i < str.length; i++) {
    const index = alphabet.indexOf(str[i].toUpperCase());
    if (index === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | index;
    bits += value.toString(2).padStart((i + 1) * 5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return new Uint8Array(bytes);
}

// HMAC-SHA1 for TOTP
async function hmacSha1(key, message) {
  const algorithm = { name: "HMAC", hash: "SHA-1" };
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    algorithm,
    false,
    ["sign"]
  );
  return await crypto.subtle.sign(algorithm, cryptoKey, message);
}

// Generate TOTP token
async function generateTOTP(secret, time = null) {
  if (!time) {
    time = Math.floor(Date.now() / 1000);
  }

  const epoch = Math.floor(time / 30);
  const message = new ArrayBuffer(8);
  const view = new Uint8Array(message);

  for (let i = 7; i >= 0; i--) {
    view[i] = epoch & 0xff;
    epoch >>= 8;
  }

  const secretBytes = base32Decode(secret);
  const hmac = await hmacSha1(secretBytes, message);
  const hmacView = new Uint8Array(hmac);

  const offset = hmacView[hmacView.length - 1] & 0x0f;
  const code =
    ((hmacView[offset] & 0x7f) << 24) |
    ((hmacView[offset + 1] & 0xff) << 16) |
    ((hmacView[offset + 2] & 0xff) << 8) |
    (hmacView[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

// Verify TOTP token
async function verifyTOTP(secret, token, time = null) {
  if (!time) {
    time = Math.floor(Date.now() / 1000);
  }

  const timeWindow = Math.floor(time / 30);

  for (let i = -WINDOW_SIZE; i <= WINDOW_SIZE; i++) {
    const epoch = timeWindow + i;
    const message = new ArrayBuffer(8);
    const view = new Uint8Array(message);

    for (let j = 7; j >= 0; j--) {
      view[j] = epoch & 0xff;
      epoch >>= 8;
    }

    const secretBytes = base32Decode(secret);
    const hmac = await hmacSha1(secretBytes, message);
    const hmacView = new Uint8Array(hmac);

    const offset = hmacView[hmacView.length - 1] & 0x0f;
    const code =
      ((hmacView[offset] & 0x7f) << 24) |
      ((hmacView[offset + 1] & 0xff) << 16) |
      ((hmacView[offset + 2] & 0xff) << 8) |
      (hmacView[offset + 3] & 0xff);

    const totp = (code % 1000000).toString().padStart(6, "0");
    if (totp === token) {
      return true;
    }
  }

  return false;
}

// Generate QR Code URL using qrserver API
function getQRCodeURL(secret, issuer = APP_NAME, accountName = "user") {
  const otpauthURL = encodeURIComponent(
    `otpauth://totp/${issuer}:${accountName}?secret=${secret}&issuer=${issuer}`
  );
  return `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${otpauthURL}`;
}

// HTML for setup page
function getSetupHTML(secret, qrUrl) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Setup 2FA Authenticator</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      max-width: 400px;
      width: 100%;
      padding: 40px;
    }
    h1 {
      color: #333;
      margin-bottom: 10px;
      font-size: 24px;
    }
    .subtitle {
      color: #666;
      margin-bottom: 30px;
      font-size: 14px;
    }
    .qr-section {
      text-align: center;
      margin-bottom: 30px;
    }
    .qr-code {
      max-width: 100%;
      height: auto;
      border: 2px solid #667eea;
      border-radius: 8px;
      padding: 10px;
      background: white;
    }
    .secret-section {
      background: #f5f5f5;
      padding: 15px;
      border-radius: 8px;
      margin-bottom: 20px;
    }
    .secret-label {
      color: #666;
      font-size: 12px;
      margin-bottom: 8px;
      display: block;
    }
    .secret-code {
      font-family: 'Courier New', monospace;
      font-size: 16px;
      letter-spacing: 2px;
      color: #333;
      word-break: break-all;
      font-weight: bold;
    }
    .copy-btn {
      background: #667eea;
      color: white;
      border: none;
      padding: 8px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      margin-top: 10px;
      transition: background 0.3s;
    }
    .copy-btn:hover {
      background: #5568d3;
    }
    .verify-section {
      margin-top: 30px;
      padding-top: 30px;
      border-top: 2px solid #eee;
    }
    .verify-label {
      color: #333;
      font-weight: bold;
      margin-bottom: 10px;
      display: block;
    }
    .code-input {
      width: 100%;
      padding: 12px;
      font-size: 24px;
      text-align: center;
      letter-spacing: 10px;
      border: 2px solid #ddd;
      border-radius: 8px;
      font-family: monospace;
      margin-bottom: 15px;
      transition: border-color 0.3s;
    }
    .code-input:focus {
      outline: none;
      border-color: #667eea;
    }
    .verify-btn {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .verify-btn:hover {
      transform: translateY(-2px);
    }
    .verify-btn:active {
      transform: translateY(0);
    }
    .info-text {
      color: #666;
      font-size: 12px;
      margin-top: 10px;
      line-height: 1.6;
    }
    .success {
      background: #d4edda;
      color: #155724;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 20px;
      display: none;
    }
    .error {
      background: #f8d7da;
      color: #721c24;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 20px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔐 Setup 2FA</h1>
    <p class="subtitle">Secure your account with time-based authentication</p>
    
    <div class="success" id="success">✓ 2FA enabled successfully!</div>
    <div class="error" id="error"></div>

    <div class="qr-section">
      <img src="${qrUrl}" alt="QR Code" class="qr-code">
      <p class="info-text" style="margin-top: 20px;">Scan this QR code with your authenticator app</p>
    </div>

    <div class="secret-section">
      <label class="secret-label">Or enter this secret manually:</label>
      <div class="secret-code">${secret}</div>
      <button class="copy-btn" onclick="copySecret()">Copy Secret</button>
    </div>

    <div class="verify-section">
      <label class="verify-label">Verify 6-digit code:</label>
      <input 
        type="text" 
        id="totpCode" 
        class="code-input" 
        placeholder="000000" 
        maxlength="6" 
        inputmode="numeric"
        pattern="[0-9]*"
      >
      <button class="verify-btn" onclick="verifyCode()">Verify & Enable 2FA</button>
      <p class="info-text">Enter the 6-digit code from your authenticator app to complete setup</p>
    </div>
  </div>

  <script>
    function copySecret() {
      const secret = '${secret}';
      navigator.clipboard.writeText(secret).then(() => {
        alert('Secret copied to clipboard!');
      });
    }

    function verifyCode() {
      const code = document.getElementById('totpCode').value;
      const errorDiv = document.getElementById('error');
      const successDiv = document.getElementById('success');

      if (code.length !== 6) {
        errorDiv.textContent = 'Please enter a 6-digit code';
        errorDiv.style.display = 'block';
        return;
      }

      fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          successDiv.style.display = 'block';
          errorDiv.style.display = 'none';
          setTimeout(() => window.location.href = '/protected', 2000);
        } else {
          errorDiv.textContent = 'Invalid code. Please try again.';
          errorDiv.style.display = 'block';
          document.getElementById('totpCode').value = '';
        }
      });
    }

    document.getElementById('totpCode').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') verifyCode();
    });
  </script>
</body>
</html>
  `;
}

// HTML for protected page
function getProtectedHTML(currentCode, nextCode, timeLeft) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>2FA Protected Area</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      max-width: 500px;
      width: 100%;
      padding: 40px;
      text-align: center;
    }
    h1 {
      color: #333;
      margin-bottom: 20px;
      font-size: 28px;
    }
    .success-badge {
      display: inline-block;
      background: #d4edda;
      color: #155724;
      padding: 12px 24px;
      border-radius: 8px;
      margin-bottom: 30px;
      font-weight: bold;
    }
    .info-section {
      background: #f5f5f5;
      padding: 20px;
      border-radius: 8px;
      margin: 20px 0;
    }
    .code-display {
      font-family: 'Courier New', monospace;
      font-size: 32px;
      font-weight: bold;
      color: #667eea;
      letter-spacing: 4px;
      margin: 15px 0;
    }
    .timer-bar {
      height: 4px;
      background: #ddd;
      border-radius: 2px;
      overflow: hidden;
      margin: 10px 0;
    }
    .timer-fill {
      height: 100%;
      background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
      transition: width 0.1s linear;
      border-radius: 2px;
    }
    .time-label {
      font-size: 12px;
      color: #666;
      margin-top: 5px;
    }
    .logout-btn {
      background: #667eea;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 16px;
      margin-top: 20px;
      transition: background 0.3s;
    }
    .logout-btn:hover {
      background: #5568d3;
    }
    .next-code-section {
      background: #fff3cd;
      color: #856404;
      padding: 15px;
      border-radius: 8px;
      margin-top: 20px;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>✓ 2FA Enabled</h1>
    <div class="success-badge">You're authenticated!</div>
    
    <div class="info-section">
      <div>Current Code:</div>
      <div class="code-display">${currentCode}</div>
      <div class="timer-bar">
        <div class="timer-fill" id="timerFill" style="width: ${timeLeft}%"></div>
      </div>
      <div class="time-label">Expires in <span id="timeLeft">${Math.ceil(timeLeft / 30)}</span>s</div>
    </div>

    <div class="next-code-section">
      Next code in: <strong>${nextCode}</strong>
    </div>

    <div class="info-section">
      <p>Your 2FA is stored in cookies for this throwaway account.</p>
      <p style="font-size: 12px; color: #666; margin-top: 10px;">
        ⚠️ Don't use this method for production accounts!
      </p>
    </div>

    <a href="/logout">
      <button class="logout-btn">Logout & Reset 2FA</button>
    </a>
  </div>

  <script>
    function updateCodes() {
      fetch('/status')
        .then(r => r.json())
        .then(data => {
          document.querySelector('.code-display').textContent = data.current_code;
          document.getElementById('timeLeft').textContent = data.time_left;
          document.getElementById('timerFill').style.width = data.time_left_percent + '%';
        });
    }

    setInterval(updateCodes, 1000);
  </script>
</body>
</html>
  `;
}

// Main request handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = parseCookies(request);

    // Setup route
    if (url.pathname === "/" && request.method === "GET") {
      const secret = generateSecret();
      const qrUrl = getQRCodeURL(secret, APP_NAME, "user@example.com");
      const html = getSetupHTML(secret, qrUrl);

      return new Response(html, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Set-Cookie": `totp_secret=${secret}; Path=/; Max-Age=${60 * 15}; SameSite=Lax`,
        },
      });
    }

    // Verify TOTP code
    if (url.pathname === "/verify" && request.method === "POST") {
      const data = await request.json();
      const secret = cookies.totp_secret;

      if (!secret) {
        return new Response(
          JSON.stringify({ success: false, error: "No secret found" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const isValid = await verifyTOTP(secret, data.code);

      if (isValid) {
        return new Response(
          JSON.stringify({ success: true }),
          {
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie": `totp_verified=true; Path=/; Max-Age=${60 * 60 * 24}; SameSite=Lax`,
            },
          }
        );
      }

      return new Response(
        JSON.stringify({ success: false, error: "Invalid code" }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }

    // Protected area - show current TOTP
    if (url.pathname === "/protected" && request.method === "GET") {
      if (!cookies.totp_verified || !cookies.totp_secret) {
        return new Response("Unauthorized", {
          status: 401,
          headers: { "Location": "/" },
        });
      }

      const currentTime = Math.floor(Date.now() / 1000);
      const timeLeft = 30 - (currentTime % 30);
      const timeLeftPercent = (timeLeft / 30) * 100;

      const currentCode = await generateTOTP(cookies.totp_secret, currentTime);
      const nextCode = await generateTOTP(
        cookies.totp_secret,
        currentTime + 30
      );

      const html = getProtectedHTML(currentCode, nextCode, timeLeftPercent);

      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // Status endpoint for live code updates
    if (url.pathname === "/status" && request.method === "GET") {
      if (!cookies.totp_verified || !cookies.totp_secret) {
        return new Response(
          JSON.stringify({ error: "Unauthorized" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      const currentTime = Math.floor(Date.now() / 1000);
      const timeLeft = 30 - (currentTime % 30);
      const timeLeftPercent = Math.ceil((timeLeft / 30) * 100);

      const currentCode = await generateTOTP(cookies.totp_secret, currentTime);

      return new Response(
        JSON.stringify({
          current_code: currentCode,
          time_left: timeLeft,
          time_left_percent: timeLeftPercent,
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // Logout and clear cookies
    if (url.pathname === "/logout" && request.method === "GET") {
      return new Response("Logged out", {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": [
            "totp_secret=; Path=/; Max-Age=0; SameSite=Lax",
            "totp_verified=; Path=/; Max-Age=0; SameSite=Lax",
          ],
        },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

// Parse cookies from request
function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = {};
  cookieHeader.split(";").forEach((cookie) => {
    const [key, value] = cookie.trim().split("=");
    if (key) cookies[key] = decodeURIComponent(value);
  });
  return cookies;
}
