/*
 * TIME-BASED AUTHENTICATOR
 * Cloudflare Worker
 *
 * REQUIRED KV BINDING:
 *   kv
 *
 * Features:
 *   - First-run setup UI
 *   - Password setup
 *   - Password hashing with PBKDF2-SHA-256
 *   - Secure random session cookies
 *   - Only SHA-256(session token) stored in KV
 *   - Configurable session expiration
 *   - Logout
 *   - WebAuthn / Passkey authentication
 *   - Face ID / Touch ID support where the browser/device supports it
 *   - ES256 WebAuthn credentials
 *   - HTTPS-only secure cookies
 *
 * No external libraries required.
 */

const COOKIE_NAME = "auth_session";

const PASSWORD_ITERATIONS = 310000;
const PASSWORD_KEY_LENGTH = 256;

const DEFAULT_SESSION_MINUTES = 30;
const MAX_SESSION_MINUTES = 7 * 24 * 60;

const CONFIG_KEY = "auth:config";
const CRED_PREFIX = "auth:credential:";
const SESSION_PREFIX = "auth:session:";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/* =========================================================
   BASIC UTILITIES
   ========================================================= */

function json(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            ...extraHeaders
        }
    });
}

function html(body, status = 200) {
    return new Response(body, {
        status,
        headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer"
        }
    });
}

function base64urlEncode(input) {
    let bytes;

    if (typeof input === "string") {
        bytes = encoder.encode(input);
    } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
    } else {
        bytes = input;
    }

    let binary = "";

    for (const b of bytes) {
        binary += String.fromCharCode(b);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function base64urlDecode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");

    while (str.length % 4) {
        str += "=";
    }

    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function hex(bytes) {
    return [...bytes]
        .map(x => x.toString(16).padStart(2, "0"))
        .join("");
}

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

function randomToken() {
    return base64urlEncode(randomBytes(32));
}

async function sha256(value) {
    const data =
        typeof value === "string"
            ? encoder.encode(value)
            : value;

    return new Uint8Array(
        await crypto.subtle.digest("SHA-256", data)
    );
}

async function sha256Hex(value) {
    return hex(await sha256(value));
}

function timingSafeEqual(a, b) {
    const aa = encoder.encode(a);
    const bb = encoder.encode(b);

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.subtle.timingSafeEqual(aa, bb);
}

/* =========================================================
   PASSWORD HASHING
   ========================================================= */

async function hashPassword(password, saltBytes = randomBytes(16)) {
    const baseKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const derived = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: PASSWORD_ITERATIONS,
            hash: "SHA-256"
        },
        baseKey,
        PASSWORD_KEY_LENGTH
    );

    return {
        salt: base64urlEncode(saltBytes),
        hash: base64urlEncode(derived)
    };
}

async function verifyPassword(password, storedSalt, storedHash) {
    const salt = base64urlDecode(storedSalt);

    const result = await hashPassword(password, salt);

    return timingSafeEqual(result.hash, storedHash);
}

/* =========================================================
   COOKIE FUNCTIONS
   ========================================================= */

function getCookie(request, name) {
    const header = request.headers.get("Cookie");

    if (!header) {
        return null;
    }

    const cookies = header.split(";");

    for (const item of cookies) {
        const index = item.indexOf("=");

        if (index === -1) continue;

        const key = item.slice(0, index).trim();
        const value = item.slice(index + 1).trim();

        if (key === name) {
            return value;
        }
    }

    return null;
}

function sessionCookie(token, maxAge) {
    return [
        `${COOKIE_NAME}=${token}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        `Max-Age=${Math.max(0, Math.floor(maxAge))}`
    ].join("; ");
}

function expiredCookie() {
    return [
        `${COOKIE_NAME}=`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Max-Age=0"
    ].join("; ");
}

/* =========================================================
   CONFIG
   ========================================================= */

async function getConfig(env) {
    const raw = await env.kv.get(CONFIG_KEY);

    if (!raw) {
        return null;
    }

    try {
        return JSON.parse(raw);
    } catch {
        return null;
    }
}

async function saveConfig(env, config) {
    await env.kv.put(CONFIG_KEY, JSON.stringify(config));
}

/* =========================================================
   SESSION MANAGEMENT
   ========================================================= */

async function createSession(env, minutes) {
    const token = randomToken();

    const tokenHash = await sha256Hex(token);

    const now = Date.now();
    const expiresAt = now + minutes * 60 * 1000;

    const session = {
        createdAt: now,
        expiresAt
    };

    await env.kv.put(
        SESSION_PREFIX + tokenHash,
        JSON.stringify(session),
        {
            expirationTtl: Math.max(60, minutes * 60)
        }
    );

    return {
        token,
        expiresAt,
        maxAge: minutes * 60
    };
}

async function getSession(request, env) {
    const token = getCookie(request, COOKIE_NAME);

    if (!token) {
        return null;
    }

    const tokenHash = await sha256Hex(token);

    const raw = await env.kv.get(
        SESSION_PREFIX + tokenHash
    );

    if (!raw) {
        return null;
    }

    let session;

    try {
        session = JSON.parse(raw);
    } catch {
        return null;
    }

    if (!session.expiresAt || Date.now() >= session.expiresAt) {
        await env.kv.delete(
            SESSION_PREFIX + tokenHash
        );

        return null;
    }

    return {
        token,
        tokenHash,
        ...session
    };
}

async function destroySession(request, env) {
    const token = getCookie(request, COOKIE_NAME);

    if (token) {
        const hash = await sha256Hex(token);

        await env.kv.delete(
            SESSION_PREFIX + hash
        );
    }
}

/* =========================================================
   CBOR DECODER
   Minimal decoder required for WebAuthn COSE keys
   ========================================================= */

class CBORDecoder {
    constructor(bytes) {
        this.bytes = bytes;
        this.offset = 0;
    }

    readByte() {
        if (this.offset >= this.bytes.length) {
            throw new Error("Unexpected end of CBOR");
        }

        return this.bytes[this.offset++];
    }

    readLength(additional) {
        if (additional < 24) {
            return additional;
        }

        if (additional === 24) {
            return this.readByte();
        }

        if (additional === 25) {
            return (
                (this.readByte() << 8) |
                this.readByte()
            );
        }

        if (additional === 26) {
            return (
                this.readByte() * 0x1000000 +
                this.readByte() * 0x10000 +
                this.readByte() * 0x100 +
                this.readByte()
            );
        }

        if (additional === 27) {
            let value = 0;

            for (let i = 0; i < 8; i++) {
                value = value * 256 + this.readByte();
            }

            return value;
        }

        throw new Error("Unsupported CBOR length");
    }

    read() {
        const first = this.readByte();

        const major = first >> 5;
        const additional = first & 31;

        if (major === 0) {
            return this.readLength(additional);
        }

        if (major === 1) {
            return -1 - this.readLength(additional);
        }

        if (major === 2) {
            const length = this.readLength(additional);

            const value = this.bytes.slice(
                this.offset,
                this.offset + length
            );

            this.offset += length;

            return value;
        }

        if (major === 3) {
            const length = this.readLength(additional);

            const value = decoder.decode(
                this.bytes.slice(
                    this.offset,
                    this.offset + length
                )
            );

            this.offset += length;

            return value;
        }

        if (major === 4) {
            const length = this.readLength(additional);

            const array = [];

            for (let i = 0; i < length; i++) {
                array.push(this.read());
            }

            return array;
        }

        if (major === 5) {
            const length = this.readLength(additional);

            const map = new Map();

            for (let i = 0; i < length; i++) {
                const key = this.read();
                const value = this.read();

                map.set(key, value);
            }

            return map;
        }

        if (major === 7) {
            if (additional === 20) return false;
            if (additional === 21) return true;
            if (additional === 22) return null;
        }

        throw new Error(
            `Unsupported CBOR type: ${major}`
        );
    }
}

/* =========================================================
   WEBAUTHN HELPERS
   ========================================================= */

function parseClientDataJSON(bytes) {
    try {
        return JSON.parse(decoder.decode(bytes));
    } catch {
        throw new Error("Invalid clientDataJSON");
    }
}

function parseAttestationObject(bytes) {
    const decoderObj = new CBORDecoder(bytes);

    const map = decoderObj.read();

    if (!(map instanceof Map)) {
        throw new Error("Invalid attestation object");
    }

    return map;
}

function findCredentialPublicKey(attestationObject) {
    const authData = attestationObject.get("authData");

    if (!(authData instanceof Uint8Array)) {
        throw new Error("Missing authenticator data");
    }

    /*
     * authenticatorData:
     *
     * 32 bytes RP ID hash
     * 1 byte flags
     * 4 bytes sign count
     *
     * If AT flag is set:
     * 16 bytes AAGUID
     * 2 bytes credential ID length
     * credential ID
     * COSE public key
     */

    const flags = authData[32];

    if (!(flags & 0x40)) {
        throw new Error("No attested credential data");
    }

    let offset = 37;

    const aaguid = authData.slice(
        offset,
        offset + 16
    );

    offset += 16;

    const credentialIdLength =
        (authData[offset] << 8) |
        authData[offset + 1];

    offset += 2;

    const credentialId = authData.slice(
        offset,
        offset + credentialIdLength
    );

    offset += credentialIdLength;

    const coseBytes = authData.slice(offset);

    const cose = new CBORDecoder(coseBytes).read();

    return {
        aaguid,
        credentialId,
        cose
    };
}

async function coseToCryptoKey(cose) {
    /*
     * COSE EC2:
     * 1  = kty
     * 3  = alg
     * -1 = curve
     * -2 = x
     * -3 = y
     *
     * ES256:
     * kty 2
     * alg -7
     * curve 1
     */

    const kty = cose.get(1);
    const alg = cose.get(3);
    const curve = cose.get(-1);
    const x = cose.get(-2);
    const y = cose.get(-3);

    if (
        kty !== 2 ||
        alg !== -7 ||
        curve !== 1
    ) {
        throw new Error(
            "Only ES256 WebAuthn credentials are supported"
        );
    }

    if (
        !(x instanceof Uint8Array) ||
        !(y instanceof Uint8Array) ||
        x.length !== 32 ||
        y.length !== 32
    ) {
        throw new Error("Invalid ES256 public key");
    }

    const raw = new Uint8Array(65);

    raw[0] = 0x04;

    raw.set(x, 1);
    raw.set(y, 33);

    return crypto.subtle.importKey(
        "raw",
        raw,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        false,
        ["verify"]
    );
}

/* =========================================================
   DER -> IEEE P1363
   WebAuthn signatures are DER encoded.
   WebCrypto verification uses raw r || s.
   ========================================================= */

function derToRawSignature(der) {
    const bytes = der instanceof Uint8Array
        ? der
        : new Uint8Array(der);

    if (bytes[0] !== 0x30) {
        throw new Error("Invalid DER signature");
    }

    let offset = 1;

    let sequenceLength = bytes[offset++];

    if (sequenceLength & 0x80) {
        const count = sequenceLength & 0x7f;
        sequenceLength = 0;

        for (let i = 0; i < count; i++) {
            sequenceLength =
                sequenceLength * 256 +
                bytes[offset++];
        }
    }

    if (bytes[offset++] !== 0x02) {
        throw new Error("Invalid DER R");
    }

    let rLength = bytes[offset++];

    const r = bytes.slice(
        offset,
        offset + rLength
    );

    offset += rLength;

    if (bytes[offset++] !== 0x02) {
        throw new Error("Invalid DER S");
    }

    let sLength = bytes[offset++];

    const s = bytes.slice(
        offset,
        offset + sLength
    );

    function normalizeInteger(value) {
        let start = 0;

        while (
            value.length - start > 32 &&
            value[start] === 0
        ) {
            start++;
        }

        value = value.slice(start);

        if (value.length > 32) {
            throw new Error("ECDSA integer too large");
        }

        const result = new Uint8Array(32);

        result.set(
            value,
            32 - value.length
        );

        return result;
    }

    const raw = new Uint8Array(64);

    raw.set(normalizeInteger(r), 0);
    raw.set(normalizeInteger(s), 32);

    return raw;
}

/* =========================================================
   WEBAUTHN REGISTRATION
   ========================================================= */

async function verifyRegistration(
    request,
    credential
) {
    const body = await request.json();

    if (
        !body.id ||
        !body.rawId ||
        !body.response
    ) {
        throw new Error("Invalid registration request");
    }

    const clientDataJSON =
        base64urlDecode(body.response.clientDataJSON);

    const attestationObject =
        base64urlDecode(body.response.attestationObject);

    const clientData =
        parseClientDataJSON(clientDataJSON);

    const origin = new URL(request.url).origin;

    if (clientData.type !== "webauthn.create") {
        throw new Error("Invalid WebAuthn type");
    }

    if (clientData.origin !== origin) {
        throw new Error("Invalid WebAuthn origin");
    }

    const challenge = body.expectedChallenge;

    if (
        !challenge ||
        clientData.challenge !== challenge
    ) {
        throw new Error("Invalid WebAuthn challenge");
    }

    const attestation =
        parseAttestationObject(attestationObject);

    const {
        credentialId,
        cose
    } = findCredentialPublicKey(attestation);

    const credentialIdEncoded =
        base64urlEncode(credentialId);

    const publicKey =
        await coseToCryptoKey(cose);

    return {
        id: credentialIdEncoded,
        publicKey,
        publicKeyCose: base64urlEncode(
            attestationObject.get("authData")
        ),
        transports:
            body.response.transports || []
    };
}

/* =========================================================
   WEBAUTHN ASSERTION
   ========================================================= */

async function verifyAssertion(
    request,
    credentialRecord,
    expectedChallenge
) {
    const body = await request.json();

    if (!body.response) {
        throw new Error("Invalid assertion");
    }

    const clientDataJSON =
        base64urlDecode(
            body.response.clientDataJSON
        );

    const authenticatorData =
        base64urlDecode(
            body.response.authenticatorData
        );

    const signature =
        base64urlDecode(
            body.response.signature
        );

    const clientData =
        parseClientDataJSON(clientDataJSON);

    const origin = new URL(request.url).origin;

    if (
        clientData.type !==
        "webauthn.get"
    ) {
        throw new Error("Invalid WebAuthn type");
    }

    if (clientData.origin !== origin) {
        throw new Error("Invalid WebAuthn origin");
    }

    if (
        clientData.challenge !==
        expectedChallenge
    ) {
        throw new Error("Invalid challenge");
    }

    if (authenticatorData.length < 37) {
        throw new Error("Invalid authenticator data");
    }

    const expectedRpHash =
        await sha256(
            new URL(request.url).hostname
        );

    const actualRpHash =
        authenticatorData.slice(0, 32);

    if (
        !crypto.subtle.timingSafeEqual(
            expectedRpHash,
            actualRpHash
        )
    ) {
        throw new Error("Invalid RP ID");
    }

    const flags = authenticatorData[32];

    /*
     * UP = User Present
     */
    if (!(flags & 0x01)) {
        throw new Error(
            "User presence was not verified"
        );
    }

    /*
     * UV = User Verified
     *
     * Face ID normally causes the authenticator
     * to set this flag.
     */
    if (!(flags & 0x04)) {
        throw new Error(
            "User verification required"
        );
    }

    const clientHash =
        await sha256(clientDataJSON);

    const signedData =
        new Uint8Array(
            authenticatorData.length +
            clientHash.length
        );

    signedData.set(authenticatorData, 0);
    signedData.set(
        clientHash,
        authenticatorData.length
    );

    const rawSignature =
        derToRawSignature(signature);

    const publicKey =
        await crypto.subtle.importKey(
            "jwk",
            credentialRecord.publicKey,
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false,
            ["verify"]
        );

    const valid =
        await crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: "SHA-256"
            },
            publicKey,
            rawSignature,
            signedData
        );

    if (!valid) {
        throw new Error(
            "Invalid WebAuthn signature"
        );
    }

    return true;
}

/* =========================================================
   CHALLENGES
   ========================================================= */

async function createChallenge(env) {
    const challenge = base64urlEncode(
        randomBytes(32)
    );

    await env.kv.put(
        "auth:challenge:" + challenge,
        JSON.stringify({
            createdAt: Date.now()
        }),
        {
            expirationTtl: 300
        }
    );

    return challenge;
}

async function consumeChallenge(env, challenge) {
    const key =
        "auth:challenge:" + challenge;

    const value = await env.kv.get(key);

    if (!value) {
        return false;
    }

    await env.kv.delete(key);

    try {
        const parsed = JSON.parse(value);

        if (
            Date.now() - parsed.createdAt >
            5 * 60 * 1000
        ) {
            return false;
        }
    } catch {
        return false;
    }

    return true;
}

/* =========================================================
   PAGES
   ========================================================= */

function setupPage() {
    return html(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authenticator Setup</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#0b0b0f;
    color:#fff;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
.card{
    width:min(430px,92vw);
    padding:32px;
    border-radius:24px;
    background:#17171d;
    box-shadow:0 20px 60px #0008;
}
h1{margin-top:0}
p{color:#aaa;line-height:1.5}
input,button{
    width:100%;
    padding:14px;
    margin-top:12px;
    border-radius:12px;
    border:0;
    font-size:16px;
}
input{
    background:#25252d;
    color:white;
}
button{
    background:#fff;
    color:#111;
    font-weight:600;
}
button.secondary{
    background:#292931;
    color:white;
}
#status{
    margin-top:18px;
    color:#aaa;
    min-height:24px;
}
.small{
    font-size:13px;
    color:#777;
}
</style>
</head>
<body>
<div class="card">
<h1>Set up authenticator</h1>

<p>
Create the password used to unlock this authenticator.
Your password itself will never be stored.
</p>

<form id="form">
<input
    id="password"
    type="password"
    placeholder="Password"
    autocomplete="new-password"
    required
>
<input
    id="confirm"
    type="password"
    placeholder="Confirm password"
    autocomplete="new-password"
    required
>

<input
    id="minutes"
    type="number"
    value="${DEFAULT_SESSION_MINUTES}"
    min="1"
    max="${MAX_SESSION_MINUTES}"
    placeholder="Session minutes"
>

<button type="submit">
Create authenticator
</button>
</form>

<div id="status"></div>

<p class="small">
After setup, you can register Face ID / Touch ID /
another passkey from the authenticator.
</p>
</div>

<script>
const form = document.getElementById("form");
const status = document.getElementById("status");

form.addEventListener("submit", async e => {
    e.preventDefault();

    const password =
        document.getElementById("password").value;

    const confirm =
        document.getElementById("confirm").value;

    const minutes =
        Number(document.getElementById("minutes").value);

    if (password.length < 8) {
        status.textContent =
            "Password must be at least 8 characters.";
        return;
    }

    if (password !== confirm) {
        status.textContent =
            "Passwords do not match.";
        return;
    }

    status.textContent = "Creating authenticator...";

    const response = await fetch("/api/setup", {
        method:"POST",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({
            password,
            minutes
        })
    });

    const data = await response.json();

    if (!response.ok) {
        status.textContent =
            data.error || "Setup failed.";
        return;
    }

    location.href = "/";
});
</script>
</body>
</html>
`);
}

function loginPage() {
    return html(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unlock</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#0b0b0f;
    color:#fff;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
.card{
    width:min(430px,92vw);
    padding:32px;
    border-radius:24px;
    background:#17171d;
    box-shadow:0 20px 60px #0008;
}
h1{margin-top:0}
p{color:#aaa}
input,button{
    width:100%;
    padding:14px;
    margin-top:12px;
    border-radius:12px;
    border:0;
    font-size:16px;
}
input{
    background:#25252d;
    color:white;
}
button{
    background:#fff;
    color:#111;
    font-weight:600;
}
button.secondary{
    background:#292931;
    color:white;
}
#status{
    margin-top:18px;
    color:#aaa;
    min-height:24px;
}
</style>
</head>
<body>
<div class="card">

<h1>Authenticator locked</h1>

<p>
Enter your password or use your registered
Face ID / passkey.
</p>

<form id="login">
<input
    id="password"
    type="password"
    placeholder="Password"
    autocomplete="current-password"
    required
>

<button>
Unlock
</button>
</form>

<button
    class="secondary"
    id="passkey"
    type="button"
>
Use Face ID / Passkey
</button>

<div id="status"></div>

</div>

<script>
const status =
    document.getElementById("status");

function b64ToBytes(str){
    str = str.replace(/-/g,"+").replace(/_/g,"/");
    while(str.length % 4) str += "=";

    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);

    for(let i=0;i<bin.length;i++)
        bytes[i] = bin.charCodeAt(i);

    return bytes;
}

function bytesToB64(bytes){
    let s="";
    for(const b of bytes)
        s += String.fromCharCode(b);

    return btoa(s)
        .replace(/\\+/g,"-")
        .replace(/\\//g,"_")
        .replace(/=+$/,"");
}

async function loginPassword(){
    status.textContent = "Unlocking...";

    const password =
        document.getElementById("password").value;

    const response = await fetch("/api/login",{
        method:"POST",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({password})
    });

    const data = await response.json();

    if(!response.ok){
        status.textContent =
            data.error || "Invalid password.";
        return;
    }

    location.href = "/";
}

document
.getElementById("login")
.addEventListener("submit",e=>{
    e.preventDefault();
    loginPassword();
});

async function loginPasskey(){
    try{
        status.textContent =
            "Waiting for Face ID...";

        const start =
            await fetch("/api/webauthn/login/start",{
                method:"POST"
            });

        const options =
            await start.json();

        if(!start.ok)
            throw new Error(options.error);

        options.publicKey.challenge =
            b64ToBytes(options.publicKey.challenge);

        if(options.publicKey.allowCredentials){
            options.publicKey.allowCredentials =
                options.publicKey.allowCredentials.map(x=>({
                    ...x,
                    id:b64ToBytes(x.id)
                }));
        }

        const credential =
            await navigator.credentials.get(
                options
            );

        const response =
            credential.response;

        const result = {
            id:credential.id,
            rawId:bytesToB64(
                new Uint8Array(credential.rawId)
            ),
            type:credential.type,
            response:{
                clientDataJSON:bytesToB64(
                    new Uint8Array(
                        response.clientDataJSON
                    )
                ),
                authenticatorData:bytesToB64(
                    new Uint8Array(
                        response.authenticatorData
                    )
                ),
                signature:bytesToB64(
                    new Uint8Array(
                        response.signature
                    )
                ),
                userHandle:response.userHandle
                    ? bytesToB64(
                        new Uint8Array(
                            response.userHandle
                        )
                    )
                    : null
            }
        };

        const verify =
            await fetch("/api/webauthn/login/finish",{
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify(result)
            });

        const data =
            await verify.json();

        if(!verify.ok)
            throw new Error(data.error);

        location.href="/";

    }catch(error){
        status.textContent =
            error.message ||
            "Face ID authentication failed.";
    }
}

document
.getElementById("passkey")
.addEventListener("click",loginPasskey);
</script>
</body>
</html>
`);
}

function protectedPage(session, config) {
    const expires =
        new Date(session.expiresAt)
            .toLocaleString();

    return html(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authenticator</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    background:#0b0b0f;
    color:#fff;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
main{
    width:min(700px,92vw);
    margin:60px auto;
}
.card{
    background:#17171d;
    padding:28px;
    border-radius:24px;
    margin-bottom:20px;
}
h1{margin-top:0}
.status{
    padding:14px;
    border-radius:12px;
    background:#25252d;
    margin-top:15px;
}
button{
    border:0;
    border-radius:12px;
    padding:13px 18px;
    margin-top:10px;
    font-size:15px;
    font-weight:600;
}
.primary{
    background:#fff;
    color:#111;
}
.danger{
    background:#402020;
    color:#fff;
}
input{
    width:100%;
    padding:13px;
    margin-top:10px;
    border-radius:10px;
    border:0;
    background:#25252d;
    color:#fff;
}
</style>
</head>

<body>
<main>

<div class="card">
<h1>🔐 Authenticator</h1>

<div class="status">
<strong>Unlocked</strong><br>
Session expires:<br>
${escapeHTML(expires)}
</div>
</div>

<div class="card">
<h2>Face ID / Passkey</h2>

<p>
Register this device so you can unlock with
Face ID, Touch ID, or the device's passkey system.
</p>

<button
    class="primary"
    id="register"
>
Register this device
</button>

<div id="passkeyStatus"></div>
</div>

<div class="card">
<h2>Session</h2>

<p>
Your session expires automatically after
${config.sessionMinutes} minutes.
</p>

<button
    class="danger"
    id="logout"
>
Lock now
</button>
</div>

</main>

<script>
function bytesToB64(bytes){
    let s="";
    for(const b of bytes)
        s += String.fromCharCode(b);

    return btoa(s)
        .replace(/\\+/g,"-")
        .replace(/\\//g,"_")
        .replace(/=+$/,"");
}

function b64ToBytes(str){
    str = str.replace(/-/g,"+").replace(/_/g,"/");
    while(str.length % 4) str += "=";

    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);

    for(let i=0;i<bin.length;i++)
        bytes[i]=bin.charCodeAt(i);

    return bytes;
}

async function registerPasskey(){

    const status =
        document.getElementById("passkeyStatus");

    try{

        status.textContent =
            "Preparing Face ID registration...";

        const start =
            await fetch(
                "/api/webauthn/register/start",
                {method:"POST"}
            );

        const options =
            await start.json();

        if(!start.ok)
            throw new Error(options.error);

        options.publicKey.challenge =
            b64ToBytes(
                options.publicKey.challenge
            );

        options.publicKey.user.id =
            b64ToBytes(
                options.publicKey.user.id
            );

        const credential =
            await navigator.credentials.create(
                options
            );

        if(!credential)
            throw new Error(
                "No credential was created."
            );

        const response =
            credential.response;

        const transports =
            typeof response.getTransports ===
            "function"
                ? response.getTransports()
                : [];

        const data = {

            id:credential.id,

            rawId:bytesToB64(
                new Uint8Array(
                    credential.rawId
                )
            ),

            type:credential.type,

            expectedChallenge:
                options.publicKey.challenge
                    ? bytesToB64(
                        options.publicKey.challenge
                    )
                    : null,

            response:{
                clientDataJSON:bytesToB64(
                    new Uint8Array(
                        response.clientDataJSON
                    )
                ),

                attestationObject:bytesToB64(
                    new Uint8Array(
                        response.attestationObject
                    )
                ),

                transports
            }
        };

        /*
         * The challenge is returned by the Worker
         * as base64url. We need to send it separately
         * because the Worker verifies it.
         */
        data.expectedChallenge =
            options._challenge;

        const finish =
            await fetch(
                "/api/webauthn/register/finish",
                {
                    method:"POST",
                    headers:{
                        "Content-Type":
                            "application/json"
                    },
                    body:JSON.stringify(data)
                }
            );

        const result =
            await finish.json();

        if(!finish.ok)
            throw new Error(result.error);

        status.textContent =
            "✓ This device can now use Face ID / passkey.";

    }catch(error){

        status.textContent =
            error.message ||
            "Passkey registration failed.";
    }
}

document
.getElementById("register")
.addEventListener(
    "click",
    registerPasskey
);

document
.getElementById("logout")
.addEventListener(
    "click",
    async()=>{
        await fetch(
            "/api/logout",
            {method:"POST"}
        );

        location.href="/";
    }
);
</script>

</body>
</html>
`);
}

/* =========================================================
   HTML ESCAPING
   ========================================================= */

function escapeHTML(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* =========================================================
   WEBAUTHN OPTIONS
   ========================================================= */

async function registrationOptions(
    request,
    env
) {
    const config = await getConfig(env);

    if (!config) {
        throw new Error(
            "Authenticator is not configured"
        );
    }

    const challenge =
        await createChallenge(env);

    const userId =
        config.userId;

    const hostname =
        new URL(request.url).hostname;

    return {
        publicKey: {
            challenge: base64urlDecode(challenge),

            rp: {
                name: "Authenticator",
                id: hostname
            },

            user: {
                id: base64urlDecode(userId),
                name: "owner",
                displayName: "Authenticator Owner"
            },

            pubKeyCredParams: [
                {
                    type: "public-key",
                    alg: -7
                }
            ],

            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "required"
            },

            timeout: 60000,

            attestation: "none"
        },

        _challenge: challenge
    };
}

/* =========================================================
   MAIN WORKER
   ========================================================= */

export default {

    async fetch(request, env) {

        try {

            if (!env.kv) {
                return new Response(
                    "ERROR: KV binding 'kv' is missing.",
                    {status:500}
                );
            }

            const url =
                new URL(request.url);

            const config =
                await getConfig(env);

            /* =============================================
               FIRST-RUN SETUP
               ============================================= */

            if (
                !config &&
                url.pathname !== "/api/setup"
            ) {

                if (
                    url.pathname.startsWith("/api/")
                ) {
                    return json({
                        error:
                            "Authenticator has not been configured."
                    }, 503);
                }

                return setupPage();
            }

            /* =============================================
               SETUP
               ============================================= */

            if (
                url.pathname === "/api/setup" &&
                request.method === "POST"
            ) {

                if (config) {
                    return json({
                        error:
                            "Authenticator is already configured."
                    }, 409);
                }

                const body =
                    await request.json();

                const password =
                    String(body.password || "");

                let minutes =
                    Number(body.minutes);

                if (
                    !Number.isFinite(minutes) ||
                    minutes < 1
                ) {
                    minutes =
                        DEFAULT_SESSION_MINUTES;
                }

                minutes =
                    Math.min(
                        Math.floor(minutes),
                        MAX_SESSION_MINUTES
                    );

                if (password.length < 8) {
                    return json({
                        error:
                            "Password must be at least 8 characters."
                    }, 400);
                }

                const passwordData =
                    await hashPassword(password);

                const newConfig = {
                    version: 1,

                    passwordSalt:
                        passwordData.salt,

                    passwordHash:
                        passwordData.hash,

                    sessionMinutes:
                        minutes,

                    userId:
                        base64urlEncode(
                            randomBytes(32)
                        ),

                    createdAt:
                        Date.now()
                };

                /*
                 * Small race-condition protection:
                 * check again immediately before writing.
                 */
                const existing =
                    await env.kv.get(CONFIG_KEY);

                if (existing) {
                    return json({
                        error:
                            "Authenticator was already configured."
                    }, 409);
                }

                await saveConfig(
                    env,
                    newConfig
                );

                return json({
                    ok:true
                });
            }

            /* =============================================
               PASSWORD LOGIN
               ============================================= */

            if (
                url.pathname === "/api/login" &&
                request.method === "POST"
            ) {

                const body =
                    await request.json();

                const password =
                    String(body.password || "");

                const valid =
                    await verifyPassword(
                        password,
                        config.passwordSalt,
                        config.passwordHash
                    );

                if (!valid) {
                    /*
                     * Deliberately generic response.
                     */
                    return json({
                        error:
                            "Invalid password."
                    }, 401);
                }

                const session =
                    await createSession(
                        env,
                        config.sessionMinutes
                    );

                return json(
                    {ok:true},
                    200,
                    {
                        "Set-Cookie":
                            sessionCookie(
                                session.token,
                                session.maxAge
                            )
                    }
                );
            }

            /* =============================================
               LOGOUT
               ============================================= */

            if (
                url.pathname === "/api/logout" &&
                request.method === "POST"
            ) {

                await destroySession(
                    request,
                    env
                );

                return json(
                    {ok:true},
                    200,
                    {
                        "Set-Cookie":
                            expiredCookie()
                    }
                );
            }

            /* =============================================
               WEBAUTHN REGISTER START
               ============================================= */

            if (
                url.pathname ===
                "/api/webauthn/register/start" &&
                request.method === "POST"
            ) {

                const session =
                    await getSession(
                        request,
                        env
                    );

                if (!session) {
                    return json({
                        error:
                            "Authentication required."
                    }, 401);
                }

                const options =
                    await registrationOptions(
                        request,
                        env
                    );

                return json(options);
            }

            /* =============================================
               WEBAUTHN REGISTER FINISH
               ============================================= */

            if (
                url.pathname ===
                "/api/webauthn/register/finish" &&
                request.method === "POST"
            ) {

                const session =
                    await getSession(
                        request,
                        env
                    );

                if (!session) {
                    return json({
                        error:
                            "Authentication required."
                    }, 401);
                }

                const body =
                    await request.json();

                if (!body.expectedChallenge) {
                    return json({
                        error:
                            "Missing challenge."
                    }, 400);
                }

                const challengeValid =
                    await consumeChallenge(
                        env,
                        body.expectedChallenge
                    );

                if (!challengeValid) {
                    return json({
                        error:
                            "Invalid or expired challenge."
                    }, 400);
                }

                /*
                 * Reconstruct the body expected by
                 * verifyRegistration().
                 */
                const fakeRequest =
                    new Request(
                        request.url,
                        {
                            method:"POST",
                            body:JSON.stringify(body)
                        }
                    );

                const registered =
                    await verifyRegistration(
                        fakeRequest,
                        {
                            expectedChallenge:
                                body.expectedChallenge
                        }
                    );

                /*
                 * verifyRegistration currently returns
                 * the public key object. Convert the COSE
                 * public key to JWK for KV storage.
                 *
                 * Re-read the attestation to extract
                 * the EC coordinates.
                 */

                const attestationObject =
                    base64urlDecode(
                        body.response.attestationObject
                    );

                const attestation =
                    parseAttestationObject(
                        attestationObject
                    );

                const authData =
                    attestation.get("authData");

                const parsed =
                    findCredentialPublicKey(
                        attestation
                    );

                const cose =
                    parsed.cose;

                const x =
                    cose.get(-2);

                const y =
                    cose.get(-3);

                const credentialId =
                    base64urlEncode(
                        parsed.credentialId
                    );

                const jwk = {
                    kty:"EC",
                    crv:"P-256",
                    x:base64urlEncode(x),
                    y:base64urlEncode(y),
                    ext:true
                };

                const credentialRecord = {
                    id:credentialId,
                    publicKey:jwk,
                    createdAt:Date.now(),
                    transports:
                        body.response.transports ||
                        []
                };

                await env.kv.put(
                    CRED_PREFIX + credentialId,
                    JSON.stringify(
                        credentialRecord
                    )
                );

                return json({
                    ok:true,
                    credentialId
                });
            }

            /* =============================================
               WEBAUTHN LOGIN START
               ============================================= */

            if (
                url.pathname ===
                "/api/webauthn/login/start" &&
                request.method === "POST"
            ) {

                const challenge =
                    await createChallenge(env);

                const keys =
                    await env.kv.list({
                        prefix:CRED_PREFIX
                    });

                const allowCredentials =
                    [];

                for (
                    const key of keys.keys
                ) {

                    const raw =
                        await env.kv.get(
                            key.name
                        );

                    if (!raw) continue;

                    try {

                        const record =
                            JSON.parse(raw);

                        allowCredentials.push({
                            type:"public-key",
                            id:record.id,
                            transports:
                                record.transports || []
                        });

                    } catch {}
                }

                if (
                    allowCredentials.length === 0
                ) {

                    return json({
                        error:
                            "No passkeys have been registered yet."
                    }, 400);
                }

                return json({
                    publicKey:{
                        challenge,
                        rpId:
                            new URL(request.url)
                                .hostname,

                        allowCredentials,

                        userVerification:
                            "required",

                        timeout:60000
                    }
                });
            }

            /* =============================================
               WEBAUTHN LOGIN FINISH
               ============================================= */

            if (
                url.pathname ===
                "/api/webauthn/login/finish" &&
                request.method === "POST"
            ) {

                const body =
                    await request.json();

                if (!body.id) {
                    return json({
                        error:
                            "Missing credential ID."
                    }, 400);
                }

                /*
                 * The challenge is stored in the KV namespace.
                 * The browser's clientDataJSON contains it,
                 * but we don't know it until after parsing it.
                 */

                const clientDataJSON =
                    base64urlDecode(
                        body.response.clientDataJSON
                    );

                const clientData =
                    parseClientDataJSON(
                        clientDataJSON
                    );

                if (!clientData.challenge) {
                    return json({
                        error:
                            "Missing challenge."
                    }, 400);
                }

                const challengeValid =
                    await consumeChallenge(
                        env,
                        clientData.challenge
                    );

                if (!challengeValid) {
                    return json({
                        error:
                            "Invalid or expired challenge."
                    }, 400);
                }

                const credentialId =
                    body.id;

                const raw =
                    await env.kv.get(
                        CRED_PREFIX +
                        credentialId
                    );

                if (!raw) {
                    return json({
                        error:
                            "Unknown passkey."
                    }, 401);
                }

                const credentialRecord =
                    JSON.parse(raw);

                await verifyAssertion(
                    new Request(
                        request.url,
                        {
                            method:"POST",
                            body:JSON.stringify(body)
                        }
                    ),
                    credentialRecord,
                    clientData.challenge
                );

                const session =
                    await createSession(
                        env,
                        config.sessionMinutes
                    );

                return json(
                    {
                        ok:true
                    },
                    200,
                    {
                        "Set-Cookie":
                            sessionCookie(
                                session.token,
                                session.maxAge
                            )
                    }
                );
            }

            /* =============================================
               API AUTH STATUS
               ============================================= */

            if (
                url.pathname ===
                "/api/auth/status"
            ) {

                const session =
                    await getSession(
                        request,
                        env
                    );

                if (!session) {
                    return json({
                        authenticated:false
                    }, 401);
                }

                return json({
                    authenticated:true,
                    expiresAt:
                        session.expiresAt
                });
            }

            /* =============================================
               PROTECTED ROOT
               ============================================= */

            const session =
                await getSession(
                    request,
                    env
                );

            if (!session) {
                return loginPage();
            }

            return protectedPage(
                session,
                config
            );

        } catch (error) {

            console.error(error);

            return json({
                error:
                    "Internal authentication error.",
                detail:
                    String(error?.message || error)
            }, 500);
        }
    }
};
