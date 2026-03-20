/* ═══════════════════════════════════════════════════════════════════
   FlagVault CTF — JWT Algorithm Confusion Challenge #04
   ─────────────────────────────────────────────────────
   HOW IT WORKS (CTF author notes):
   ─────────────────────────────────
   Everything is simulated client-side.

   1. LOGIN  — guest/guest123 returns a real HS256-signed JWT
      (signed with a dummy secret "supersecret").
      The payload contains { username:"guest", role:"guest" }

   2. DECODE TAB — Player can paste any JWT and see header/payload
      decoded from base64url. Live, no library needed.

   3. FORGE TAB — Player edits the header JSON (to set alg:"none")
      and payload JSON (to set role:"admin"), then clicks Forge.
      The tool builds a real base64url(header).base64url(payload).
      token with an empty signature part (trailing dot).

   4. SEND TAB — Player sends the forged token to /api/admin/dashboard.
      We detect alg:none + role:admin → grant access → show flag page.

   5. ADMIN PAGE — Full dashboard with the flag displayed.

   FLAG: FlagVault{jwt_n0n3_4lg0r1thm_1s_4_cl4ss1c_m1st4k3}
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

const FLAG = 'FlagVault{jwt_n0n3_4lg0r1thm_1s_4_cl4ss1c_m1st4k3}';

/* ══════════════════════════════
   BASE64URL HELPERS
   (no external library needed)
══════════════════════════════ */
function b64urlEncode(str) {
  // str → utf8 bytes → base64 → base64url
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecode(str) {
  // base64url → base64 → string
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    const binary = atob(s);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/* ══════════════════════════════
   SIMULATED SIGN (HS256 mock)
   Real HMAC is not needed — we
   generate a plausible-looking
   dummy signature for the guest
   token. The server (sim) ignores
   it anyway for alg:none tokens.
══════════════════════════════ */
function makeDummySig() {
  // 32 random bytes → base64url (looks like a real HMAC-SHA256)
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  let binary = '';
  arr.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

/* ══════════════════════════════
   GUEST JWT FACTORY
══════════════════════════════ */
function makeGuestJWT(username) {
  const header  = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    username: username,
    role: 'guest',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const s = makeDummySig();
  return `${h}.${p}.${s}`;
}

/* ══════════════════════════════
   SIMULATED LOGIN
══════════════════════════════ */
let currentToken = null;

function doLogin() {
  const user    = document.getElementById('login-user').value.trim();
  const pass    = document.getElementById('login-pass').value.trim();
  const btn     = document.getElementById('btn-login');
  const resDiv  = document.getElementById('login-response');
  const resBody = document.getElementById('res-body-login');
  const resCode = document.getElementById('res-status-code');

  btn.disabled = true;
  btn.textContent = '>_ SENDING...';

  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = '>_ SEND REQUEST';

    if (user === 'guest' && pass === 'guest123') {
      currentToken = makeGuestJWT(user);
      resCode.textContent = '200 OK';
      resCode.className   = 'res-status ok';
      resBody.textContent = JSON.stringify({
        status:  'success',
        message: 'Login successful',
        token:   currentToken
      }, null, 2);
      resDiv.classList.remove('hidden');

      // Auto-fill decode tab
      document.getElementById('decode-input').value = currentToken;
      decodeJWT();

      // Auto-fill forge payload with guest data
      const p = JSON.parse(b64urlDecode(currentToken.split('.')[1]));
      document.getElementById('forge-payload').value = JSON.stringify(
        { username: p.username, role: p.role, iat: p.iat, exp: p.exp }, null, 2
      );

    } else {
      resCode.textContent = '401 Unauthorized';
      resCode.className   = 'res-status err';
      resBody.textContent = JSON.stringify({
        status:  'error',
        message: `Invalid credentials for user '${user}'`
      }, null, 2);
      resDiv.classList.remove('hidden');
    }
  }, 700);
}

/* ══════════════════════════════
   JWT DECODER
══════════════════════════════ */
function decodeJWT() {
  const raw    = document.getElementById('decode-input').value.trim();
  const hEl    = document.getElementById('decoded-header');
  const pEl    = document.getElementById('decoded-payload');
  const sEl    = document.getElementById('decoded-sig');

  if (!raw) return;
  const parts = raw.split('.');
  if (parts.length < 2) {
    hEl.textContent = '[ Invalid JWT format ]';
    return;
  }

  const hDecoded = b64urlDecode(parts[0]);
  const pDecoded = b64urlDecode(parts[1]);

  try {
    hEl.textContent = JSON.stringify(JSON.parse(hDecoded), null, 2);
  } catch { hEl.textContent = hDecoded || '[ decode error ]'; }

  try {
    pEl.textContent = JSON.stringify(JSON.parse(pDecoded), null, 2);
  } catch { pEl.textContent = pDecoded || '[ decode error ]'; }

  sEl.textContent = parts[2]
    ? parts[2].substring(0, 40) + '...' + '\n[ HMAC-SHA256 — verify with secret ]'
    : '(empty) — alg:none token detected!';
  if (!parts[2]) sEl.style.color = 'var(--accent2)';
  else sEl.style.color = 'var(--accent)';
}

/* ══════════════════════════════
   JWT FORGER
══════════════════════════════ */
function forgeJWT() {
  const headerRaw  = document.getElementById('forge-header').value.trim();
  const payloadRaw = document.getElementById('forge-payload').value.trim();
  const sigRaw     = document.getElementById('forge-sig').value.trim();
  const outputDiv  = document.getElementById('forged-output');
  const tokenEl    = document.getElementById('forged-token-value');

  let header, payload;
  try { header  = JSON.parse(headerRaw);  } catch { alert('Header JSON is invalid.'); return; }
  try { payload = JSON.parse(payloadRaw); } catch { alert('Payload JSON is invalid.'); return; }

  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const s = sigRaw; // empty for alg:none

  const token = `${h}.${p}.${s}`;
  tokenEl.textContent = token;
  outputDiv.classList.remove('hidden');

  // Auto-fill the send tab
  document.getElementById('send-token').value = token;
}

/* ══════════════════════════════
   SIMULATED SERVER VERIFICATION
══════════════════════════════ */
function verifyToken(tokenStr) {
  /*
    Simulates a VULNERABLE server that:
    1. Reads the alg field FROM the token header (the bug!)
    2. If alg === "none" → skips signature check entirely
    3. Checks the role claim
  */
  const parts = tokenStr.trim().split('.');
  if (parts.length < 2) return { ok: false, reason: 'Malformed token' };

  const hRaw = b64urlDecode(parts[0]);
  const pRaw = b64urlDecode(parts[1]);
  if (!hRaw || !pRaw) return { ok: false, reason: 'Base64url decode failed' };

  let header, payload;
  try { header  = JSON.parse(hRaw);  } catch { return { ok: false, reason: 'Header JSON invalid' }; }
  try { payload = JSON.parse(pRaw);  } catch { return { ok: false, reason: 'Payload JSON invalid' }; }

  const alg = (header.alg || '').toLowerCase();

  if (alg === 'none') {
    // ⚠️ VULNERABLE: server trusts alg:none and skips verification
    if (payload.role === 'admin') {
      return { ok: true, role: 'admin', username: payload.username || 'unknown', alg: 'none' };
    } else {
      return { ok: false, reason: `Role '${payload.role}' is not authorized for this endpoint` };
    }
  }

  if (alg === 'hs256') {
    // Legitimate HS256 tokens: only the original guest token works
    // (We can't re-verify HMAC in the browser without the secret)
    // If the payload role is guest → grant guest access only
    // If the player tries to change role to admin with HS256 → reject (can't forge sig)
    if (payload.role === 'admin') {
      return { ok: false, reason: 'Signature verification failed — cannot forge HS256 without the secret key' };
    }
    return { ok: false, reason: 'This endpoint requires admin role' };
  }

  return { ok: false, reason: `Unsupported algorithm: ${header.alg}` };
}

/* ══════════════════════════════
   SEND FORGED TOKEN
══════════════════════════════ */
function sendForgedToken() {
  const tokenInput = document.getElementById('send-token');
  const token      = tokenInput.value.trim();
  const btn        = document.getElementById('btn-send-token');
  const resDiv     = document.getElementById('admin-response');
  const resCode    = document.getElementById('admin-res-code');
  const resBody    = document.getElementById('admin-res-body');

  if (!token) {
    alert('Paste a JWT token first.');
    return;
  }

  btn.disabled = true;
  btn.textContent = '>_ VERIFYING...';

  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = '>_ SEND FORGED REQUEST';

    const result = verifyToken(token);

    resDiv.classList.remove('hidden');

    if (result.ok) {
      resCode.textContent = '200 OK';
      resCode.className   = 'res-status ok';
      resBody.textContent = JSON.stringify({
        status:  'success',
        message: 'Welcome to the admin dashboard',
        user:    result.username,
        role:    result.role,
        note:    'alg:none bypass accepted — flag delivered'
      }, null, 2);

      // Show admin page after brief delay
      setTimeout(() => showAdminPage(token), 800);
    } else {
      resCode.textContent = '401 Unauthorized';
      resCode.className   = 'res-status err';
      resBody.textContent = JSON.stringify({
        status:  'error',
        message: result.reason,
        hint:    'Try setting alg to "none" and role to "admin" in the Forge tab.'
      }, null, 2);
    }
  }, 800);
}

/* ══════════════════════════════
   SHOW ADMIN PAGE
══════════════════════════════ */
function showAdminPage(token) {
  document.getElementById('page-login').classList.remove('active');
  document.getElementById('page-admin').classList.remove('hidden');
  document.getElementById('page-admin').classList.add('active');

  document.getElementById('admin-token-display').textContent = token;
  document.getElementById('flag-display').textContent = FLAG;
  window.scrollTo(0, 0);
}

function goBack() {
  document.getElementById('page-admin').classList.remove('active');
  document.getElementById('page-admin').classList.add('hidden');
  document.getElementById('page-login').classList.add('active');
}

/* ══════════════════════════════
   TABS
══════════════════════════════ */
function switchTab(name) {
  ['decode','forge','send'].forEach(t => {
    document.getElementById(`tab-${t}`).classList.remove('active');
    document.getElementById(`tab-content-${t}`).classList.remove('active');
  });
  document.getElementById(`tab-${name}`).classList.add('active');
  document.getElementById(`tab-content-${name}`).classList.add('active');
}

/* ══════════════════════════════
   HINTS
══════════════════════════════ */
function toggleHint(n) {
  const body   = document.getElementById(`hint${n}-body`);
  const toggle = document.getElementById(`hint${n}-toggle`);
  const hidden = body.classList.toggle('hidden');
  toggle.textContent = hidden ? '▼ Reveal' : '▲ Hide';
}

/* ══════════════════════════════
   FLAG SUBMISSION
══════════════════════════════ */
function submitFlag() {
  const input = document.getElementById('flag-input').value.trim();
  const res   = document.getElementById('flag-result');
  if (`FlagVault{${input}}` === FLAG) {
    res.className = 'submit-result correct';
    res.innerHTML = '✓ &nbsp;Correct! Flag accepted. +350 pts';
  } else {
    res.className = 'submit-result incorrect';
    res.innerHTML = '✗ &nbsp;Incorrect flag. Keep trying.';
  }
}

/* ══════════════════════════════
   COPY HELPERS
══════════════════════════════ */
function copyForged() {
  const val   = document.getElementById('forged-token-value').textContent;
  const toast = document.getElementById('forge-copy-toast');
  navigator.clipboard.writeText(val).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = val;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
  // also paste to send tab
  document.getElementById('send-token').value = val;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 2000);
}

function copyFlag() {
  const val   = document.getElementById('flag-display').textContent;
  const toast = document.getElementById('flag-copy-toast');
  navigator.clipboard.writeText(val).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = val;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 2000);
}

/* ══════════════════════════════
   BOOT
══════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {

  // Enter key on flag submit
  document.getElementById('flag-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitFlag();
  });

  // Enter key on login fields
  ['login-user','login-pass'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', e => {
      if (e.key === 'Enter') doLogin();
    });
  });

  // Live decode as user types in decode tab
  document.getElementById('decode-input')?.addEventListener('input', decodeJWT);

  // Console hints
  console.log('%c🔐 FlagVault CTF — JWT Algorithm Confusion', 'font-size:15px;font-weight:bold;color:#00e8c8;');
  console.log('%cStep 1: Login with guest/guest123 to get a JWT', 'color:#f5a623;font-family:monospace;');
  console.log('%cStep 2: Decode the token. Notice alg:HS256 and role:guest', 'color:#f5a623;font-family:monospace;');
  console.log('%cStep 3: Forge — set alg:"none" and role:"admin", empty signature', 'color:#ff2d6b;font-family:monospace;');
  console.log('%cStep 4: Send the forged token to /api/admin/dashboard', 'color:#00e8c8;font-family:monospace;');
});
