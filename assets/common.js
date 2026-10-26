// Shared by the website's pages: signing in, the session, and choosing a new password.
//
// The website holds only ciphertext: data/users.json (each sign-in) and data/app.enc.json (the
// app itself). A password opens them here in the browser. The only thing that leaves the browser
// is a new password, sealed so only the private repo's Action can open it
// (tools/gia_accounts.py), in a GitHub issue the person submits themselves.

export const $ = (selector) => document.querySelector(selector);

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key in node && !key.includes('-')) node[key] = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export class AppError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();
const USERS_URL = 'data/users.json';
const APP_URL = 'data/app.enc.json';
const PBKDF2_ITERATIONS = 600000;
const MIN_OWN_PASSWORD = 12;
const SESSION_HOURS = 12;
const REMEMBER_DAYS = 30;
const KEYS = { session: 'gia.session.v1', username: 'gia.username' };
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

export const normalizeUsername = (username) => String(username || '').normalize('NFC').trim().toLowerCase();
// Passwords ignore case, spaces and dashes (as in tools/gia_core.py).
export const normalizePassword = (password) => String(password || '').normalize('NFC').toUpperCase().replace(/[\s-]+/g, '');

// ---------------------------------------------------------------- storage

// Storage can be blocked (a private window, say). Then nothing is remembered, and that's all.
const store = {
  get(key, where = 'local') {
    try {
      return JSON.parse((where === 'session' ? sessionStorage : localStorage).getItem(key) || 'null');
    } catch {
      return null;
    }
  },
  set(key, value, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).setItem(key, JSON.stringify(value));
    } catch { /* not remembered */ }
  },
  remove(key, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).removeItem(key);
    } catch { /* nothing kept */ }
  },
};

export const lastName = {
  get: () => store.get(KEYS.username) || '',
  set: (name) => store.set(KEYS.username, name),
};

// A session lasts 12 hours, or 30 days with "Keep me signed in". It holds the user key, which
// opens the person's profile until their password changes.
export function saveSession(session) {
  clearSession();
  const hours = session.remember ? REMEMBER_DAYS * 24 : SESSION_HOURS;
  store.set(KEYS.session, { ...session, exp: Date.now() + hours * 3600 * 1000 }, session.remember ? 'local' : 'session');
}

export function loadSession() {
  const session = store.get(KEYS.session, 'session') || store.get(KEYS.session, 'local');
  if (!session?.uk || !(session.exp > Date.now())) {
    if (session) clearSession();
    return null;
  }
  return session;
}

export function clearSession() {
  store.remove(KEYS.session, 'session');
  store.remove(KEYS.session, 'local');
}

// ------------------------------------------------------------------ crypto

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64urlToBytes = (text) => b64ToBytes(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
const bytesToB64url = (bytes) => bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// AES-256-GCM as "<iv>.<ciphertext>" (base64url), with associated data saying what it is and
// whose it is: the same format as seal()/unseal() in tools/gia_core.py.
async function seal(keyBytes, bytes, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode(aad) }, key, bytes));
  return `${bytesToB64url(iv)}.${bytesToB64url(ct)}`;
}

async function unseal(keyBytes, token, aad) {
  const [iv, ct] = String(token).split('.');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlToBytes(iv), additionalData: utf8.encode(aad) }, key, b64urlToBytes(ct)));
}

const sealJSON = (keyBytes, value, aad) => seal(keyBytes, utf8.encode(JSON.stringify(value)), aad);
const unsealJSON = async (keyBytes, token, aad) => JSON.parse(fromUtf8.decode(await unseal(keyBytes, token, aad)));

async function passwordKey(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8.encode(normalizePassword(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations }, base, 256));
}

// A new user key locked with a password: what data/users.json holds for each sign-in.
async function wrapKey(userKey, password, username) {
  const salt = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
  const key = await seal(await passwordKey(password, salt, PBKDF2_ITERATIONS), userKey, `gia-user-key|${username}`);
  return { salt, iterations: PBKDF2_ITERATIONS, key };
}

// ---------------------------------------------------------------- signing in

async function fetchJSON(url, what) {
  let response;
  try {
    response = await fetch(url, { cache: 'no-cache' });
  } catch {
    throw new AppError('network', 'Couldn’t reach the website. Check your connection and try again.');
  }
  if (response.status === 404) throw new AppError('missing', `The ${what} hasn’t been published yet.`);
  if (!response.ok) throw new AppError('network', `Couldn’t load the ${what} (error ${response.status}).`);
  return response.json();
}

const usersFile = () => fetchJSON(USERS_URL, 'sign-in list');

async function userEntry(username, users) {
  return (users || await usersFile()).users?.[await sha256Hex(`gia-user:${normalizeUsername(username)}`)] || null;
}

export const SIGN_IN_AGAIN = {
  again: 'Please sign in again.',
  changed: 'Your password has changed. Please sign in with the new one.',
};
const signInAgain = (reason = 'again') => Object.assign(new AppError('signin', SIGN_IN_AGAIN[reason]), { reason });
const badLogin = () => new AppError('bad-login', 'That username and password don’t match.');

function checkBrowser() {
  if (!globalThis.crypto?.subtle) {
    throw new AppError('browser', 'This browser can’t open the website. Please use an up-to-date Chrome, Edge, Safari or Firefox.');
  }
}

export async function signIn(username, password) {
  checkBrowser();
  const name = normalizeUsername(username);
  const entry = await userEntry(name);
  if (!entry?.profile) throw badLogin();
  let userKey;
  try {
    userKey = await unseal(await passwordKey(password, entry.salt, entry.iterations), entry.key, `gia-user-key|${name}`);
  } catch {
    throw badLogin();
  }
  return { username: name, uk: bytesToB64(userKey) };
}

// Open a signed-in session: the person's profile and the app. Right after a change the two
// files can briefly disagree (GitHub Pages updates them one after the other), so this waits a
// little for them to match.
export async function openSession(session) {
  checkBrowser();
  if (!session?.uk) throw signInAgain();
  for (let attempt = 0; ; attempt += 1) {
    const users = await usersFile();
    const entry = await userEntry(session.username, users);
    if (!entry?.profile) throw signInAgain();
    let profile;
    try {
      profile = await unsealJSON(b64ToBytes(session.uk), entry.profile, `gia-profile|${session.username}`);
    } catch {
      throw signInAgain('changed');
    }
    const blob = await fetchJSON(APP_URL, 'app');
    if (blob.epoch === profile.epoch) {
      const app = await unsealJSON(b64ToBytes(profile.appKey), blob.data, `gia-app|${blob.epoch}`);
      return { profile, app };
    }
    if (attempt >= 8) throw new AppError('updating', 'The website is being updated. Please try again in a minute.');
    await sleep(4000);
  }
}

// ------------------------------------------------------------ new passwords
//
// "Forgot your password?" and "Change password" both choose a new password here. The page makes
// a new user key, locks it with the new password, and seals both with the Action's request key
// (ECDH on P-256, then HKDF and AES-GCM), so only the Action can open them. The person then
// submits it as an issue on GitHub, signed in to the GitHub account linked to their sign-in:
// that's what shows it's them. The Action applies it and republishes the website, and from then
// on only the new password works.

// Where new passwords are filed, and the Action's public key (from data/users.json).
export async function newPasswordSettings() {
  const requests = (await usersFile()).requests;
  if (!requests || !/^[\w.-]+\/[\w.-]+$/.test(requests.repo || '') || !/^[A-Za-z0-9_-]{87}$/.test(requests.key || '')) {
    throw new AppError('no-requests', 'Choosing a new password isn’t switched on yet.');
  }
  return requests;
}

// Check a password someone chooses (the same rules as check_own_password in tools/gia_core.py).
export function passwordProblem(password, username) {
  const plain = normalizePassword(password);
  if (plain.length < MIN_OWN_PASSWORD) return `Use at least ${MIN_OWN_PASSWORD} characters. A few words with spaces works well.`;
  if (new Set(plain).size < 5) return 'Use a mix of different characters.';
  const name = normalizeUsername(username).toUpperCase();
  if (plain.includes(name) || plain.includes(name.replace(/\./g, ''))) return 'Don’t include your username.';
  return null;
}

// The sealed request, as tools/gia_core.py's open_request expects it: "GIAN1.<one-off public
// key>.<iv>.<ciphertext>", holding {v, u: username, k: new user key, w: its password lock, t: when}.
export async function newPasswordRequest(requests, username, password) {
  checkBrowser();
  const name = normalizeUsername(username);
  const userKey = crypto.getRandomValues(new Uint8Array(32));
  const wrap = await wrapKey(userKey, password, name);
  const actionKey = await crypto.subtle.importKey('raw', b64urlToBytes(requests.key), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const oneOff = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: actionKey }, oneOff.privateKey, 256);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', oneOff.publicKey));
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const key = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: point, info: utf8.encode('gia/new-password') }, hkdf, 256));
  const sealed = await sealJSON(key, { v: 1, u: name, k: bytesToB64(userKey), w: wrap, t: Date.now() }, 'gia-new-password|v1');
  return { token: `GIAN1.${bytesToB64url(point)}.${sealed}`, salt: wrap.salt, username: name };
}

// The GitHub page that opens the issue, filled in. The issue holds only the sealed request.
export function issueLink(requests, token) {
  const body = '<!-- gia:new-password:v1 -->\n'
    + 'A new password for the Group Insurance Allocation website, sealed so only the website’s Action can open it. '
    + 'Submit this issue to confirm it’s you: the Action then sets the password and closes the issue.\n\n'
    + `\`\`\`gia\n${token}\n\`\`\`\n`;
  const query = new URLSearchParams({ title: 'New password for the website', body });
  return `https://github.com/${requests.repo}/issues/new?${query}`;
}

// Wait for the website to show the new password, by its salt. Resolves true once it does, or
// false after `minutes`.
export async function waitForNewPassword(username, salt, minutes = 15) {
  const deadline = Date.now() + minutes * 60 * 1000;
  while (Date.now() < deadline) {
    await sleep(5000);
    const entry = await userEntry(username).catch(() => null);
    if (entry?.salt === salt) return true;
  }
  return false;
}

// ------------------------------------------------------------- page helpers

// The eye next to a password box shows what's typed only while it's held down (with the mouse,
// a finger, or Space or Enter), and hides it again the moment it's let go.
export function holdToShow(button, inputs) {
  const set = (show) => {
    for (const input of inputs) input.type = show ? 'text' : 'password';
    button.classList.toggle('showing', show);
  };
  const hide = () => set(false);
  button.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    event.preventDefault(); // keeps the cursor in the password box
    button.setPointerCapture?.(event.pointerId);
    set(true);
  });
  for (const type of ['pointerup', 'pointercancel', 'lostpointercapture', 'blur']) button.addEventListener(type, hide);
  button.addEventListener('keydown', (event) => {
    if (event.key !== ' ' && event.key !== 'Enter') return;
    event.preventDefault();
    if (!event.repeat) set(true);
  });
  button.addEventListener('keyup', (event) => {
    if (event.key === ' ' || event.key === 'Enter') hide();
  });
  button.addEventListener('click', (event) => event.preventDefault());
  button.addEventListener('contextmenu', (event) => event.preventDefault()); // a long press on a phone
  window.addEventListener('blur', hide);
  return hide;
}
