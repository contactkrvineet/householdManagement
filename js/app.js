/* ==========================================================================
   Household Finance Tracker · Application logic
   --------------------------------------------------------------------------
   Modules (top-to-bottom):
     1. Storage keys & helpers
     2. Crypto module (Web Crypto API: PBKDF2 + AES-GCM)
     3. Vault state machine (NOT_SETUP → LOCKED → UNLOCKED)
     4. Master-password modals (setup / unlock / reset)
     5. Account country tabs (USA / Canada / India) with password reveal
     6. Income module
     7. Expense module
     8. Reminders + calendar
     9. Dashboard
    10. Tab routing, import/export, init
   ========================================================================== */

(function () {
'use strict';

// ============================================================
// 1. STORAGE KEYS
// ============================================================

const KEYS = {
  vault:      'hf-vault-v1',         // { initialized, salt, verifier, hint, setupAt }
  accounts:   'hf-accounts-v1',      // [{ id, country, type, institution, name, accountNum, username, passwordEnc, pinEnc, website, phone, notes }]
  income:     'hf-income-v1',
  expenses:   'hf-expenses-v1',
  reminders:  'hf-reminders-v1',
};

function load(key, defaultVal) {
  try {
    const v = JSON.parse(localStorage.getItem(key) || 'null');
    return v === null ? defaultVal : v;
  } catch { return defaultVal; }
}
function save(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function uid(prefix = 'id') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

function fmtCurrency(amount, currency = 'CAD') {
  const symbols = { CAD: '$', USD: 'US$', INR: '₹' };
  const sym = symbols[currency] || '$';
  if (amount == null || isNaN(amount)) return `${sym}0`;
  return sym + Number(amount).toLocaleString('en-CA', { minimumFractionDigits: 0, maximumFractionDigits: 2 });
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

function todayISO() { return new Date().toISOString().slice(0, 10); }
function thisMonth() { return new Date().toISOString().slice(0, 7); }

// ============================================================
// 1B. APP-LEVEL ENCRYPTION LAYER (v4)
// ============================================================

// All sensitive storage keys that get encrypted under the app password
const ENCRYPTED_KEYS = [
  'hf-accounts-v1',
  'hf-income-v1',
  'hf-expenses-v1',
  'hf-reminders-v1',
  'hf-akshara-v1',
  'hf-documents-meta-v1',
  'hf-investments-v1',
  'hf-subscriptions-v1',
];

// In-memory plaintext cache. Populated on unlock, cleared on lock.
const appCache = {};
let appUnlocked = false;

// Preserve originals (used during migration + for non-encrypted keys)
const _origLoad = load;
const _origSave = save;

// Patched load: returns in-memory cache for encrypted keys, plain for others
load = function (key, defaultVal) {
  if (ENCRYPTED_KEYS.includes(key)) {
    if (!appUnlocked) return defaultVal;
    return appCache[key] !== undefined ? appCache[key] : defaultVal;
  }
  return _origLoad(key, defaultVal);
};

// Patched save: updates cache + queues async encryption write
const _pendingWrites = new Map();
save = function (key, value) {
  if (ENCRYPTED_KEYS.includes(key)) {
    if (!appUnlocked) {
      console.warn(`Attempted save to ${key} while locked - ignored`);
      return;
    }
    appCache[key] = value;
    // Debounce per-key writes (last write wins within 50ms window)
    if (_pendingWrites.has(key)) clearTimeout(_pendingWrites.get(key));
    _pendingWrites.set(key, setTimeout(async () => {
      _pendingWrites.delete(key);
      try {
        const enc = await encryptText(JSON.stringify(value), vaultKey);
        _origSave(key, enc);
      } catch (e) {
        console.error(`Failed to encrypt ${key}:`, e);
      }
    }, 50));
  } else {
    _origSave(key, value);
  }
};



const PBKDF2_ITERATIONS = 250000;
const VERIFIER_PLAINTEXT = 'VAULT-OK-2026';

function bytesToBase64(bytes) {
  let bin = '';
  bytes.forEach(b => { bin += String.fromCharCode(b); });
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function deriveKey(password, saltBytes) {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptText(plaintext, key) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return { iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) };
}

async function decryptText(blob, key) {
  const dec = new TextDecoder();
  const iv = base64ToBytes(blob.iv);
  const ct = base64ToBytes(blob.ct);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return dec.decode(pt);
}

// ============================================================
// 3. VAULT STATE
// ============================================================

let vaultKey = null;     // in-memory CryptoKey
let vaultUnlockedAt = null;
const AUTO_LOCK_MS = 15 * 60 * 1000; // 15 min

function vaultState() {
  const v = load(KEYS.vault, null);
  if (!v || !v.initialized) return 'NOT_SETUP';
  return vaultKey ? 'UNLOCKED' : 'LOCKED';
}

function checkAutoLock() {
  if (vaultKey && vaultUnlockedAt && (Date.now() - vaultUnlockedAt > AUTO_LOCK_MS)) {
    lockVault();
    alert('Vault auto-locked after 15 minutes of inactivity.');
  }
}
setInterval(checkAutoLock, 30000);

function refreshVaultUI() {
  const state = vaultState();
  const dot = document.querySelector('.vault-dot');
  const text = document.getElementById('vault-status-text');
  const btn = document.getElementById('vault-toggle');
  if (state === 'UNLOCKED') {
    dot.classList.add('unlocked');
    text.textContent = 'Vault unlocked';
    btn.textContent = '🔒 Lock';
  } else if (state === 'LOCKED') {
    dot.classList.remove('unlocked');
    text.textContent = 'Vault locked';
    btn.textContent = 'Unlock vault';
  } else {
    dot.classList.remove('unlocked');
    text.textContent = 'Vault not set up';
    btn.textContent = 'Set up vault';
  }
}

function lockVault() {
  vaultKey = null;
  vaultUnlockedAt = null;
  refreshVaultUI();
  rerenderAccountTabs(); // re-mask any revealed passwords
}

async function setupNewVault(password, hint) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);
  const verifier = await encryptText(VERIFIER_PLAINTEXT, key);
  save(KEYS.vault, {
    initialized: true,
    salt: bytesToBase64(salt),
    verifier,
    hint: hint || '',
    setupAt: new Date().toISOString(),
  });
  vaultKey = key;
  vaultUnlockedAt = Date.now();
  refreshVaultUI();
}

async function tryUnlockVault(password) {
  const v = load(KEYS.vault, null);
  if (!v || !v.initialized) throw new Error('Vault not set up');
  const salt = base64ToBytes(v.salt);
  const key = await deriveKey(password, salt);
  try {
    const decoded = await decryptText(v.verifier, key);
    if (decoded !== VERIFIER_PLAINTEXT) throw new Error('Verifier mismatch');
    vaultKey = key;
    vaultUnlockedAt = Date.now();
    refreshVaultUI();
    return true;
  } catch (e) {
    throw new Error('Wrong master password');
  }
}

async function changeMasterPassword(oldPwd, newPwd, newHint) {
  // First verify the old password unlocks
  await tryUnlockVault(oldPwd);
  // Now re-encrypt all stored passwords with new key
  const oldKey = vaultKey;
  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newKey = await deriveKey(newPwd, newSalt);
  const accounts = load(KEYS.accounts, []);
  for (const a of accounts) {
    for (const f of ['passwordEnc', 'pinEnc']) {
      if (a[f]) {
        try {
          const pt = await decryptText(a[f], oldKey);
          a[f] = await encryptText(pt, newKey);
        } catch (e) { /* skip if undecryptable */ }
      }
    }
  }
  save(KEYS.accounts, accounts);
  const newVerifier = await encryptText(VERIFIER_PLAINTEXT, newKey);
  save(KEYS.vault, {
    initialized: true,
    salt: bytesToBase64(newSalt),
    verifier: newVerifier,
    hint: newHint || '',
    setupAt: load(KEYS.vault).setupAt,
    changedAt: new Date().toISOString(),
  });
  vaultKey = newKey;
  vaultUnlockedAt = Date.now();
  refreshVaultUI();
  rerenderAccountTabs();
}

function resetVault() {
  // Wipe everything credential-related
  const accounts = load(KEYS.accounts, []);
  accounts.forEach(a => { delete a.passwordEnc; delete a.pinEnc; });
  save(KEYS.accounts, accounts);
  localStorage.removeItem(KEYS.vault);
  vaultKey = null;
  vaultUnlockedAt = null;
  refreshVaultUI();
  rerenderAccountTabs();
}

// ============================================================
// 4. VAULT MODALS
// ============================================================

const vaultModal = document.getElementById('vault-modal');
const vaultModalContent = document.getElementById('vault-modal-content');

function pwStrengthScore(pwd) {
  let s = 0;
  if (pwd.length >= 8)  s++;
  if (pwd.length >= 12) s++;
  if (pwd.length >= 16) s++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) s++;
  if (/\d/.test(pwd))   s++;
  if (/[^A-Za-z0-9]/.test(pwd)) s++;
  return Math.min(s, 5);
}
function pwStrengthLabel(s) {
  return ['', 'Weak', 'Fair', 'Medium', 'Good', 'Strong'][s] || '';
}
function pwStrengthClass(s) {
  if (s <= 1) return '';
  if (s === 2) return 'medium';
  if (s === 3) return 'good';
  return 'strong';
}

function showVaultModalSetup() {
  vaultModalContent.innerHTML = `
    <h3>🔐 Set up your password vault</h3>
    <p>Choose a master password to encrypt stored credentials. It's never sent anywhere and never written to disk — only held in memory while you use the app.</p>

    <div class="modal-warning">
      <strong>⚠ Critical:</strong> If you forget this master password, your stored passwords are <strong>permanently unrecoverable</strong>. Write it down somewhere safe (paper, separate password manager).
    </div>

    <div class="field">
      <label class="field-label">Master password</label>
      <input type="password" id="setup-pwd" placeholder="At least 12 characters">
      <div class="pw-strength"><div class="pw-strength-bar" id="pw-bar"></div></div>
      <div class="pw-hint" id="pw-hint">Use a mix of upper/lowercase, numbers, and symbols.</div>
    </div>
    <div class="field">
      <label class="field-label">Confirm master password</label>
      <input type="password" id="setup-pwd2" placeholder="Re-enter the same password">
    </div>
    <div class="field">
      <label class="field-label">Hint (optional, shown when unlocking)</label>
      <input type="text" id="setup-hint" placeholder="e.g. 'usual one + dog name'">
    </div>

    <div class="modal-actions">
      <button class="btn ghost" id="vault-cancel">Cancel</button>
      <button class="btn moss" id="vault-create">Create vault</button>
    </div>
  `;
  vaultModal.style.display = 'flex';

  const pwd = document.getElementById('setup-pwd');
  const pwd2 = document.getElementById('setup-pwd2');
  const hint = document.getElementById('setup-hint');
  const bar = document.getElementById('pw-bar');
  const hintText = document.getElementById('pw-hint');

  pwd.addEventListener('input', () => {
    const s = pwStrengthScore(pwd.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'pw-strength-bar ' + pwStrengthClass(s);
    hintText.textContent = pwd.value.length === 0
      ? 'Use a mix of upper/lowercase, numbers, and symbols.'
      : `Strength: ${pwStrengthLabel(s)} (${pwd.value.length} chars)`;
  });

  document.getElementById('vault-cancel').onclick = () => { vaultModal.style.display = 'none'; };
  document.getElementById('vault-create').onclick = async () => {
    if (pwd.value.length < 8) { alert('Password must be at least 8 characters.'); return; }
    if (pwd.value !== pwd2.value) { alert('Passwords do not match.'); return; }
    try {
      await setupNewVault(pwd.value, hint.value);
      vaultModal.style.display = 'none';
      rerenderAccountTabs();
    } catch (e) {
      alert('Failed to create vault: ' + e.message);
    }
  };
  setTimeout(() => pwd.focus(), 100);
}

function showVaultModalUnlock(onSuccess) {
  const v = load(KEYS.vault, null);
  const hintHtml = v && v.hint
    ? `<div class="pw-hint">💡 Hint: <em>${escapeHtml(v.hint)}</em></div>`
    : '';
  vaultModalContent.innerHTML = `
    <h3>🔓 Unlock vault</h3>
    <p>Enter your master password to decrypt stored credentials.</p>
    <div class="field">
      <label class="field-label">Master password</label>
      <input type="password" id="unlock-pwd" autofocus>
      ${hintHtml}
      <div id="unlock-error" style="color:var(--terracotta);font-size:12px;margin-top:6px;display:none;"></div>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="unlock-cancel">Cancel</button>
      <button class="btn ghost" id="unlock-change">Change password…</button>
      <button class="btn moss" id="unlock-go">Unlock</button>
    </div>
  `;
  vaultModal.style.display = 'flex';

  const pwd = document.getElementById('unlock-pwd');
  setTimeout(() => pwd.focus(), 100);

  async function attempt() {
    try {
      await tryUnlockVault(pwd.value);
      vaultModal.style.display = 'none';
      rerenderAccountTabs();
      if (typeof onSuccess === 'function') onSuccess();
    } catch (e) {
      const err = document.getElementById('unlock-error');
      err.textContent = '✗ ' + e.message;
      err.style.display = '';
      pwd.value = '';
      pwd.focus();
    }
  }
  document.getElementById('unlock-cancel').onclick = () => { vaultModal.style.display = 'none'; };
  document.getElementById('unlock-go').onclick = attempt;
  pwd.addEventListener('keydown', e => { if (e.key === 'Enter') attempt(); });
  document.getElementById('unlock-change').onclick = () => { showVaultModalChange(); };
}

function showVaultModalChange() {
  vaultModalContent.innerHTML = `
    <h3>🔁 Change master password</h3>
    <p>Re-encrypts all stored passwords with the new key. You'll need to enter the current password to authorize this.</p>
    <div class="field">
      <label class="field-label">Current master password</label>
      <input type="password" id="ch-old">
    </div>
    <div class="field">
      <label class="field-label">New master password</label>
      <input type="password" id="ch-new1">
      <div class="pw-strength"><div class="pw-strength-bar" id="ch-bar"></div></div>
    </div>
    <div class="field">
      <label class="field-label">Confirm new password</label>
      <input type="password" id="ch-new2">
    </div>
    <div class="field">
      <label class="field-label">Hint (optional)</label>
      <input type="text" id="ch-hint" value="${escapeHtml((load(KEYS.vault) || {}).hint || '')}">
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="ch-cancel">Cancel</button>
      <button class="btn moss" id="ch-go">Change password</button>
    </div>
  `;
  const new1 = document.getElementById('ch-new1');
  const bar = document.getElementById('ch-bar');
  new1.addEventListener('input', () => {
    const s = pwStrengthScore(new1.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'pw-strength-bar ' + pwStrengthClass(s);
  });
  document.getElementById('ch-cancel').onclick = () => { vaultModal.style.display = 'none'; };
  document.getElementById('ch-go').onclick = async () => {
    const oldP = document.getElementById('ch-old').value;
    const new1v = new1.value;
    const new2v = document.getElementById('ch-new2').value;
    const hint = document.getElementById('ch-hint').value;
    if (new1v.length < 8) { alert('New password must be at least 8 characters.'); return; }
    if (new1v !== new2v) { alert('New passwords do not match.'); return; }
    try {
      await changeMasterPassword(oldP, new1v, hint);
      vaultModal.style.display = 'none';
      alert('✓ Master password changed and all stored credentials re-encrypted.');
    } catch (e) {
      alert('✗ ' + e.message);
    }
  };
}

// Vault toggle button
document.getElementById('vault-toggle').addEventListener('click', () => {
  const state = vaultState();
  if (state === 'NOT_SETUP') showVaultModalSetup();
  else if (state === 'LOCKED') showVaultModalUnlock();
  else lockVault();
});

// Click outside modal to close
vaultModal.addEventListener('click', e => {
  if (e.target === vaultModal) vaultModal.style.display = 'none';
});

// ============================================================
// 5. ACCOUNT TABS (USA / Canada / India)
// ============================================================

const ACCOUNT_TYPES = {
  USA: ['Checking', 'Savings', 'Credit Card', '401(k)', 'IRA', 'Roth IRA', 'Brokerage', 'HSA', 'Crypto', 'Other'],
  Canada: ['Chequing', 'Savings', 'Credit Card', 'TFSA', 'RRSP', 'RESP', 'LIRA', 'FHSA', 'Non-Registered', 'Crypto', 'Other'],
  India: ['Savings', 'Salary Account', 'Fixed Deposit', 'Recurring Deposit', 'PPF', 'EPF', 'NPS', 'Demat / Stocks', 'Mutual Fund', 'NRE', 'NRO', 'Credit Card', 'Insurance / ULIP', 'Other'],
};
const COUNTRY_CURRENCY = { USA: 'USD', Canada: 'CAD', India: 'INR' };

function renderCountryTab(country) {
  const container = document.querySelector(`#${country.toLowerCase()} [data-country]`);
  if (!container) return;
  const accounts = load(KEYS.accounts, []).filter(a => a.country === country);
  const state = vaultState();

  const header = `
    <div class="country-header">
      <h2>${country === 'USA' ? '🇺🇸' : country === 'Canada' ? '🇨🇦' : '🇮🇳'} ${country} accounts</h2>
      <div>
        <button class="btn amber" data-add-acc="${country}">+ Add account</button>
      </div>
    </div>
    <p style="color:var(--ink-soft);font-size:13.5px;margin-bottom:18px;">
      ${accounts.length} account${accounts.length !== 1 ? 's' : ''} tracked · Default currency: ${COUNTRY_CURRENCY[country]}
      ${state === 'UNLOCKED' ? '· <span style="color:var(--sage-dark);">vault unlocked</span>' : ''}
    </p>
  `;

  if (accounts.length === 0) {
    container.innerHTML = header + `
      <div class="vault-empty">
        <p>No accounts added yet.</p>
        <p style="margin-top:10px;">Click <strong>+ Add account</strong> to start tracking institutions in ${country}.</p>
      </div>
    `;
  } else {
    const grid = accounts.map(a => renderAccountCard(a)).join('');
    container.innerHTML = header + `<div class="account-grid">${grid}</div>`;
  }

  // Wire up the Add button
  container.querySelector('[data-add-acc]')?.addEventListener('click', () => showAccountModal(country, null));

  // Wire up per-card buttons
  container.querySelectorAll('[data-edit-acc]').forEach(b =>
    b.addEventListener('click', () => showAccountModal(country, b.dataset.editAcc))
  );
  container.querySelectorAll('[data-del-acc]').forEach(b =>
    b.addEventListener('click', () => deleteAccount(b.dataset.delAcc))
  );
  container.querySelectorAll('[data-reveal]').forEach(b =>
    b.addEventListener('click', () => revealField(b.dataset.reveal, b.dataset.field))
  );
  container.querySelectorAll('[data-copy]').forEach(b =>
    b.addEventListener('click', () => copyField(b.dataset.copy, b.dataset.field))
  );
}

function rerenderAccountTabs() {
  ['USA', 'Canada', 'India'].forEach(renderCountryTab);
  renderDashboard();
}

function renderAccountCard(a) {
  const fields = [];

  if (a.institution) fields.push(['Institution', escapeHtml(a.institution), null]);
  if (a.accountNum) fields.push(['Account #', escapeHtml(a.accountNum), 'plain']);
  if (a.routingOrIfsc) {
    const lbl = a.country === 'USA' ? 'Routing #' : a.country === 'Canada' ? 'Transit/Inst' : 'IFSC';
    fields.push([lbl, escapeHtml(a.routingOrIfsc), 'plain']);
  }
  if (a.username) fields.push(['Username', escapeHtml(a.username), 'plain']);

  // Password
  if (a.passwordEnc) {
    fields.push(['Password', `<span class="acc-field-value masked" id="pw-${a.id}">••••••••••</span>
      <span class="acc-field-actions">
        <button class="btn-mini" data-reveal="${a.id}" data-field="password">👁 Show</button>
        <button class="btn-mini" data-copy="${a.id}" data-field="password">⧉ Copy</button>
      </span>`, 'html']);
  }
  // PIN
  if (a.pinEnc) {
    fields.push(['PIN', `<span class="acc-field-value masked" id="pin-${a.id}">••••</span>
      <span class="acc-field-actions">
        <button class="btn-mini" data-reveal="${a.id}" data-field="pin">👁 Show</button>
        <button class="btn-mini" data-copy="${a.id}" data-field="pin">⧉ Copy</button>
      </span>`, 'html']);
  }
  if (a.website) {
    let displayHost = a.website;
    let safeHref = a.website;
    try {
      // Try parsing as-is first
      displayHost = new URL(a.website).hostname.replace(/^www\./, '');
    } catch {
      // Fall back to prepending https:// if scheme is missing
      try {
        const u = new URL('https://' + a.website);
        displayHost = u.hostname.replace(/^www\./, '');
        safeHref = 'https://' + a.website;
      } catch {
        // Give up — show raw string, omit href
        displayHost = a.website;
        safeHref = null;
      }
    }
    if (safeHref) {
      fields.push(['Website', `<a class="acc-link" href="${escapeHtml(safeHref)}" target="_blank" rel="noopener">${escapeHtml(displayHost)}</a>`, 'html']);
    } else {
      fields.push(['Website', escapeHtml(displayHost), 'plain']);
    }
  }
  if (a.phone) fields.push(['Phone', escapeHtml(a.phone), 'plain']);

  const fieldsHtml = fields.map(([label, value, kind]) => {
    if (kind === 'html') {
      return `<div class="acc-field"><span class="acc-field-label">${label}</span>${value}</div>`;
    }
    return `<div class="acc-field"><span class="acc-field-label">${label}</span><span class="acc-field-value">${value}</span></div>`;
  }).join('');

  const notesHtml = a.notes ? `<div class="acc-notes">${escapeHtml(a.notes)}</div>` : '';

  return `
    <div class="account-card" data-acc-id="${a.id}">
      <div class="acc-head">
        <div class="acc-name">${escapeHtml(a.name || a.institution || 'Unnamed account')}</div>
        <span class="acc-type-tag">${escapeHtml(a.type || 'Account')}</span>
      </div>
      ${a.institution && a.name && a.name !== a.institution ? `<div class="acc-institution">${escapeHtml(a.institution)}</div>` : ''}
      ${fieldsHtml}
      ${notesHtml}
      <div class="acc-actions">
        <button class="btn ghost btn-sm" data-edit-acc="${a.id}">edit</button>
        <button class="btn-icon" data-del-acc="${a.id}" title="Delete">✕</button>
      </div>
    </div>
  `;
}

async function revealField(accId, field) {
  if (vaultState() === 'NOT_SETUP') {
    alert('Set up a vault first to store and reveal encrypted credentials.');
    showVaultModalSetup();
    return;
  }
  if (vaultState() === 'LOCKED') {
    showVaultModalUnlock(() => revealField(accId, field));
    return;
  }
  const accounts = load(KEYS.accounts, []);
  const a = accounts.find(x => x.id === accId);
  if (!a) return;
  const encField = field === 'password' ? a.passwordEnc : a.pinEnc;
  if (!encField) return;
  try {
    const plain = await decryptText(encField, vaultKey);
    const el = document.getElementById((field === 'password' ? 'pw-' : 'pin-') + accId);
    if (!el) return;
    const originalHtml = el.outerHTML;
    el.classList.remove('masked');
    el.textContent = plain;
    // Re-mask after 30 seconds
    setTimeout(() => {
      const el2 = document.getElementById((field === 'password' ? 'pw-' : 'pin-') + accId);
      if (el2) {
        el2.classList.add('masked');
        el2.textContent = field === 'password' ? '••••••••••' : '••••';
      }
    }, 30000);
  } catch (e) {
    alert('Failed to decrypt: ' + e.message);
  }
  vaultUnlockedAt = Date.now(); // reset auto-lock timer
}

async function copyField(accId, field) {
  if (vaultState() === 'LOCKED') {
    showVaultModalUnlock(() => copyField(accId, field));
    return;
  }
  if (vaultState() === 'NOT_SETUP') return;
  const accounts = load(KEYS.accounts, []);
  const a = accounts.find(x => x.id === accId);
  const encField = field === 'password' ? a.passwordEnc : a.pinEnc;
  if (!encField) return;
  try {
    const plain = await decryptText(encField, vaultKey);
    await navigator.clipboard.writeText(plain);
    // Brief visual feedback
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copied';
    setTimeout(() => { btn.textContent = orig; }, 1200);
  } catch (e) {
    alert('Failed to copy: ' + e.message);
  }
  vaultUnlockedAt = Date.now();
}

function deleteAccount(accId) {
  const accounts = load(KEYS.accounts, []);
  const a = accounts.find(x => x.id === accId);
  if (!a) return;
  if (!confirm(`Delete "${a.name || a.institution}"?\n\nThis cannot be undone.`)) return;
  save(KEYS.accounts, accounts.filter(x => x.id !== accId));
  rerenderAccountTabs();
}

const accountModal = document.getElementById('account-modal');
const accountModalContent = document.getElementById('account-modal-content');

function showAccountModal(country, accId) {
  const accounts = load(KEYS.accounts, []);
  const existing = accId ? accounts.find(a => a.id === accId) : null;
  const types = ACCOUNT_TYPES[country];

  accountModalContent.innerHTML = `
    <h3>${existing ? '✏ Edit' : '+ Add'} ${country} account</h3>
    <div class="modal-grid">
      <div class="field">
        <label class="field-label">Institution *</label>
        <input type="text" id="m-institution" value="${escapeHtml(existing?.institution || '')}" placeholder="e.g. CIBC, Chase, HDFC">
      </div>
      <div class="field">
        <label class="field-label">Account type *</label>
        <select id="m-type">
          ${types.map(t => `<option value="${t}" ${existing?.type === t ? 'selected' : ''}>${t}</option>`).join('')}
        </select>
      </div>
      <div class="field span-full">
        <label class="field-label">Account nickname (optional)</label>
        <input type="text" id="m-name" value="${escapeHtml(existing?.name || '')}" placeholder="e.g. Joint chequing">
      </div>
      <div class="field">
        <label class="field-label">Account number (or last 4)</label>
        <input type="text" id="m-accnum" value="${escapeHtml(existing?.accountNum || '')}" placeholder="•••• 1234">
      </div>
      <div class="field">
        <label class="field-label">${country === 'USA' ? 'Routing #' : country === 'Canada' ? 'Transit / Institution' : 'IFSC code'}</label>
        <input type="text" id="m-routing" value="${escapeHtml(existing?.routingOrIfsc || '')}">
      </div>
      <div class="field">
        <label class="field-label">Username / login</label>
        <input type="text" id="m-username" value="${escapeHtml(existing?.username || '')}">
      </div>
      <div class="field">
        <label class="field-label">Website</label>
        <input type="url" id="m-website" value="${escapeHtml(existing?.website || '')}" placeholder="https://...">
      </div>
      <div class="field">
        <label class="field-label">🔐 Password</label>
        <input type="password" id="m-password" placeholder="${existing?.passwordEnc ? 'Leave blank to keep existing' : '(will be encrypted)'}">
      </div>
      <div class="field">
        <label class="field-label">🔐 PIN</label>
        <input type="password" id="m-pin" placeholder="${existing?.pinEnc ? 'Leave blank to keep existing' : '(will be encrypted)'}">
      </div>
      <div class="field span-full">
        <label class="field-label">Phone (customer service)</label>
        <input type="text" id="m-phone" value="${escapeHtml(existing?.phone || '')}">
      </div>
      <div class="field span-full">
        <label class="field-label">Notes</label>
        <textarea id="m-notes" rows="2" style="resize:vertical;">${escapeHtml(existing?.notes || '')}</textarea>
      </div>
    </div>
    <div class="modal-warning" id="m-vault-warn" style="display:${vaultState() === 'UNLOCKED' ? 'none' : 'block'};">
      ⚠ Vault is ${vaultState() === 'NOT_SETUP' ? 'not set up' : 'locked'}. ${vaultState() === 'NOT_SETUP' ? 'Set up' : 'Unlock'} the vault to save passwords / PINs.
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="m-cancel">Cancel</button>
      <button class="btn moss" id="m-save">${existing ? 'Save changes' : 'Add account'}</button>
    </div>
  `;
  accountModal.style.display = 'flex';

  document.getElementById('m-cancel').onclick = () => { accountModal.style.display = 'none'; };
  document.getElementById('m-save').onclick = async () => {
    const inst = document.getElementById('m-institution').value.trim();
    if (!inst) { alert('Institution is required.'); return; }

    const rec = existing || { id: uid('acc'), country };
    rec.institution = inst;
    rec.type = document.getElementById('m-type').value;
    rec.name = document.getElementById('m-name').value.trim();
    rec.accountNum = document.getElementById('m-accnum').value.trim();
    rec.routingOrIfsc = document.getElementById('m-routing').value.trim();
    rec.username = document.getElementById('m-username').value.trim();
    rec.website = (function() {
      const v = document.getElementById('m-website').value.trim();
      if (!v) return '';
      // Auto-prepend https:// if scheme missing and it parses correctly
      if (!/^[a-z]+:\/\//i.test(v)) {
        try {
          new URL('https://' + v);
          return 'https://' + v;
        } catch {
          return v; // keep as-is, render will handle gracefully
        }
      }
      return v;
    })();
    rec.phone = document.getElementById('m-phone').value.trim();
    rec.notes = document.getElementById('m-notes').value.trim();
    const newPw = document.getElementById('m-password').value;
    const newPin = document.getElementById('m-pin').value;

    // Encrypt new secrets if vault is unlocked
    if (newPw || newPin) {
      if (vaultState() === 'NOT_SETUP') {
        accountModal.style.display = 'none';
        alert('Set up a vault first. Reopen the form and re-enter the password.');
        showVaultModalSetup();
        return;
      }
      if (vaultState() === 'LOCKED') {
        showVaultModalUnlock(() => {
          // resume save after unlock
          (async () => {
            if (newPw) rec.passwordEnc = await encryptText(newPw, vaultKey);
            if (newPin) rec.pinEnc = await encryptText(newPin, vaultKey);
            persistAccountRecord(rec, existing);
            accountModal.style.display = 'none';
          })();
        });
        return;
      }
      try {
        if (newPw) rec.passwordEnc = await encryptText(newPw, vaultKey);
        if (newPin) rec.pinEnc = await encryptText(newPin, vaultKey);
      } catch (e) {
        alert('Encryption failed: ' + e.message);
        return;
      }
    }

    persistAccountRecord(rec, existing);
    accountModal.style.display = 'none';
  };
}

function persistAccountRecord(rec, existing) {
  const accounts = load(KEYS.accounts, []);
  if (existing) {
    const idx = accounts.findIndex(a => a.id === existing.id);
    if (idx >= 0) accounts[idx] = rec;
  } else {
    accounts.push(rec);
  }
  save(KEYS.accounts, accounts);
  rerenderAccountTabs();
}

accountModal.addEventListener('click', e => {
  if (e.target === accountModal) accountModal.style.display = 'none';
});

// ============================================================
// 6. INCOME MODULE
// ============================================================

function getIncome() { return load(KEYS.income, []); }
function saveIncome(arr) { save(KEYS.income, arr); }

document.getElementById('inc-date').valueAsDate = new Date();

document.getElementById('add-income-btn').addEventListener('click', () => {
  const date = document.getElementById('inc-date').value;
  const person = document.getElementById('inc-person').value;
  const source = document.getElementById('inc-source').value;
  const amount = parseFloat(document.getElementById('inc-amount').value);
  const currency = document.getElementById('inc-currency').value;
  const notes = document.getElementById('inc-notes').value.trim();
  if (!date || isNaN(amount) || amount <= 0) {
    alert('Please enter a valid date and amount.');
    return;
  }
  const arr = getIncome();
  arr.push({ id: uid('inc'), date, person, source, amount, currency, notes });
  saveIncome(arr);
  document.getElementById('inc-amount').value = '';
  document.getElementById('inc-notes').value = '';
  renderIncome();
  renderDashboard();
});

function renderIncome() {
  const all = getIncome();
  const yearSel = document.getElementById('inc-year-filter');
  const personSel = document.getElementById('inc-person-filter');
  const currSel = document.getElementById('inc-curr-filter');

  // Populate year dropdown
  const years = [...new Set(all.map(i => i.date.slice(0, 4)))].sort();
  if (years.length === 0) years.push(new Date().getFullYear().toString());
  const currentYear = yearSel.value || years[years.length - 1];
  yearSel.innerHTML = years.map(y => `<option value="${y}" ${y === currentYear ? 'selected' : ''}>${y}</option>`).join('');

  const year = yearSel.value;
  const personFilter = personSel.value;
  const currency = currSel.value;
  const filtered = all.filter(i => i.date.startsWith(year) && i.currency === currency &&
                                   (personFilter === 'all' || i.person === personFilter));

  // Monthly summary
  const monthly = {};
  for (let m = 1; m <= 12; m++) {
    monthly[m] = { Vineet: 0, Saroj: 0, Joint: 0, Total: 0 };
  }
  filtered.forEach(i => {
    const m = parseInt(i.date.slice(5, 7), 10);
    monthly[m][i.person] = (monthly[m][i.person] || 0) + i.amount;
    monthly[m].Total += i.amount;
  });

  const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const tbody = document.querySelector('#income-monthly tbody');
  let totalV = 0, totalS = 0, totalJ = 0, totalT = 0;
  tbody.innerHTML = monthNames.map((mn, i) => {
    const m = i + 1;
    const r = monthly[m];
    totalV += r.Vineet; totalS += r.Saroj; totalJ += r.Joint; totalT += r.Total;
    return `<tr>
      <td>${mn} ${year}</td>
      <td class="num">${r.Vineet > 0 ? fmtCurrency(r.Vineet, currency) : '—'}</td>
      <td class="num">${r.Saroj > 0 ? fmtCurrency(r.Saroj, currency) : '—'}</td>
      <td class="num">${r.Joint > 0 ? fmtCurrency(r.Joint, currency) : '—'}</td>
      <td class="num total">${r.Total > 0 ? fmtCurrency(r.Total, currency) : '—'}</td>
    </tr>`;
  }).join('') + `<tr class="month-row">
      <td><strong>Total ${year}</strong></td>
      <td class="num"><strong>${fmtCurrency(totalV, currency)}</strong></td>
      <td class="num"><strong>${fmtCurrency(totalS, currency)}</strong></td>
      <td class="num"><strong>${fmtCurrency(totalJ, currency)}</strong></td>
      <td class="num total"><strong>${fmtCurrency(totalT, currency)}</strong></td>
    </tr>`;

  // Transaction list
  const listBody = document.querySelector('#income-list tbody');
  const sorted = filtered.slice().sort((a, b) => b.date.localeCompare(a.date));
  if (sorted.length === 0) {
    listBody.innerHTML = `<tr class="empty-row"><td colspan="6">No income recorded for ${year} ${currency}.</td></tr>`;
  } else {
    listBody.innerHTML = sorted.map(i => `<tr>
      <td>${i.date}</td>
      <td>${escapeHtml(i.person)}</td>
      <td><span class="cat-tag">${escapeHtml(i.source)}</span></td>
      <td>${escapeHtml(i.notes || '')}</td>
      <td class="num">${fmtCurrency(i.amount, i.currency)}</td>
      <td><button class="btn-icon" data-del-inc="${i.id}" title="Delete">✕</button></td>
    </tr>`).join('');
    listBody.querySelectorAll('[data-del-inc]').forEach(b => {
      b.addEventListener('click', () => {
        if (!confirm('Delete this income entry?')) return;
        saveIncome(getIncome().filter(x => x.id !== b.dataset.delInc));
        renderIncome();
        renderDashboard();
      });
    });
  }
}

['inc-year-filter', 'inc-person-filter', 'inc-curr-filter'].forEach(id =>
  document.getElementById(id).addEventListener('change', renderIncome)
);

document.getElementById('export-income').addEventListener('click', () => {
  const arr = getIncome();
  if (arr.length === 0) { alert('No income to export.'); return; }
  const rows = [['Date', 'Person', 'Source', 'Amount', 'Currency', 'Notes']];
  arr.forEach(i => rows.push([i.date, i.person, i.source, i.amount.toFixed(2), i.currency, i.notes || '']));
  downloadCsv(rows, `income-${todayISO()}.csv`);
});

// ============================================================
// 7. EXPENSE MODULE
// ============================================================

function getExpenses() { return load(KEYS.expenses, []); }
function saveExpenses(arr) { save(KEYS.expenses, arr); }

document.getElementById('exp-date').valueAsDate = new Date();

document.getElementById('add-expense-btn').addEventListener('click', () => {
  const date = document.getElementById('exp-date').value;
  const paidBy = document.getElementById('exp-paid').value;
  const cat = document.getElementById('exp-cat').value;
  const amount = parseFloat(document.getElementById('exp-amount').value);
  const currency = document.getElementById('exp-currency').value;
  const desc = document.getElementById('exp-desc').value.trim();
  if (!date || isNaN(amount) || amount <= 0) {
    alert('Please enter a valid date and amount.');
    return;
  }
  const arr = getExpenses();
  arr.push({ id: uid('exp'), date, paidBy, cat, amount, currency, desc });
  saveExpenses(arr);
  document.getElementById('exp-amount').value = '';
  document.getElementById('exp-desc').value = '';
  renderExpenses();
  renderDashboard();
});

function renderExpenses() {
  const all = getExpenses();
  const monthSel = document.getElementById('exp-month-filter');
  const catSel = document.getElementById('exp-cat-filter');
  const paidSel = document.getElementById('exp-paid-filter');
  const currSel = document.getElementById('exp-curr-filter');

  // Populate month filter
  const months = [...new Set(all.map(e => e.date.slice(0, 7)))].sort().reverse();
  monthSel.innerHTML = '<option value="all">All</option>' +
    months.map(m => `<option value="${m}" ${m === monthSel.value ? 'selected' : ''}>${m}</option>`).join('');
  const monthSelected = monthSel.value;

  // Populate cat filter dynamically from data
  const cats = [...new Set(all.map(e => e.cat))].sort();
  catSel.innerHTML = '<option value="all">All</option>' +
    cats.map(c => `<option value="${c}" ${c === catSel.value ? 'selected' : ''}>${c}</option>`).join('');
  const catSelected = catSel.value;

  const paidSelected = paidSel.value;
  const currency = currSel.value;

  const filtered = all.filter(e =>
    e.currency === currency &&
    (monthSelected === 'all' || e.date.startsWith(monthSelected)) &&
    (catSelected === 'all' || e.cat === catSelected) &&
    (paidSelected === 'all' || e.paidBy === paidSelected)
  );

  // Summary
  const total = filtered.reduce((s, e) => s + e.amount, 0);
  const byCat = {};
  filtered.forEach(e => { byCat[e.cat] = (byCat[e.cat] || 0) + e.amount; });
  const top = Object.entries(byCat).sort((a, b) => b[1] - a[1]).slice(0, 4);

  const summary = document.getElementById('exp-summary');
  summary.innerHTML = `<div class="summary-card total"><div class="label">Filtered total</div><div class="amount">${fmtCurrency(total, currency)}</div></div>` +
    top.map(([c, a]) => `<div class="summary-card"><div class="label">${c}</div><div class="amount">${fmtCurrency(a, currency)}</div></div>`).join('');

  // Table
  const listBody = document.querySelector('#expense-list tbody');
  const sorted = filtered.slice().sort((a, b) => b.date.localeCompare(a.date));
  if (sorted.length === 0) {
    listBody.innerHTML = `<tr class="empty-row"><td colspan="6">No expenses match these filters.</td></tr>`;
  } else {
    listBody.innerHTML = sorted.map(e => `<tr>
      <td>${e.date}</td>
      <td>${escapeHtml(e.paidBy)}</td>
      <td><span class="cat-tag">${escapeHtml(e.cat)}</span></td>
      <td>${escapeHtml(e.desc || '')}</td>
      <td class="num">${fmtCurrency(e.amount, e.currency)}</td>
      <td><button class="btn-icon" data-del-exp="${e.id}" title="Delete">✕</button></td>
    </tr>`).join('');
    listBody.querySelectorAll('[data-del-exp]').forEach(b => {
      b.addEventListener('click', () => {
        if (!confirm('Delete this expense?')) return;
        saveExpenses(getExpenses().filter(x => x.id !== b.dataset.delExp));
        renderExpenses();
        renderDashboard();
      });
    });
  }
}

['exp-month-filter', 'exp-cat-filter', 'exp-paid-filter', 'exp-curr-filter'].forEach(id =>
  document.getElementById(id).addEventListener('change', renderExpenses)
);

document.getElementById('export-expenses').addEventListener('click', () => {
  const arr = getExpenses();
  if (arr.length === 0) { alert('No expenses to export.'); return; }
  const rows = [['Date', 'Paid by', 'Category', 'Description', 'Amount', 'Currency']];
  arr.forEach(e => rows.push([e.date, e.paidBy, e.cat, e.desc || '', e.amount.toFixed(2), e.currency]));
  downloadCsv(rows, `expenses-${todayISO()}.csv`);
});

// ============================================================
// 8. REMINDERS + CALENDAR
// ============================================================

function getReminders() { return load(KEYS.reminders, []); }
function saveReminders(arr) { save(KEYS.reminders, arr); }

let calMonth = new Date().getMonth();
let calYear = new Date().getFullYear();

function renderCalendar() {
  const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December'];
  document.getElementById('cal-month-year').textContent = `${monthNames[calMonth]} ${calYear}`;

  const firstDay = new Date(calYear, calMonth, 1).getDay(); // 0=Sun
  // Shift to Mon-first: convert to 0=Mon..6=Sun
  const firstDayMon = (firstDay + 6) % 7;
  const daysInMonth = new Date(calYear, calMonth + 1, 0).getDate();
  const today = new Date();
  const todayKey = today.toISOString().slice(0, 10);
  const reminders = expandRecurringReminders(calYear, calMonth);

  const headers = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  let html = headers.map(h => `<div class="cal-header">${h}</div>`).join('');

  // Prev-month days for leading blanks
  const prevMonth = new Date(calYear, calMonth, 0);
  const daysInPrev = prevMonth.getDate();
  for (let i = firstDayMon - 1; i >= 0; i--) {
    const d = daysInPrev - i;
    html += `<div class="cal-cell dim"><span>${d}</span><div class="cal-dots"></div></div>`;
  }

  for (let d = 1; d <= daysInMonth; d++) {
    const ymd = `${calYear}-${String(calMonth + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const dayOfWeek = new Date(calYear, calMonth, d).getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
    const isToday = ymd === todayKey;
    const dayRem = reminders.filter(r => r.date === ymd);
    const dots = dayRem.map(r => `<span class="cal-dot ${r.category}"></span>`).join('');
    html += `<div class="cal-cell ${isToday ? 'today' : ''} ${isWeekend ? 'weekend' : ''}" data-date="${ymd}">
      <span>${d}</span>
      <div class="cal-dots">${dots}</div>
    </div>`;
  }

  // Trailing days
  const totalShown = firstDayMon + daysInMonth;
  const trailing = (7 - (totalShown % 7)) % 7;
  for (let i = 1; i <= trailing; i++) {
    html += `<div class="cal-cell dim"><span>${i}</span><div class="cal-dots"></div></div>`;
  }

  const cal = document.getElementById('calendar');
  cal.innerHTML = html;

  // Click cell to add reminder for that day
  cal.querySelectorAll('.cal-cell[data-date]').forEach(c => {
    c.addEventListener('click', () => {
      document.getElementById('reminder-form').style.display = '';
      document.getElementById('rem-date').value = c.dataset.date;
      document.getElementById('rem-title').focus();
    });
  });
}

function expandRecurringReminders(year, month) {
  const all = getReminders();
  const result = [];
  const monthStart = new Date(year, month, 1);
  const monthEnd = new Date(year, month + 1, 0);

  all.forEach(r => {
    const rd = new Date(r.date);
    result.push(r);
    if (r.recurring === 'monthly') {
      // Add monthly instances within the visible month
      const day = rd.getDate();
      const ymd = `${year}-${String(month + 1).padStart(2, '0')}-${String(Math.min(day, monthEnd.getDate())).padStart(2, '0')}`;
      if (ymd !== r.date && monthStart <= new Date(ymd) && new Date(ymd) <= monthEnd) {
        result.push({ ...r, date: ymd, recurringInstance: true });
      }
    } else if (r.recurring === 'yearly') {
      if (rd.getMonth() === month && rd.getFullYear() !== year) {
        const ymd = `${year}-${String(month + 1).padStart(2, '0')}-${String(rd.getDate()).padStart(2, '0')}`;
        result.push({ ...r, date: ymd, recurringInstance: true });
      }
    }
  });
  return result;
}

function renderReminderList() {
  const all = getReminders().slice().sort((a, b) => a.date.localeCompare(b.date));
  const today = todayISO();
  const upcoming = all.filter(r => r.date >= today || r.recurring !== 'none').slice(0, 10);
  const list = document.getElementById('reminder-list');
  if (upcoming.length === 0) {
    list.innerHTML = '<div class="mini-list"><div class="empty">No reminders yet. Click + Add or tap a calendar date.</div></div>';
    return;
  }
  list.innerHTML = upcoming.map(r => {
    const past = r.date < today && r.recurring === 'none';
    const rec = r.recurring && r.recurring !== 'none' ? ` · ↻ ${r.recurring}` : '';
    return `<div class="reminder-item ${r.category} ${past ? 'past' : ''}">
      <span class="rem-date">${r.date}</span>
      <span class="rem-title">${escapeHtml(r.title)}</span>
      <span class="rem-meta">${r.category}${rec}</span>
      <span class="rem-actions">
        <button class="btn-icon" data-del-rem="${r.id}" title="Delete">✕</button>
      </span>
    </div>`;
  }).join('');
  list.querySelectorAll('[data-del-rem]').forEach(b => {
    b.addEventListener('click', () => {
      if (!confirm('Delete this reminder?')) return;
      saveReminders(getReminders().filter(x => x.id !== b.dataset.delRem));
      renderCalendar();
      renderReminderList();
    });
  });
}

document.getElementById('add-reminder-btn').addEventListener('click', () => {
  const form = document.getElementById('reminder-form');
  form.style.display = form.style.display === 'none' ? '' : 'none';
  if (form.style.display !== 'none') {
    document.getElementById('rem-date').valueAsDate = new Date();
    document.getElementById('rem-title').focus();
  }
});

document.getElementById('save-reminder').addEventListener('click', () => {
  const date = document.getElementById('rem-date').value;
  const title = document.getElementById('rem-title').value.trim();
  const category = document.getElementById('rem-cat').value;
  const recurring = document.getElementById('rem-recur').value;
  if (!date || !title) { alert('Date and title are required.'); return; }
  const arr = getReminders();
  arr.push({ id: uid('rem'), date, title, category, recurring });
  saveReminders(arr);
  document.getElementById('rem-title').value = '';
  document.getElementById('reminder-form').style.display = 'none';
  renderCalendar();
  renderReminderList();
});

document.getElementById('cancel-reminder').addEventListener('click', () => {
  document.getElementById('reminder-form').style.display = 'none';
});

document.getElementById('cal-prev').addEventListener('click', () => {
  if (--calMonth < 0) { calMonth = 11; calYear--; }
  renderCalendar();
});
document.getElementById('cal-next').addEventListener('click', () => {
  if (++calMonth > 11) { calMonth = 0; calYear++; }
  renderCalendar();
});
document.getElementById('cal-today').addEventListener('click', () => {
  calMonth = new Date().getMonth();
  calYear = new Date().getFullYear();
  renderCalendar();
});

// ============================================================
// 9. DASHBOARD
// ============================================================

function renderDashboard() {
  const tm = thisMonth();
  const income = getIncome().filter(i => i.date.startsWith(tm) && i.currency === 'CAD');
  const expenses = getExpenses().filter(e => e.date.startsWith(tm) && e.currency === 'CAD');

  const incTotal = income.reduce((s, i) => s + i.amount, 0);
  const incV = income.filter(i => i.person === 'Vineet').reduce((s, i) => s + i.amount, 0);
  const incS = income.filter(i => i.person === 'Saroj').reduce((s, i) => s + i.amount, 0);
  const expTotal = expenses.reduce((s, e) => s + e.amount, 0);
  const net = incTotal - expTotal;

  document.getElementById('stat-income').textContent = fmtCurrency(incTotal);
  document.getElementById('stat-income-detail').textContent = `Vineet ${fmtCurrency(incV)} · Saroj ${fmtCurrency(incS)}`;
  document.getElementById('stat-expenses').textContent = fmtCurrency(expTotal);
  document.getElementById('stat-expenses-detail').textContent = `${expenses.length} transaction${expenses.length !== 1 ? 's' : ''}`;
  const netEl = document.getElementById('stat-net');
  netEl.textContent = (net >= 0 ? '' : '−') + fmtCurrency(Math.abs(net));
  netEl.className = 'stat-value ' + (net >= 0 ? 'positive' : 'negative');
  document.getElementById('stat-net-detail').textContent = net >= 0 ? 'Saving this month' : 'Overspent this month';

  const accs = load(KEYS.accounts, []);
  const usa = accs.filter(a => a.country === 'USA').length;
  const ca = accs.filter(a => a.country === 'Canada').length;
  const ind = accs.filter(a => a.country === 'India').length;
  document.getElementById('stat-accounts').textContent = accs.length;
  document.getElementById('stat-accounts-detail').textContent = `USA ${usa} · CA ${ca} · IN ${ind}`;

  // Recent income
  const recI = getIncome().slice().sort((a, b) => b.date.localeCompare(a.date)).slice(0, 5);
  document.getElementById('recent-income').innerHTML = recI.length
    ? recI.map(i => `<div class="mini-row">
        <span>${i.date} · ${escapeHtml(i.person)} · ${escapeHtml(i.source)}</span>
        <span class="mini-amt pos">+${fmtCurrency(i.amount, i.currency)}</span>
      </div>`).join('')
    : '<div class="empty">No income recorded yet.</div>';

  // Recent expenses
  const recE = getExpenses().slice().sort((a, b) => b.date.localeCompare(a.date)).slice(0, 5);
  document.getElementById('recent-expenses').innerHTML = recE.length
    ? recE.map(e => `<div class="mini-row">
        <span>${e.date} · ${escapeHtml(e.cat)} · ${escapeHtml(e.desc || '—')}</span>
        <span class="mini-amt neg">−${fmtCurrency(e.amount, e.currency)}</span>
      </div>`).join('')
    : '<div class="empty">No expenses recorded yet.</div>';

  // Update today's date in header
  const d = new Date();
  document.getElementById('today-date').textContent = d.toLocaleDateString('en-CA', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
  });
}

// ============================================================
// 10. TAB ROUTING + IMPORT/EXPORT + INIT
// ============================================================

document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
});

document.querySelectorAll('[data-jump]').forEach(a => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelector(`.tab[data-tab="${a.dataset.jump}"]`)?.click();
  });
});

function downloadCsv(rows, filename) {
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

document.getElementById('export-all').addEventListener('click', () => {
  const all = {
    exportedAt: new Date().toISOString(),
    income: getIncome(),
    expenses: getExpenses(),
    reminders: getReminders(),
    accounts: load(KEYS.accounts, []),  // includes encrypted password blobs
    vault: load(KEYS.vault, null),       // includes salt + verifier (needed to decrypt elsewhere)
  };
  const blob = new Blob([JSON.stringify(all, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `household-finance-${todayISO()}.json`; a.click();
  URL.revokeObjectURL(url);
});

document.getElementById('import-all').addEventListener('click', () => {
  document.getElementById('import-file').click();
});
document.getElementById('import-file').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    try {
      const data = JSON.parse(ev.target.result);
      if (!confirm('Replace ALL current data with the imported file? This cannot be undone.')) return;
      if (data.income)    save(KEYS.income, data.income);
      if (data.expenses)  save(KEYS.expenses, data.expenses);
      if (data.reminders) save(KEYS.reminders, data.reminders);
      if (data.accounts)  save(KEYS.accounts, data.accounts);
      if (data.vault)     save(KEYS.vault, data.vault);
      lockVault();
      renderEverything();
      alert('✓ Data imported. Unlock the vault to access encrypted passwords.');
    } catch (err) {
      alert('Failed to import: ' + err.message);
    }
  };
  reader.readAsText(file);
});

function renderEverything() {
  refreshVaultUI();
  renderDashboard();
  renderIncome();
  renderExpenses();
  renderCalendar();
  renderReminderList();
  rerenderAccountTabs();
}

// Initial render
renderEverything();



// ============================================================
// 11. AKSHARA MODULE
// ============================================================

const AKSHARA_KEY = 'hf-akshara-v1';

function getAk() {
  return load(AKSHARA_KEY, {
    personal: { name: 'Akshara', dob: '', grade: '', bloodType: '', photo: null },
    school: { name: '', address: '', principal: '', teacher: '', phone: '', website: '', notes: '' },
    health: {
      familyDoctor: '', familyDoctorPhone: '',
      dentist: '', dentistPhone: '',
      pediatrician: '', pediatricianPhone: '',
      allergies: '', medications: '', notes: ''
    },
    activities: [],
    contacts: [],
    notes: []
  });
}
function saveAk(d) { save(AKSHARA_KEY, d); }

function calcAge(dob) {
  if (!dob) return '—';
  const b = new Date(dob);
  const t = new Date();
  let age = t.getFullYear() - b.getFullYear();
  const m = t.getMonth() - b.getMonth();
  if (m < 0 || (m === 0 && t.getDate() < b.getDate())) age--;
  return age >= 0 ? age + ' yr' : '—';
}

function renderAkshara() {
  const d = getAk();
  document.getElementById('ak-name').textContent = d.personal.name || 'Akshara';
  document.getElementById('ak-avatar').textContent = (d.personal.name || 'A').charAt(0).toUpperCase();
  document.getElementById('ak-dob').textContent = d.personal.dob || '—';
  document.getElementById('ak-age').textContent = calcAge(d.personal.dob);
  document.getElementById('ak-grade').textContent = d.personal.grade || '—';
  document.getElementById('ak-blood').textContent = d.personal.bloodType || '—';

  // School
  const s = d.school;
  const schoolHtml = (s.name || s.principal || s.teacher || s.phone) ? [
    s.name && `<div class="profile-line"><span class="pl-label">School</span><span class="pl-value">${escapeHtml(s.name)}</span></div>`,
    s.address && `<div class="profile-line"><span class="pl-label">Address</span><span class="pl-value">${escapeHtml(s.address)}</span></div>`,
    s.principal && `<div class="profile-line"><span class="pl-label">Principal</span><span class="pl-value">${escapeHtml(s.principal)}</span></div>`,
    s.teacher && `<div class="profile-line"><span class="pl-label">Teacher</span><span class="pl-value">${escapeHtml(s.teacher)}</span></div>`,
    s.phone && `<div class="profile-line"><span class="pl-label">Phone</span><span class="pl-value">${escapeHtml(s.phone)}</span></div>`,
    s.website && `<div class="profile-line"><span class="pl-label">Website</span><span class="pl-value"><a class="acc-link" href="${escapeHtml(s.website)}" target="_blank">${escapeHtml(s.website.replace(/^https?:\/\//, ''))}</a></span></div>`,
    s.notes && `<div class="profile-line"><span class="pl-label">Notes</span><span class="pl-value">${escapeHtml(s.notes)}</span></div>`,
  ].filter(Boolean).join('') : '<div class="profile-empty">No school info yet.</div>';
  document.getElementById('ak-school').innerHTML = schoolHtml;

  // Health
  const h = d.health;
  const hasHealth = h.familyDoctor || h.dentist || h.pediatrician || h.allergies || h.medications;
  const healthHtml = hasHealth ? [
    h.familyDoctor && `<div class="profile-line"><span class="pl-label">Dr (Fam)</span><span class="pl-value">${escapeHtml(h.familyDoctor)}${h.familyDoctorPhone ? ' · ' + escapeHtml(h.familyDoctorPhone) : ''}</span></div>`,
    h.dentist && `<div class="profile-line"><span class="pl-label">Dentist</span><span class="pl-value">${escapeHtml(h.dentist)}${h.dentistPhone ? ' · ' + escapeHtml(h.dentistPhone) : ''}</span></div>`,
    h.pediatrician && `<div class="profile-line"><span class="pl-label">Pediatrician</span><span class="pl-value">${escapeHtml(h.pediatrician)}${h.pediatricianPhone ? ' · ' + escapeHtml(h.pediatricianPhone) : ''}</span></div>`,
    h.allergies && `<div class="profile-line"><span class="pl-label">Allergies</span><span class="pl-value" style="color:var(--terracotta);">${escapeHtml(h.allergies)}</span></div>`,
    h.medications && `<div class="profile-line"><span class="pl-label">Meds</span><span class="pl-value">${escapeHtml(h.medications)}</span></div>`,
    h.notes && `<div class="profile-line"><span class="pl-label">Notes</span><span class="pl-value">${escapeHtml(h.notes)}</span></div>`,
  ].filter(Boolean).join('') : '<div class="profile-empty">No health info yet.</div>';
  document.getElementById('ak-health').innerHTML = healthHtml;

  // Activities
  const actHtml = d.activities.length ? d.activities.map((a, i) => `
    <div class="profile-list-item">
      <div class="item-name">${escapeHtml(a.name)}</div>
      <div class="item-meta">
        ${a.instructor ? '👤 ' + escapeHtml(a.instructor) : ''}
        ${a.schedule ? ' · ⏰ ' + escapeHtml(a.schedule) : ''}
        ${a.location ? ' · 📍 ' + escapeHtml(a.location) : ''}
      </div>
      ${a.notes ? `<div class="item-meta" style="margin-top:3px;">${escapeHtml(a.notes)}</div>` : ''}
      <div class="item-actions">
        <button class="btn-mini" data-ak-edit-item="activities" data-ak-idx="${i}">edit</button>
        <button class="btn-mini danger" data-ak-del-item="activities" data-ak-idx="${i}">✕</button>
      </div>
    </div>`).join('') : '<div class="profile-empty">No activities listed.</div>';
  document.getElementById('ak-activities').innerHTML = actHtml;

  // Contacts
  const conHtml = d.contacts.length ? d.contacts.map((c, i) => `
    <div class="profile-list-item">
      <div class="item-name">${escapeHtml(c.name)} <span style="font-weight:400;color:var(--ink-soft);font-size:12px;">· ${escapeHtml(c.relationship || '')}</span></div>
      <div class="item-meta">
        ${c.phone ? '📞 ' + escapeHtml(c.phone) : ''}
        ${c.email ? ' · ✉ ' + escapeHtml(c.email) : ''}
      </div>
      <div class="item-actions">
        <button class="btn-mini" data-ak-edit-item="contacts" data-ak-idx="${i}">edit</button>
        <button class="btn-mini danger" data-ak-del-item="contacts" data-ak-idx="${i}">✕</button>
      </div>
    </div>`).join('') : '<div class="profile-empty">No emergency contacts yet.</div>';
  document.getElementById('ak-contacts').innerHTML = conHtml;

  // Notes
  const notesHtml = d.notes.length ? d.notes.slice().reverse().map((n, idx) => {
    const i = d.notes.length - 1 - idx;
    return `
    <div class="profile-list-item">
      <div class="item-name">${escapeHtml(n.title)}</div>
      <div class="item-meta">📅 ${n.date}</div>
      ${n.content ? `<div style="margin-top:5px;font-size:12.5px;color:var(--ink);">${escapeHtml(n.content)}</div>` : ''}
      <div class="item-actions">
        <button class="btn-mini danger" data-ak-del-item="notes" data-ak-idx="${i}">✕</button>
      </div>
    </div>`;
  }).join('') : '<div class="profile-empty">No notes recorded yet.</div>';
  document.getElementById('ak-notes').innerHTML = notesHtml;

  // Wire up list-item actions
  document.querySelectorAll('[data-ak-edit-item]').forEach(b =>
    b.addEventListener('click', () => showAksharaListItemModal(b.dataset.akEditItem, parseInt(b.dataset.akIdx)))
  );
  document.querySelectorAll('[data-ak-del-item]').forEach(b =>
    b.addEventListener('click', () => {
      if (!confirm('Delete this entry?')) return;
      const dd = getAk();
      dd[b.dataset.akDelItem].splice(parseInt(b.dataset.akIdx), 1);
      saveAk(dd);
      renderAkshara();
    })
  );
}

const aksharaModal = document.getElementById('akshara-modal');
const aksharaModalContent = document.getElementById('akshara-modal-content');

function showAksharaModal(section) {
  const d = getAk();

  let inner = '';
  if (section === 'personal') {
    const p = d.personal;
    inner = `
      <h3>✏ Edit personal info</h3>
      <div class="modal-grid">
        <div class="field"><label class="field-label">Name</label><input type="text" id="ak-f-name" value="${escapeHtml(p.name)}"></div>
        <div class="field"><label class="field-label">Date of birth</label><input type="date" id="ak-f-dob" value="${escapeHtml(p.dob)}"></div>
        <div class="field"><label class="field-label">Grade / class</label><input type="text" id="ak-f-grade" value="${escapeHtml(p.grade)}"></div>
        <div class="field"><label class="field-label">Blood type</label><input type="text" id="ak-f-blood" value="${escapeHtml(p.bloodType)}" placeholder="e.g. O+"></div>
      </div>`;
  } else if (section === 'school') {
    const s = d.school;
    inner = `
      <h3>✏ Edit school info</h3>
      <div class="modal-grid">
        <div class="field span-full"><label class="field-label">School name</label><input type="text" id="ak-f-sname" value="${escapeHtml(s.name)}"></div>
        <div class="field span-full"><label class="field-label">Address</label><input type="text" id="ak-f-saddress" value="${escapeHtml(s.address)}"></div>
        <div class="field"><label class="field-label">Principal</label><input type="text" id="ak-f-sprincipal" value="${escapeHtml(s.principal)}"></div>
        <div class="field"><label class="field-label">Teacher</label><input type="text" id="ak-f-steacher" value="${escapeHtml(s.teacher)}"></div>
        <div class="field"><label class="field-label">Phone</label><input type="text" id="ak-f-sphone" value="${escapeHtml(s.phone)}"></div>
        <div class="field"><label class="field-label">Website</label><input type="url" id="ak-f-swebsite" value="${escapeHtml(s.website)}"></div>
        <div class="field span-full"><label class="field-label">Notes</label><textarea id="ak-f-snotes" rows="2">${escapeHtml(s.notes)}</textarea></div>
      </div>`;
  } else if (section === 'health') {
    const h = d.health;
    inner = `
      <h3>✏ Edit health info</h3>
      <div class="modal-grid">
        <div class="field"><label class="field-label">Family doctor</label><input type="text" id="ak-f-hfd" value="${escapeHtml(h.familyDoctor)}"></div>
        <div class="field"><label class="field-label">Phone</label><input type="text" id="ak-f-hfdp" value="${escapeHtml(h.familyDoctorPhone)}"></div>
        <div class="field"><label class="field-label">Dentist</label><input type="text" id="ak-f-hd" value="${escapeHtml(h.dentist)}"></div>
        <div class="field"><label class="field-label">Phone</label><input type="text" id="ak-f-hdp" value="${escapeHtml(h.dentistPhone)}"></div>
        <div class="field"><label class="field-label">Pediatrician</label><input type="text" id="ak-f-hp" value="${escapeHtml(h.pediatrician)}"></div>
        <div class="field"><label class="field-label">Phone</label><input type="text" id="ak-f-hpp" value="${escapeHtml(h.pediatricianPhone)}"></div>
        <div class="field span-full"><label class="field-label">⚠ Allergies</label><input type="text" id="ak-f-hallergies" value="${escapeHtml(h.allergies)}" placeholder="e.g. peanuts, penicillin"></div>
        <div class="field span-full"><label class="field-label">Current medications</label><input type="text" id="ak-f-hmeds" value="${escapeHtml(h.medications)}"></div>
        <div class="field span-full"><label class="field-label">Notes</label><textarea id="ak-f-hnotes" rows="2">${escapeHtml(h.notes)}</textarea></div>
      </div>`;
  }

  aksharaModalContent.innerHTML = inner + `
    <div class="modal-actions">
      <button class="btn ghost" id="ak-cancel">Cancel</button>
      <button class="btn moss" id="ak-save">Save</button>
    </div>`;
  aksharaModal.style.display = 'flex';

  document.getElementById('ak-cancel').onclick = () => { aksharaModal.style.display = 'none'; };
  document.getElementById('ak-save').onclick = () => {
    const dd = getAk();
    if (section === 'personal') {
      dd.personal = {
        name: document.getElementById('ak-f-name').value.trim() || 'Akshara',
        dob: document.getElementById('ak-f-dob').value,
        grade: document.getElementById('ak-f-grade').value.trim(),
        bloodType: document.getElementById('ak-f-blood').value.trim(),
        photo: dd.personal.photo
      };
    } else if (section === 'school') {
      dd.school = {
        name: document.getElementById('ak-f-sname').value.trim(),
        address: document.getElementById('ak-f-saddress').value.trim(),
        principal: document.getElementById('ak-f-sprincipal').value.trim(),
        teacher: document.getElementById('ak-f-steacher').value.trim(),
        phone: document.getElementById('ak-f-sphone').value.trim(),
        website: document.getElementById('ak-f-swebsite').value.trim(),
        notes: document.getElementById('ak-f-snotes').value.trim()
      };
    } else if (section === 'health') {
      dd.health = {
        familyDoctor: document.getElementById('ak-f-hfd').value.trim(),
        familyDoctorPhone: document.getElementById('ak-f-hfdp').value.trim(),
        dentist: document.getElementById('ak-f-hd').value.trim(),
        dentistPhone: document.getElementById('ak-f-hdp').value.trim(),
        pediatrician: document.getElementById('ak-f-hp').value.trim(),
        pediatricianPhone: document.getElementById('ak-f-hpp').value.trim(),
        allergies: document.getElementById('ak-f-hallergies').value.trim(),
        medications: document.getElementById('ak-f-hmeds').value.trim(),
        notes: document.getElementById('ak-f-hnotes').value.trim()
      };
    }
    saveAk(dd);
    aksharaModal.style.display = 'none';
    renderAkshara();
  };
}

function showAksharaListItemModal(listKey, idx) {
  const d = getAk();
  const item = idx != null && idx >= 0 ? d[listKey][idx] : null;
  let inner = '';

  if (listKey === 'activities') {
    const a = item || { name: '', instructor: '', schedule: '', location: '', notes: '' };
    inner = `
      <h3>${item ? '✏ Edit' : '+ Add'} activity</h3>
      <div class="modal-grid">
        <div class="field span-full"><label class="field-label">Activity name *</label><input type="text" id="ak-i-name" value="${escapeHtml(a.name)}" placeholder="e.g. Karate"></div>
        <div class="field"><label class="field-label">Instructor</label><input type="text" id="ak-i-inst" value="${escapeHtml(a.instructor)}"></div>
        <div class="field"><label class="field-label">Schedule</label><input type="text" id="ak-i-sched" value="${escapeHtml(a.schedule)}" placeholder="e.g. Tue/Thu 5pm"></div>
        <div class="field span-full"><label class="field-label">Location</label><input type="text" id="ak-i-loc" value="${escapeHtml(a.location)}"></div>
        <div class="field span-full"><label class="field-label">Notes</label><textarea id="ak-i-notes" rows="2">${escapeHtml(a.notes)}</textarea></div>
      </div>`;
  } else if (listKey === 'contacts') {
    const c = item || { name: '', relationship: '', phone: '', email: '', notes: '' };
    inner = `
      <h3>${item ? '✏ Edit' : '+ Add'} emergency contact</h3>
      <div class="modal-grid">
        <div class="field"><label class="field-label">Name *</label><input type="text" id="ak-i-name" value="${escapeHtml(c.name)}"></div>
        <div class="field"><label class="field-label">Relationship</label><input type="text" id="ak-i-rel" value="${escapeHtml(c.relationship)}" placeholder="e.g. Grandma"></div>
        <div class="field"><label class="field-label">Phone</label><input type="text" id="ak-i-phone" value="${escapeHtml(c.phone)}"></div>
        <div class="field"><label class="field-label">Email</label><input type="email" id="ak-i-email" value="${escapeHtml(c.email)}"></div>
        <div class="field span-full"><label class="field-label">Notes</label><textarea id="ak-i-notes" rows="2">${escapeHtml(c.notes)}</textarea></div>
      </div>`;
  } else if (listKey === 'notes') {
    const n = item || { date: todayISO(), title: '', content: '' };
    inner = `
      <h3>${item ? '✏ Edit' : '+ Add'} note</h3>
      <div class="modal-grid">
        <div class="field"><label class="field-label">Date</label><input type="date" id="ak-i-date" value="${escapeHtml(n.date)}"></div>
        <div class="field"><label class="field-label">Title *</label><input type="text" id="ak-i-title" value="${escapeHtml(n.title)}" placeholder="e.g. Lost first tooth"></div>
        <div class="field span-full"><label class="field-label">Details</label><textarea id="ak-i-content" rows="3">${escapeHtml(n.content)}</textarea></div>
      </div>`;
  }

  aksharaModalContent.innerHTML = inner + `
    <div class="modal-actions">
      <button class="btn ghost" id="ak-i-cancel">Cancel</button>
      <button class="btn moss" id="ak-i-save">${item ? 'Save changes' : 'Add'}</button>
    </div>`;
  aksharaModal.style.display = 'flex';

  document.getElementById('ak-i-cancel').onclick = () => { aksharaModal.style.display = 'none'; };
  document.getElementById('ak-i-save').onclick = () => {
    const dd = getAk();
    let rec;
    if (listKey === 'activities') {
      const name = document.getElementById('ak-i-name').value.trim();
      if (!name) { alert('Name is required.'); return; }
      rec = {
        name,
        instructor: document.getElementById('ak-i-inst').value.trim(),
        schedule: document.getElementById('ak-i-sched').value.trim(),
        location: document.getElementById('ak-i-loc').value.trim(),
        notes: document.getElementById('ak-i-notes').value.trim()
      };
    } else if (listKey === 'contacts') {
      const name = document.getElementById('ak-i-name').value.trim();
      if (!name) { alert('Name is required.'); return; }
      rec = {
        name,
        relationship: document.getElementById('ak-i-rel').value.trim(),
        phone: document.getElementById('ak-i-phone').value.trim(),
        email: document.getElementById('ak-i-email').value.trim(),
        notes: document.getElementById('ak-i-notes').value.trim()
      };
    } else if (listKey === 'notes') {
      const title = document.getElementById('ak-i-title').value.trim();
      if (!title) { alert('Title is required.'); return; }
      rec = {
        date: document.getElementById('ak-i-date').value || todayISO(),
        title,
        content: document.getElementById('ak-i-content').value.trim()
      };
    }
    if (item) { dd[listKey][idx] = rec; }
    else { dd[listKey].push(rec); }
    saveAk(dd);
    aksharaModal.style.display = 'none';
    renderAkshara();
  };
}

document.querySelectorAll('[data-edit-ak]').forEach(b =>
  b.addEventListener('click', () => showAksharaModal(b.dataset.editAk))
);
document.querySelectorAll('[data-add-ak]').forEach(b =>
  b.addEventListener('click', () => showAksharaListItemModal(b.dataset.addAk))
);
aksharaModal.addEventListener('click', e => {
  if (e.target === aksharaModal) aksharaModal.style.display = 'none';
});

// ============================================================
// 12. DOCUMENTS MODULE (IndexedDB-backed)
// ============================================================

const DOCS_META_KEY = 'hf-documents-meta-v1';
const DB_NAME = 'hf-documents';
const STORE_NAME = 'files';

function openDocsDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function storeBlob(id, blob, isEncrypted, iv) {
  const db = await openDocsDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put({ id, blob, encrypted: isEncrypted, iv });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getBlob(id) {
  const db = await openDocsDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(id);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function deleteBlob(id) {
  const db = await openDocsDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function getDocsMeta() { return load(DOCS_META_KEY, []); }
function saveDocsMeta(arr) { save(DOCS_META_KEY, arr); }

function fileTypeIcon(name, mime) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'].includes(ext)) return '🖼';
  if (ext === 'pdf') return '📕';
  if (['doc', 'docx', 'odt', 'rtf'].includes(ext)) return '📄';
  if (['xls', 'xlsx', 'csv', 'ods'].includes(ext)) return '📊';
  if (['ppt', 'pptx', 'odp', 'key'].includes(ext)) return '📊';
  if (['zip', 'tar', 'gz', 'rar', '7z'].includes(ext)) return '🗜';
  if (['mp4', 'avi', 'mov', 'mkv', 'webm'].includes(ext)) return '🎬';
  if (['mp3', 'wav', 'flac', 'm4a', 'ogg'].includes(ext)) return '🎵';
  if (['txt', 'md', 'log'].includes(ext)) return '📝';
  return '📄';
}

function formatBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

let pendingUploadFiles = [];

const uploadArea = document.getElementById('upload-area');
const fileInput = document.getElementById('file-input');
const uploadOptions = document.getElementById('upload-options');

document.getElementById('browse-files').addEventListener('click', (e) => {
  e.stopPropagation();
  fileInput.click();
});
uploadArea.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
  pendingUploadFiles = Array.from(e.target.files);
  if (pendingUploadFiles.length > 0) showUploadOptions();
});

['dragenter', 'dragover'].forEach(ev =>
  uploadArea.addEventListener(ev, (e) => { e.preventDefault(); uploadArea.classList.add('dragover'); })
);
['dragleave', 'drop'].forEach(ev =>
  uploadArea.addEventListener(ev, (e) => { e.preventDefault(); uploadArea.classList.remove('dragover'); })
);
uploadArea.addEventListener('drop', (e) => {
  pendingUploadFiles = Array.from(e.dataTransfer.files);
  if (pendingUploadFiles.length > 0) showUploadOptions();
});

function showUploadOptions() {
  const preview = document.getElementById('upload-files-preview');
  preview.innerHTML = pendingUploadFiles.map(f => `
    <div class="upload-file-row">
      <span>${fileTypeIcon(f.name, f.type)} ${escapeHtml(f.name)}</span>
      <span class="file-size">${formatBytes(f.size)}</span>
    </div>
  `).join('');
  uploadOptions.style.display = '';
  uploadArea.style.display = 'none';
}

document.getElementById('cancel-upload').addEventListener('click', () => {
  pendingUploadFiles = [];
  fileInput.value = '';
  uploadOptions.style.display = 'none';
  uploadArea.style.display = '';
});

document.getElementById('confirm-upload').addEventListener('click', async () => {
  const cat = document.getElementById('doc-cat').value;
  const country = document.getElementById('doc-country').value;
  const tagsRaw = document.getElementById('doc-tags').value;
  const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
  const encryptChoice = document.getElementById('doc-encrypt').value === 'yes';

  if (encryptChoice) {
    if (vaultState() === 'NOT_SETUP') {
      alert('Set up the vault first to encrypt documents.');
      showVaultModalSetup();
      return;
    }
    if (vaultState() === 'LOCKED') {
      showVaultModalUnlock(() => document.getElementById('confirm-upload').click());
      return;
    }
  }

  const btn = document.getElementById('confirm-upload');
  btn.disabled = true;
  btn.textContent = 'Uploading...';

  const meta = getDocsMeta();
  let success = 0, failed = 0;

  for (const file of pendingUploadFiles) {
    try {
      const id = uid('doc');
      const buf = await file.arrayBuffer();
      let blobToStore = new Blob([buf], { type: file.type });
      let isEnc = false;
      let ivStored = null;
      if (encryptChoice) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, buf);
        blobToStore = new Blob([new Uint8Array(ct)]);
        isEnc = true;
        ivStored = bytesToBase64(iv);
      }
      await storeBlob(id, blobToStore, isEnc, ivStored);
      meta.push({
        id, name: file.name, size: file.size, type: file.type,
        category: cat, country, tags,
        encrypted: isEnc, uploadedAt: todayISO()
      });
      success++;
    } catch (e) {
      console.error('Upload failed:', file.name, e);
      failed++;
    }
  }
  saveDocsMeta(meta);

  btn.disabled = false;
  btn.textContent = '⤒ Upload all';
  pendingUploadFiles = [];
  fileInput.value = '';
  uploadOptions.style.display = 'none';
  uploadArea.style.display = '';

  renderDocs();
  if (failed > 0) alert(`Uploaded ${success}, ${failed} failed. See console.`);
});

async function openDoc(id) {
  const meta = getDocsMeta().find(m => m.id === id);
  if (!meta) return;
  if (meta.encrypted) {
    if (vaultState() !== 'UNLOCKED') {
      showVaultModalUnlock(() => openDoc(id));
      return;
    }
  }
  try {
    const rec = await getBlob(id);
    if (!rec) { alert('File data missing from IndexedDB.'); return; }
    let blob = rec.blob;
    if (meta.encrypted && rec.iv) {
      const ct = await blob.arrayBuffer();
      const iv = base64ToBytes(rec.iv);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, vaultKey, ct);
      blob = new Blob([pt], { type: meta.type });
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    vaultUnlockedAt = Date.now();
  } catch (e) {
    alert('Failed to open: ' + e.message);
  }
}

async function deleteDoc(id) {
  const meta = getDocsMeta().find(m => m.id === id);
  if (!meta) return;
  if (!confirm(`Delete "${meta.name}"? This cannot be undone.`)) return;
  await deleteBlob(id);
  saveDocsMeta(getDocsMeta().filter(m => m.id !== id));
  renderDocs();
}

function renderDocs() {
  const all = getDocsMeta();

  // Populate category filter
  const cats = [...new Set(all.map(m => m.category))].sort();
  const catFilter = document.getElementById('doc-cat-filter');
  const currentCat = catFilter.value;
  catFilter.innerHTML = '<option value="all">All</option>' +
    cats.map(c => `<option value="${escapeHtml(c)}" ${c === currentCat ? 'selected' : ''}>${escapeHtml(c)}</option>`).join('');

  const catSel = catFilter.value;
  const countrySel = document.getElementById('doc-country-filter').value;
  const search = document.getElementById('doc-search').value.toLowerCase().trim();

  const filtered = all.filter(m =>
    (catSel === 'all' || m.category === catSel) &&
    (countrySel === 'all' || m.country === countrySel) &&
    (!search || m.name.toLowerCase().includes(search) || (m.tags || []).some(t => t.toLowerCase().includes(search)))
  );

  // Stats
  const totalSize = all.reduce((s, m) => s + (m.size || 0), 0);
  const encCount = all.filter(m => m.encrypted).length;
  document.getElementById('doc-stats').innerHTML = `
    <div class="doc-stat"><div class="label">Total files</div><div class="value">${all.length}</div></div>
    <div class="doc-stat"><div class="label">Total size</div><div class="value">${formatBytes(totalSize)}</div></div>
    <div class="doc-stat"><div class="label">🔐 Encrypted</div><div class="value">${encCount}</div></div>
    <div class="doc-stat"><div class="label">Showing</div><div class="value">${filtered.length}</div></div>
  `;

  const grid = document.getElementById('document-grid');
  if (filtered.length === 0) {
    grid.innerHTML = `<div class="doc-empty">
      <p>${all.length === 0 ? 'No documents uploaded yet.' : 'No documents match these filters.'}</p>
      ${all.length === 0 ? '<p style="margin-top:8px;">Drag files into the area above, or click <strong>Browse</strong>.</p>' : ''}
    </div>`;
    return;
  }

  grid.innerHTML = filtered.slice().reverse().map(m => `
    <div class="doc-card">
      <div class="doc-card-head">
        <div class="doc-icon">${fileTypeIcon(m.name, m.type)}</div>
        <div class="doc-card-title">
          <div class="doc-name">${escapeHtml(m.name)}</div>
          <div class="doc-meta">${formatBytes(m.size)} · ${m.uploadedAt}</div>
        </div>
      </div>
      <div class="doc-tags">
        <span class="doc-tag cat">${escapeHtml(m.category)}</span>
        <span class="doc-tag country">${escapeHtml(m.country)}</span>
        ${m.encrypted ? '<span class="doc-tag encrypted">🔐 encrypted</span>' : ''}
        ${(m.tags || []).map(t => `<span class="doc-tag">${escapeHtml(t)}</span>`).join('')}
      </div>
      <div class="doc-actions">
        <button class="btn ghost btn-sm" data-doc-open="${m.id}">⤓ Open / Download</button>
        <button class="btn-icon" data-doc-del="${m.id}" title="Delete">✕</button>
      </div>
    </div>
  `).join('');

  grid.querySelectorAll('[data-doc-open]').forEach(b =>
    b.addEventListener('click', () => openDoc(b.dataset.docOpen))
  );
  grid.querySelectorAll('[data-doc-del]').forEach(b =>
    b.addEventListener('click', () => deleteDoc(b.dataset.docDel))
  );
}

['doc-cat-filter', 'doc-country-filter'].forEach(id =>
  document.getElementById(id).addEventListener('change', renderDocs)
);
document.getElementById('doc-search').addEventListener('input', renderDocs);

// Initial Akshara + Documents render
renderAkshara();
renderDocs();



// ============================================================
// 13. SECURITY HARDENING
// ============================================================

// Bump PBKDF2 iterations for NEW vaults (existing vaults keep their original count)
const NEW_PBKDF2_ITERATIONS = 600000;

const SEC_KEY = 'hf-security-v1';
const LOCKOUT_KEY = 'hf-lockout-v1';

function getSecurityPrefs() {
  return load(SEC_KEY, {
    idleMinutes: 15,
    lockOnHide: false,
    clipboardClearSec: 30,
    notifications: false,
  });
}
function saveSecurityPrefs(p) { save(SEC_KEY, p); }

// --- Brute-force lockout ---

function getLockoutState() {
  return load(LOCKOUT_KEY, { failedAttempts: 0, lockedUntil: 0 });
}
function saveLockoutState(s) { save(LOCKOUT_KEY, s); }

function recordFailedAttempt() {
  const s = getLockoutState();
  s.failedAttempts++;
  // Exponential backoff
  if (s.failedAttempts >= 10) s.lockedUntil = Date.now() + 30 * 60 * 1000;
  else if (s.failedAttempts >= 5) s.lockedUntil = Date.now() + 5 * 60 * 1000;
  else if (s.failedAttempts >= 3) s.lockedUntil = Date.now() + 30 * 1000;
  saveLockoutState(s);
}

function clearLockoutState() {
  saveLockoutState({ failedAttempts: 0, lockedUntil: 0 });
}

function lockoutRemainingMs() {
  const s = getLockoutState();
  return Math.max(0, s.lockedUntil - Date.now());
}

// --- Patch tryUnlockVault to enforce lockout + count failed attempts ---

const _origTryUnlock = tryUnlockVault;
tryUnlockVault = async function (password) {
  const remaining = lockoutRemainingMs();
  if (remaining > 0) {
    const sec = Math.ceil(remaining / 1000);
    throw new Error(`Too many failed attempts. Try again in ${sec >= 60 ? Math.ceil(sec / 60) + ' min' : sec + ' sec'}.`);
  }
  try {
    await _origTryUnlock(password);
    clearLockoutState();
    return true;
  } catch (e) {
    recordFailedAttempt();
    const s = getLockoutState();
    const msg = e.message + (s.failedAttempts >= 3 ? ` (attempt ${s.failedAttempts}, locking out)` : ` (attempt ${s.failedAttempts})`);
    throw new Error(msg);
  }
};

// --- Patch setupNewVault to use 600k iterations + store iteration count ---

const _origSetup = setupNewVault;
setupNewVault = async function (password, hint) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // Manually replicate setup with new iteration count
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: NEW_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const verifier = await encryptText(VERIFIER_PLAINTEXT, key);
  save(KEYS.vault, {
    initialized: true,
    salt: bytesToBase64(salt),
    verifier,
    hint: hint || '',
    setupAt: new Date().toISOString(),
    iterations: NEW_PBKDF2_ITERATIONS,
  });
  vaultKey = key;
  vaultUnlockedAt = Date.now();
  refreshVaultUI();
};

// --- Patch deriveKey to read iterations from vault metadata when available ---

const _origDeriveKey = deriveKey;
deriveKey = async function (password, saltBytes) {
  const v = load(KEYS.vault, null);
  const iters = (v && v.iterations) ? v.iterations : PBKDF2_ITERATIONS;
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: iters, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

// --- Auto-lock on visibility change (configurable) ---

document.addEventListener('visibilitychange', () => {
  const prefs = getSecurityPrefs();
  if (document.hidden && prefs.lockOnHide && vaultKey) {
    lockVault();
  }
});

// --- Idle detection (configurable) ---

let lastActivity = Date.now();
['mousemove', 'keypress', 'click', 'scroll', 'touchstart'].forEach(ev =>
  document.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true })
);

setInterval(() => {
  const prefs = getSecurityPrefs();
  if (prefs.idleMinutes > 0 && vaultKey) {
    if (Date.now() - lastActivity > prefs.idleMinutes * 60 * 1000) {
      lockVault();
      console.log('Vault auto-locked: idle');
    }
  }
}, 15000);

// --- Patch copyField to auto-clear clipboard ---

const _origCopyField = copyField;
copyField = async function (accId, field) {
  await _origCopyField(accId, field);
  const prefs = getSecurityPrefs();
  if (prefs.clipboardClearSec > 0) {
    setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
      } catch { /* clipboard may be inaccessible */ }
    }, prefs.clipboardClearSec * 1000);
  }
};

// --- Privacy / Panic mode ---

document.getElementById('privacy-btn').addEventListener('click', () => {
  const isPrivate = document.body.classList.toggle('privacy-mode');
  if (isPrivate) {
    lockVault();
    document.querySelector('.tab[data-tab="dashboard"]').click();
  }
});

// --- Security panel toggle + render ---

document.getElementById('toggle-security-details').addEventListener('click', () => {
  const det = document.getElementById('security-details');
  const btn = document.getElementById('toggle-security-details');
  const shown = det.style.display !== 'none';
  det.style.display = shown ? 'none' : '';
  btn.textContent = shown ? 'show settings' : 'hide settings';
});

['sec-idle', 'sec-hide', 'sec-clip', 'sec-notif'].forEach(id => {
  document.getElementById(id).addEventListener('change', () => {
    const prefs = getSecurityPrefs();
    prefs.idleMinutes = parseInt(document.getElementById('sec-idle').value);
    prefs.lockOnHide = document.getElementById('sec-hide').value === 'yes';
    prefs.clipboardClearSec = parseInt(document.getElementById('sec-clip').value);
    prefs.notifications = document.getElementById('sec-notif').value === 'on';
    saveSecurityPrefs(prefs);
    if (prefs.notifications && Notification.permission === 'default') {
      Notification.requestPermission();
    }
    renderSecurityPanel();
  });
});

function renderSecurityPanel() {
  const prefs = getSecurityPrefs();
  document.getElementById('sec-idle').value = prefs.idleMinutes;
  document.getElementById('sec-hide').value = prefs.lockOnHide ? 'yes' : 'no';
  document.getElementById('sec-clip').value = prefs.clipboardClearSec;
  document.getElementById('sec-notif').value = prefs.notifications ? 'on' : 'off';

  const v = load(KEYS.vault, null);
  const vState = vaultState();
  const iters = (v && v.iterations) ? v.iterations : (v ? PBKDF2_ITERATIONS : NEW_PBKDF2_ITERATIONS);
  const lockout = getLockoutState();
  const secure = window.isSecureContext;
  const accCount = load(KEYS.accounts, []).filter(a => a.passwordEnc || a.pinEnc).length;

  const chips = [
    `<span class="sec-chip ${vState === 'UNLOCKED' ? 'warn' : 'ok'}">🔐 Vault ${vState.toLowerCase().replace('_', ' ')}</span>`,
    `<span class="sec-chip ok">PBKDF2: ${iters.toLocaleString()} iterations</span>`,
    `<span class="sec-chip ok">AES-GCM 256</span>`,
    `<span class="sec-chip ${secure ? 'ok' : 'danger'}">${secure ? '✓' : '⚠'} ${secure ? 'Secure context' : 'Insecure (http://)'}</span>`,
    `<span class="sec-chip ${prefs.idleMinutes > 0 ? 'ok' : 'warn'}">Idle lock: ${prefs.idleMinutes > 0 ? prefs.idleMinutes + ' min' : 'OFF'}</span>`,
    `<span class="sec-chip ${prefs.lockOnHide ? 'ok' : 'warn'}">Tab-hide lock: ${prefs.lockOnHide ? 'ON' : 'OFF'}</span>`,
    `<span class="sec-chip ${prefs.clipboardClearSec > 0 ? 'ok' : 'warn'}">Clipboard clear: ${prefs.clipboardClearSec > 0 ? prefs.clipboardClearSec + 's' : 'OFF'}</span>`,
    `<span class="sec-chip">Encrypted credentials: ${accCount}</span>`,
  ];
  if (lockout.failedAttempts > 0) {
    chips.push(`<span class="sec-chip danger">Failed attempts: ${lockout.failedAttempts}</span>`);
  }
  document.getElementById('security-summary').innerHTML = chips.join(' ');

  const recs = [];
  if (!secure) recs.push('<strong>⚠ Switch to file:// or https://</strong> — plain http:// is unsafe for this app.');
  if (prefs.idleMinutes === 0) recs.push('Consider enabling idle auto-lock so the vault doesn\'t stay open if you walk away.');
  if (!prefs.lockOnHide) recs.push('Turn on <strong>Lock on tab hide</strong> for extra protection when switching browsers / tabs.');
  if (v && (v.iterations || PBKDF2_ITERATIONS) < 600000) {
    recs.push('Your vault uses 250k PBKDF2 iterations. Change your master password to upgrade to 600k iterations.');
  }
  recs.push('Use a strong unique master password (16+ chars) and never reuse it elsewhere.');
  recs.push('Enable <strong>full-disk encryption</strong> on this computer (BitLocker / FileVault / LUKS).');
  recs.push('Export the backup JSON regularly. Store on an encrypted USB drive, not cloud sync.');
  recs.push('For your most-critical credentials (primary banking, govt portals), prefer a dedicated password manager like Bitwarden.');
  document.getElementById('security-recs').innerHTML =
    '<strong>Recommendations</strong><ul>' + recs.map(r => `<li>${r}</li>`).join('') + '</ul>';
}

// ============================================================
// 14. REMINDER TIME (extend existing reminder module)
// ============================================================

// Patch save-reminder to include time
const _origSaveRem = document.getElementById('save-reminder').onclick;
document.getElementById('save-reminder').onclick = null;
document.getElementById('save-reminder').addEventListener('click', () => {
  const date = document.getElementById('rem-date').value;
  const time = document.getElementById('rem-time').value || '';
  const title = document.getElementById('rem-title').value.trim();
  const category = document.getElementById('rem-cat').value;
  const recurring = document.getElementById('rem-recur').value;
  if (!date || !title) { alert('Date and title are required.'); return; }
  const arr = getReminders();
  arr.push({ id: uid('rem'), date, time, title, category, recurring });
  saveReminders(arr);
  document.getElementById('rem-title').value = '';
  document.getElementById('rem-time').value = '';
  document.getElementById('reminder-form').style.display = 'none';
  renderCalendar();
  renderReminderList();
  scheduleNotifications();
}, { capture: true });

// Override renderReminderList to include time pill
const _origRenderReminderList = renderReminderList;
renderReminderList = function () {
  const all = getReminders().slice().sort((a, b) => {
    if (a.date !== b.date) return a.date.localeCompare(b.date);
    return (a.time || '').localeCompare(b.time || '');
  });
  const today = todayISO();
  const upcoming = all.filter(r => r.date >= today || r.recurring !== 'none').slice(0, 12);
  const list = document.getElementById('reminder-list');
  if (upcoming.length === 0) {
    list.innerHTML = '<div class="mini-list"><div class="empty">No reminders yet. Click + Add or tap a calendar date.</div></div>';
    return;
  }
  list.innerHTML = upcoming.map(r => {
    const past = r.date < today && r.recurring === 'none';
    const rec = r.recurring && r.recurring !== 'none' ? ` · ↻ ${r.recurring}` : '';
    const timePill = r.time ? `<span class="rem-time-pill">${r.time}</span>` : '';
    return `<div class="reminder-item ${r.category} ${past ? 'past' : ''}">
      <span class="rem-date">${r.date}${timePill}</span>
      <span class="rem-title">${escapeHtml(r.title)}</span>
      <span class="rem-meta">${r.category}${rec}</span>
      <span class="rem-actions">
        <button class="btn-icon" data-del-rem="${r.id}" title="Delete">✕</button>
      </span>
    </div>`;
  }).join('');
  list.querySelectorAll('[data-del-rem]').forEach(b => {
    b.addEventListener('click', () => {
      if (!confirm('Delete this reminder?')) return;
      saveReminders(getReminders().filter(x => x.id !== b.dataset.delRem));
      renderCalendar();
      renderReminderList();
    });
  });
};

// Browser notification scheduling
let notifTimeouts = [];
function scheduleNotifications() {
  notifTimeouts.forEach(t => clearTimeout(t));
  notifTimeouts = [];
  const prefs = getSecurityPrefs();
  if (!prefs.notifications || Notification.permission !== 'granted') return;
  const now = Date.now();
  const oneDay = 24 * 60 * 60 * 1000;
  getReminders().forEach(r => {
    if (!r.time) return;
    const target = new Date(`${r.date}T${r.time}:00`).getTime();
    if (target > now && target - now < oneDay) {
      notifTimeouts.push(setTimeout(() => {
        new Notification(`🔔 ${r.title}`, {
          body: `${r.date} ${r.time} · ${r.category}`,
          tag: r.id,
        });
      }, target - now));
    }
  });
}

// ============================================================
// 15. INVESTMENT MODULE
// ============================================================

const INV_KEY = 'hf-investments-v1';
function getInvs() { return load(INV_KEY, []); }
function saveInvs(a) { save(INV_KEY, a); }

document.getElementById('inv-date').valueAsDate = new Date();

document.getElementById('add-inv-btn').addEventListener('click', () => {
  const type = document.getElementById('inv-type').value;
  const name = document.getElementById('inv-name').value.trim();
  const inst = document.getElementById('inv-inst').value.trim();
  const invested = parseFloat(document.getElementById('inv-invested').value);
  const currency = document.getElementById('inv-currency').value;
  const currentRaw = document.getElementById('inv-current').value;
  const current = currentRaw ? parseFloat(currentRaw) : null;
  const country = document.getElementById('inv-country').value;
  const date = document.getElementById('inv-date').value;
  const maturity = document.getElementById('inv-maturity').value;
  const rateRaw = document.getElementById('inv-rate').value;
  const rate = rateRaw ? parseFloat(rateRaw) : null;
  const notes = document.getElementById('inv-notes').value.trim();

  if (!name || isNaN(invested) || invested <= 0) {
    alert('Name and a valid invested amount are required.');
    return;
  }
  const arr = getInvs();
  arr.push({
    id: uid('inv'), type, name, institution: inst, invested, current,
    currency, country, purchaseDate: date, maturityDate: maturity,
    rate, notes, addedAt: todayISO(),
  });
  saveInvs(arr);
  ['inv-name', 'inv-inst', 'inv-invested', 'inv-current', 'inv-maturity', 'inv-rate', 'inv-notes'].forEach(id =>
    document.getElementById(id).value = ''
  );
  renderInvs();
});

function renderInvs() {
  const all = getInvs();
  const typeF = document.getElementById('inv-type-filter');
  const types = [...new Set(all.map(i => i.type))].sort();
  const curT = typeF.value;
  typeF.innerHTML = '<option value="all">All</option>' +
    types.map(t => `<option value="${t}" ${t === curT ? 'selected' : ''}>${t}</option>`).join('');

  const typeSel = typeF.value;
  const countrySel = document.getElementById('inv-country-filter').value;
  const currSel = document.getElementById('inv-curr-filter').value;
  const filtered = all.filter(i =>
    (typeSel === 'all' || i.type === typeSel) &&
    (countrySel === 'all' || i.country === countrySel) &&
    (currSel === 'all' || i.currency === currSel)
  );

  // Stats by currency
  const byCurrency = {};
  filtered.forEach(i => {
    if (!byCurrency[i.currency]) byCurrency[i.currency] = { invested: 0, current: 0, count: 0 };
    byCurrency[i.currency].invested += i.invested;
    byCurrency[i.currency].current += (i.current != null ? i.current : i.invested);
    byCurrency[i.currency].count++;
  });

  const stats = document.getElementById('inv-stats');
  if (Object.keys(byCurrency).length === 0) {
    stats.innerHTML = `<div class="doc-stat"><div class="label">Total holdings</div><div class="value">0</div></div>`;
  } else {
    stats.innerHTML = Object.entries(byCurrency).map(([c, v]) => {
      const gain = v.current - v.invested;
      const pct = v.invested > 0 ? (gain / v.invested * 100).toFixed(1) : 0;
      return `
        <div class="doc-stat"><div class="label">${c} invested (${v.count})</div><div class="value">${fmtCurrency(v.invested, c)}</div></div>
        <div class="doc-stat" style="border-left-color: ${gain >= 0 ? 'var(--sage)' : 'var(--terracotta)'}">
          <div class="label">${c} current value</div>
          <div class="value">${fmtCurrency(v.current, c)}</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:${gain >= 0 ? 'var(--sage)' : 'var(--terracotta)'};margin-top:3px;">
            ${gain >= 0 ? '+' : ''}${fmtCurrency(gain, c)} (${gain >= 0 ? '+' : ''}${pct}%)
          </div>
        </div>`;
    }).join('');
  }

  const grid = document.getElementById('inv-grid');
  if (filtered.length === 0) {
    grid.innerHTML = `<div class="doc-empty"><p>${all.length === 0 ? 'No investments tracked yet.' : 'No investments match these filters.'}</p></div>`;
    return;
  }

  grid.innerHTML = filtered.slice().reverse().map(i => {
    const cur = i.current != null ? i.current : i.invested;
    const gain = cur - i.invested;
    const pct = i.invested > 0 ? (gain / i.invested * 100).toFixed(1) : 0;
    return `
      <div class="inv-card">
        <div class="inv-head">
          <div>
            <div class="inv-name">${escapeHtml(i.name)}</div>
            <div class="inv-meta">${escapeHtml(i.type)}${i.institution ? ' · ' + escapeHtml(i.institution) : ''}</div>
          </div>
          <span class="doc-tag country">${i.country}</span>
        </div>
        <div class="inv-detail"><span class="lbl">Invested</span><span class="val">${fmtCurrency(i.invested, i.currency)}</span></div>
        <div class="inv-detail"><span class="lbl">Current value</span><span class="val">${fmtCurrency(cur, i.currency)}</span></div>
        ${i.current != null ? `<div class="inv-detail"><span class="lbl">Gain/Loss</span><span class="val ${gain >= 0 ? 'pos' : 'neg'}">${gain >= 0 ? '+' : ''}${fmtCurrency(gain, i.currency)} (${gain >= 0 ? '+' : ''}${pct}%)</span></div>` : ''}
        ${i.purchaseDate ? `<div class="inv-detail"><span class="lbl">Purchase</span><span class="val">${i.purchaseDate}</span></div>` : ''}
        ${i.maturityDate ? `<div class="inv-detail"><span class="lbl">Maturity</span><span class="val">${i.maturityDate}</span></div>` : ''}
        ${i.rate != null ? `<div class="inv-detail"><span class="lbl">Rate</span><span class="val">${i.rate}%</span></div>` : ''}
        ${i.notes ? `<div style="font-size:12px;color:var(--ink-soft);font-style:italic;margin-top:4px;">${escapeHtml(i.notes)}</div>` : ''}
        <div class="acc-actions">
          <button class="btn-icon" data-del-inv="${i.id}" title="Delete">✕</button>
        </div>
      </div>`;
  }).join('');

  grid.querySelectorAll('[data-del-inv]').forEach(b =>
    b.addEventListener('click', () => {
      if (!confirm('Delete this investment record?')) return;
      saveInvs(getInvs().filter(x => x.id !== b.dataset.delInv));
      renderInvs();
    })
  );
}

['inv-type-filter', 'inv-country-filter', 'inv-curr-filter'].forEach(id =>
  document.getElementById(id).addEventListener('change', renderInvs)
);

document.getElementById('export-inv').addEventListener('click', () => {
  const arr = getInvs();
  if (arr.length === 0) { alert('No investments to export.'); return; }
  const rows = [['Type', 'Name', 'Institution', 'Country', 'Currency', 'Invested', 'Current', 'Purchase', 'Maturity', 'Rate%', 'Notes']];
  arr.forEach(i => rows.push([
    i.type, i.name, i.institution || '', i.country, i.currency,
    i.invested.toFixed(2), i.current != null ? i.current.toFixed(2) : '',
    i.purchaseDate || '', i.maturityDate || '',
    i.rate != null ? i.rate.toString() : '', i.notes || ''
  ]));
  downloadCsv(rows, `investments-${todayISO()}.csv`);
});

// ============================================================
// 16. SUBSCRIPTIONS MODULE
// ============================================================

const SUB_KEY = 'hf-subscriptions-v1';
function getSubs() { return load(SUB_KEY, []); }
function saveSubs(a) { save(SUB_KEY, a); }

document.getElementById('sub-next').valueAsDate = new Date();

function monthlyEquivalent(cost, cycle) {
  switch (cycle) {
    case 'weekly':    return cost * 52 / 12;
    case 'monthly':   return cost;
    case 'quarterly': return cost / 3;
    case 'yearly':    return cost / 12;
    case 'biennial':  return cost / 24;
    default: return cost;
  }
}

document.getElementById('add-sub-btn').addEventListener('click', () => {
  const name = document.getElementById('sub-name').value.trim();
  const category = document.getElementById('sub-cat').value;
  const cost = parseFloat(document.getElementById('sub-cost').value);
  const currency = document.getElementById('sub-currency').value;
  const cycle = document.getElementById('sub-cycle').value;
  const nextBilling = document.getElementById('sub-next').value;
  const status = document.getElementById('sub-status').value;
  const paidBy = document.getElementById('sub-paid').value;
  const notes = document.getElementById('sub-notes').value.trim();

  if (!name || isNaN(cost) || cost <= 0) {
    alert('Service name and a valid cost are required.');
    return;
  }
  const arr = getSubs();
  arr.push({ id: uid('sub'), name, category, cost, currency, cycle, nextBilling, status, paidBy, notes, addedAt: todayISO() });
  saveSubs(arr);
  ['sub-name', 'sub-cost', 'sub-notes'].forEach(id => document.getElementById(id).value = '');
  renderSubs();
});

function renderSubs() {
  const all = getSubs();
  const catF = document.getElementById('sub-cat-filter');
  const cats = [...new Set(all.map(s => s.category))].sort();
  const curC = catF.value;
  catF.innerHTML = '<option value="all">All</option>' +
    cats.map(c => `<option value="${c}" ${c === curC ? 'selected' : ''}>${c}</option>`).join('');

  const statusSel = document.getElementById('sub-status-filter').value;
  const catSel = catF.value;
  const currSel = document.getElementById('sub-curr-filter').value;

  const filtered = all.filter(s =>
    (statusSel === 'all' || s.status === statusSel) &&
    (catSel === 'all' || s.category === catSel) &&
    (currSel === 'all' || s.currency === currSel)
  );

  // Stats by currency for active subscriptions
  const byCurrency = {};
  filtered.filter(s => s.status === 'active' || s.status === 'trial').forEach(s => {
    if (!byCurrency[s.currency]) byCurrency[s.currency] = { monthly: 0, count: 0 };
    byCurrency[s.currency].monthly += monthlyEquivalent(s.cost, s.cycle);
    byCurrency[s.currency].count++;
  });

  const stats = document.getElementById('sub-stats');
  if (Object.keys(byCurrency).length === 0) {
    stats.innerHTML = `<div class="doc-stat"><div class="label">Active subs</div><div class="value">0</div></div>`;
  } else {
    stats.innerHTML = Object.entries(byCurrency).map(([c, v]) => `
      <div class="doc-stat"><div class="label">${c} monthly (${v.count})</div><div class="value">${fmtCurrency(v.monthly, c)}</div></div>
      <div class="doc-stat" style="border-left-color: var(--amber);"><div class="label">${c} yearly</div><div class="value">${fmtCurrency(v.monthly * 12, c)}</div></div>
    `).join('');
  }

  const grid = document.getElementById('sub-grid');
  if (filtered.length === 0) {
    grid.innerHTML = `<div class="doc-empty"><p>${all.length === 0 ? 'No subscriptions tracked yet.' : 'No subscriptions match these filters.'}</p></div>`;
    return;
  }

  const today = todayISO();
  grid.innerHTML = filtered.slice().reverse().map(s => {
    const monthly = monthlyEquivalent(s.cost, s.cycle);
    const yearly = monthly * 12;
    const upcoming = s.nextBilling && s.nextBilling >= today;
    const daysUntil = upcoming ? Math.ceil((new Date(s.nextBilling) - new Date(today)) / 86400000) : null;
    return `
      <div class="sub-card">
        <div class="sub-head">
          <div>
            <div class="sub-name">${escapeHtml(s.name)}</div>
            <div class="sub-meta">${escapeHtml(s.category)} · ${escapeHtml(s.cycle)} · ${escapeHtml(s.paidBy)}</div>
          </div>
          <span class="status-pill ${s.status}">${s.status}</span>
        </div>
        <div class="sub-amount">${fmtCurrency(s.cost, s.currency)}<span style="font-size:13px;color:var(--ink-soft);font-weight:500;">/${s.cycle === 'monthly' ? 'mo' : s.cycle === 'yearly' ? 'yr' : s.cycle}</span></div>
        <div class="inv-detail"><span class="lbl">Monthly equiv</span><span class="val">${fmtCurrency(monthly, s.currency)}</span></div>
        <div class="inv-detail"><span class="lbl">Yearly</span><span class="val">${fmtCurrency(yearly, s.currency)}</span></div>
        ${s.nextBilling ? `<div class="inv-detail"><span class="lbl">Next billing</span><span class="val ${daysUntil != null && daysUntil <= 7 ? 'neg' : ''}">${s.nextBilling}${daysUntil != null ? ' (' + daysUntil + ' d)' : ''}</span></div>` : ''}
        ${s.notes ? `<div style="font-size:12px;color:var(--ink-soft);font-style:italic;margin-top:4px;">${escapeHtml(s.notes)}</div>` : ''}
        <div class="acc-actions">
          <button class="btn-icon" data-del-sub="${s.id}" title="Delete">✕</button>
        </div>
      </div>`;
  }).join('');

  grid.querySelectorAll('[data-del-sub]').forEach(b =>
    b.addEventListener('click', () => {
      if (!confirm('Delete this subscription?')) return;
      saveSubs(getSubs().filter(x => x.id !== b.dataset.delSub));
      renderSubs();
    })
  );
}

['sub-status-filter', 'sub-cat-filter', 'sub-curr-filter'].forEach(id =>
  document.getElementById(id).addEventListener('change', renderSubs)
);

document.getElementById('export-sub').addEventListener('click', () => {
  const arr = getSubs();
  if (arr.length === 0) { alert('No subscriptions to export.'); return; }
  const rows = [['Service', 'Category', 'Cost', 'Currency', 'Cycle', 'Next billing', 'Status', 'Paid by', 'Notes']];
  arr.forEach(s => rows.push([
    s.name, s.category, s.cost.toFixed(2), s.currency, s.cycle,
    s.nextBilling || '', s.status, s.paidBy, s.notes || ''
  ]));
  downloadCsv(rows, `subscriptions-${todayISO()}.csv`);
});

// Sync subscription next-billing dates to reminders
document.getElementById('sync-sub-reminders').addEventListener('click', () => {
  const subs = getSubs().filter(s => s.status === 'active' && s.nextBilling);
  if (subs.length === 0) { alert('No active subscriptions with next billing dates.'); return; }
  const rems = getReminders();
  let added = 0;
  subs.forEach(s => {
    const exists = rems.find(r => r.title === `${s.name} · ${fmtCurrency(s.cost, s.currency)}` && r.date === s.nextBilling);
    if (!exists) {
      rems.push({
        id: uid('rem'),
        date: s.nextBilling,
        time: '',
        title: `${s.name} · ${fmtCurrency(s.cost, s.currency)}`,
        category: 'bill',
        recurring: s.cycle === 'monthly' ? 'monthly' : (s.cycle === 'yearly' ? 'yearly' : 'none'),
      });
      added++;
    }
  });
  saveReminders(rems);
  renderCalendar();
  renderReminderList();
  alert(`✓ Synced ${added} reminder${added !== 1 ? 's' : ''} from active subscriptions.`);
});

// ============================================================
// INITIAL RENDER
// ============================================================

renderSecurityPanel();
renderInvs();
renderSubs();
scheduleNotifications();

// Show insecure context warning on first load
if (!window.isSecureContext) {
  console.warn('⚠ Running in insecure context. Switch to file:// or https:// for production use.');
}



// ============================================================
// 17. APP LOCK SCREEN & UNLOCK CONTROLLER (v4)
// ============================================================

const lockOverlay = document.getElementById('app-lock-overlay');
const lockContent = document.getElementById('lock-content');

function pwStrength(pwd) {
  let s = 0;
  if (pwd.length >= 8) s++;
  if (pwd.length >= 12) s++;
  if (pwd.length >= 16) s++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) s++;
  if (/\d/.test(pwd)) s++;
  if (/[^A-Za-z0-9]/.test(pwd)) s++;
  return Math.min(s, 5);
}
function pwStrengthCls(s) {
  if (s <= 1) return '';
  if (s === 2) return 'medium';
  if (s === 3) return 'good';
  return 'strong';
}

function showLockSetup() {
  // Detect existing plaintext data for migration warning
  const existingPlaintextKeys = ENCRYPTED_KEYS.filter(k => {
    const raw = localStorage.getItem(k);
    if (!raw) return false;
    try {
      const parsed = JSON.parse(raw);
      // If it looks like an encrypted blob (has iv + ct), it's already encrypted
      if (parsed && parsed.iv && parsed.ct) return false;
      return true;
    } catch { return false; }
  });
  const hasExisting = existingPlaintextKeys.length > 0;

  lockContent.innerHTML = `
    <h2>Welcome — set up your master password</h2>
    <p>This password encrypts <strong>everything</strong> in this app: income, expenses, investments, subscriptions, accounts, Akshara's info, document metadata, and all credentials.</p>

    ${hasExisting ? `<div class="lock-info">
      📦 Existing data found in this browser (${existingPlaintextKeys.length} sections). It will be encrypted automatically when you set your password.
    </div>` : ''}

    <div class="lock-warning">
      <strong>⚠ Critical — read this</strong>
      If you forget this password, ALL your data is permanently unrecoverable. There is no reset, no email recovery, no backdoor. Write it on paper. Store in a fire safe or bank deposit box.
    </div>

    <div class="lock-field">
      <label>Master password (12+ chars recommended)</label>
      <input type="password" id="lock-pwd1" autocomplete="new-password">
      <div class="lock-pw-strength"><div class="lock-pw-strength-bar" id="lock-pw-bar"></div></div>
      <div id="lock-pw-hint" class="lock-hint-display"></div>
    </div>
    <div class="lock-field">
      <label>Confirm master password</label>
      <input type="password" id="lock-pwd2" autocomplete="new-password">
    </div>
    <div class="lock-field">
      <label>Hint (optional — shown on unlock screen)</label>
      <input type="text" id="lock-hint" placeholder="e.g. 'usual one + birthday'">
    </div>
    <div class="lock-error" id="lock-error"></div>
    <div class="lock-actions">
      <button class="btn moss" id="lock-create" style="flex:2;">Create vault &amp; unlock</button>
    </div>
  `;

  const pwd1 = document.getElementById('lock-pwd1');
  const pwd2 = document.getElementById('lock-pwd2');
  const bar = document.getElementById('lock-pw-bar');
  const hint = document.getElementById('lock-pw-hint');

  pwd1.addEventListener('input', () => {
    const s = pwStrength(pwd1.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'lock-pw-strength-bar ' + pwStrengthCls(s);
    const labels = ['', 'Very weak', 'Weak', 'Medium', 'Good', 'Strong'];
    hint.textContent = pwd1.value ? `Strength: ${labels[s]} (${pwd1.value.length} chars)` : '';
  });

  document.getElementById('lock-create').addEventListener('click', async () => {
    const p1 = pwd1.value;
    const p2 = pwd2.value;
    const hintVal = document.getElementById('lock-hint').value;
    const err = document.getElementById('lock-error');
    err.textContent = '';
    if (p1.length < 8) { err.textContent = 'Password must be at least 8 characters.'; return; }
    if (p1 !== p2) { err.textContent = 'Passwords do not match.'; return; }
    try {
      lockContent.innerHTML = '<div class="lock-progress">⏳ Deriving key + encrypting data...</div>';
      await setupNewVault(p1, hintVal);
      // setupNewVault sets vaultKey + saves vault metadata
      await migrateAndUnlock(true);
    } catch (e) {
      lockContent.innerHTML = '';
      showLockSetup();
      document.getElementById('lock-error').textContent = 'Setup failed: ' + e.message;
    }
  });

  setTimeout(() => pwd1.focus(), 200);
}

function showLockUnlock() {
  const v = _origLoad(KEYS.vault, null);
  const hintHtml = v && v.hint
    ? `<div class="lock-hint-display">💡 Hint: <em>${escapeHtml(v.hint)}</em></div>`
    : '';
  const lockout = getLockoutState();
  const remainingMs = Math.max(0, lockout.lockedUntil - Date.now());
  const lockedOut = remainingMs > 0;

  lockContent.innerHTML = `
    <h2>Unlock vault</h2>
    <p>Enter your master password to decrypt your data.</p>
    ${lockedOut ? `<div class="lock-warning"><strong>🚫 Locked out</strong>Too many failed attempts. Try again in ${Math.ceil(remainingMs / 1000)} seconds.</div>` : ''}
    <div class="lock-field">
      <label>Master password</label>
      <input type="password" id="lock-pwd" autocomplete="current-password" ${lockedOut ? 'disabled' : ''}>
      ${hintHtml}
    </div>
    <div class="lock-error" id="lock-error"></div>
    <div class="lock-actions">
      <button class="btn moss" id="lock-unlock" ${lockedOut ? 'disabled' : ''}>Unlock</button>
    </div>
    <div style="margin-top:14px;font-size:11px;color:var(--ink-soft);text-align:center;">
      <a href="#" id="lock-reset" style="color:var(--terracotta);">⚠ Reset vault (deletes all data)</a>
    </div>
  `;

  const pwd = document.getElementById('lock-pwd');
  if (!lockedOut) setTimeout(() => pwd.focus(), 200);

  async function attemptUnlock() {
    const err = document.getElementById('lock-error');
    err.textContent = '';
    try {
      lockContent.innerHTML = '<div class="lock-progress">⏳ Verifying + decrypting...</div>';
      await tryUnlockVault(pwd.value);
      await migrateAndUnlock(false);
    } catch (e) {
      showLockUnlock(); // re-render with fresh state
      document.getElementById('lock-error').textContent = '✗ ' + e.message;
    }
  }

  document.getElementById('lock-unlock').addEventListener('click', attemptUnlock);
  if (!lockedOut) pwd.addEventListener('keydown', e => { if (e.key === 'Enter') attemptUnlock(); });

  document.getElementById('lock-reset').addEventListener('click', (e) => {
    e.preventDefault();
    if (!confirm('⚠ This will PERMANENTLY DELETE all data in this app:\n\n• Vault credentials\n• Income & expense records\n• Investments & subscriptions\n• Akshara\'s profile\n• Document metadata (file blobs in IndexedDB stay)\n• All reminders\n\nThis cannot be undone. Are you absolutely sure?')) return;
    if (!confirm('Last chance. Type-confirm with a second click. Really wipe everything?')) return;
    // Wipe localStorage entries for this app
    ENCRYPTED_KEYS.forEach(k => localStorage.removeItem(k));
    localStorage.removeItem(KEYS.vault);
    localStorage.removeItem('hf-lockout-v1');
    localStorage.removeItem('hf-security-v1');
    showLockSetup();
  });
}

async function migrateAndUnlock(isNewSetup) {
  // For each ENCRYPTED_KEY, check if it's already encrypted or plaintext
  // If plaintext: encrypt it now
  // If encrypted: decrypt into appCache
  const vaultMeta = _origLoad(KEYS.vault, {});
  const isMigrating = !vaultMeta.appEncrypted;

  for (const key of ENCRYPTED_KEYS) {
    const raw = localStorage.getItem(key);
    if (!raw) {
      appCache[key] = undefined;
      continue;
    }
    let parsed;
    try { parsed = JSON.parse(raw); } catch { continue; }

    if (parsed && parsed.iv && parsed.ct) {
      // Already encrypted - decrypt it
      try {
        const plain = await decryptText(parsed, vaultKey);
        appCache[key] = JSON.parse(plain);
      } catch (e) {
        console.error(`Failed to decrypt ${key}:`, e);
        appCache[key] = undefined;
      }
    } else {
      // Plaintext data — load into cache + encrypt back to localStorage
      appCache[key] = parsed;
      try {
        const enc = await encryptText(JSON.stringify(parsed), vaultKey);
        _origSave(key, enc);
      } catch (e) {
        console.error(`Failed to encrypt ${key} during migration:`, e);
      }
    }
  }

  // Mark vault as fully app-encrypted
  if (isMigrating) {
    const v = _origLoad(KEYS.vault, {});
    v.appEncrypted = true;
    v.migratedAt = new Date().toISOString();
    _origSave(KEYS.vault, v);
  }

  appUnlocked = true;
  document.body.classList.add('app-ready');
  lockOverlay.style.display = 'none';

  // Re-render everything with newly available data
  if (typeof renderEverything === 'function') renderEverything();
  if (typeof renderSecurityPanel === 'function') renderSecurityPanel();
  if (typeof renderInvs === 'function') renderInvs();
  if (typeof renderSubs === 'function') renderSubs();
  if (typeof renderAkshara === 'function') renderAkshara();
  if (typeof renderDocs === 'function') renderDocs();
  if (typeof scheduleNotifications === 'function') scheduleNotifications();
}

// Show lock screen on init (replaces the earlier renderEverything call)
function showInitialLockScreen() {
  const v = _origLoad(KEYS.vault, null);
  if (!v || !v.initialized) {
    showLockSetup();
  } else {
    showLockUnlock();
  }
}

// Lock app: clear in-memory data + show lock screen
function lockApp() {
  // Cancel any pending encrypted writes
  _pendingWrites.forEach(t => clearTimeout(t));
  _pendingWrites.clear();
  // Clear in-memory data
  for (const k of ENCRYPTED_KEYS) delete appCache[k];
  appUnlocked = false;
  vaultKey = null;
  vaultUnlockedAt = null;
  document.body.classList.remove('app-ready');
  lockOverlay.style.display = 'flex';
  showLockUnlock();
}

// Override the original lockVault() to also lock the app
const _origLockVault = lockVault;
lockVault = function () {
  lockApp();
};

// Hook the existing vault-toggle button: when locked, route to full lock screen
document.getElementById('vault-toggle').addEventListener('click', (e) => {
  if (vaultKey) {
    e.stopImmediatePropagation();
    lockApp();
  }
}, true);

// Privacy button: lock app entirely (overrides v3 partial blur)
const _origPrivacyHandler = document.getElementById('privacy-btn');
_origPrivacyHandler.replaceWith(_origPrivacyHandler.cloneNode(true));
document.getElementById('privacy-btn').addEventListener('click', () => {
  document.body.classList.toggle('privacy-mode');
});

// Initialize on load
showInitialLockScreen();



// ============================================================
// 18. TIER 2 ENCRYPTION (v5 — second password for specific tabs)
// ============================================================

const VAULT2_KEY = 'hf-vault2-v1';
const VERIFIER2_PLAINTEXT = 'TIER2-OK-2026';

let vault2Key = null;
let tier2Unlocked = false;
let tier2UnlockedAt = null;
const TIER2_AUTO_LOCK_MS = 5 * 60 * 1000; // 5 min default for tier 2

// Protectable areas — group of data keys + which tabs they affect
const PROTECTABLE_AREAS = {
  accounts: {
    label: 'Account credentials',
    desc: 'USA, Canada &amp; India bank accounts',
    keys: ['hf-accounts-v1'],
    tabs: ['usa', 'canada', 'india'],
  },
  income: {
    label: 'Income records',
    desc: 'Monthly salary &amp; income transactions',
    keys: ['hf-income-v1'],
    tabs: ['income'],
  },
  expenses: {
    label: 'Expense records',
    desc: 'All expense transactions',
    keys: ['hf-expenses-v1'],
    tabs: ['expenses'],
  },
  investments: {
    label: 'Investments',
    desc: 'MF, ETF, FD, RD, stocks, crypto',
    keys: ['hf-investments-v1'],
    tabs: ['investments'],
  },
  subscriptions: {
    label: 'Subscriptions',
    desc: 'Recurring services &amp; bills',
    keys: ['hf-subscriptions-v1'],
    tabs: ['subscriptions'],
  },
  akshara: {
    label: 'Akshara profile',
    desc: 'Personal info, school, health, contacts',
    keys: ['hf-akshara-v1'],
    tabs: ['akshara'],
  },
  documents: {
    label: 'Documents',
    desc: 'Document metadata (file blobs unchanged)',
    keys: ['hf-documents-meta-v1'],
    tabs: ['documents'],
  },
};

function getProtectedKeys() {
  const v = _origLoad(KEYS.vault, {});
  return v.protectedKeys || [];
}
function setProtectedKeys(arr) {
  const v = _origLoad(KEYS.vault, {});
  v.protectedKeys = [...new Set(arr)];
  _origSave(KEYS.vault, v);
}
function isKeyProtected(key) { return getProtectedKeys().includes(key); }
function isTabProtected(tabId) {
  const protected_ = getProtectedKeys();
  for (const area of Object.values(PROTECTABLE_AREAS)) {
    if (area.tabs.includes(tabId)) {
      if (area.keys.some(k => protected_.includes(k))) return true;
    }
  }
  return false;
}
function tier2Initialized() {
  const v2 = _origLoad(VAULT2_KEY, null);
  return !!(v2 && v2.initialized);
}

// --- Patch load() to gate protected keys behind tier 2 ---
const _v5LoadOrig = load;
load = function (key, defaultVal) {
  if (ENCRYPTED_KEYS.includes(key) && isKeyProtected(key)) {
    if (!appUnlocked || !tier2Unlocked) return defaultVal;
    return appCache[key] !== undefined ? appCache[key] : defaultVal;
  }
  return _v5LoadOrig(key, defaultVal);
};

// --- Patch save() to use vault2Key for protected keys ---
const _v5SaveOrig = save;
save = function (key, value) {
  if (ENCRYPTED_KEYS.includes(key) && isKeyProtected(key)) {
    if (!appUnlocked || !tier2Unlocked) {
      console.warn(`Save to protected key ${key} blocked — tier 2 locked`);
      return;
    }
    appCache[key] = value;
    if (_pendingWrites.has(key)) clearTimeout(_pendingWrites.get(key));
    _pendingWrites.set(key, setTimeout(async () => {
      _pendingWrites.delete(key);
      try {
        const enc = await encryptText(JSON.stringify(value), vault2Key);
        _origSave(key, enc);
      } catch (e) {
        console.error(`Failed tier-2 encrypt ${key}:`, e);
      }
    }, 50));
  } else {
    _v5SaveOrig(key, value);
  }
};

// --- Tier 2 setup ---
async function setupTier2(password, hint) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: NEW_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
  const verifier = await encryptText(VERIFIER2_PLAINTEXT, key);
  _origSave(VAULT2_KEY, {
    initialized: true,
    salt: bytesToBase64(salt),
    verifier, hint: hint || '',
    setupAt: new Date().toISOString(),
    iterations: NEW_PBKDF2_ITERATIONS,
  });
  vault2Key = key;
  tier2Unlocked = true;
  tier2UnlockedAt = Date.now();
}

async function tryUnlockTier2(password) {
  const v2 = _origLoad(VAULT2_KEY, null);
  if (!v2 || !v2.initialized) throw new Error('Tier 2 not set up');
  const salt = base64ToBytes(v2.salt);
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  const iters = v2.iterations || NEW_PBKDF2_ITERATIONS;
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
  try {
    const dec = await decryptText(v2.verifier, key);
    if (dec !== VERIFIER2_PLAINTEXT) throw new Error('bad verifier');
  } catch {
    throw new Error('Wrong tier 2 password');
  }
  vault2Key = key;
  tier2Unlocked = true;
  tier2UnlockedAt = Date.now();
  // Decrypt protected keys into appCache
  for (const k of getProtectedKeys()) {
    const raw = localStorage.getItem(k);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.iv && parsed.ct) {
        const plain = await decryptText(parsed, vault2Key);
        appCache[k] = JSON.parse(plain);
      }
    } catch (e) {
      console.error(`Tier-2 decrypt failed for ${k}:`, e);
    }
  }
}

function lockTier2() {
  vault2Key = null;
  tier2Unlocked = false;
  tier2UnlockedAt = null;
  // Remove protected keys from cache (they need tier 2 to access)
  for (const k of getProtectedKeys()) delete appCache[k];
  refreshTier2UI();
  rerenderAfterTier2Change();
}

function refreshTier2UI() {
  const statusEl = document.getElementById('tier2-status');
  const toggleEl = document.getElementById('tier2-toggle');
  const dotEl = document.getElementById('tier2-dot');
  const textEl = document.getElementById('tier2-status-text');
  if (!statusEl) return;

  if (!tier2Initialized()) {
    statusEl.style.display = 'none';
    toggleEl.style.display = 'none';
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('protected-locked', 'protected-unlocked'));
    return;
  }

  statusEl.style.display = '';
  toggleEl.style.display = '';
  if (tier2Unlocked) {
    dotEl.classList.add('unlocked');
    dotEl.classList.remove('locked');
    textEl.textContent = 'Tier 2 unlocked';
    toggleEl.textContent = '🔓 Lock Tier 2';
  } else {
    dotEl.classList.remove('unlocked');
    dotEl.classList.add('locked');
    textEl.textContent = 'Tier 2 locked';
    toggleEl.textContent = '🔒 Unlock Tier 2';
  }

  // Mark protected tabs
  document.querySelectorAll('.tab').forEach(t => {
    const tabId = t.dataset.tab;
    if (isTabProtected(tabId)) {
      t.classList.toggle('protected-locked', !tier2Unlocked);
      t.classList.toggle('protected-unlocked', tier2Unlocked);
    } else {
      t.classList.remove('protected-locked', 'protected-unlocked');
    }
  });
}

function rerenderAfterTier2Change() {
  if (typeof renderDashboard === 'function') renderDashboard();
  if (typeof renderIncome === 'function') renderIncome();
  if (typeof renderExpenses === 'function') renderExpenses();
  if (typeof rerenderAccountTabs === 'function') rerenderAccountTabs();
  if (typeof renderInvs === 'function') renderInvs();
  if (typeof renderSubs === 'function') renderSubs();
  if (typeof renderAkshara === 'function') renderAkshara();
  if (typeof renderDocs === 'function') renderDocs();
  renderTier2Summary();
}

// --- Tab switching intercept ---
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', (e) => {
    const tabId = btn.dataset.tab;
    if (isTabProtected(tabId) && !tier2Unlocked) {
      e.stopImmediatePropagation();
      e.preventDefault();
      showTier2UnlockModal(tabId);
    }
  }, true);
});

// --- Auto-lock tier 2 on idle (separate, shorter than master) ---
setInterval(() => {
  if (tier2Unlocked && tier2UnlockedAt) {
    if (Date.now() - lastActivity > TIER2_AUTO_LOCK_MS) {
      lockTier2();
      console.log('Tier 2 auto-locked (idle)');
    }
  }
}, 20000);

// --- Tier 2 toggle button in header ---
document.getElementById('tier2-toggle').addEventListener('click', () => {
  if (tier2Unlocked) lockTier2();
  else showTier2UnlockModal();
});

// --- Migrate keys between tier 1 and tier 2 protection ---
async function applyTier2Changes(keysToProtect, keysToUnprotect) {
  if (!appUnlocked) throw new Error('App must be unlocked');
  if (!tier2Unlocked) throw new Error('Tier 2 must be unlocked');

  for (const k of keysToProtect) {
    if (appCache[k] === undefined) continue;
    const enc = await encryptText(JSON.stringify(appCache[k]), vault2Key);
    _origSave(k, enc);
  }
  for (const k of keysToUnprotect) {
    if (appCache[k] === undefined) continue;
    const enc = await encryptText(JSON.stringify(appCache[k]), vaultKey);
    _origSave(k, enc);
  }

  const current = getProtectedKeys();
  const updated = current
    .filter(k => !keysToUnprotect.includes(k))
    .concat(keysToProtect.filter(k => !current.includes(k)));
  setProtectedKeys(updated);
  refreshTier2UI();
}

// ============================================================
// TIER 2 MODALS
// ============================================================

const tier2Modal = document.getElementById('tier2-modal');
const tier2Content = document.getElementById('tier2-modal-content');

function showTier2UnlockModal(targetTab) {
  if (!tier2Initialized()) {
    showTier2ManageModal();
    return;
  }
  const v2 = _origLoad(VAULT2_KEY, null);
  const hintHtml = v2 && v2.hint
    ? `<div style="font-size:12px;color:var(--amber);font-style:italic;margin-top:6px;">💡 Hint: <em>${escapeHtml(v2.hint)}</em></div>`
    : '';

  tier2Content.innerHTML = `
    <h3>🔒🔒 Unlock Tier 2</h3>
    <p>This is your <strong>second password</strong> — different from your master password. It protects sensitive tabs.</p>
    ${targetTab ? `<p style="color:var(--amber);">Target tab: <strong>${escapeHtml(targetTab.toUpperCase())}</strong></p>` : ''}
    <div class="field">
      <label class="field-label">Tier 2 password</label>
      <input type="password" id="t2u-pwd" autocomplete="off">
      ${hintHtml}
      <div id="t2u-err" style="color:var(--terracotta);font-size:12px;margin-top:6px;display:none;"></div>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="t2u-cancel">Cancel</button>
      <button class="btn moss" id="t2u-go">Unlock</button>
    </div>
  `;
  tier2Modal.style.display = 'flex';
  const pwd = document.getElementById('t2u-pwd');
  setTimeout(() => pwd.focus(), 100);

  async function attempt() {
    try {
      await tryUnlockTier2(pwd.value);
      tier2Modal.style.display = 'none';
      refreshTier2UI();
      rerenderAfterTier2Change();
      if (targetTab) {
        const tabBtn = document.querySelector(`.tab[data-tab="${targetTab}"]`);
        if (tabBtn) tabBtn.click();
      }
    } catch (e) {
      const err = document.getElementById('t2u-err');
      err.textContent = '✗ ' + e.message;
      err.style.display = '';
      pwd.value = '';
      pwd.focus();
    }
  }
  document.getElementById('t2u-cancel').onclick = () => { tier2Modal.style.display = 'none'; };
  document.getElementById('t2u-go').onclick = attempt;
  pwd.addEventListener('keydown', e => { if (e.key === 'Enter') attempt(); });
}

function showTier2ManageModal() {
  if (!tier2Initialized()) {
    showTier2SetupModal();
    return;
  }
  if (!tier2Unlocked) {
    showTier2UnlockModal();
    return;
  }

  const protected_ = getProtectedKeys();
  tier2Content.innerHTML = `
    <h3>🔒🔒 Manage Tier 2 protection</h3>
    <p>Toggle which areas require the tier 2 password to access. Changes re-encrypt the data.</p>
    <div class="protection-list">
      ${Object.entries(PROTECTABLE_AREAS).map(([id, area]) => {
        const isProt = area.keys.some(k => protected_.includes(k));
        return `
          <label class="protection-row">
            <input type="checkbox" data-pa="${id}" ${isProt ? 'checked' : ''}>
            <div class="pr-label">
              <span class="pr-name">${area.label}</span>
              <span class="pr-tabs">${area.desc} · tabs: ${area.tabs.join(', ')}</span>
            </div>
            <span class="pr-status ${isProt ? 'protected' : 'open'}">${isProt ? '🔒 Protected' : 'Open'}</span>
          </label>
        `;
      }).join('')}
    </div>

    <div class="t2-sub-action">
      <h5>Advanced</h5>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn ghost btn-sm" id="t2-change-pwd">Change tier 2 password…</button>
        <button class="btn ghost btn-sm" id="t2-disable" style="color:var(--terracotta);">Disable tier 2 entirely</button>
      </div>
    </div>

    <div class="modal-actions">
      <button class="btn ghost" id="t2m-cancel">Cancel</button>
      <button class="btn moss" id="t2m-save">Apply changes</button>
    </div>
  `;
  tier2Modal.style.display = 'flex';

  document.getElementById('t2m-cancel').onclick = () => { tier2Modal.style.display = 'none'; };
  document.getElementById('t2m-save').onclick = async () => {
    const checks = document.querySelectorAll('.protection-list input[type="checkbox"]');
    const newProtected = new Set();
    checks.forEach(cb => {
      if (cb.checked) {
        PROTECTABLE_AREAS[cb.dataset.pa].keys.forEach(k => newProtected.add(k));
      }
    });
    const current = new Set(getProtectedKeys());
    const toProtect = [...newProtected].filter(k => !current.has(k));
    const toUnprotect = [...current].filter(k => !newProtected.has(k));
    try {
      tier2Content.innerHTML = '<div class="lock-progress">⏳ Re-encrypting data…</div>';
      await applyTier2Changes(toProtect, toUnprotect);
      tier2Modal.style.display = 'none';
      rerenderAfterTier2Change();
    } catch (e) {
      alert('Failed: ' + e.message);
    }
  };

  document.getElementById('t2-change-pwd').onclick = () => showTier2ChangePasswordModal();
  document.getElementById('t2-disable').onclick = () => showTier2DisableModal();
}

function showTier2SetupModal() {
  tier2Content.innerHTML = `
    <h3>🔒🔒 Set up Tier 2 protection</h3>
    <p>Create a <strong>second password</strong> — different from your master — to protect specific tabs.</p>

    <div class="lock-warning">
      <strong>⚠ Important</strong>
      The tier 2 password must be different from your master password to actually add security. If you forget it, the protected data is permanently unrecoverable (you can still access non-protected tabs with your master password).
    </div>

    <div class="modal-grid">
      <div class="field span-full">
        <label class="field-label">Tier 2 password</label>
        <input type="password" id="t2s-pwd1">
        <div class="lock-pw-strength"><div class="lock-pw-strength-bar" id="t2s-bar"></div></div>
      </div>
      <div class="field span-full">
        <label class="field-label">Confirm tier 2 password</label>
        <input type="password" id="t2s-pwd2">
      </div>
      <div class="field span-full">
        <label class="field-label">Hint (shown on unlock)</label>
        <input type="text" id="t2s-hint">
      </div>
    </div>

    <h4 style="font-family:'Fraunces',serif;color:var(--amber);font-size:14px;margin-top:18px;">Areas to protect</h4>
    <div class="protection-list">
      ${Object.entries(PROTECTABLE_AREAS).map(([id, area]) => `
        <label class="protection-row">
          <input type="checkbox" data-pa="${id}" ${id === 'accounts' ? 'checked' : ''}>
          <div class="pr-label">
            <span class="pr-name">${area.label}</span>
            <span class="pr-tabs">${area.desc}</span>
          </div>
        </label>
      `).join('')}
    </div>

    <div id="t2s-err" style="color:var(--terracotta);font-size:12px;margin-top:6px;display:none;"></div>
    <div class="modal-actions">
      <button class="btn ghost" id="t2s-cancel">Cancel</button>
      <button class="btn moss" id="t2s-go">Set up &amp; encrypt</button>
    </div>
  `;
  tier2Modal.style.display = 'flex';

  const p1 = document.getElementById('t2s-pwd1');
  const bar = document.getElementById('t2s-bar');
  p1.addEventListener('input', () => {
    const s = pwStrength(p1.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'lock-pw-strength-bar ' + pwStrengthCls(s);
  });

  document.getElementById('t2s-cancel').onclick = () => { tier2Modal.style.display = 'none'; };
  document.getElementById('t2s-go').onclick = async () => {
    const p1v = p1.value;
    const p2v = document.getElementById('t2s-pwd2').value;
    const hint = document.getElementById('t2s-hint').value;
    const err = document.getElementById('t2s-err');
    err.style.display = 'none';
    if (p1v.length < 8) { err.textContent = 'Password must be at least 8 characters.'; err.style.display = ''; return; }
    if (p1v !== p2v) { err.textContent = 'Passwords do not match.'; err.style.display = ''; return; }

    // Detect same as master (warning, not block)
    let isSame = false;
    try {
      const v = _origLoad(KEYS.vault, null);
      if (v && v.salt) {
        const testKey = await deriveKey(p1v, base64ToBytes(v.salt));
        try {
          const dec = await decryptText(v.verifier, testKey);
          if (dec === VERIFIER_PLAINTEXT) isSame = true;
        } catch {}
      }
    } catch {}
    if (isSame) {
      if (!confirm('⚠ This password is the same as your master password. Using the same password defeats the purpose of tier 2 protection. Continue anyway?')) return;
    }

    // Collect selected areas
    const checks = document.querySelectorAll('.protection-list input[type="checkbox"]');
    const selectedAreas = [];
    checks.forEach(cb => { if (cb.checked) selectedAreas.push(cb.dataset.pa); });

    try {
      tier2Content.innerHTML = '<div class="lock-progress">⏳ Setting up tier 2 + encrypting selected data…</div>';
      await setupTier2(p1v, hint);

      const keysToProtect = [];
      selectedAreas.forEach(a => keysToProtect.push(...PROTECTABLE_AREAS[a].keys));
      if (keysToProtect.length > 0) {
        await applyTier2Changes(keysToProtect, []);
      }
      tier2Modal.style.display = 'none';
      refreshTier2UI();
      rerenderAfterTier2Change();
    } catch (e) {
      alert('Setup failed: ' + e.message);
      showTier2SetupModal();
    }
  };
  setTimeout(() => p1.focus(), 100);
}

function showTier2ChangePasswordModal() {
  tier2Content.innerHTML = `
    <h3>🔁 Change Tier 2 password</h3>
    <p>Re-encrypts all tier-2-protected data with a new password.</p>
    <div class="field">
      <label class="field-label">Current tier 2 password</label>
      <input type="password" id="t2c-old">
    </div>
    <div class="field">
      <label class="field-label">New tier 2 password</label>
      <input type="password" id="t2c-new1">
      <div class="lock-pw-strength"><div class="lock-pw-strength-bar" id="t2c-bar"></div></div>
    </div>
    <div class="field">
      <label class="field-label">Confirm new password</label>
      <input type="password" id="t2c-new2">
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="t2c-cancel">Cancel</button>
      <button class="btn moss" id="t2c-go">Change password</button>
    </div>
  `;
  const n1 = document.getElementById('t2c-new1');
  const bar = document.getElementById('t2c-bar');
  n1.addEventListener('input', () => {
    const s = pwStrength(n1.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'lock-pw-strength-bar ' + pwStrengthCls(s);
  });
  document.getElementById('t2c-cancel').onclick = () => showTier2ManageModal();
  document.getElementById('t2c-go').onclick = async () => {
    const oldP = document.getElementById('t2c-old').value;
    const new1 = n1.value;
    const new2 = document.getElementById('t2c-new2').value;
    if (new1.length < 8) { alert('Min 8 chars'); return; }
    if (new1 !== new2) { alert('Passwords do not match'); return; }
    try {
      await tryUnlockTier2(oldP);
    } catch (e) {
      alert('Current password incorrect.');
      return;
    }
    // Generate new salt/key
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const enc = new TextEncoder();
    const material = await crypto.subtle.importKey(
      'raw', enc.encode(new1), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    const newKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: newSalt, iterations: NEW_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    // Re-encrypt all protected data with new key
    for (const k of getProtectedKeys()) {
      if (appCache[k] !== undefined) {
        const encBlob = await encryptText(JSON.stringify(appCache[k]), newKey);
        _origSave(k, encBlob);
      }
    }
    const newVerifier = await encryptText(VERIFIER2_PLAINTEXT, newKey);
    _origSave(VAULT2_KEY, {
      initialized: true,
      salt: bytesToBase64(newSalt),
      verifier: newVerifier,
      hint: (_origLoad(VAULT2_KEY, {}).hint) || '',
      setupAt: (_origLoad(VAULT2_KEY, {}).setupAt) || new Date().toISOString(),
      changedAt: new Date().toISOString(),
      iterations: NEW_PBKDF2_ITERATIONS,
    });
    vault2Key = newKey;
    tier2Modal.style.display = 'none';
    alert('✓ Tier 2 password changed.');
  };
}

function showTier2DisableModal() {
  tier2Content.innerHTML = `
    <h3>🔓 Disable Tier 2</h3>
    <div class="lock-warning">
      <strong>⚠ This will:</strong>
      <ul style="margin: 6px 0 0 18px;">
        <li>Decrypt all tier-2-protected data</li>
        <li>Re-encrypt it under your master password only</li>
        <li>Delete the tier 2 vault metadata</li>
        <li>All protected tabs become accessible with just the master password</li>
      </ul>
    </div>
    <p>You will need to enter your tier 2 password one last time to authorize.</p>
    <div class="field">
      <label class="field-label">Tier 2 password</label>
      <input type="password" id="t2d-pwd">
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="t2d-cancel">Cancel</button>
      <button class="btn danger" id="t2d-go">Disable tier 2</button>
    </div>
  `;
  document.getElementById('t2d-cancel').onclick = () => showTier2ManageModal();
  document.getElementById('t2d-go').onclick = async () => {
    const pwd = document.getElementById('t2d-pwd').value;
    try {
      await tryUnlockTier2(pwd);
    } catch (e) {
      alert('Wrong password.');
      return;
    }
    const protectedKeys = getProtectedKeys();
    for (const k of protectedKeys) {
      if (appCache[k] !== undefined) {
        const enc = await encryptText(JSON.stringify(appCache[k]), vaultKey);
        _origSave(k, enc);
      }
    }
    setProtectedKeys([]);
    localStorage.removeItem(VAULT2_KEY);
    vault2Key = null;
    tier2Unlocked = false;
    tier2Modal.style.display = 'none';
    refreshTier2UI();
    rerenderAfterTier2Change();
    alert('✓ Tier 2 disabled. Data is now protected by master password only.');
  };
}

// Wire up Manage button in security panel
document.getElementById('tier2-manage-btn').addEventListener('click', () => {
  if (!tier2Initialized()) showTier2SetupModal();
  else if (!tier2Unlocked) showTier2UnlockModal();
  else showTier2ManageModal();
});

// Render tier 2 summary in security panel
function renderTier2Summary() {
  const el = document.getElementById('tier2-summary');
  if (!el) return;
  if (!tier2Initialized()) {
    el.innerHTML = '<span class="t2-chip warn">Tier 2 not set up</span>';
    return;
  }
  const protected_ = getProtectedKeys();
  const areas = Object.entries(PROTECTABLE_AREAS).filter(([_, area]) =>
    area.keys.some(k => protected_.includes(k))
  );
  el.innerHTML =
    `<span class="t2-chip ${tier2Unlocked ? 'ok' : 'active'}">${tier2Unlocked ? '🔓 Unlocked' : '🔒 Locked'}</span>` +
    `<span class="t2-chip">${areas.length} of ${Object.keys(PROTECTABLE_AREAS).length} areas protected</span>` +
    areas.map(([_, a]) => `<span class="t2-chip ok">${a.label}</span>`).join('');
}

// Close modal on backdrop click
tier2Modal.addEventListener('click', (e) => {
  if (e.target === tier2Modal) tier2Modal.style.display = 'none';
});

// ============================================================
// 19. PER-TAB JSON EXPORTS
// ============================================================

function exportJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

document.getElementById('export-income-json').addEventListener('click', () => {
  exportJson(`income-${todayISO()}.json`, getIncome());
});
document.getElementById('export-expenses-json').addEventListener('click', () => {
  exportJson(`expenses-${todayISO()}.json`, getExpenses());
});
document.getElementById('export-inv-json').addEventListener('click', () => {
  exportJson(`investments-${todayISO()}.json`, getInvs());
});
document.getElementById('export-sub-json').addEventListener('click', () => {
  exportJson(`subscriptions-${todayISO()}.json`, getSubs());
});

// Inject action-bars with Export JSON for tabs that don't have one
function injectExportButton(sectionId, label, filenameBase, dataFn) {
  const section = document.getElementById(sectionId);
  if (!section || section.querySelector(`#export-${sectionId}-json`)) return;
  const bar = document.createElement('div');
  bar.className = 'action-bar';
  bar.style.marginTop = '24px';
  bar.innerHTML = `
    <div class="left">${label}</div>
    <div><button class="btn ghost" id="export-${sectionId}-json">⤓ Export JSON</button></div>
  `;
  section.appendChild(bar);
  document.getElementById(`export-${sectionId}-json`).addEventListener('click', () => {
    exportJson(`${filenameBase}-${todayISO()}.json`, dataFn());
  });
}

injectExportButton('akshara', 'Akshara profile backup', 'akshara', () => getAk());
injectExportButton('documents', 'Document metadata backup (file blobs not included)', 'documents-metadata', () => getDocsMeta());

// Per-country account exports
['usa', 'canada', 'india'].forEach(c => {
  const cap = c.charAt(0).toUpperCase() + c.slice(1);
  const countryName = c === 'usa' ? 'USA' : cap;
  injectExportButton(c, `${countryName} accounts backup (passwords stay encrypted)`, `accounts-${c}`, () => {
    return load(KEYS.accounts, []).filter(a => a.country === countryName);
  });
});

// ============================================================
// HOOK INTO V4 UNLOCK: refresh tier 2 UI after master unlock
// ============================================================

const _v5OrigMigrate = migrateAndUnlock;
migrateAndUnlock = async function(isNewSetup) {
  await _v5OrigMigrate(isNewSetup);
  refreshTier2UI();
  renderTier2Summary();
};

// Update lockApp to also lock tier 2
const _v5LockApp = lockApp;
lockApp = function() {
  vault2Key = null;
  tier2Unlocked = false;
  tier2UnlockedAt = null;
  _v5LockApp();
};

// Initial UI refresh in case app was already unlocked when this code ran
if (appUnlocked) {
  refreshTier2UI();
  renderTier2Summary();
}



// ============================================================
// 20. POLICIES MODULE (v6)
// ============================================================

const POL_KEY = 'hf-policies-v1';

// Add to ENCRYPTED_KEYS so it gets app-level encryption
if (!ENCRYPTED_KEYS.includes(POL_KEY)) ENCRYPTED_KEYS.push(POL_KEY);

// Add to PROTECTABLE_AREAS for tier 2
PROTECTABLE_AREAS.policies = {
  label: 'Insurance policies',
  desc: 'Life, health, term, ULIP, vehicle, property',
  keys: [POL_KEY],
  tabs: ['policies'],
};

function getPols() { return load(POL_KEY, []); }
function savePols(arr) { save(POL_KEY, arr); }

const POL_FREQ_LABEL = {
  'yearly': '/yr', 'half-yearly': '/6mo', 'quarterly': '/qtr',
  'monthly': '/mo', 'single': ' (paid)',
};
function annualizedPremium(p) {
  switch (p.frequency) {
    case 'monthly':     return p.premium * 12;
    case 'quarterly':   return p.premium * 4;
    case 'half-yearly': return p.premium * 2;
    case 'yearly':      return p.premium;
    case 'single':      return 0;
    default:            return p.premium;
  }
}

document.getElementById('pol-start').valueAsDate = new Date();

document.getElementById('add-pol-btn').addEventListener('click', () => {
  const f = id => document.getElementById(id).value;
  const ff = id => document.getElementById(id).value.trim();
  const type = f('pol-type');
  const name = ff('pol-name');
  const insurer = ff('pol-insurer');
  const number = ff('pol-num');
  const insured = f('pol-insured');
  const country = f('pol-country');
  const coverage = parseFloat(f('pol-coverage'));
  const currency = f('pol-currency');
  const premiumRaw = f('pol-premium');
  const premium = premiumRaw ? parseFloat(premiumRaw) : 0;
  const frequency = f('pol-freq');
  const startDate = f('pol-start');
  const endDate = f('pol-end');
  const nextDue = f('pol-next');
  const status = f('pol-status');
  const beneficiary = ff('pol-beneficiary');
  const agent = ff('pol-agent');
  const notes = ff('pol-notes');

  if (!name || isNaN(coverage) || coverage <= 0) {
    alert('Policy name and sum assured are required.');
    return;
  }
  const arr = getPols();
  arr.push({
    id: uid('pol'), type, name, insurer, number, insured, country,
    coverage, currency, premium, frequency, startDate, endDate, nextDue,
    status, beneficiary, agent, notes, addedAt: todayISO(),
  });
  savePols(arr);
  ['pol-name', 'pol-insurer', 'pol-num', 'pol-coverage', 'pol-premium',
   'pol-end', 'pol-next', 'pol-beneficiary', 'pol-agent', 'pol-notes'].forEach(id =>
    document.getElementById(id).value = ''
  );
  renderPols();
});

function renderPols() {
  const all = getPols();

  const statusSel = document.getElementById('pol-status-filter').value;
  const insuredSel = document.getElementById('pol-insured-filter').value;
  const countrySel = document.getElementById('pol-country-filter').value;
  const currSel = document.getElementById('pol-curr-filter').value;

  const filtered = all.filter(p =>
    (statusSel === 'all' || p.status === statusSel) &&
    (insuredSel === 'all' || p.insured === insuredSel) &&
    (countrySel === 'all' || p.country === countrySel) &&
    (currSel === 'all' || p.currency === currSel)
  );

  // Summary stats grouped by currency
  const byCurrency = {};
  filtered.filter(p => p.status === 'active' || p.status === 'paid-up').forEach(p => {
    if (!byCurrency[p.currency]) byCurrency[p.currency] = { coverage: 0, annualPrem: 0, count: 0 };
    byCurrency[p.currency].coverage += p.coverage;
    byCurrency[p.currency].annualPrem += annualizedPremium(p);
    byCurrency[p.currency].count++;
  });

  const stats = document.getElementById('pol-stats');
  if (Object.keys(byCurrency).length === 0) {
    stats.innerHTML = `<div class="doc-stat"><div class="label">Active policies</div><div class="value">0</div></div>`;
  } else {
    stats.innerHTML = Object.entries(byCurrency).map(([c, v]) => `
      <div class="doc-stat" style="border-left-color: var(--gold);">
        <div class="label">${c} coverage (${v.count})</div>
        <div class="value">${fmtCurrency(v.coverage, c)}</div>
      </div>
      <div class="doc-stat"><div class="label">${c} annual premium</div><div class="value">${fmtCurrency(v.annualPrem, c)}</div></div>
    `).join('');
  }

  const grid = document.getElementById('pol-grid');
  if (filtered.length === 0) {
    grid.innerHTML = `<div class="doc-empty"><p>${all.length === 0 ? 'No policies tracked yet.' : 'No policies match these filters.'}</p></div>`;
    return;
  }

  const today = todayISO();
  grid.innerHTML = filtered.slice().reverse().map(p => {
    const annual = annualizedPremium(p);
    const upcoming = p.nextDue && p.nextDue >= today;
    const daysUntil = upcoming ? Math.ceil((new Date(p.nextDue) - new Date(today)) / 86400000) : null;
    return `
      <div class="pol-card">
        <div class="pol-card-head">
          <div>
            <div class="pol-name">${escapeHtml(p.name)}</div>
            <div class="pol-meta">${escapeHtml(p.type)} · ${escapeHtml(p.insurer || '—')} · ${escapeHtml(p.country)}</div>
          </div>
          <span class="status-pill ${p.status}">${p.status}</span>
        </div>
        <div class="pol-coverage">${fmtCurrency(p.coverage, p.currency)}<span style="font-size:11px;color:var(--ink-soft);font-weight:500;font-family:'JetBrains Mono',monospace;"> sum assured</span></div>
        <div class="inv-detail"><span class="lbl">Insured</span><span class="val">${escapeHtml(p.insured)}</span></div>
        ${p.beneficiary ? `<div class="inv-detail"><span class="lbl">Beneficiary</span><span class="val">${escapeHtml(p.beneficiary)}</span></div>` : ''}
        ${p.premium ? `<div class="inv-detail"><span class="lbl">Premium</span><span class="val">${fmtCurrency(p.premium, p.currency)}${POL_FREQ_LABEL[p.frequency] || ''}</span></div>` : ''}
        ${annual ? `<div class="inv-detail"><span class="lbl">Annual</span><span class="val">${fmtCurrency(annual, p.currency)}</span></div>` : ''}
        ${p.number ? `<div class="inv-detail"><span class="lbl">Policy #</span><span class="val" style="font-family:'JetBrains Mono',monospace;font-size:11.5px;">${escapeHtml(p.number)}</span></div>` : ''}
        ${p.startDate ? `<div class="inv-detail"><span class="lbl">Start</span><span class="val">${p.startDate}</span></div>` : ''}
        ${p.endDate ? `<div class="inv-detail"><span class="lbl">Maturity</span><span class="val">${p.endDate}</span></div>` : ''}
        ${p.nextDue ? `<div class="inv-detail"><span class="lbl">Next due</span><span class="val ${daysUntil != null && daysUntil <= 14 ? 'neg' : ''}">${p.nextDue}${daysUntil != null ? ' (' + daysUntil + ' d)' : ''}</span></div>` : ''}
        ${p.agent ? `<div style="font-size:12px;color:var(--ink-soft);margin-top:4px;">👤 ${escapeHtml(p.agent)}</div>` : ''}
        ${p.notes ? `<div style="font-size:12px;color:var(--ink-soft);font-style:italic;margin-top:4px;">${escapeHtml(p.notes)}</div>` : ''}
        <div class="acc-actions">
          <button class="btn-icon" data-del-pol="${p.id}" title="Delete">✕</button>
        </div>
      </div>`;
  }).join('');

  grid.querySelectorAll('[data-del-pol]').forEach(b =>
    b.addEventListener('click', () => {
      if (!confirm('Delete this policy record?')) return;
      savePols(getPols().filter(x => x.id !== b.dataset.delPol));
      renderPols();
    })
  );
}

['pol-status-filter', 'pol-insured-filter', 'pol-country-filter', 'pol-curr-filter'].forEach(id =>
  document.getElementById(id).addEventListener('change', renderPols)
);

document.getElementById('export-pol').addEventListener('click', () => {
  const arr = getPols();
  if (arr.length === 0) { alert('No policies to export.'); return; }
  const rows = [['Type', 'Name', 'Insurer', 'Number', 'Insured', 'Country', 'Coverage', 'Currency', 'Premium', 'Frequency', 'Start', 'End', 'Next Due', 'Status', 'Beneficiary', 'Agent', 'Notes']];
  arr.forEach(p => rows.push([
    p.type, p.name, p.insurer || '', p.number || '', p.insured, p.country,
    p.coverage.toFixed(2), p.currency,
    p.premium ? p.premium.toFixed(2) : '', p.frequency,
    p.startDate || '', p.endDate || '', p.nextDue || '',
    p.status, p.beneficiary || '', p.agent || '', p.notes || ''
  ]));
  downloadCsv(rows, `policies-${todayISO()}.csv`);
});

document.getElementById('export-pol-json').addEventListener('click', () => {
  const arr = getPols();
  if (arr.length === 0) { alert('No policies to export.'); return; }
  exportJson(`policies-${todayISO()}.json`, arr);
});

// Sync policy premium dates to reminders
document.getElementById('sync-pol-reminders').addEventListener('click', () => {
  const pols = getPols().filter(p => p.status === 'active' && p.nextDue);
  if (pols.length === 0) { alert('No active policies with next-due dates.'); return; }
  const rems = getReminders();
  let added = 0;
  pols.forEach(p => {
    const title = `${p.name} premium · ${fmtCurrency(p.premium, p.currency)}`;
    const exists = rems.find(r => r.title === title && r.date === p.nextDue);
    if (!exists) {
      rems.push({
        id: uid('rem'),
        date: p.nextDue,
        time: '',
        title,
        category: 'bill',
        recurring: p.frequency === 'monthly' ? 'monthly' :
                   (p.frequency === 'yearly' ? 'yearly' : 'none'),
      });
      added++;
    }
  });
  saveReminders(rems);
  renderCalendar();
  renderReminderList();
  alert(`✓ Synced ${added} premium reminder${added !== 1 ? 's' : ''}.`);
});

// ============================================================
// 21. CHANGE MASTER PASSWORD (prominent button)
// ============================================================

const changePwModal = document.getElementById('changepw-modal');
const changePwContent = document.getElementById('changepw-modal-content');

function showChangePasswordModal() {
  if (!appUnlocked) { alert('Unlock the vault first.'); return; }
  changePwContent.innerHTML = `
    <h3>🔁 Change master password</h3>
    <p>Re-encrypts all your data with the new password. Your current data is preserved.</p>
    <div class="lock-info">
      ℹ After changing, your <strong>recovery code (if set)</strong> will need to be re-generated. We'll prompt you for it.
    </div>
    <div class="field">
      <label class="field-label">Current master password</label>
      <input type="password" id="cpw-old" autocomplete="off">
    </div>
    <div class="field">
      <label class="field-label">New master password</label>
      <input type="password" id="cpw-new1" autocomplete="off">
      <div class="lock-pw-strength"><div class="lock-pw-strength-bar" id="cpw-bar"></div></div>
    </div>
    <div class="field">
      <label class="field-label">Confirm new password</label>
      <input type="password" id="cpw-new2" autocomplete="off">
    </div>
    <div class="field">
      <label class="field-label">Hint (optional)</label>
      <input type="text" id="cpw-hint" value="${escapeHtml((_origLoad(KEYS.vault) || {}).hint || '')}">
    </div>
    <div id="cpw-err" style="color:var(--terracotta);font-size:12px;display:none;"></div>
    <div class="modal-actions">
      <button class="btn ghost" id="cpw-cancel">Cancel</button>
      <button class="btn moss" id="cpw-go">Change password</button>
    </div>
  `;
  changePwModal.style.display = 'flex';

  const n1 = document.getElementById('cpw-new1');
  const bar = document.getElementById('cpw-bar');
  n1.addEventListener('input', () => {
    const s = pwStrength(n1.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'lock-pw-strength-bar ' + pwStrengthCls(s);
  });

  document.getElementById('cpw-cancel').onclick = () => { changePwModal.style.display = 'none'; };
  document.getElementById('cpw-go').onclick = async () => {
    const oldP = document.getElementById('cpw-old').value;
    const new1 = n1.value;
    const new2 = document.getElementById('cpw-new2').value;
    const hint = document.getElementById('cpw-hint').value;
    const err = document.getElementById('cpw-err');
    err.style.display = 'none';
    if (new1.length < 8) { err.textContent = 'Min 8 characters.'; err.style.display = ''; return; }
    if (new1 !== new2) { err.textContent = 'Passwords do not match.'; err.style.display = ''; return; }
    try {
      changePwContent.innerHTML = '<div class="lock-progress">⏳ Re-encrypting all data with new password…</div>';
      await changeMasterPassword(oldP, new1, hint);
      // Recovery becomes stale - clear it
      const v = _origLoad(KEYS.vault, {});
      if (v.recoveryEnabled) {
        v.recoveryEnabled = false;
        delete v.wrappedDekByRecovery;
        delete v.recoverySalt;
        delete v.recoveryIterations;
        _origSave(KEYS.vault, v);
        changePwModal.style.display = 'none';
        alert('✓ Master password changed.\n\n⚠ Your recovery code is no longer valid. Set up a new one in Security → Manage recovery code.');
      } else {
        changePwModal.style.display = 'none';
        alert('✓ Master password changed. All data re-encrypted with new password.');
      }
      renderRecoverySummary();
    } catch (e) {
      changePwContent.innerHTML = '';
      showChangePasswordModal();
      document.getElementById('cpw-err').textContent = '✗ ' + e.message;
      document.getElementById('cpw-err').style.display = '';
    }
  };
  setTimeout(() => document.getElementById('cpw-old').focus(), 100);
}

document.getElementById('change-pwd-btn').addEventListener('click', showChangePasswordModal);
changePwModal.addEventListener('click', (e) => {
  if (e.target === changePwModal) changePwModal.style.display = 'none';
});

// ============================================================
// 22. RECOVERY CODE SYSTEM
// ============================================================

const recoveryModal = document.getElementById('recovery-modal');
const recoveryContent = document.getElementById('recovery-modal-content');

// Generate a random 24-char recovery code in groups of 4
// Uses base32 alphabet (no confusing chars like 0/O/1/I)
function generateRecoveryCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  let code = '';
  for (let i = 0; i < bytes.length; i++) {
    code += alphabet[bytes[i] % alphabet.length];
    if ((i + 1) % 4 === 0 && i < bytes.length - 1) code += '-';
  }
  return code;
}

function normalizeRecoveryCode(code) {
  return code.replace(/[\s-]/g, '').toUpperCase();
}

async function deriveRecoveryKey(normalizedCode, salt) {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(normalizedCode), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: NEW_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

// Set up recovery for the FIRST time (no existing recovery)
// Stores the MASTER PASSWORD encrypted with a key derived from recovery code.
// Trade-off: encrypted password is in the vault — but the recovery key is needed to decrypt it.
async function setupRecovery(currentPassword) {
  // Verify the current password first
  await tryUnlockVault(currentPassword);
  // Generate recovery code + salt
  const code = generateRecoveryCode();
  const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
  const normalized = normalizeRecoveryCode(code);
  const recoveryKey = await deriveRecoveryKey(normalized, recoverySalt);
  // Encrypt the master password under recoveryKey
  const wrappedPassword = await encryptText(currentPassword, recoveryKey);
  // Save to vault metadata
  const v = _origLoad(KEYS.vault, {});
  v.recoveryEnabled = true;
  v.recoverySalt = bytesToBase64(recoverySalt);
  v.recoveryIterations = NEW_PBKDF2_ITERATIONS;
  v.wrappedDekByRecovery = wrappedPassword; // (legacy field name; actually wraps password)
  v.recoveryCreatedAt = new Date().toISOString();
  _origSave(KEYS.vault, v);
  return code;
}

// Forgot password: recover with code, then prompt for new password
async function recoverWithCode(code) {
  const v = _origLoad(KEYS.vault, {});
  if (!v.recoveryEnabled) throw new Error('Recovery is not set up for this vault.');
  const recoverySalt = base64ToBytes(v.recoverySalt);
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length < 20) throw new Error('Recovery code is too short.');
  const recoveryKey = await deriveRecoveryKey(normalized, recoverySalt);
  let originalPassword;
  try {
    originalPassword = await decryptText(v.wrappedDekByRecovery, recoveryKey);
  } catch {
    throw new Error('Wrong recovery code.');
  }
  return originalPassword; // caller uses this to unlock + change password
}

function showRecoveryManageModal() {
  if (!appUnlocked) { alert('Unlock the vault first.'); return; }
  const v = _origLoad(KEYS.vault, {});

  if (!v.recoveryEnabled) {
    showRecoverySetupModal();
    return;
  }

  // Recovery already set up — show management options
  recoveryContent.innerHTML = `
    <h3>🔑 Manage recovery code</h3>
    <div class="modal-success">
      ✓ Recovery code is active. Created on ${(v.recoveryCreatedAt || '').slice(0, 10)}.
    </div>
    <p>You can rotate (regenerate) the recovery code or disable recovery entirely. To view your current code you'd need to set up a new one (we never store it in readable form).</p>
    <div class="lock-warning">
      <strong>⚠ If you've lost your recovery code:</strong>
      Generate a new one now while you're logged in. The old code becomes invalid.
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="rec-cancel">Close</button>
      <button class="btn ghost" id="rec-disable">Disable recovery</button>
      <button class="btn moss" id="rec-rotate">Generate new code</button>
    </div>
  `;
  recoveryModal.style.display = 'flex';

  document.getElementById('rec-cancel').onclick = () => { recoveryModal.style.display = 'none'; };
  document.getElementById('rec-rotate').onclick = () => showRecoverySetupModal(true);
  document.getElementById('rec-disable').onclick = () => {
    if (!confirm('Disable recovery? If you later forget your master password, your data will be permanently inaccessible.')) return;
    const v2 = _origLoad(KEYS.vault, {});
    v2.recoveryEnabled = false;
    delete v2.wrappedDekByRecovery;
    delete v2.recoverySalt;
    delete v2.recoveryIterations;
    delete v2.recoveryCreatedAt;
    _origSave(KEYS.vault, v2);
    recoveryModal.style.display = 'none';
    renderRecoverySummary();
    alert('✓ Recovery disabled.');
  };
}

function showRecoverySetupModal(isRotate) {
  recoveryContent.innerHTML = `
    <h3>🔑 ${isRotate ? 'Generate new recovery code' : 'Set up recovery code'}</h3>
    <p>Enter your current master password. We'll generate a one-time recovery code that lets you reset your password if you ever forget it.</p>
    <div class="lock-warning">
      <strong>⚠ Critical</strong>
      The recovery code will be shown <strong>once</strong>. Write it down on paper or store it in a separate password manager. Anyone with the code can reset your master password.
    </div>
    <div class="field">
      <label class="field-label">Current master password</label>
      <input type="password" id="rs-pwd" autocomplete="off">
    </div>
    <div id="rs-err" style="color:var(--terracotta);font-size:12px;display:none;"></div>
    <div class="modal-actions">
      <button class="btn ghost" id="rs-cancel">Cancel</button>
      <button class="btn moss" id="rs-go">Generate code</button>
    </div>
  `;
  recoveryModal.style.display = 'flex';

  document.getElementById('rs-cancel').onclick = () => { recoveryModal.style.display = 'none'; };
  document.getElementById('rs-go').onclick = async () => {
    const pwd = document.getElementById('rs-pwd').value;
    const err = document.getElementById('rs-err');
    err.style.display = 'none';
    if (!pwd) { err.textContent = 'Enter your master password.'; err.style.display = ''; return; }
    try {
      recoveryContent.innerHTML = '<div class="lock-progress">⏳ Generating recovery code…</div>';
      const code = await setupRecovery(pwd);
      showRecoveryCodeOnce(code);
    } catch (e) {
      showRecoverySetupModal(isRotate);
      document.getElementById('rs-err').textContent = '✗ ' + e.message;
      document.getElementById('rs-err').style.display = '';
    }
  };
  setTimeout(() => document.getElementById('rs-pwd').focus(), 100);
}

function showRecoveryCodeOnce(code) {
  recoveryContent.innerHTML = `
    <h3>🔑 Your recovery code</h3>
    <div class="lock-warning">
      <strong>⚠ Save this NOW. You will not see it again.</strong>
      Write it on paper. Store in a fire safe. Or save in a separate password manager (1Password, Bitwarden). <strong>Do NOT save in the same place as your master password.</strong>
    </div>
    <div class="recovery-code-display" id="rec-code-text">${code}</div>
    <div class="recovery-code-actions">
      <button class="btn ghost btn-sm" id="rec-copy">⧉ Copy to clipboard</button>
      <button class="btn ghost btn-sm" id="rec-download">⤓ Download as .txt</button>
      <button class="btn ghost btn-sm" onclick="window.print()">🖨 Print</button>
    </div>
    <p style="font-size:12px;color:var(--ink-soft);text-align:center;margin-top:14px;">
      With this code, anyone can reset your master password and access your data. <strong>Treat it like a backup key, not just a password reset.</strong>
    </p>
    <div class="field" style="margin-top:18px;">
      <label class="field-label">Type the code below to confirm you have saved it</label>
      <input type="text" id="rec-confirm" class="recovery-input" placeholder="ABCD-EFGH-...">
    </div>
    <div class="modal-actions">
      <button class="btn moss" id="rec-done" disabled>I have saved it — close</button>
    </div>
  `;
  const confirmEl = document.getElementById('rec-confirm');
  const doneBtn = document.getElementById('rec-done');
  confirmEl.addEventListener('input', () => {
    const typed = confirmEl.value.replace(/\s/g, '').toUpperCase();
    const target = code.replace(/-/g, '').toUpperCase();
    const cleanTyped = typed.replace(/-/g, '');
    doneBtn.disabled = cleanTyped !== target;
  });
  document.getElementById('rec-copy').onclick = async () => {
    await navigator.clipboard.writeText(code);
    document.getElementById('rec-copy').textContent = '✓ Copied';
    setTimeout(() => document.getElementById('rec-copy').textContent = '⧉ Copy to clipboard', 1500);
  };
  document.getElementById('rec-download').onclick = () => {
    const content = `Household Finance — Recovery Code\nGenerated: ${new Date().toISOString()}\n\nCode: ${code}\n\nThis code lets anyone reset your master password and access your data.\nStore it separately from your master password.\n`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recovery-code-${todayISO()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };
  doneBtn.onclick = () => {
    recoveryModal.style.display = 'none';
    renderRecoverySummary();
  };
  setTimeout(() => confirmEl.focus(), 200);
}

function showRecoverFlow() {
  // Used from the lock screen "Forgot password?" link
  // Step 1: enter recovery code → step 2: enter new password → step 3: done
  const v = _origLoad(KEYS.vault, {});
  if (!v.recoveryEnabled) {
    alert('Recovery is not set up for this vault. Without the master password, the data is permanently encrypted.\n\nIf you have a JSON backup from a different device, you can import it after resetting the vault.');
    return;
  }
  recoveryContent.innerHTML = `
    <h3>🔑 Recover access</h3>
    <p>Enter your <strong>24-character recovery code</strong>. After verification, you can set a new master password.</p>
    <div class="field">
      <label class="field-label">Recovery code</label>
      <input type="text" id="rf-code" class="recovery-input" placeholder="ABCD-EFGH-IJKL-MNOP-QRST-UVWX" autocomplete="off">
      <p class="pw-hint" style="margin-top:6px;">Dashes are optional. Case-insensitive.</p>
    </div>
    <div id="rf-err" style="color:var(--terracotta);font-size:12px;display:none;"></div>
    <div class="modal-actions">
      <button class="btn ghost" id="rf-cancel">Cancel</button>
      <button class="btn moss" id="rf-verify">Verify code</button>
    </div>
  `;
  recoveryModal.style.display = 'flex';

  document.getElementById('rf-cancel').onclick = () => { recoveryModal.style.display = 'none'; };
  document.getElementById('rf-verify').onclick = async () => {
    const code = document.getElementById('rf-code').value;
    const err = document.getElementById('rf-err');
    err.style.display = 'none';
    try {
      recoveryContent.innerHTML = '<div class="lock-progress">⏳ Verifying recovery code…</div>';
      const originalPassword = await recoverWithCode(code);
      // We now have the original password — show new-password screen
      showRecoverNewPasswordModal(originalPassword);
    } catch (e) {
      showRecoverFlow();
      document.getElementById('rf-err').textContent = '✗ ' + e.message;
      document.getElementById('rf-err').style.display = '';
    }
  };
  setTimeout(() => document.getElementById('rf-code').focus(), 100);
}

function showRecoverNewPasswordModal(originalPassword) {
  recoveryContent.innerHTML = `
    <h3>✓ Recovery verified — set a new password</h3>
    <p>Choose a new master password. All your data will be re-encrypted with it.</p>
    <div class="field">
      <label class="field-label">New master password</label>
      <input type="password" id="rn-new1" autocomplete="off">
      <div class="lock-pw-strength"><div class="lock-pw-strength-bar" id="rn-bar"></div></div>
    </div>
    <div class="field">
      <label class="field-label">Confirm new password</label>
      <input type="password" id="rn-new2" autocomplete="off">
    </div>
    <div class="field">
      <label class="field-label">Hint (optional)</label>
      <input type="text" id="rn-hint">
    </div>
    <div id="rn-err" style="color:var(--terracotta);font-size:12px;display:none;"></div>
    <div class="modal-actions">
      <button class="btn moss" id="rn-go">Set new password &amp; unlock</button>
    </div>
  `;
  const n1 = document.getElementById('rn-new1');
  const bar = document.getElementById('rn-bar');
  n1.addEventListener('input', () => {
    const s = pwStrength(n1.value);
    bar.style.width = (s / 5 * 100) + '%';
    bar.className = 'lock-pw-strength-bar ' + pwStrengthCls(s);
  });

  document.getElementById('rn-go').onclick = async () => {
    const new1 = n1.value;
    const new2 = document.getElementById('rn-new2').value;
    const hint = document.getElementById('rn-hint').value;
    const err = document.getElementById('rn-err');
    err.style.display = 'none';
    if (new1.length < 8) { err.textContent = 'Min 8 characters.'; err.style.display = ''; return; }
    if (new1 !== new2) { err.textContent = 'Passwords do not match.'; err.style.display = ''; return; }
    try {
      recoveryContent.innerHTML = '<div class="lock-progress">⏳ Re-encrypting all data with new password…</div>';
      await changeMasterPassword(originalPassword, new1, hint);
      // Recovery is now invalid (old wrapped password decrypts to old password, which won't work)
      // So invalidate recovery — user should set up a new code
      const v = _origLoad(KEYS.vault, {});
      v.recoveryEnabled = false;
      delete v.wrappedDekByRecovery;
      delete v.recoverySalt;
      delete v.recoveryIterations;
      _origSave(KEYS.vault, v);
      recoveryModal.style.display = 'none';
      alert('✓ Password reset complete!\n\nNow unlock with your new password.\n\n⚠ Set up a new recovery code from Security → Manage recovery code.');
      // Re-show lock screen to let user log in
      lockApp();
    } catch (e) {
      recoveryContent.innerHTML = '';
      showRecoverNewPasswordModal(originalPassword);
      document.getElementById('rn-err').textContent = '✗ ' + e.message;
      document.getElementById('rn-err').style.display = '';
    }
  };
  setTimeout(() => n1.focus(), 100);
}

function renderRecoverySummary() {
  const el = document.getElementById('recovery-summary');
  if (!el) return;
  const v = _origLoad(KEYS.vault, {});
  if (v.recoveryEnabled) {
    el.innerHTML = `<span class="rec-chip ok">✓ Recovery enabled</span><span class="rec-chip">Set up ${(v.recoveryCreatedAt || '').slice(0, 10)}</span>`;
  } else {
    el.innerHTML = `<span class="rec-chip warn">⚠ Recovery not set up</span><span class="rec-chip">If you forget your password, data is lost</span>`;
  }
}

document.getElementById('recovery-manage-btn').addEventListener('click', showRecoveryManageModal);
recoveryModal.addEventListener('click', (e) => {
  if (e.target === recoveryModal) recoveryModal.style.display = 'none';
});

// ============================================================
// 23. ADD "FORGOT PASSWORD?" LINK TO LOCK SCREEN
// ============================================================

// Patch showLockUnlock to add forgot-password link
const _v6OrigShowLockUnlock = showLockUnlock;
showLockUnlock = function () {
  _v6OrigShowLockUnlock();
  // Inject forgot-password link if recovery is enabled
  const v = _origLoad(KEYS.vault, null);
  if (v && v.recoveryEnabled) {
    const actions = document.querySelector('#lock-content .lock-actions');
    if (actions && !document.getElementById('lock-forgot-link')) {
      const div = document.createElement('div');
      div.className = 'lock-forgot';
      div.innerHTML = `<a href="#" id="lock-forgot-link">🔑 Forgot password? Use recovery code</a>`;
      actions.parentNode.insertBefore(div, actions.nextSibling);
      document.getElementById('lock-forgot-link').addEventListener('click', (e) => {
        e.preventDefault();
        showRecoverFlow();
      });
    }
  }
};

// ============================================================
// 24. INITIAL RENDER — wire up after master unlock
// ============================================================

const _v6OrigMigrate = migrateAndUnlock;
migrateAndUnlock = async function(isNewSetup) {
  await _v6OrigMigrate(isNewSetup);
  renderRecoverySummary();
  if (typeof renderPols === 'function') renderPols();
  // Prompt new vaults to set up recovery
  if (isNewSetup) {
    setTimeout(() => {
      if (confirm('🔑 Set up a recovery code now?\n\nA recovery code lets you reset your master password if you forget it — without losing data.\n\nYou can do this later from Security → Manage recovery code.')) {
        showRecoverySetupModal();
      }
    }, 500);
  }
};

// Also render on app load if already unlocked
if (appUnlocked) {
  renderRecoverySummary();
  renderPols();
}

})();
