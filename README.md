# Household Finance Tracker

A single-page personal finance app for Vineet & Saroj. Tracks income, expenses, calendar reminders, and bank account credentials across USA / Canada / India. Passwords are encrypted client-side with a master password using the browser's native Web Crypto API.

No build step, no dependencies, no cloud sync. Open `index.html` and it runs.

## Project structure

```
household-finance/
├── index.html       # Markup: header, tabs, all 6 sections, modal dialogs
├── css/
│   └── styles.css   # All styling
├── js/
│   └── app.js       # All logic (10 modules)
├── README.md        # This file
├── serve.sh         # python3 -m http.server helper
└── .gitignore
```

## Tabs

| Tab | What it does |
|---|---|
| **Dashboard** | This month's income / expenses / net, mini calendar with reminder dots, upcoming reminders, recent transactions, total accounts tracked |
| **Income** | Add monthly income per person (Vineet / Saroj / Joint). Monthly summary table with totals. Filterable by year, person, currency |
| **Expenses** | Log household expenses by category, paid-by, currency. Filterable views, category breakdown, CSV export |
| **🇺🇸 USA** | US bank accounts, credit cards, 401(k), IRA, brokerage, HSA, crypto |
| **🇨🇦 Canada** | Canadian accounts: chequing, TFSA, RRSP, RESP, FHSA, LIRA, etc. |
| **🇮🇳 India** | Indian accounts: savings, FD, PPF, EPF, NPS, NRE, NRO, mutual funds, ULIP, etc. |

## Password vault — how the encryption works

### Architecture

- **Master password** — never stored anywhere. You enter it once per session to unlock the vault.
- **Key derivation:** PBKDF2-SHA256 with 250,000 iterations. Salt is randomly generated once and stored.
- **Encryption:** AES-GCM 256-bit. New 12-byte random IV per encryption (means encrypting the same password twice gives different ciphertext).
- **Verification:** A known plaintext string `"VAULT-OK-2026"` is encrypted at setup and stored alongside the salt. To verify a master password attempt, we decrypt this token — if it succeeds and matches, the password is right.
- **In-memory only:** The derived `CryptoKey` lives in a single JavaScript variable. Tab close = key gone.
- **Auto-lock:** 15 minutes of inactivity → vault locks itself.

### State machine

```
NOT_SETUP ──[user creates master pw]──> LOCKED ──[correct password]──> UNLOCKED
                                          ↑                              │
                                          └──[manual lock / auto-lock]───┘
```

### Storage layout

```
hf-vault-v1     { initialized, salt, verifier:{iv,ct}, hint, setupAt }
hf-accounts-v1  [{ id, country, type, institution, name,
                   accountNum, routingOrIfsc, username,
                   passwordEnc:{iv,ct}, pinEnc:{iv,ct},
                   website, phone, notes }]
hf-income-v1    [{ id, date, person, source, amount, currency, notes }]
hf-expenses-v1  [{ id, date, paidBy, cat, amount, currency, desc }]
hf-reminders-v1 [{ id, date, title, category, recurring }]
```

### What is and isn't encrypted

| Field | Encrypted? | Why |
|---|---|---|
| Password | ✓ Yes | Sensitive credential |
| PIN | ✓ Yes | Sensitive credential |
| Institution name | ✗ No | Used in card titles / filtering |
| Account number | ✗ No | You should enter last-4 only |
| Username | ✗ No | Less sensitive; needed for display |
| Notes | ✗ No | Plain text by design |
| Income / expenses | ✗ No | Financial *amounts*, not credentials |

If you want everything encrypted (including amounts and notes), tell me and I'll extend the model.

### ⚠ Important limitations

- **Forgetting your master password = data loss.** No recovery. Write it down somewhere safe.
- **Client-side encryption** is secure against someone stealing your localStorage backup. It is *not* secure against malware on your machine reading browser memory while the vault is unlocked.
- For mission-critical credentials (your bank's primary login), use a dedicated password manager (Bitwarden, 1Password). This tool is for less-critical credentials and overview.
- **Browser-bound storage.** Data doesn't sync between devices. Use the JSON export to back up.

## Running locally

```bash
# Option A: open directly
open index.html

# Option B: local server (recommended for dev)
./serve.sh
# then visit http://localhost:8000
```

Note: `file://` and `http://localhost` are different origins for localStorage — pick one.

## First-time flow

1. Open the app
2. Click **"Set up vault"** in the top-right header
3. Choose a strong master password (12+ chars recommended)
4. Optionally set a hint (something only you'd understand — *not* the password itself)
5. Start adding accounts in the country tabs — passwords get encrypted as you save them

## Daily workflow

- Log income / expenses as they happen
- Add reminders for bill dates, taxes, anniversaries
- Click any calendar date to jump-add a reminder for that day
- Click 👁 Show on any password — vault unlocks (if locked), password reveals for 30 sec then re-masks
- Click ⧉ Copy to copy the password to clipboard (still requires vault to be unlocked)

## Backup & restore

**Export all** (bottom of page) → downloads `household-finance-YYYY-MM-DD.json` containing everything including the encrypted vault. You can:
- Save it on a USB drive as backup
- Import on another browser/device with **Import**

The salt and verifier travel with the export, so the master password works on imported data too.

**Per-section CSV exports** are available on Income and Expense tabs (no encrypted data in those).

## Customizing

### Theme colors

Edit `css/styles.css` `:root` block:

```css
--paper: #f3eee3;       /* page bg */
--ink: #1a2530;         /* body text */
--moss: #2a4759;        /* primary */
--amber: #b87333;       /* secondary */
--sage: #6b8055;        /* income / positive */
--terracotta: #a04428;  /* expenses / warnings */
```

### Account types

Edit `ACCOUNT_TYPES` constant near the top of the country-tab section in `app.js`:

```js
const ACCOUNT_TYPES = {
  USA:    ['Checking', 'Savings', 'Credit Card', '401(k)', ...],
  Canada: ['Chequing', 'Savings', 'Credit Card', 'TFSA', ...],
  India:  ['Savings', 'Salary Account', 'Fixed Deposit', ...],
};
```

### Expense categories

Edit the `<select id="exp-cat">` `<option>` list in `index.html`.

### Auto-lock duration

In `app.js`, change `AUTO_LOCK_MS = 15 * 60 * 1000;` to your preferred milliseconds.

## Privacy notes

- Nothing leaves your browser. No analytics, no telemetry, no network calls (except loading Google Fonts which can be removed).
- To run fully offline: download the Fraunces/Outfit/JetBrains-Mono font files locally and serve them via CSS `@font-face` instead of the Google Fonts CDN.

## License

Personal use. Adapt freely.


## What's new in v2

### 🌑 Dark green/black theme
The whole app now uses a vibrant emerald-on-near-black palette designed for low-light use. All accent colors (income green, expense red, billing colors, calendar dots) are tuned for readability on the dark surface.

### 👧 Akshara tab
A 3-column profile layout for tracking everything about your daughter:
- **Personal:** name, DOB, auto-calculated age, grade, blood type
- **Emergency contacts:** name, relationship, phone, email
- **School:** name, address, principal, teacher, phone, website, notes
- **Activities:** karate, dance, etc. with instructor, schedule, location
- **Health:** family doctor, dentist, pediatrician (each with phone), allergies, current medications
- **Notes & milestones:** dated entries for memorable events

### 📁 Documents tab
Upload and store important documents securely:
- **3-column grid** of document cards with file-type icons
- **Drag-and-drop** or click to browse
- **IndexedDB** storage — handles files much larger than the 5MB localStorage cap (typically GBs available)
- **Optional AES-GCM encryption** per upload (requires unlocked vault)
- **Categories:** Identity, Tax, Bank Statement, Insurance, Property, Medical, School, Receipt, Legal, Vehicle, Other
- **Country tagging** + custom tags
- **Filter** by category, country, or text search
- Stats: total files, total size, encrypted count, showing count
- Click **Download** to retrieve any document (decrypts automatically if needed)

### Storage architecture

| Where | Stores |
|---|---|
| localStorage `hf-*` | Finance data, accounts, reminders, Akshara profile, document metadata |
| IndexedDB `hf-documents` / `files` | Actual document blobs (encrypted or plaintext) |
| In-memory only | `vaultKey` (AES-GCM CryptoKey) |
