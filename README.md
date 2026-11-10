# BonDhu Bitto — Savings & Monthly Kisti Management

A full-stack starter application with:
- Administrator and member sign-in
- Member account creation and activation/deactivation
- Monthly kisti/payment recording
- Individual member savings history
- Organization dashboard and monthly collection totals
- CSV export of the payment ledger
- SQLite database (created automatically)

## Requirements
- Node.js 20 or newer
- npm

## Setup (Windows / VS Code)
1. Extract the ZIP file.
2. Open the extracted `bondhu-bitto` folder in VS Code.
3. Open Terminal → New Terminal.
4. Run `npm install`.
5. Copy `.env.example` to a new file named `.env`.
6. Edit `.env` and set:
   - `JWT_SECRET` to a long random string (at least 32 characters)
   - `ADMIN_EMAIL` to the administrator's email
   - `ADMIN_PASSWORD` to a strong password of at least 10 characters
7. Run `npm start`.
8. Open `http://localhost:3000` in your browser.

The initial administrator is created automatically the first time the server starts.
The database is stored in `data/bondhu-bitto.sqlite`.

## Important before real use
This is a functional starter project, not a certified banking or accounting system.
- Deploy only over HTTPS.
- Use a strong, private JWT secret and admin password.
- Back up the `data/` directory regularly and test restoring backups.
- Restrict access to authorized administrators.
- Have the organization's rules, receipts, approval process, audit trail, privacy notice and financial controls reviewed before recording real member money.
- Do not expose the SQLite database or `.env` file publicly.
- For multiple server instances or larger scale, move to PostgreSQL and managed session/auth infrastructure.
- Members are created by an administrator; share their login details securely and ask them to change temporary passwords (password-change workflow should be added before production use).

## Current limitations
- No online payment gateway or automatic bKash/Nagad verification.
- No automated SMS/email reminders.
- No password reset or member self-registration.
- No editing/reversal workflow for payment mistakes; administrator can delete a payment, so maintain independent backups and approval records.
- No downloadable PDF receipt yet.
