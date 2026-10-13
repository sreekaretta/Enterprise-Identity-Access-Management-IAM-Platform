# Google OAuth 2.0 Setup Guide

This guide explains how to get Google OAuth credentials so the
"Continue with Google" button works on the IAM Lab login page.

## Prerequisites
- A Google account
- Access to [Google Cloud Console](https://console.cloud.google.com/)

---

## Step 1 — Create a Google Cloud Project

1. Open [console.cloud.google.com](https://console.cloud.google.com/)
2. Click the project selector (top bar) → **New Project**
3. Name it `IAM Lab` → **Create**

---

## Step 2 — Enable the Google+ / People API

1. In the left menu go to **APIs & Services → Library**
2. Search for **"Google People API"** → Enable it

---

## Step 3 — Configure the OAuth Consent Screen

1. **APIs & Services → OAuth consent screen**
2. User Type: **External** → Create
3. Fill in:
   - App name: `IAM Lab`
   - User support email: your email
   - Developer contact email: your email
4. Scopes: click **Add or Remove Scopes** → add:
   - `openid`
   - `email`
   - `profile`
5. Test users: add your own Google email address
6. Save & Continue

---

## Step 4 — Create OAuth Client Credentials

1. **APIs & Services → Credentials → Create Credentials → OAuth client ID**
2. Application type: **Web application**
3. Name: `IAM Lab Dev`
4. Authorized JavaScript origins:
   ```
   https://127.0.0.1:5000
   ```
5. Authorized redirect URIs:
   ```
   https://127.0.0.1:5000/oauth/google/callback
   ```
6. Click **Create**
7. Copy the **Client ID** and **Client Secret** shown in the popup

---

## Step 5 — Set Environment Variables

### Windows (Command Prompt)
```cmd
set GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
set GOOGLE_CLIENT_SECRET=your-client-secret-here
python app.py
```

### Windows (PowerShell)
```powershell
$env:GOOGLE_CLIENT_ID="your-client-id-here.apps.googleusercontent.com"
$env:GOOGLE_CLIENT_SECRET="your-client-secret-here"
python app.py
```

### Linux / macOS
```bash
export GOOGLE_CLIENT_ID="your-client-id-here.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret-here"
python app.py
```

---

## Step 6 — Test

1. Open `https://127.0.0.1:5000` (accept the browser security warning)
2. The login page will show a **"Continue with Google"** button
3. Click it → Google's consent page → authorize → redirected back to IAM Lab
4. The app matches the Google account email to an existing user in the database

> **Note:** The demo seed accounts use `@iam.lab` emails which don't exist on Google.
> To test OAuth, either:
> - Edit a demo user's email to match your real Google email, **or**
> - Create a new user in the IAM Lab with your real Google email address

---

## How It Works (for Interviews)

1. User clicks "Continue with Google"
2. App generates a random **CSRF state token** and stores it in the Flask session
3. User is redirected to Google's authorization endpoint with:
   - `client_id`, `redirect_uri`, `scope=openid email profile`
   - `state` for CSRF protection
4. Google authenticates the user and redirects back to `/oauth/google/callback`
5. App verifies the `state` matches (CSRF check)
6. App exchanges the **authorization code** for an **access token** (server-to-server POST)
7. App calls Google's userinfo endpoint with the Bearer token
8. App looks up the email in the local database
9. If found and active → user is logged in (session created)
10. If the user also has TOTP enabled → redirected to `/totp/verify` first

This is the **OAuth 2.0 Authorization Code Flow** — the most secure OAuth flow,
where the client secret never leaves the server.
