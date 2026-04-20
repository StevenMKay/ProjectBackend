require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const admin   = require('firebase-admin');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const Stripe  = require('stripe');
const multer  = require('multer');
const pdfParse = require('pdf-parse');
const { google } = require('googleapis');

// Multer: in-memory storage for resume uploads (max 10MB)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// Stripe init (graceful if key not set yet)
const stripe = process.env.STRIPE_SECRET_KEY && !process.env.STRIPE_SECRET_KEY.startsWith('YOUR_')
    ? Stripe(process.env.STRIPE_SECRET_KEY)
    : null;

// ============================================================
// FIREBASE ADMIN INITIALISATION
// ============================================================
// Place your service account JSON file at:
//   projectbackend/serviceAccountKey.json
// Download it from: Firebase Console -> Project Settings ->
// Service Accounts -> Generate new private key.
//
// SECURITY: NEVER commit this file to git.
// Add to .gitignore:  serviceAccountKey.json
//
let adminInitialised = false;
try {
    let serviceAccount;
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
        // Railway / cloud: credentials stored as env var
        serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
    } else {
        // Local development: credentials stored as file
        serviceAccount = require('./serviceAccountKey.json');
    }
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    adminInitialised = true;
    console.log('[Firebase Admin] Initialised successfully');
} catch (e) {
    console.warn('[Firebase Admin] Could not initialise - admin routes disabled:', e.message);
}

const auth = adminInitialised ? admin.auth() : null;
const db   = adminInitialised ? getFirestore(admin.app()) : null;

const app = express();

// Manual CORS — handles preflight OPTIONS reliably on Railway
app.use((req, res, next) => {
    const allowedOrigin = process.env.ALLOWED_ORIGIN || '*';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-tenant-id');
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') {
        return res.status(200).json({});
    }
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Diagnostic endpoint — confirms which version is deployed
app.get('/api/ping', (req, res) => res.json({ ok: true, version: 'v3' }));

const API_KEY = process.env.YOUTUBE_API_KEY || 'YOUR_YOUTUBE_API_KEY';

// YouTube OAuth configuration for membership verification
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const YT_OWNER_REFRESH_TOKEN = process.env.YT_OWNER_REFRESH_TOKEN;
const BACKEND_URL = process.env.BACKEND_URL || 'https://projectbackend-production-aa38.up.railway.app';

function createYTOAuthClient() {
    return new google.auth.OAuth2(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        BACKEND_URL + '/api/builder/youtube-callback'
    );
}

// ============================================================
// YOUTUBE PROXY (existing)
// ============================================================
app.get('/api/youtube', async (req, res) => {
  const { playlistId, maxResults, id } = req.query;
  let url = '';
  if (id) {
    url = `https://www.googleapis.com/youtube/v3/videos?part=snippet,contentDetails&id=${id}&key=${API_KEY}`;
  } else {
    url = `https://www.googleapis.com/youtube/v3/playlistItems?part=snippet,contentDetails&playlistId=${playlistId}&maxResults=${maxResults || 5}&key=${API_KEY}`;
  }
  try {
    const response = await fetch(url);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch from YouTube API' });
  }
});

// ============================================================
// OWNER BYPASS — UIDs in this list always have full admin access
// ============================================================
const OWNER_UIDS_ADMIN = ['M49k5gv2ovcAHVrMnRf9jmWMxts1'];

// ============================================================
// ADMIN AUTH MIDDLEWARE
// ============================================================
// Verifies the Firebase ID token in the Authorization header
// and checks the user has role: "admin" in Firestore.
// Site owners (OWNER_UIDS_ADMIN) bypass the Firestore role check.
//
async function requireAdmin(req, res, next) {
    if (!adminInitialised) {
        return res.status(503).json({ error: 'Admin service not configured. See backend setup instructions.' });
    }
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        const decoded = await auth.verifyIdToken(token);
        // Site owner always has admin access — no Firestore doc required
        if (OWNER_UIDS_ADMIN.includes(decoded.uid)) {
            req.adminUid = decoded.uid;
            return next();
        }
        const userDoc  = await db.collection('users').doc(decoded.uid).get();
        if (!userDoc.exists || userDoc.data().role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: admin role required' });
        }
        req.adminUid = decoded.uid;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ============================================================
// TENANT AUTH MIDDLEWARE
// ============================================================
// Any provisioned user (or site owner). Populates req.uid and req.userDoc.
//
async function requireAuth(req, res, next) {
    if (!adminInitialised) return res.status(503).json({ error: 'Backend not configured' });
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        const decoded = await auth.verifyIdToken(token);
        req.uid = decoded.uid;
        // Site owner gets a synthetic admin profile
        if (OWNER_UIDS_ADMIN.includes(decoded.uid)) {
            req.userDoc = { tenantId: 'admin', role: 'admin', email: decoded.email || '', displayName: '' };
            return next();
        }
        const doc = await db.collection('users').doc(decoded.uid).get();
        if (!doc.exists) return res.status(403).json({ error: 'Account not provisioned' });
        req.userDoc = doc.data();
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ============================================================
// ADMIN ROUTES — TENANTS
// ============================================================

// List all tenants
app.get('/api/admin/tenants', requireAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('tenants').get();
        const tenants  = [];
        for (const doc of snapshot.docs) {
            // Count users in this tenant
            const users = await db.collection('users')
                .where('tenantId', '==', doc.id).get();
            tenants.push({ id: doc.id, ...doc.data(), userCount: users.size });
        }
        res.json(tenants);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to list tenants' });
    }
});

// Create a tenant
app.post('/api/admin/tenants', requireAdmin, async (req, res) => {
    const { tenantId, companyName, plan, maxSeats } = req.body;
    if (!tenantId || !companyName) {
        return res.status(400).json({ error: 'tenantId and companyName are required' });
    }
    // tenantId must be slug-safe
    if (!/^[a-z0-9-]+$/.test(tenantId)) {
        return res.status(400).json({ error: 'tenantId must be lowercase letters, numbers and hyphens only' });
    }
    try {
        const ref = db.collection('tenants').doc(tenantId);
        const existing = await ref.get();
        if (existing.exists) return res.status(409).json({ error: 'Tenant ID already exists' });
        await ref.set({
            companyName,
            plan:     plan     || 'standard',
            maxSeats: maxSeats || 10,
            active:   true,
            createdAt: new Date().toISOString()
        });
        res.json({ success: true, tenantId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create tenant' });
    }
});

// Update a tenant (plan, seats, active status)
app.patch('/api/admin/tenants/:tenantId', requireAdmin, async (req, res) => {
    const { tenantId } = req.params;
    const updates = {};
    const allowed = ['companyName', 'plan', 'maxSeats', 'active'];
    allowed.forEach(function(k) { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    try {
        await db.collection('tenants').doc(tenantId).update(updates);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update tenant' });
    }
});

// ============================================================
// ADMIN ROUTES — USERS
// ============================================================

// List all users
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('users').get();
        const users = snapshot.docs.map(function(doc) {
            return { uid: doc.id, ...doc.data() };
        });
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to list users' });
    }
});

// Create a user and assign to a tenant
app.post('/api/admin/users', requireAdmin, async (req, res) => {
    const { email, password, displayName, tenantId, role } = req.body;
    if (!email || !password || !tenantId) {
        return res.status(400).json({ error: 'email, password and tenantId are required' });
    }
    // Verify tenant exists and is active
    const tenantDoc = await db.collection('tenants').doc(tenantId).get();
    if (!tenantDoc.exists) return res.status(404).json({ error: 'Tenant not found' });
    if (!tenantDoc.data().active) return res.status(403).json({ error: 'Tenant is inactive' });

    // Check seat limit
    const existingUsers = await db.collection('users').where('tenantId', '==', tenantId).get();
    if (existingUsers.size >= (tenantDoc.data().maxSeats || 10)) {
        return res.status(403).json({ error: 'Seat limit reached for this tenant' });
    }

    try {
        const userRecord = await auth.createUser({ email, password, displayName: displayName || '' });
        await db.collection('users').doc(userRecord.uid).set({
            tenantId,
            displayName: displayName || '',
            email,
            role: role || 'member',
            createdAt: new Date().toISOString()
        });
        res.json({ success: true, uid: userRecord.uid });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message || 'Failed to create user' });
    }
});

// Update a user (role, tenantId, displayName)
app.patch('/api/admin/users/:uid', requireAdmin, async (req, res) => {
    const { uid } = req.params;
    const updates = {};
    const allowed = ['role', 'tenantId', 'displayName'];
    allowed.forEach(function(k) { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    try {
        await db.collection('users').doc(uid).update(updates);
        if (req.body.displayName) await auth.updateUser(uid, { displayName: req.body.displayName });
        if (req.body.email)       await auth.updateUser(uid, { email: req.body.email });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Disable / re-enable a user
app.patch('/api/admin/users/:uid/status', requireAdmin, async (req, res) => {
    const { uid } = req.params;
    const { disabled } = req.body;
    try {
        await auth.updateUser(uid, { disabled: !!disabled });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

// Delete a user permanently
app.delete('/api/admin/users/:uid', requireAdmin, async (req, res) => {
    const { uid } = req.params;
    try {
        await auth.deleteUser(uid);
        await db.collection('users').doc(uid).delete();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// ============================================================
// TENANT SELF-SERVICE ROUTES
// ============================================================

// List members of the caller's tenant
app.get('/api/tenant/members', requireAuth, async (req, res) => {
    try {
        const snap = await db.collection('users').where('tenantId', '==', req.userDoc.tenantId).get();
        res.json(snap.docs.map(d => ({ uid: d.id, ...d.data() })));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to list members' });
    }
});

// Invite a new member to the caller's tenant (admin only)
// Creates a Firebase Auth account + Firestore profile + invite token.
// The front-end passes the token to /api/tenant/send-invite-email
// so the invitee receives a branded "set your password" email.

// Generate a secure invite token and store it in Firestore
async function generateInviteToken({ uid, email, tenantId }) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days
    await db.collection('inviteTokens').doc(token).set({
        uid,
        email,
        tenantId,
        expiresAt,
        used: false,
        attempts: 0,
        createdAt: new Date().toISOString()
    });
    return token;
}

app.post('/api/tenant/invite', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') {
        return res.status(403).json({ error: 'Only team admins can invite members' });
    }
    const { email, displayName, role } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email is required' });

    const tenantId = req.userDoc.tenantId;
    try {
        // Check seat limit if a tenant doc exists
        const tenantDoc = await db.collection('tenants').doc(tenantId).get();
        if (tenantDoc.exists) {
            const currentMembers = await db.collection('users').where('tenantId', '==', tenantId).get();
            if (currentMembers.size >= (tenantDoc.data().maxSeats || 10)) {
                return res.status(403).json({ error: 'Seat limit reached. Contact your administrator to upgrade.' });
            }
        }
        // Create Firebase Auth account with a temp password
        const tempPwd = Math.random().toString(36).slice(-8) + 'Aa1!';
        const userRecord = await auth.createUser({ email, password: tempPwd, displayName: displayName || '' });
        // Create Firestore profile
        await db.collection('users').doc(userRecord.uid).set({
            tenantId,
            email,
            displayName: displayName || '',
            role: (role === 'admin' ? 'admin' : role === 'viewer' ? 'viewer' : 'member'),
            createdAt: new Date().toISOString()
        });
        // Generate invite token for password setup
        const token = await generateInviteToken({ uid: userRecord.uid, email, tenantId });
        res.json({ success: true, uid: userRecord.uid, inviteToken: token });
    } catch (err) {
        if (err.code === 'auth/email-already-exists') {
            return res.status(409).json({ error: 'This email already has an account.' });
        }
        console.error(err);
        res.status(500).json({ error: err.message || 'Failed to invite user' });
    }
});

// Update a member's profile fields (admin only)
app.patch('/api/tenant/members/:uid', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') {
        return res.status(403).json({ error: 'Only team admins can edit members' });
    }
    const { uid } = req.params;
    try {
        const doc = await db.collection('users').doc(uid).get();
        if (!doc.exists || doc.data().tenantId !== req.userDoc.tenantId) {
            return res.status(404).json({ error: 'Member not found in your team' });
        }
        const updates = {};
        const allowed = ['displayName', 'jobTitle', 'dept', 'role'];
        allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
        if (updates.role && !['admin', 'member', 'viewer'].includes(updates.role)) {
            return res.status(400).json({ error: 'Invalid role value' });
        }
        if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No valid fields to update' });
        await db.collection('users').doc(uid).update(updates);
        if (updates.displayName) await auth.updateUser(uid, { displayName: updates.displayName });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message || 'Failed to update member' });
    }
});

// Remove a member from the caller's tenant (admin only)
app.delete('/api/tenant/members/:uid', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') {
        return res.status(403).json({ error: 'Only team admins can remove members' });
    }
    const { uid } = req.params;
    if (uid === req.uid) return res.status(400).json({ error: 'Cannot remove yourself' });
    try {
        const doc = await db.collection('users').doc(uid).get();
        if (!doc.exists || doc.data().tenantId !== req.userDoc.tenantId) {
            return res.status(404).json({ error: 'Member not found in your team' });
        }
        await auth.deleteUser(uid);
        await db.collection('users').doc(uid).delete();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message || 'Failed to remove member' });
    }
});

// ============================================================
// INVITE TOKEN ENDPOINTS (unauthenticated — token IS the auth)
// ============================================================

// Validate an invite token — safe for email link prefetchers (read-only)
app.post('/api/invite/validate', express.json(), async (req, res) => {
    if (!db) return res.status(503).json({ valid: false, reason: 'Backend not configured' });
    const { token } = req.body;
    if (!token || typeof token !== 'string') return res.json({ valid: false, reason: 'Missing token' });
    try {
        const doc = await db.collection('inviteTokens').doc(token).get();
        if (!doc.exists) return res.json({ valid: false, reason: 'Invalid or expired link. Ask your admin to resend the invitation.' });
        const data = doc.data();
        if (data.used) return res.json({ valid: false, reason: 'This setup link has already been used. Sign in with your email and password, or click "Forgot password?" if needed.' });
        if (new Date(data.expiresAt) < new Date()) return res.json({ valid: false, reason: 'This setup link has expired. Ask your admin to resend the invitation.' });
        // Look up display name from user doc
        const userDoc = await db.collection('users').doc(data.uid).get();
        const displayName = userDoc.exists ? (userDoc.data().displayName || '') : '';
        // Look up company name from tenant
        let companyName = '';
        if (data.tenantId) {
            const tenantDoc = await db.collection('tenants').doc(data.tenantId).get();
            companyName = tenantDoc.exists ? (tenantDoc.data().companyName || '') : '';
        }
        res.json({ valid: true, email: data.email, displayName, companyName });
    } catch (err) {
        console.error('[Invite] Validate error:', err.message);
        res.status(500).json({ valid: false, reason: 'Server error. Please try again.' });
    }
});

// Accept an invite token — set the user's password
app.post('/api/invite/accept', express.json(), async (req, res) => {
    if (!db || !auth) return res.status(503).json({ error: 'Backend not configured' });
    const { token, password } = req.body;
    if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Missing token' });
    if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password is required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
        return res.status(400).json({ error: 'Password must contain at least one letter and one number' });
    }
    try {
        const docRef = db.collection('inviteTokens').doc(token);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(400).json({ error: 'Invalid or expired link. Ask your admin to resend the invitation.' });
        const data = doc.data();
        if (data.used) return res.status(400).json({ error: 'This setup link has already been used. Sign in with your email and password, or click "Forgot password?" if needed.' });
        if (new Date(data.expiresAt) < new Date()) return res.status(400).json({ error: 'This setup link has expired. Ask your admin to resend the invitation.' });
        // Rate limit: max 5 attempts per token
        if ((data.attempts || 0) >= 5) return res.status(429).json({ error: 'Too many attempts. Ask your admin to resend the invitation.' });
        await docRef.update({ attempts: (data.attempts || 0) + 1 });
        // Set the user's password via Admin SDK
        await auth.updateUser(data.uid, { password });
        // Mark token as used
        await docRef.update({ used: true, usedAt: new Date().toISOString() });
        res.json({ success: true, email: data.email });
    } catch (err) {
        console.error('[Invite] Accept error:', err.message);
        res.status(500).json({ error: 'Failed to set password. Please try again.' });
    }
});

// ============================================================
// EMAIL — Resend HTTP API (Railway blocks outbound SMTP)
// Set RESEND_API_KEY, SMTP_USER (from address), SMTP_FROM_NAME in Railway vars
// ============================================================
const FROM_NAME  = process.env.SMTP_FROM_NAME || 'NotebookPM';
const FROM_EMAIL = process.env.SMTP_USER || 'noreply@careersolutionsfortoday.com';

if (process.env.RESEND_API_KEY) {
    console.log('[Email] Resend configured, sending from:', FROM_EMAIL);
} else {
    console.warn('[Email] RESEND_API_KEY not set. Add it to Railway env vars.');
}

async function sendCustomEmail({ to, subject, html }) {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) throw new Error('RESEND_API_KEY not configured. Add it to Railway env vars.');
    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: `${FROM_NAME} <${FROM_EMAIL}>`, to: [to], subject, html })
    });
    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.message || `Resend API error ${response.status}`);
    }
}

function buildInviteEmailHtml({ displayName, inviterName, companyName, link }) {
    const inviterDisplay  = inviterName  || 'Your team admin';
    const companyDisplay  = companyName && companyName !== 'Notebook' ? companyName : 'NotebookPM';
    const recipientGreet  = displayName ? `Hi ${displayName},` : 'Hi there,';
    const LOGO = 'https://raw.githubusercontent.com/StevenMKay/CareerSolutionsForToday/0205845e0a19b0d6f83005dc19f37741fc82e403/icons/CareerIcon.png';
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:40px 16px;"><tr><td align="center">
<table width="100%" style="max-width:560px;" cellpadding="0" cellspacing="0"><tr><td style="background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="background:linear-gradient(135deg,#1e40af 0%,#3b82f6 100%);padding:32px 40px;text-align:center;">
    <div style="font-size:24px;font-weight:800;color:#fff;letter-spacing:-0.5px;">NotebookPM</div>
    <div style="font-size:12px;color:rgba(255,255,255,0.7);margin-top:4px;letter-spacing:0.3px;">PROJECT &amp; TEAM MANAGEMENT</div>
  </td></tr></table>
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:36px 40px;">
    <h2 style="margin:0 0 16px;font-size:22px;color:#0f172a;font-weight:700;">You've been invited!</h2>
    <p style="margin:0 0 14px;color:#475569;font-size:15px;line-height:1.65;">${recipientGreet}</p>
    <p style="margin:0 0 14px;color:#475569;font-size:15px;line-height:1.65;"><strong style="color:#1e293b;">${inviterDisplay}</strong> has invited you to join <strong style="color:#2563eb;">NotebookPM</strong> &mdash; a shared workspace for managing projects and collaborating with your team.</p>
    <p style="margin:0 0 28px;color:#475569;font-size:15px;line-height:1.65;">Click the button below to set your password and activate your account. You'll be taken straight to NotebookPM when you're done.</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 28px;"><tr><td style="background:#2563eb;border-radius:8px;box-shadow:0 2px 8px rgba(37,99,235,0.35);">
      <a href="${link}" style="display:inline-block;padding:15px 36px;color:#fff;font-weight:700;font-size:16px;text-decoration:none;">Set My Password &rarr;</a>
    </td></tr></table>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px;border-top:1px solid #e2e8f0;padding-top:20px;"><tr>
      <td style="width:52px;vertical-align:middle;"><img src="${LOGO}" alt="Career Solutions" width="44" height="44" style="border-radius:8px;display:block;"></td>
      <td style="padding-left:14px;vertical-align:middle;">
        <div style="font-size:13px;font-weight:700;color:#1e293b;">Career Solutions for Today</div>
        <div style="font-size:12px;color:#64748b;margin-top:2px;">Empowering careers, one project at a time.</div>
        <div style="font-size:12px;margin-top:2px;"><a href="https://careersolutionsfortoday.com" style="color:#2563eb;text-decoration:none;">careersolutionsfortoday.com</a></div>
      </td>
    </tr></table>
    <p style="margin:0;color:#94a3b8;font-size:12px;line-height:1.6;">If you didn't expect this invitation, you can safely ignore this email. The link expires in 7 days.</p>
  </td></tr></table>
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:18px 40px;text-align:center;">
    <p style="margin:0;color:#94a3b8;font-size:12px;">NotebookPM &nbsp;&middot;&nbsp; <a href="https://notebookpm.com" style="color:#64748b;text-decoration:none;">notebookpm.com</a> &nbsp;&middot;&nbsp; Powered by Career Solutions for Today</p>
  </td></tr></table>
</td></tr></table>
</td></tr></table></body></html>`;
}

function buildResetEmailHtml({ displayName, link }) {
    const recipientGreet = displayName ? `Hi ${displayName},` : 'Hi there,';
    const LOGO = 'https://raw.githubusercontent.com/StevenMKay/CareerSolutionsForToday/0205845e0a19b0d6f83005dc19f37741fc82e403/icons/CareerIcon.png';
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:40px 16px;"><tr><td align="center">
<table width="100%" style="max-width:560px;" cellpadding="0" cellspacing="0"><tr><td style="background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="background:linear-gradient(135deg,#1e40af 0%,#3b82f6 100%);padding:32px 40px;text-align:center;">
    <div style="font-size:24px;font-weight:800;color:#fff;letter-spacing:-0.5px;">NotebookPM</div>
    <div style="font-size:12px;color:rgba(255,255,255,0.7);margin-top:4px;letter-spacing:0.3px;">PROJECT &amp; TEAM MANAGEMENT</div>
  </td></tr></table>
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:36px 40px;">
    <h2 style="margin:0 0 16px;font-size:22px;color:#0f172a;font-weight:700;">Password Reset</h2>
    <p style="margin:0 0 14px;color:#475569;font-size:15px;line-height:1.65;">${recipientGreet}</p>
    <p style="margin:0 0 28px;color:#475569;font-size:15px;line-height:1.65;">A password reset has been requested for your <strong style="color:#1e293b;">NotebookPM</strong> account. Click below to choose a new password.</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 28px;"><tr><td style="background:#2563eb;border-radius:8px;box-shadow:0 2px 8px rgba(37,99,235,0.35);">
      <a href="${link}" style="display:inline-block;padding:15px 36px;color:#fff;font-weight:700;font-size:16px;text-decoration:none;">Reset My Password &rarr;</a>
    </td></tr></table>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 28px;"><tr><td style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:16px 20px;">
      <p style="margin:0 0 6px;font-size:13px;color:#1e40af;font-weight:700;">After resetting your password:</p>
      <p style="margin:0;font-size:13px;color:#3b82f6;line-height:1.6;">Visit <a href="https://notebookpm.com" style="color:#1d4ed8;font-weight:700;text-decoration:none;">NotebookPM.com</a> and sign in with your email address.</p>
    </td></tr></table>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px;border-top:1px solid #e2e8f0;padding-top:20px;"><tr>
      <td style="width:52px;vertical-align:middle;"><img src="${LOGO}" alt="Career Solutions" width="44" height="44" style="border-radius:8px;display:block;"></td>
      <td style="padding-left:14px;vertical-align:middle;">
        <div style="font-size:13px;font-weight:700;color:#1e293b;">Career Solutions for Today</div>
        <div style="font-size:12px;color:#64748b;margin-top:2px;">Empowering careers, one project at a time.</div>
        <div style="font-size:12px;margin-top:2px;"><a href="https://careersolutionsfortoday.com" style="color:#2563eb;text-decoration:none;">careersolutionsfortoday.com</a></div>
      </td>
    </tr></table>
    <p style="margin:0;color:#94a3b8;font-size:12px;line-height:1.6;">If you did not request this, you can safely ignore this email. The link expires in 7 days.</p>
  </td></tr></table>
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:18px 40px;text-align:center;">
    <p style="margin:0;color:#94a3b8;font-size:12px;">NotebookPM &nbsp;&middot;&nbsp; <a href="https://notebookpm.com" style="color:#64748b;text-decoration:none;">notebookpm.com</a> &nbsp;&middot;&nbsp; Powered by Career Solutions for Today</p>
  </td></tr></table>
</td></tr></table>
</td></tr></table></body></html>`;
}

// Send branded invite email (admin only)
app.post('/api/tenant/send-invite-email', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    const { email, displayName, inviterName, companyName, inviteToken } = req.body;
    if (!email) return res.status(400).json({ error: 'email is required' });
    if (!inviteToken) return res.status(400).json({ error: 'inviteToken is required' });
    try {
        const link = `https://notebookpm.com/ProjectTracker.html?invite=${inviteToken}`;
        await sendCustomEmail({ to: email, subject: `You've been invited to join NotebookPM`, html: buildInviteEmailHtml({ displayName, inviterName, companyName, link }) });
        res.json({ success: true });
    } catch (err) {
        console.error('[Email] Invite failed:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Send password reset email to an existing member (admin only)
// Generates a fresh invite token so the member can set a new password
app.post('/api/tenant/members/:uid/send-reset', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    const { uid } = req.params;
    try {
        const doc = await db.collection('users').doc(uid).get();
        if (!doc.exists || doc.data().tenantId !== req.userDoc.tenantId) return res.status(404).json({ error: 'Member not found' });
        const { email, displayName, tenantId } = doc.data();
        const token = await generateInviteToken({ uid, email, tenantId });
        const link = `https://notebookpm.com/ProjectTracker.html?invite=${token}`;
        await sendCustomEmail({ to: email, subject: 'Reset your NotebookPM password', html: buildResetEmailHtml({ displayName, link }) });
        res.json({ success: true });
    } catch (err) {
        console.error('[Email] Reset failed:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// TENANT INFO — account & subscription data for the dashboard
// ============================================================
app.get('/api/tenant/info', requireAuth, async (req, res) => {
    try {
        const tenantId = req.userDoc.tenantId;
        const tenantDoc = await db.collection('tenants').doc(tenantId).get();
        if (!tenantDoc.exists) return res.json({ plan: 'free', maxSeats: 1, memberCount: 1, active: true });
        const data = tenantDoc.data();
        const members = await db.collection('users').where('tenantId', '==', tenantId).get();
        let subscriptionStatus = null;
        let trialEnd = null;
        let currentPeriodEnd = null;
        let cancelAtPeriodEnd = false;
        if (stripe && data.stripeSubscriptionId) {
            try {
                const sub = await stripe.subscriptions.retrieve(data.stripeSubscriptionId);
                subscriptionStatus = sub.status;
                trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
                currentPeriodEnd = sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
                cancelAtPeriodEnd = sub.cancel_at_period_end || false;
            } catch (e) { console.warn('[Billing] Could not fetch subscription:', e.message); }
        }
        res.json({
            tenantId,
            companyName: data.companyName || '',
            plan: data.plan || 'standard',
            maxSeats: data.maxSeats || 10,
            memberCount: members.size,
            active: data.active !== false,
            subscriptionStatus,
            trialEnd,
            currentPeriodEnd,
            cancelAtPeriodEnd
        });
    } catch (err) {
        console.error('[Tenant] Info error:', err.message);
        res.status(500).json({ error: 'Failed to load account info' });
    }
});

// ============================================================
// BILLING ROUTES — STRIPE SUBSCRIPTIONS
// ============================================================

const PLANS = {
    standard:     { priceId: () => process.env.STRIPE_PRICE_STANDARD,     maxSeats: 10  },
    professional: { priceId: () => process.env.STRIPE_PRICE_PROFESSIONAL, maxSeats: 25  },
    enterprise:   { priceId: () => process.env.STRIPE_PRICE_ENTERPRISE,   maxSeats: 100 }
};

// Create Stripe Checkout Session
app.post('/api/billing/checkout', async (req, res) => {
    try {
    if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
    if (!db)     return res.status(503).json({ error: 'Database not configured' });

    const { plan, companyName, adminEmail, tenantId } = req.body;

    if (!plan || !PLANS[plan])            return res.status(400).json({ error: 'Invalid plan' });
    if (!companyName || !adminEmail)      return res.status(400).json({ error: 'Missing companyName or adminEmail' });
    if (!tenantId || !/^[a-z0-9-]+$/.test(tenantId))
                                          return res.status(400).json({ error: 'Invalid tenantId — lowercase letters, numbers, hyphens only' });
    if (!adminEmail.includes('@'))        return res.status(400).json({ error: 'Invalid email' });

    // Prevent duplicate tenant IDs
    const existing = await db.collection('tenants').doc(tenantId).get();
    if (existing.exists) return res.status(409).json({ error: 'That company ID is already taken. Choose a different one.' });

    const priceId = PLANS[plan].priceId();
    if (!priceId || priceId.startsWith('price_YOUR_'))
        return res.status(503).json({ error: 'Plan price not configured yet' });

    try {
        const session = await stripe.checkout.sessions.create({
            mode: 'subscription',
            payment_method_types: ['card'],
            customer_email: adminEmail,
            line_items: [{ price: priceId, quantity: 1 }],
            subscription_data: {
                trial_period_days: 7,
            },
            metadata: {
                companyName,
                tenantId,
                adminEmail,
                plan,
                maxSeats: String(PLANS[plan].maxSeats)
            },
            success_url: `${process.env.SITE_URL || 'https://www.careersolutionsfortoday.com'}/license-success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url:  `${process.env.SITE_URL || 'https://www.careersolutionsfortoday.com'}/license-pricing.html?cancelled=1`,
        });
        res.json({ url: session.url });
    } catch (err) {
        console.error('[Billing] Checkout error:', err.message);
        res.status(500).json({ error: err.message || 'Failed to create checkout session' });
    }
    } catch (err) {
        console.error('[Billing] Outer checkout error:', err.message);
        res.status(500).json({ error: err.message || 'Server error' });
    }
});

// Create Stripe Customer Portal session — lets users manage subscription
app.post('/api/billing/portal', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') return res.status(403).json({ error: 'Only admins can manage billing' });
    try {
        if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
        const tenantId = req.userDoc.tenantId;
        const tenantDoc = await db.collection('tenants').doc(tenantId).get();
        if (!tenantDoc.exists || !tenantDoc.data().stripeCustomerId) {
            return res.status(400).json({ error: 'No billing account found. Contact support.' });
        }
        const session = await stripe.billingPortal.sessions.create({
            customer: tenantDoc.data().stripeCustomerId,
            return_url: `${process.env.SITE_URL || 'https://www.careersolutionsfortoday.com'}/ProjectTracker.html`,
        });
        res.json({ url: session.url });
    } catch (err) {
        console.error('[Billing] Portal error:', err.message);
        res.status(500).json({ error: 'Failed to open billing portal' });
    }
});

// Stripe Webhook — auto-provision tenant on successful payment
// Must use express.raw() so Stripe can verify the request signature
app.post('/api/billing/webhook',
    express.raw({ type: 'application/json' }),
    async (req, res) => {
        if (!stripe) return res.status(503).send('Billing not configured');

        const sig = req.headers['stripe-signature'];
        let event;
        try {
            event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        } catch (err) {
            console.error('[Billing] Webhook signature failed:', err.message);
            return res.status(400).send('Webhook signature verification failed');
        }

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            const { companyName, tenantId, adminEmail, plan, maxSeats } = session.metadata || {};

            // Only process tenant provisioning if this is a NotebookPM checkout (has tenantId)
            if (tenantId && adminEmail) {

            try {
                // 1. Create tenant record in Firestore
                await db.collection('tenants').doc(tenantId).set({
                    companyName,
                    plan,
                    maxSeats: parseInt(maxSeats, 10),
                    active: true,
                    stripeCustomerId: session.customer,
                    stripeSubscriptionId: session.subscription,
                    createdAt: new Date().toISOString()
                });

                // 2. Create admin Firebase Auth account with a random temp password
                const tempPassword = Math.random().toString(36).slice(-8)
                    + Math.random().toString(36).slice(-8).toUpperCase() + '1!';
                const userRecord = await auth.createUser({
                    email: adminEmail,
                    password: tempPassword,
                    displayName: companyName + ' Admin'
                });

                // 3. Write user record to Firestore
                await db.collection('users').doc(userRecord.uid).set({
                    tenantId,
                    email: adminEmail,
                    displayName: companyName + ' Admin',
                    role: 'admin',
                    createdAt: new Date().toISOString()
                });

                // 4. Generate invite token and email setup link to the buyer
                const inviteToken = await generateInviteToken({ uid: userRecord.uid, email: adminEmail, tenantId });
                const setupLink = `https://notebookpm.com/ProjectTracker.html?invite=${inviteToken}`;
                console.log('[Billing] Provisioned:', tenantId, '| Admin:', adminEmail);
                try {
                    await sendCustomEmail({
                        to: adminEmail,
                        subject: 'Your NotebookPM account is ready!',
                        html: buildInviteEmailHtml({ displayName: companyName + ' Admin', inviterName: 'NotebookPM', companyName, link: setupLink })
                    });
                    console.log('[Billing] Setup email sent to', adminEmail);
                } catch (emailErr) {
                    console.error('[Billing] Setup email failed for', adminEmail, emailErr.message, '| Manual link:', setupLink);
                }

            } catch (err) {
                console.error('[Billing] Provisioning error for', tenantId, err.message);
                // Return 200 so Stripe doesn't retry — log for manual resolution
            }
            } // end if (tenantId && adminEmail)
        }

        if (event.type === 'customer.subscription.deleted') {
            // Deactivate tenant when subscription is cancelled
            const sub = event.data.object;
            const snap = await db.collection('tenants')
                .where('stripeSubscriptionId', '==', sub.id).limit(1).get();
            if (!snap.empty) {
                await snap.docs[0].ref.update({ active: false });
                console.log('[Billing] Deactivated tenant for subscription', sub.id);
            }
            // Also deactivate any resume builder subscriptions
            const builderSnap = await db.collection('builderSubscriptions')
                .where('stripeSubscriptionId', '==', sub.id).limit(1).get();
            if (!builderSnap.empty) {
                await builderSnap.docs[0].ref.update({ active: false });
                console.log('[Billing] Deactivated builder subscription for', sub.id);
            }
        }

        // Resume Builder subscription activation
        if (event.type === 'checkout.session.completed') {
            const session2 = event.data.object;
            if (session2.metadata && session2.metadata.product === 'resume-builder') {
                const email = (session2.metadata.email || session2.customer_email || '').toLowerCase();
                if (email) {
                    try {
                        await db.collection('builderSubscriptions').doc(email).set({
                            active: true,
                            stripeCustomerId: session2.customer,
                            stripeSubscriptionId: session2.subscription,
                            email,
                            createdAt: new Date().toISOString()
                        });
                        console.log('[Billing] Resume Builder subscription activated for', email);
                    } catch (err) {
                        console.error('[Billing] Builder sub activation error for', email, err.message);
                    }
                }
            }
        }

        res.json({ received: true });
    }
);

// ============================================================
// RESUME BUILDER BILLING ROUTES
// ============================================================

// Create Stripe Checkout Session for Resume Builder
app.post('/api/builder/checkout', async (req, res) => {
    try {
        if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
        const { email } = req.body;
        if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email is required' });

        const priceId = process.env.STRIPE_PRICE_BUILDER || 'price_1TKfmxLdhN0HRKYRdcAu2rwN';

        const session = await stripe.checkout.sessions.create({
            mode: 'subscription',
            payment_method_types: ['card'],
            customer_email: email,
            line_items: [{ price: priceId, quantity: 1 }],
            metadata: {
                product: 'resume-builder',
                email: email.toLowerCase()
            },
            success_url: `${process.env.SITE_URL || 'https://www.careersolutionsfortoday.com'}/resumebuilder.html?upgraded=1`,
            cancel_url:  `${process.env.SITE_URL || 'https://www.careersolutionsfortoday.com'}/resumebuilder.html?cancelled=1`,
        });
        res.json({ url: session.url });
    } catch (err) {
        console.error('[Builder] Checkout error:', err.message);
        res.status(500).json({ error: err.message || 'Failed to create checkout session' });
    }
});

// Check Resume Builder subscription status
app.get('/api/builder/check-subscription', async (req, res) => {
    try {
        const email = (req.query.email || '').toLowerCase().trim();
        if (!email) return res.json({ subscribed: false });
        if (!db) return res.json({ subscribed: false });
        const doc = await db.collection('builderSubscriptions').doc(email).get();
        if (doc.exists && doc.data().active) {
            return res.json({ subscribed: true });
        }
        if (doc.exists) {
            return res.json({ subscribed: false, hadSubscription: true });
        }
        res.json({ subscribed: false });
    } catch (err) {
        console.error('[Builder] Check subscription error:', err.message);
        res.json({ subscribed: false });
    }
});

// ============================================================
// RESUME BUILDER API ROUTES
// ============================================================

// Soft auth: tries to resolve user & tenant from token, but doesn't block if missing
async function optionalAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token || !adminInitialised) return next();
    try {
        const decoded = await auth.verifyIdToken(token);
        req.uid = decoded.uid;
        // Always try the real Firestore user doc first (has the actual tenantId)
        const doc = await db.collection('users').doc(decoded.uid).get();
        if (doc.exists) {
            req.userDoc = doc.data();
        } else if (OWNER_UIDS_ADMIN.includes(decoded.uid)) {
            req.userDoc = { tenantId: 'admin', role: 'admin', email: decoded.email || '' };
        }
    } catch (e) { /* ignore auth errors — continue without user context */ }
    next();
}

// ============================================================
// SERVER-SIDE USAGE ENFORCEMENT FOR RESUME BUILDER
// ============================================================

// Require a valid Firebase token — blocks unauthenticated requests
async function requireBuilderAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    if (!adminInitialised) return res.status(503).json({ error: 'Auth service unavailable' });
    try {
        const decoded = await auth.verifyIdToken(token);
        req.uid = decoded.uid;
        req.userEmail = (decoded.email || '').toLowerCase();
        const doc = await db.collection('users').doc(decoded.uid).get();
        if (doc.exists) {
            req.userDoc = doc.data();
        } else if (OWNER_UIDS_ADMIN.includes(decoded.uid)) {
            req.userDoc = { tenantId: 'admin', role: 'admin', email: decoded.email || '' };
        }
    } catch (e) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    next();
}

// Check builder usage quotas server-side before allowing AI calls
// Sets req.builderAccess with tier info for downstream use
async function checkBuilderQuota(req, res, next) {
    // Owners always pass
    if (OWNER_UIDS_ADMIN.includes(req.uid)) {
        req.builderAccess = { tier: 'owner' };
        return next();
    }
    try {
        // Check subscription status
        const subDoc = req.userEmail
            ? await db.collection('builderSubscriptions').doc(req.userEmail).get()
            : null;
        const isSubscriber = subDoc && subDoc.exists && subDoc.data().active === true;

        if (isSubscriber) {
            req.builderAccess = { tier: 'subscriber' };
            return next();
        }

        // Read usage doc
        const usageDoc = await db.collection('builderUsage').doc(req.uid).get();
        const usage = usageDoc.exists ? usageDoc.data() : {};

        const freeUsesCount = usage.count || 0;
        const singlePurchased = usage.singlePurchase || false;
        const singlePurchaseDate = usage.singlePurchaseDate
            ? (usage.singlePurchaseDate.toDate ? usage.singlePurchaseDate.toDate() : new Date(usage.singlePurchaseDate))
            : null;
        const aiUsesRemaining = usage.aiUsesRemaining ?? 0;

        // Single purchase active check (within 30 days)
        const singlePurchaseActive = singlePurchased && singlePurchaseDate
            && (Date.now() - singlePurchaseDate.getTime()) < 30 * 24 * 60 * 60 * 1000;

        // Free trial: freeUsesCount < 1 means they haven't used their free plan yet
        if (freeUsesCount < 1) {
            req.builderAccess = { tier: 'free_trial', aiUsesRemaining: 3 };
            return next();
        }

        // $1 single purchase with remaining AI uses
        if (singlePurchaseActive && aiUsesRemaining > 0) {
            req.builderAccess = { tier: 'single_purchase', aiUsesRemaining };
            return next();
        }

        // No valid access
        return res.status(403).json({
            error: 'Usage limit reached',
            code: 'QUOTA_EXCEEDED',
            message: singlePurchaseActive
                ? 'You have used all your AI uses for this purchase. Upgrade to a subscription for unlimited access.'
                : 'Your free trial has been used. Purchase a plan to continue.'
        });
    } catch (err) {
        console.error('[Builder] Quota check error:', err.message);
        // On error, allow the request through to avoid blocking legitimate users
        req.builderAccess = { tier: 'unknown' };
        next();
    }
}

// Deduct one AI use server-side (called after successful AI response)
async function deductAIUseServer(req) {
    if (!req.uid || !req.builderAccess) return;
    const { tier } = req.builderAccess;
    // Owners and subscribers don't get deducted
    if (tier === 'owner' || tier === 'subscriber') return;
    try {
        // Use Firestore increment to safely decrement (atomic operation)
        await db.collection('builderUsage').doc(req.uid).set({
            aiUsesRemaining: FieldValue.increment(-1),
            updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });
    } catch (e) {
        console.error('[Builder] Server-side AI deduct error:', e.message);
    }
}

// Helper: get OpenAI key from env or Firestore tenant settings (same key the Project Tracker uses)
async function getOpenAIKey(req) {
    // 1. Prefer env var if set
    if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;
    // 2. Fall back to tenant's stored AI key in Firestore
    if (db && req.userDoc && req.userDoc.tenantId) {
        const doc = await db.collection('tenants').doc(req.userDoc.tenantId)
            .collection('settings').doc('extended').get();
        if (doc.exists && doc.data().aiApiKey) return doc.data().aiApiKey;
    }
    // 3. For site owner: scan all tenants for a key (owner may not have a user doc)
    if (db && req.uid && OWNER_UIDS_ADMIN.includes(req.uid)) {
        const snap = await db.collection('tenants').limit(5).get();
        for (const tdoc of snap.docs) {
            const settingsDoc = await db.collection('tenants').doc(tdoc.id)
                .collection('settings').doc('extended').get();
            if (settingsDoc.exists && settingsDoc.data().aiApiKey) return settingsDoc.data().aiApiKey;
        }
    }
    // 4. For builder users without a tenant: scan all tenants for any available key
    if (db) {
        try {
            const snap = await db.collection('tenants').limit(5).get();
            for (const tdoc of snap.docs) {
                const settingsDoc = await db.collection('tenants').doc(tdoc.id)
                    .collection('settings').doc('extended').get();
                if (settingsDoc.exists && settingsDoc.data().aiApiKey) return settingsDoc.data().aiApiKey;
            }
        } catch (e) { console.warn('[getOpenAIKey] Tenant scan error:', e.message); }
    }
    return null;
}

// Helper: call OpenAI chat completions
async function callOpenAI(apiKey, systemPrompt, userPrompt, model, maxTokens, jsonMode, temperature) {
    const body = {
        model: model || 'gpt-4o',
        messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user',   content: userPrompt }
        ],
        max_tokens: maxTokens || 4000,
        temperature: temperature !== undefined ? temperature : 0.7
    };
    if (jsonMode) body.response_format = { type: 'json_object' };
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
        body: JSON.stringify(body)
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ? err.error.message : 'OpenAI API error ' + res.status);
    }
    const data = await res.json();
    if (!data.choices || !data.choices[0]) throw new Error('No response from OpenAI');
    return data.choices[0].message.content;
}

// Robustly extract JSON from an AI response string
function extractJSON(text) {
    // 1. Strip markdown code fences
    let cleaned = text.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim();
    // 2. Try direct parse first
    try { return JSON.parse(cleaned); } catch (_) {}
    // 3. Find the outermost { ... } in the string
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start !== -1 && end > start) {
        try { return JSON.parse(cleaned.slice(start, end + 1)); } catch (_) {}
    }
    return null;
}

// Helper: extract text from uploaded file buffer
async function extractTextFromFile(file) {
    const ext = (file.originalname || '').split('.').pop().toLowerCase();
    if (ext === 'pdf') {
        const data = await pdfParse(file.buffer);
        return data.text;
    }
    // For txt, docx (plain text fallback), and other text-based formats
    return file.buffer.toString('utf-8');
}

// Helper: call OpenAI chat completions with vision (text + PNG images)
async function callOpenAIWithImages(apiKey, systemPrompt, textContent, base64PngImages, model, maxTokens, jsonMode, temperature) {
    const userContent = [{ type: 'text', text: textContent }];
    for (const img of base64PngImages) {
        userContent.push({
            type: 'image_url',
            image_url: { url: `data:image/png;base64,${img}`, detail: 'high' }
        });
    }
    const body = {
        model: model || 'gpt-4o',
        messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userContent }
        ],
        max_tokens: maxTokens || 4000,
        temperature: temperature !== undefined ? temperature : 0.7
    };
    if (jsonMode) body.response_format = { type: 'json_object' };
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
        body: JSON.stringify(body)
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ? err.error.message : 'OpenAI API error ' + res.status);
    }
    const data = await res.json();
    if (!data.choices || !data.choices[0]) throw new Error('No response from OpenAI');
    return data.choices[0].message.content;
}

// POST /api/builder/parse-resume
// Accepts multipart: file OR text field
app.post('/api/builder/parse-resume', requireBuilderAuth, checkBuilderQuota, upload.single('file'), async (req, res) => {
    try {
        let resumeText = '';
        if (req.file) {
            resumeText = await extractTextFromFile(req.file);
        } else if (req.body && req.body.text) {
            resumeText = req.body.text;
        }
        if (!resumeText || !resumeText.trim()) {
            return res.status(400).json({ error: 'No resume content provided' });
        }

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'AI service temporarily unavailable. Please try again later.' });

        const systemPrompt = `You are a resume parsing expert that handles ANY text format — structured resumes, messy copy-paste, unformatted text dumps, bullet points, paragraph form, LinkedIn profile scrapes, or even text fragments. Extract whatever structured data you can find. Return ONLY valid JSON (no markdown fences) with this exact structure:
{
  "name": "Full Name (or 'Unknown' if not found)",
  "current_title": "Most Recent Job Title (or best guess from context)",
  "summary": "Brief professional summary or summary statement from the resume",
  "phone": "Phone number if found",
  "email": "Email if found",
  "address": "Full mailing address or City, State if found",
  "linkedin": "LinkedIn URL if found",
  "github": "GitHub URL if found",
  "website": "Personal website/portfolio URL if found",
  "twitter": "Twitter/X URL if found",
  "experience": [{"company":"Company Name","title":"Job Title","dates":"Date Range","location":"City, State","role_summary":"The paragraph description of the role before the bullet points","bullets":["Achievement 1","Achievement 2"]}],
  "skills": ["Skill 1","Skill 2"],
  "education": [{"degree":"Degree Name","school":"School Name","year":"Year"}],
  "certifications": [{"name":"Cert Name","issuer":"Issuing Organization","year":"Year","url":""}],
  "achievements": [{"title":"Achievement Title","description":"Description with quantified impact"}],
  "leadership_engagement": [{"title":"Role Title","organization":"Organization","description":"Description"}],
  "volunteer_experience": [{"organization":"Organization Name","role":"Role/Title","dates":"Date Range","description":"Description of contributions"}],
  "projects": [{"title":"Project Name","description":"Brief description","url":"URL if found","technologies":["Tech1","Tech2"]}],
  "languages": ["English (Native)","Spanish (Conversational)"]
}

CRITICAL: Be extremely flexible with input format. The text may be:
- A well-formatted resume with clear sections
- Raw text copied from LinkedIn or a website
- Unformatted fragments with no clear section headings
- A mix of bullet points and paragraphs with inconsistent formatting
- Jumbled text from a multi-column PDF where sidebar content is interleaved
- Simple text with just a name, job title, and a few sentences
NEVER fail — always return the best extraction possible from whatever input is given. If data is ambiguous, make your best guess. If a section has no data, use an empty string or empty array.

CRITICAL INSTRUCTIONS FOR EXPERIENCE EXTRACTION:
- The resume text may come from a multi-column PDF where text from sidebars (skills, education, contact info) is interleaved with the main content. Carefully separate sidebar content from experience content.
- Extract EVERY job/position listed. Do NOT skip or truncate any entries.
- For EACH job, extract ALL bullet points — even if there are 5, 8, or 10+ bullets per role.
- If a job has a paragraph description before the bullet points, include it in "role_summary".
- If a job title contains the company name (e.g. "Vice President, Faculty III | Chase Bank"), separate the title from the company name.
- Preserve the original wording of bullet points. Do not summarize or combine them.
- Pay special attention to associate-level, analyst, or junior positions — they are equally important as senior roles. Do NOT skip them.
- If bullet points or accomplishments appear separated from a job title by sidebar text (skills, contact info), associate them with the correct role based on context.
- Each experience entry MUST include the title, company, and ALL bullets found for that role. Never return an empty bullets array if the resume text contains achievements for that role.
VERIFICATION: After building the experience array, count the total number of distinct job titles/positions you extracted. Scan the resume text again for any position you missed. If the resume mentions more roles than you have in the array, go back and extract them.

BULLET ASSIGNMENT STRATEGY:
1. First pass: identify every distinct job header (title + company + date range) in the resume.
2. Build a skeleton: map each job header to its position in the document.
3. Second pass: for each bullet point or accomplishment, assign it to the job header that IMMEDIATELY PRECEDES it in the document flow. If sidebar text (skills, contact info, education) is interleaved between a job header and its bullets, skip over the sidebar text and still assign the bullets to the preceding job header.
4. NEVER assign a bullet to a role that comes later in the document or that has a date range inconsistent with the bullet's context.
5. If unsure, use the date range and job context to determine the correct assignment.
If a field cannot be determined, use an empty string or empty array. Extract every detail available — do not skip sections.`;

        // Check if client sent rendered PDF page images for vision-based parsing
        let pageImages = [];
        if (req.body && req.body.page_images_json) {
            try {
                pageImages = JSON.parse(req.body.page_images_json);
                console.log(`[Builder] Received ${pageImages.length} page image(s) from client for vision parsing`);
            } catch (e) {
                console.warn('[Builder] Failed to parse page_images_json, falling back to text-only');
            }
        }

        let result;
        if (pageImages.length > 0) {
            const visionUserText = `I have attached the actual resume pages as images so you can see the true layout (columns, sections, sidebar vs main content). Use the IMAGES as the PRIMARY source for understanding which bullets belong to which job role, and which sections are sidebar vs main content. Here is also the raw extracted text as a supplement:\n\n${resumeText}`;
            result = await callOpenAIWithImages(apiKey, systemPrompt, visionUserText, pageImages, 'gpt-4o', 16000, true, 0.2);
        } else {
            result = await callOpenAI(apiKey, systemPrompt, resumeText, 'gpt-4o', 16000, true, 0.2);
        }
        const resumeData = extractJSON(result);
        if (!resumeData) {
            console.error('[Builder] parse-resume: unparseable AI response:', result.slice(0, 500));
            return res.status(500).json({ error: 'Failed to parse AI response as JSON' });
        }

        await deductAIUseServer(req);
        res.json({ resume_data: resumeData, raw_text: resumeText });
    } catch (err) {
        console.error('[Builder] parse-resume error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/builder/enhance-resume
// AI-enhances resume content (experience bullets, summary, skills) for a target role
app.post('/api/builder/enhance-resume', requireBuilderAuth, checkBuilderQuota, express.json(), async (req, res) => {
    try {
        const { experience, skills, summary, job_description, job_title } = req.body || {};
        if (!experience && !skills && !summary) {
            return res.status(400).json({ error: 'No resume content provided to enhance' });
        }

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'AI service temporarily unavailable. Please try again later.' });

        const systemPrompt = `You are a professional resume writer and ATS optimization expert. Enhance the provided resume content to better target the specified role. 

Guidelines:
- Reword experience bullets to incorporate relevant keywords from the job description
- Make bullets achievement-oriented with quantified results where possible (use realistic metrics if not provided)
- Enhance the professional summary to align with the target role
- Reorder and augment skills to prioritize those matching the job description
- Maintain truthfulness — enhance wording, don't fabricate experience
- Keep bullets concise (1-2 lines each)
- Use strong action verbs to start each bullet

Return ONLY valid JSON (no markdown fences) with this structure:
{
  "experience": [{"company":"Same Company","title":"Same Title","dates":"Same Dates","location":"Same Location","bullets":["Enhanced bullet 1","Enhanced bullet 2"]}],
  "skills": ["Prioritized Skill 1","Skill 2"],
  "summary": "Enhanced professional summary targeting the role"
}`;

        const userPrompt = `Target Role: ${job_title || 'Not specified'}
Job Description: ${job_description || 'Not provided'}

Resume Content to Enhance:
${JSON.stringify({ experience, skills, summary }, null, 2)}`;

        const result = await callOpenAI(apiKey, systemPrompt, userPrompt, 'gpt-4o', 4000, true);
        const enhancedData = extractJSON(result);
        if (!enhancedData) {
            console.error('[Builder] enhance-resume: unparseable AI response:', result.slice(0, 500));
            return res.status(500).json({ error: 'Failed to parse AI enhancement response' });
        }

        await deductAIUseServer(req);
        res.json({ enhanced_data: enhancedData });
    } catch (err) {
        console.error('[Builder] enhance-resume error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/builder/research-role
app.post('/api/builder/research-role', requireBuilderAuth, checkBuilderQuota, express.json(), async (req, res) => {
    try {
        const { job_title, company, job_description } = req.body || {};
        if (!job_title) return res.status(400).json({ error: 'job_title is required' });

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'AI service temporarily unavailable. Please try again later.' });

        const systemPrompt = `You are a career research expert. Analyze the target role and provide insights. Return ONLY valid JSON (no markdown fences) with this structure:
{
  "role_summary": "Overview of the role and its importance",
  "key_responsibilities": ["Responsibility 1","Responsibility 2","Responsibility 3"],
  "critical_skills": ["Skill 1","Skill 2","Skill 3"],
  "company_context": "Brief context about the company if provided, otherwise 'Not specified'"
}`;

        const userPrompt = `Target Role: ${job_title}\nCompany: ${company || 'Not specified'}\nJob Description: ${job_description || 'Not provided'}`;

        const result = await callOpenAI(apiKey, systemPrompt, userPrompt, 'gpt-4o', 4000, true);
        const roleResearch = extractJSON(result);
        if (!roleResearch) {
            console.error('[Builder] research-role: unparseable AI response:', result.slice(0, 500));
            return res.status(500).json({ error: 'Failed to parse AI response as JSON' });
        }

        await deductAIUseServer(req);
        res.json({ role_research: roleResearch });
    } catch (err) {
        console.error('[Builder] research-role error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// GET /api/builder/plan-count — returns how many plans a user has
app.get('/api/builder/plan-count', optionalAuth, async (req, res) => {
    try {
        if (!req.uid) return res.json({ count: 0 });
        if (!db) return res.json({ count: 0 });
        const snap = await db.collection('plans').where('userId', '==', req.uid).count().get();
        res.json({ count: snap.data().count || 0 });
    } catch (err) {
        console.error('[Builder] plan-count error:', err.message);
        res.json({ count: 0 });
    }
});

const MAX_PLANS_SUBSCRIBER = 5;

// POST /api/builder/generate
app.post('/api/builder/generate', requireBuilderAuth, checkBuilderQuota, express.json(), async (req, res) => {
    try {
        const { resume_data, role_context, plan_type, sections, job_description, plan_context } = req.body || {};

        // Server-side plan limit: subscribers can have up to 5 plans (owners exempt)
        if (db && req.uid && !OWNER_UIDS_ADMIN.includes(req.uid)) {
            if (!req.body.editing_plan_id) {
                const snap = await db.collection('plans').where('userId', '==', req.uid).count().get();
                const planCount = snap.data().count || 0;
                if (planCount >= MAX_PLANS_SUBSCRIBER) {
                    return res.status(403).json({ error: `You've reached the maximum of ${MAX_PLANS_SUBSCRIBER} plans. Please delete an existing plan to create a new one.` });
                }
            }
        }
        if (!resume_data || !plan_type) return res.status(400).json({ error: 'resume_data and plan_type are required' });

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'AI service temporarily unavailable. Please try again later.' });

        const sectionList = (sections || ['plan']).join(', ');

        // Build timeframe guidance based on plan type
        let timeframeGuidance;
        if (plan_type === '12-month') {
            timeframeGuidance = 'Use MONTH-based timeframes for each phase, e.g. "Months 1-3", "Months 4-6", "Months 7-9", "Months 10-12". Do NOT use day-based timeframes like "Days 1-90".';
        } else if (plan_type === '2-year') {
            timeframeGuidance = 'Use MONTH-based timeframes for each phase, e.g. "Months 1-6", "Months 7-12", "Months 13-18", "Months 19-24". Do NOT use day-based timeframes.';
        } else {
            timeframeGuidance = 'Use day-based timeframes for each phase, e.g. "Days 1-30", "Days 31-60", "Days 61-90".';
        }

        // Include plan context if provided
        const planContextNote = plan_context ? `\n\nADDITIONAL PLAN CONTEXT FROM THE USER (incorporate this into the plan strategy and phases):\n${plan_context}` : '';

        const systemPrompt = `You are an expert career coach and executive resume strategist. Generate a comprehensive, deeply detailed ${plan_type} career plan and resume content.${planContextNote}

CRITICAL: The executive_summary, plan_phases, and ALL plan content must be written in FIRST PERSON voice from the candidate's perspective. Use "I", "my", "I will", "I bring" — NEVER refer to the candidate in the third person (do NOT write "The purpose of this plan is to align [Name] with..." or "[Name] brings..."). This is the candidate's own plan, presented in their own voice.

CRITICAL: Identify key skills, qualifications, terminology, and keywords from the job description provided. Weave these keywords naturally throughout the plan phases, executive summary, success criteria, and skills to demonstrate direct alignment between the candidate's experience and the target role requirements. This keyword alignment is essential for the content to be compelling.

Return ONLY valid JSON (no markdown fences) with this EXACT structure:
{
  "hero": {
    "name": "Candidate Full Name",
    "target_title": "Target Role Title",
    "subtitle": "Current title or tagline",
    "company": "Target Company",
    "plan_type": "${plan_type}",
    "tagline": "A detailed 3-5 sentence professional tagline (at least 60 words). Describe the candidate's core expertise, years of relevant experience, specific domain strengths, quantified career highlights (e.g. managed $X portfolios, led X-person teams, delivered X% improvements), and their unique value proposition for this specific role. Reference key qualifications from the job description. This should read like a polished executive brief — substantive and specific, not generic."
  },
  "executive_summary": "A detailed 3-4 paragraph executive summary written in FIRST PERSON. First paragraph: my strategic vision for the role and what I aim to accomplish. Second paragraph: my unique qualifications and how they align with the role. Third paragraph: the expected outcomes and measurable impact I will deliver. Fourth paragraph (if applicable): my forward-looking strategic direction. Make this substantive — at least 200 words.",
  "plan_phases": [
    {
      "phase": "PHASE 1",
      "label": "Phase Label (e.g. Assess & Diagnose)",
      "title": "Descriptive Phase Title",
      "timeframe": "Days 1-30",
      "objective": "One clear sentence describing the phase objective",
      "actions": ["Detailed action 1 — be specific and include context", "Action 2", "Action 3", "Action 4", "Action 5"],
      "tools_and_technology": [{"name": "Tool/System Name", "description": "What it does and how it helps"}, {"name": "Tool 2", "description": "Description"}],
      "milestones": ["Specific measurable milestone 1", "Milestone 2", "Milestone 3", "Milestone 4", "Milestone 5"],
      "executive_value": "A full paragraph explaining the executive-level business value of completing this phase. Why does this matter to leadership? What risk does it mitigate? What value does it create?"
    }
  ],
  "success_summary": ["Specific measurable outcome by end of plan", "Second outcome", "Third outcome", "Fourth outcome", "Fifth outcome", "Sixth outcome"],
  "kpis": [
    {"metric": "KPI Name", "target": "Target Value", "icon": "target"}
  ],
  "success_criteria": ["Criterion 1 — specific and measurable", "Criterion 2", "Criterion 3"],
  "experience": [
    {"title": "Job Title", "company": "Company Name", "dates": "Date Range", "location": "City, State", "bullets": ["Achievement with quantified impact", "Another achievement"]}
  ],
  "leadership_engagement": [
    {"title": "Leadership Role Title", "organization": "Organization/Program Name", "description": "Brief description of the role and impact"}
  ],
  "skills": ["Skill 1", "Skill 2"],
  "education": [{"degree": "Degree Name", "school": "School Name", "year": "Year"}],
  "certifications": [{"name": "Cert Name", "issuer": "Issuer", "year": "Year", "url": ""}],
  "achievements": [{"title": "Achievement Title", "description": "Detailed description with quantified impact", "icon": "award"}],
  "leadership": [{"role": "Role Name", "description": "Description"}]
}

IMPORTANT GUIDELINES:
- For plan_phases: You MUST generate EXACTLY 3 phases for 90-day plans, 4 for 12-month, 4 for 2-year plans. Do NOT stop after Phase 1. Every phase must be fully detailed with all fields populated.
- TIMEFRAME FORMAT: ${timeframeGuidance}
- Each phase MUST have at least 5 detailed actions, 2+ tools, 5 milestones, and a substantial executive_value paragraph
- The executive_summary must be at least 200 words and deeply reference the job requirements
- Experience: Preserve ALL jobs from the resume data. Do NOT drop, merge, or skip any positions. Include ALL original bullets for each job — reword them to emphasize alignment with the target role, but never reduce the bullet count.
- Skills should include both the candidate's existing skills AND key skills from the job description
- KPIs should have 6-8 specific metrics with realistic targets
- Achievements: Extract achievements from the resume data (quantified results, promotions, awards) AND generate additional relevant achievements. Each must have quantified impact (revenue, percentages, team sizes, cost savings).
- Include sections: ${sectionList}. For any section not in the list, include a minimal placeholder array/object.
- CRITICAL: Your response must contain the COMPLETE JSON object with ALL sections fully populated. Do not truncate or cut short any section. Every array must contain all its items.`;

        const userPrompt = `Resume Data: ${JSON.stringify(resume_data)}

Target Role Context: ${JSON.stringify(role_context || {})}

Job Description (use keywords from this): ${job_description || 'Not provided'}

Plan Type: ${plan_type}
Sections to emphasize: ${sectionList}

Generate deeply detailed, rich content for each section. Match the depth and quality of a professional executive-level career plan website.`;

        const result = await callOpenAI(apiKey, systemPrompt, userPrompt, 'gpt-4o', 16000, true);
        const generated = extractJSON(result);
        if (!generated) {
            console.error('[Builder] generate: unparseable AI response:', result.slice(0, 500));
            return res.status(500).json({ error: 'Failed to parse AI response as JSON' });
        }

        await deductAIUseServer(req);
        res.json({ generated });
    } catch (err) {
        console.error('[Builder] generate error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/builder/career-path
app.post('/api/builder/career-path', requireBuilderAuth, checkBuilderQuota, express.json(), async (req, res) => {
    try {
        const { current_role, target_role, target_company, skills, experience, education } = req.body || {};
        if (!target_role) return res.status(400).json({ error: 'target_role is required' });

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'AI service temporarily unavailable. Please try again later.' });

        const systemPrompt = `You are an expert career advisor. Generate a detailed career path roadmap. Return ONLY valid JSON (no markdown fences) with this structure:
{
  "current_assessment": "Assessment of current position and strengths",
  "target_analysis": "What the target role requires and why it's a good fit",
  "gap_analysis": ["Skill or experience gap 1", "Gap 2", "Gap 3"],
  "milestones": [
    { "title": "Milestone title", "timeframe": "0-3 months", "actions": ["Specific action 1", "Action 2"], "skills_to_develop": ["Skill 1"] }
  ],
  "recommended_certifications": ["Certification 1", "Certification 2"],
  "networking_strategy": "Detailed networking advice for this career transition",
  "timeline_estimate": "Estimated time to reach the target role"
}
Generate 4-6 milestones with realistic timeframes. Be specific and actionable.`;

        const userPrompt = `Current Role: ${current_role || 'Not specified'}
Target Role: ${target_role}
Target Company: ${target_company || 'Not specified'}
Current Skills: ${JSON.stringify(skills || [])}
Experience: ${JSON.stringify(experience || [])}
Education: ${JSON.stringify(education || [])}`;

        const result = await callOpenAI(apiKey, systemPrompt, userPrompt, 'gpt-4o', 4000, true);
        const careerPath = extractJSON(result);
        if (!careerPath) return res.status(500).json({ error: 'Failed to parse career path response' });

        await deductAIUseServer(req);
        res.json(careerPath);
    } catch (err) {
        console.error('[Builder] career-path error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// LINKEDIN IMPORT ENDPOINTS
// ============================================================

// Helper: detect LinkedIn login/auth wall page
function isLinkedInLoginPage(title, desc) {
    const combined = ((title || '') + ' ' + (desc || '')).toLowerCase();
    const loginIndicators = ['linkedin login', 'sign in', 'log in', 'join now'];
    if (loginIndicators.some(ind => combined.includes(ind)) && !combined.includes('hiring')) return true;
    if (combined.includes('keep in touch with people you know')) return true;
    return false;
}

// Helper: extract job ID from LinkedIn URL
function extractLinkedInJobId(url) {
    const m1 = url.match(/\/jobs\/view\/(\d+)/);
    if (m1) return m1[1];
    const m2 = url.match(/currentJobId=(\d+)/);
    if (m2) return m2[1];
    const m3 = url.match(/\/jobs\/(\d+)/);
    if (m3) return m3[1];
    return '';
}

// Helper: HTML entity decode
function htmlDecode(str) {
    if (!str) return '';
    return str.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
              .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

// Helper: fetch URL with multiple User-Agent strategies (tries different UAs)
const FETCH_USER_AGENTS = [
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
];
async function fetchWithGooglebot(url) {
    let lastError;
    for (const ua of FETCH_USER_AGENTS) {
        try {
            const response = await fetch(url, {
                headers: {
                    'User-Agent': ua,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                },
                redirect: 'follow',
            });
            const html = await response.text();
            // If we got meaningful content (not a blank/tiny page), return it
            if (html.length > 500) return html;
        } catch (e) { lastError = e; }
    }
    if (lastError) throw lastError;
    return '';
}

// Helper: extract meta from HTML
function extractMeta(html) {
    const ogTitle = html.match(/<meta[^>]*property="og:title"[^>]*content="([^"]+)"/i);
    const ogDesc = html.match(/<meta[^>]*property="og:description"[^>]*content="([^"]+)"/i);
    const titleTag = html.match(/<title[^>]*>(.*?)<\/title>/is);
    const descMeta = html.match(/<meta[^>]*name="description"[^>]*content="([^"]+)"/i);
    const ldJson = html.match(/<script[^>]*type="application\/ld\+json"[^>]*>(.*?)<\/script>/is);

    // Try to extract full job description from HTML body (LinkedIn public pages)
    let bodyDesc = '';
    const bodyPatterns = [
        /<div[^>]*class="[^"]*show-more-less-html__markup[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
        /<div[^>]*class="[^"]*description__text[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
        /<section[^>]*class="[^"]*show-more-less-html[^"]*"[^>]*>([\s\S]*?)<\/section>/i,
        /<div[^>]*class="[^"]*jobs-description-content__text[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
    ];
    for (const pat of bodyPatterns) {
        const m = html.match(pat);
        if (m && m[1]) {
            bodyDesc = m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
            if (bodyDesc.length > 100) break;
        }
    }

    return {
        title: (ogTitle ? ogTitle[1] : titleTag ? titleTag[1] : '').trim(),
        desc: (ogDesc ? ogDesc[1] : descMeta ? descMeta[1] : '').trim(),
        bodyDesc: bodyDesc.slice(0, 5000),
        structured: ldJson ? ldJson[1].trim() : '',
    };
}

// POST /api/builder/import-linkedin-profile
app.post('/api/builder/import-linkedin-profile', optionalAuth, express.json(), async (req, res) => {
    try {
        const { url } = req.body || {};
        if (!url || !url.includes('linkedin.com/in/')) {
            return res.status(400).json({ error: 'Please provide a valid LinkedIn profile URL' });
        }

        // Fetch with Googlebot UA
        let pageContent = '';
        try {
            pageContent = await fetchWithGooglebot(url);
        } catch(e) {
            console.error('[LinkedIn import] Fetch error:', e.message);
        }

        const meta = extractMeta(pageContent);

        // Detect login page
        if (isLinkedInLoginPage(meta.title, meta.desc) || (!meta.title && !meta.desc)) {
            return res.status(422).json({
                error: 'LinkedIn requires authentication to view profiles. Please try one of these alternatives:\n\n1. Download your LinkedIn profile as PDF (Profile > More > Save to PDF) and upload it in the file upload area\n2. Copy your profile text and paste it in the text area\n3. Manually enter your information in the contact fields'
            });
        }

        // Try regex-based extraction: "FirstName LastName - Title - Company | LinkedIn"
        const profilePattern = meta.title.match(/^(.+?)\s*[-–—]\s*(.+?)\s*[-–—]\s*(.+?)\s*[|]\s*LinkedIn/);
        let parsedDirect = null;
        if (profilePattern) {
            parsedDirect = {
                name: htmlDecode(profilePattern[1].trim()),
                current_title: htmlDecode(profilePattern[2].trim()),
                current_company: htmlDecode(profilePattern[3].trim()),
                linkedin: url,
                summary: htmlDecode(meta.desc),
                experience: [{ title: htmlDecode(profilePattern[2].trim()), company: htmlDecode(profilePattern[3].trim()), location: '', dates: '', bullets: [] }],
                education: [], skills: [], certifications: [],
                email: '', phone: '', location: ''
            };
        } else if (meta.title.includes(' - ') && meta.title.includes('LinkedIn')) {
            const parts = meta.title.replace(/\s*[|]\s*LinkedIn.*$/, '').split(/\s*[-–—]\s*/);
            const name = htmlDecode((parts[0] || '').trim());
            const title = htmlDecode((parts[1] || '').trim());
            const company = htmlDecode((parts[2] || '').trim());
            if (name) {
                parsedDirect = {
                    name, current_title: title, current_company: company,
                    linkedin: url, summary: htmlDecode(meta.desc),
                    experience: title ? [{ title, company, location: '', dates: '', bullets: [] }] : [],
                    education: [], skills: [], certifications: [],
                    email: '', phone: '', location: ''
                };
            }
        }

        // If regex extraction worked, return without AI
        if (parsedDirect && parsedDirect.name) {
            return res.json({ resume_data: parsedDirect });
        }

        // Try AI parsing as fallback
        const apiKey = await getOpenAIKey(req);
        if (apiKey) {
            const scrapedText = `LinkedIn URL: ${url}\nPage Title: ${meta.title}\nPage Description: ${meta.desc}${meta.structured ? '\nStructured Data: ' + meta.structured.slice(0, 2000) : ''}`;
            const systemPrompt = `You are a resume parser. Given this LinkedIn profile data, extract and enhance it into structured resume JSON. Return ONLY valid JSON with this structure: {"name":"","current_title":"","summary":"","email":"","phone":"","linkedin":"","location":"","experience":[],"skills":[],"education":[],"certifications":[]}. Fill in what you can from the data. For empty fields, use empty strings/arrays.`;
            const result = await callOpenAI(apiKey, systemPrompt, scrapedText, 'gpt-4o', 4000, true);
            const parsed = extractJSON(result);
            if (parsed) {
                parsed.linkedin = url;
                return res.json({ resume_data: parsed });
            }
        }

        // Last fallback: return whatever meta we got
        if (meta.title) {
            return res.json({
                resume_data: {
                    name: htmlDecode(meta.title.split(/\s*[-–—|]\s*/)[0] || ''),
                    current_title: '', summary: htmlDecode(meta.desc),
                    linkedin: url, location: '', experience: [], skills: [],
                    education: [], certifications: [], email: '', phone: ''
                }
            });
        }

        return res.status(422).json({
            error: 'LinkedIn blocked the request. Please download your profile as PDF (Profile → More → Save to PDF) and upload it instead.'
        });
    } catch(err) {
        console.error('[Builder] import-linkedin-profile error:', err.message);
        res.status(500).json({ error: 'Failed to import LinkedIn profile: ' + err.message });
    }
});

// POST /api/builder/import-linkedin-job
app.post('/api/builder/import-linkedin-job', optionalAuth, express.json(), async (req, res) => {
    try {
        const { url } = req.body || {};
        if (!url || (!url.includes('linkedin.com/job') && !url.includes('currentJobId'))) {
            return res.status(400).json({ error: 'Please provide a valid LinkedIn job URL' });
        }

        // Extract job ID and try the public /jobs/view/ URL first
        const jobId = extractLinkedInJobId(url);
        let meta = { title: '', desc: '', structured: '' };

        // Try public job view URL with Googlebot UA
        if (jobId) {
            try {
                const html = await fetchWithGooglebot(`https://www.linkedin.com/jobs/view/${jobId}`);
                meta = extractMeta(html);
            } catch(e) {
                console.warn('[LinkedIn job] Guest fetch failed:', e.message);
            }
        }

        // Fallback: try original URL if guest fetch didn't get data
        if (!meta.title && !meta.desc) {
            try {
                const html = await fetchWithGooglebot(url);
                meta = extractMeta(html);
            } catch(e) {
                console.warn('[LinkedIn job] URL fetch failed:', e.message);
            }
        }

        // Detect login page
        if (isLinkedInLoginPage(meta.title, meta.desc)) {
            return res.status(422).json({
                error: 'LinkedIn requires authentication to view this job posting. Please try:\n\n1. Open the job in LinkedIn, copy the job title, company, and description\n2. Paste them directly into the fields below\n3. Or try using the direct job link format: linkedin.com/jobs/view/[jobId]'
            });
        }

        // Try structured data (ld+json) first
        if (meta.structured) {
            try {
                const sd = JSON.parse(meta.structured);
                if (sd && sd.title) {
                    return res.json({
                        job_title: htmlDecode(sd.title || ''),
                        company: htmlDecode((sd.hiringOrganization && sd.hiringOrganization.name) || ''),
                        location: (sd.jobLocation && sd.jobLocation[0] && sd.jobLocation[0].address)
                            ? htmlDecode(sd.jobLocation[0].address.addressLocality || '') : '',
                        description: htmlDecode((sd.description || '').slice(0, 5000))
                    });
                }
            } catch(e) { /* ignore JSON parse errors */ }
        }

        // Regex-based parsing from LinkedIn title: "[Company] hiring [Title] in [Location] | LinkedIn"
        const hiringMatch = meta.title.match(/^(.+?)\s+hiring\s+(.+?)\s+in\s+(.+?)\s*[|]\s*LinkedIn/);
        if (hiringMatch) {
            return res.json({
                job_title: htmlDecode(hiringMatch[2].trim()),
                company: htmlDecode(hiringMatch[1].trim()),
                location: htmlDecode(hiringMatch[3].trim()),
                description: htmlDecode(meta.bodyDesc || meta.desc)
            });
        }
        // Looser match: "[Company] hiring [Title] | LinkedIn"
        if (meta.title.includes(' hiring ')) {
            const parts = meta.title.split(' hiring ');
            const company = htmlDecode(parts[0].trim());
            let rest = parts[1] || '';
            rest = rest.replace(/\s*[|]\s*LinkedIn.*$/, '');
            const locMatch = rest.match(/\s+in\s+(.+)$/);
            const location = locMatch ? htmlDecode(locMatch[1].trim()) : '';
            const jobTitle = locMatch ? htmlDecode(rest.slice(0, locMatch.index).trim()) : htmlDecode(rest.trim());
            if (jobTitle) {
                return res.json({ job_title: jobTitle, company, location, description: htmlDecode(meta.bodyDesc || meta.desc) });
            }
        }

        // Fallback: try AI parsing
        if (meta.title || meta.desc) {
            const apiKey = await getOpenAIKey(req);
            if (apiKey) {
                const systemPrompt = `Given this LinkedIn job posting data, extract the job title, company name, location, and job description. Return ONLY valid JSON: {"job_title":"","company":"","location":"","description":""}. If data looks like a login page, return {"error":"login_page"}.`;
                const userText = `Title: ${meta.title}\nDescription: ${meta.bodyDesc || meta.desc}`;
                const result = await callOpenAI(apiKey, systemPrompt, userText, 'gpt-4o', 4000, true);
                const parsed = extractJSON(result);
                if (parsed && !parsed.error) return res.json(parsed);
            }
            // Last fallback: return raw meta
            const parts = meta.title.split(/\s*[-–—|]\s*/);
            return res.json({ job_title: htmlDecode(parts[0] || ''), company: htmlDecode(parts[1] || ''), location: '', description: htmlDecode(meta.desc) });
        }

        return res.status(422).json({
            error: 'Could not extract job details. LinkedIn may have blocked the request. Please copy and paste the job details manually.'
        });
    } catch(err) {
        console.error('[Builder] import-linkedin-job error:', err.message);
        res.status(500).json({ error: 'Failed to import LinkedIn job: ' + err.message });
    }
});

// ============================================================
// YOUTUBE MEMBERSHIP VERIFICATION (OAuth flow)
// ============================================================
// Requires env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
// YT_OWNER_REFRESH_TOKEN (channel owner's token with
// youtube.channel-memberships.creator scope)

// Step 1: Return a Google OAuth consent URL for the user
app.get('/api/builder/youtube-auth-url', (req, res) => {
    const email = (req.query.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email is required' });
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        return res.status(503).json({ error: 'YouTube verification is not configured yet. Please try again later.' });
    }
    try {
        const oauth2Client = createYTOAuthClient();
        // state carries the user email so callback can associate the result
        const state = Buffer.from(JSON.stringify({ email })).toString('base64url');
        const url = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            prompt: 'consent',
            scope: ['https://www.googleapis.com/auth/youtube.readonly'],
            state
        });
        res.json({ url });
    } catch (err) {
        console.error('[YT Auth] Error generating auth URL:', err.message);
        res.status(500).json({ error: 'Failed to generate YouTube auth URL' });
    }
});

// Step 2: OAuth callback — identify user's channel, check membership via owner token
app.get('/api/builder/youtube-callback', async (req, res) => {
    const { code, state, error: oauthError } = req.query;

    // Helper to send result back to popup opener
    function sendPopupResult(type, message) {
        const escaped = (message || '').replace(/'/g, "\\'").replace(/</g, '&lt;');
        const origin = process.env.SITE_URL || 'https://www.careersolutionsfortoday.com';
        return res.send(`<!DOCTYPE html><html><head><title>YouTube Verification</title></head><body>
            <p>${type === 'yt-membership-verified' ? '&#10003; Membership verified! This window will close.' : escaped}</p>
            <script>
                if (window.opener) {
                    window.opener.postMessage({ type: '${type}', message: '${escaped}' }, '${origin}');
                }
                setTimeout(function() { window.close(); }, 2000);
            </script>
        </body></html>`);
    }

    if (oauthError) {
        console.error('[YT Callback] OAuth error:', oauthError);
        return sendPopupResult('yt-membership-failed', 'Authorization was cancelled or denied.');
    }

    if (!code || !state) {
        return sendPopupResult('yt-membership-failed', 'Invalid callback parameters.');
    }

    let email;
    try {
        const parsed = JSON.parse(Buffer.from(state, 'base64url').toString());
        email = (parsed.email || '').toLowerCase().trim();
    } catch {
        return sendPopupResult('yt-membership-failed', 'Invalid state parameter.');
    }

    if (!email) {
        return sendPopupResult('yt-membership-failed', 'Could not determine user email.');
    }

    try {
        // Exchange authorization code for user tokens
        const oauth2Client = createYTOAuthClient();
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);

        // Get the user's YouTube channel ID
        const youtube = google.youtube({ version: 'v3', auth: oauth2Client });
        const channelsRes = await youtube.channels.list({ part: 'id,snippet', mine: true });
        const userChannels = channelsRes.data.items || [];
        if (userChannels.length === 0) {
            return sendPopupResult('yt-membership-failed', 'No YouTube channel found for your Google account. Please make sure you have a YouTube channel.');
        }
        const userChannelId = userChannels[0].id;
        console.log(`[YT Callback] User ${email} has channel ${userChannelId}`);

        // Check membership using channel owner's stored refresh token
        if (!YT_OWNER_REFRESH_TOKEN) {
            return sendPopupResult('yt-membership-failed', 'YouTube membership verification is not fully configured. Please contact support.');
        }
        const ownerClient = createYTOAuthClient();
        ownerClient.setCredentials({ refresh_token: YT_OWNER_REFRESH_TOKEN });

        const ownerYT = google.youtube({ version: 'v3', auth: ownerClient });
        const membersRes = await ownerYT.memberships.list({
            part: 'snippet',
            mode: 'list_members',
            filterByMemberChannelId: userChannelId
        });

        const members = membersRes.data.items || [];
        if (members.length > 0) {
            // Membership confirmed — save to Firestore
            console.log(`[YT Callback] Membership VERIFIED for ${email} (channel ${userChannelId})`);
            if (db) {
                await db.collection('builderSubscriptions').doc(email).set({
                    active: true,
                    source: 'youtube-membership',
                    ytChannelId: userChannelId,
                    verifiedAt: FieldValue.serverTimestamp()
                }, { merge: true });
            }
            return sendPopupResult('yt-membership-verified', 'YouTube membership verified!');
        } else {
            console.log(`[YT Callback] No membership found for ${email} (channel ${userChannelId})`);
            return sendPopupResult('yt-membership-failed', 'YouTube membership not found. Please join the channel first, then try again.');
        }
    } catch (err) {
        console.error('[YT Callback] Error:', err.message);
        // Specific error for memberships API not available
        if (err.message && err.message.includes('memberships')) {
            return sendPopupResult('yt-membership-failed', 'YouTube memberships API is not available for this channel. Please contact support.');
        }
        return sendPopupResult('yt-membership-failed', 'Verification failed: ' + (err.message || 'Unknown error'));
    }
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
