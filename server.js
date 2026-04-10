require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const admin   = require('firebase-admin');
const { getFirestore } = require('firebase-admin/firestore');
const Stripe  = require('stripe');
const multer  = require('multer');
const pdfParse = require('pdf-parse');

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

            if (!tenantId || !adminEmail) {
                console.error('[Billing] Missing metadata on session', session.id);
                return res.status(400).send('Missing metadata');
            }

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
        }

        res.json({ received: true });
    }
);

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
    return null;
}

// Helper: call OpenAI chat completions
async function callOpenAI(apiKey, systemPrompt, userPrompt, model, maxTokens, jsonMode) {
    const body = {
        model: model || 'gpt-4o',
        messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user',   content: userPrompt }
        ],
        max_tokens: maxTokens || 4000,
        temperature: 0.7
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

// POST /api/builder/parse-resume
// Accepts multipart: file OR text field
app.post('/api/builder/parse-resume', optionalAuth, upload.single('file'), async (req, res) => {
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
        if (!apiKey) return res.status(500).json({ error: 'No AI API key found. Configure one in Project Tracker Admin → AI Settings, or set OPENAI_API_KEY env var.' });

        const systemPrompt = `You are a resume parsing expert. Extract structured data from the resume text provided. Return ONLY valid JSON (no markdown fences) with this exact structure:
{
  "name": "Full Name",
  "current_title": "Most Recent Job Title",
  "summary": "Brief professional summary",
  "phone": "Phone number if found",
  "email": "Email if found",
  "address": "Full mailing address or City, State if found",
  "linkedin": "LinkedIn URL if found",
  "github": "GitHub URL if found",
  "website": "Personal website/portfolio URL if found",
  "twitter": "Twitter/X URL if found",
  "experience": [{"company":"Company Name","title":"Job Title","dates":"Date Range","location":"City, State","bullets":["Achievement 1","Achievement 2"]}],
  "skills": ["Skill 1","Skill 2"],
  "education": [{"degree":"Degree Name","school":"School Name","year":"Year"}],
  "certifications": [{"name":"Cert Name","issuer":"Issuing Organization","year":"Year","url":""}],
  "achievements": [{"title":"Achievement Title","description":"Description with quantified impact"}],
  "leadership_engagement": [{"title":"Role Title","organization":"Organization","description":"Description"}],
  "volunteer_experience": [{"organization":"Organization Name","role":"Role/Title","dates":"Date Range","description":"Description of contributions"}],
  "projects": [{"title":"Project Name","description":"Brief description","url":"URL if found","technologies":["Tech1","Tech2"]}],
  "languages": ["English (Native)","Spanish (Conversational)"]
}
If a field cannot be determined, use an empty string or empty array. Extract every detail available — do not skip sections.`;

        const result = await callOpenAI(apiKey, systemPrompt, resumeText, 'gpt-4o', 4000, true);
        const resumeData = extractJSON(result);
        if (!resumeData) {
            console.error('[Builder] parse-resume: unparseable AI response:', result.slice(0, 500));
            return res.status(500).json({ error: 'Failed to parse AI response as JSON' });
        }

        res.json({ resume_data: resumeData, raw_text: resumeText });
    } catch (err) {
        console.error('[Builder] parse-resume error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/builder/enhance-resume
// AI-enhances resume content (experience bullets, summary, skills) for a target role
app.post('/api/builder/enhance-resume', optionalAuth, express.json(), async (req, res) => {
    try {
        const { experience, skills, summary, job_description, job_title } = req.body || {};
        if (!experience && !skills && !summary) {
            return res.status(400).json({ error: 'No resume content provided to enhance' });
        }

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'No AI API key found.' });

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

        res.json({ enhanced_data: enhancedData });
    } catch (err) {
        console.error('[Builder] enhance-resume error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/builder/research-role
app.post('/api/builder/research-role', optionalAuth, express.json(), async (req, res) => {
    try {
        const { job_title, company, job_description } = req.body || {};
        if (!job_title) return res.status(400).json({ error: 'job_title is required' });

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'No AI API key found. Configure one in Project Tracker Admin → AI Settings, or set OPENAI_API_KEY env var.' });

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

        res.json({ role_research: roleResearch });
    } catch (err) {
        console.error('[Builder] research-role error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/builder/generate
app.post('/api/builder/generate', optionalAuth, express.json(), async (req, res) => {
    try {
        const { resume_data, role_context, plan_type, sections, job_description } = req.body || {};
        if (!resume_data || !plan_type) return res.status(400).json({ error: 'resume_data and plan_type are required' });

        const apiKey = await getOpenAIKey(req);
        if (!apiKey) return res.status(500).json({ error: 'No AI API key found. Configure one in Project Tracker Admin → AI Settings, or set OPENAI_API_KEY env var.' });

        const sectionList = (sections || ['plan']).join(', ');
        const systemPrompt = `You are an expert career coach and executive resume strategist. Generate a comprehensive, deeply detailed ${plan_type} career plan and resume content.

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
    "tagline": "A compelling 2-sentence professional tagline describing the candidate's value proposition for this specific role"
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
- For plan_phases: Generate 3 phases for 90-day plans, 4 for 12-month, 4 for 2-year plans
- Each phase MUST have at least 5 detailed actions, 2+ tools, 5 milestones, and a substantial executive_value paragraph
- The executive_summary must be at least 200 words and deeply reference the job requirements
- Experience should be tailored from the resume data — rewrite bullets to emphasize alignment with the target role
- Skills should include both the candidate's existing skills AND key skills from the job description
- KPIs should have 6-8 specific metrics with realistic targets
- Achievements should highlight quantified impact (revenue, percentages, team sizes)
- Include sections: ${sectionList}. For any section not in the list, include a minimal placeholder array/object.`;

        const userPrompt = `Resume Data: ${JSON.stringify(resume_data)}

Target Role Context: ${JSON.stringify(role_context || {})}

Job Description (use keywords from this): ${job_description || 'Not provided'}

Plan Type: ${plan_type}
Sections to emphasize: ${sectionList}

Generate deeply detailed, rich content for each section. Match the depth and quality of a professional executive-level career plan website.`;

        const result = await callOpenAI(apiKey, systemPrompt, userPrompt, 'gpt-4o', 8000, true);
        const generated = extractJSON(result);
        if (!generated) {
            console.error('[Builder] generate: unparseable AI response:', result.slice(0, 500));
            return res.status(500).json({ error: 'Failed to parse AI response as JSON' });
        }

        res.json({ generated });
    } catch (err) {
        console.error('[Builder] generate error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
