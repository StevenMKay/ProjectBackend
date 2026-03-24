require('dotenv').config();
const express = require('express');
const fetch   = require('node-fetch');
const cors    = require('cors');
const admin   = require('firebase-admin');
const { getFirestore } = require('firebase-admin/firestore');
const Stripe  = require('stripe');

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
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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
// Creates a Firebase Auth account + Firestore profile.
// The front-end should call auth.sendPasswordResetEmail(email) afterwards
// so the invitee receives a "set your password" email from Firebase.
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
        res.json({ success: true, uid: userRecord.uid });
    } catch (err) {
        if (err.code === 'auth/email-already-exists') {
            return res.status(409).json({ error: 'This email already has an account.' });
        }
        console.error(err);
        res.status(500).json({ error: err.message || 'Failed to invite user' });
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
// EMAIL — nodemailer (configure via Railway env vars)
// SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS, SMTP_FROM_NAME
// ============================================================
const nodemailer = require('nodemailer');

let emailTransporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    emailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: parseInt(process.env.SMTP_PORT || '587') === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        tls: { rejectUnauthorized: false }
    });
    console.log('[Email] SMTP configured:', process.env.SMTP_USER);
} else {
    console.warn('[Email] SMTP not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS on Railway.');
}

const FROM_NAME  = process.env.SMTP_FROM_NAME || 'NotebookPM';
const FROM_EMAIL = process.env.SMTP_USER || '';

async function sendCustomEmail({ to, subject, html }) {
    if (!emailTransporter) throw new Error('SMTP not configured on server. Add SMTP_HOST, SMTP_USER, SMTP_PASS to Railway env vars.');
    await emailTransporter.sendMail({ from: `"${FROM_NAME}" <${FROM_EMAIL}>`, to, subject, html });
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
    <p style="margin:0 0 14px;color:#475569;font-size:15px;line-height:1.65;"><strong style="color:#1e293b;">${inviterDisplay}</strong> has invited you to join <strong style="color:#1e293b;">${companyDisplay}</strong> on <strong style="color:#2563eb;">NotebookPM</strong> &mdash; a shared workspace for managing projects and collaborating with your team.</p>
    <p style="margin:0 0 28px;color:#475569;font-size:15px;line-height:1.65;">Click the button below to set your password and activate your account.</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 0 28px;"><tr><td style="background:#2563eb;border-radius:8px;box-shadow:0 2px 8px rgba(37,99,235,0.35);">
      <a href="${link}" style="display:inline-block;padding:15px 36px;color:#fff;font-weight:700;font-size:16px;text-decoration:none;">Set My Password &rarr;</a>
    </td></tr></table>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 28px;"><tr><td style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:16px 20px;">
      <p style="margin:0 0 6px;font-size:13px;color:#1e40af;font-weight:700;">After setting your password:</p>
      <p style="margin:0;font-size:13px;color:#3b82f6;line-height:1.6;">Visit <a href="https://notebookpm.com" style="color:#1d4ed8;font-weight:700;text-decoration:none;">NotebookPM.com</a> and sign in with your email address to access your workspace.</p>
    </td></tr></table>
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px;border-top:1px solid #e2e8f0;padding-top:20px;"><tr>
      <td style="width:52px;vertical-align:middle;"><img src="${LOGO}" alt="Career Solutions" width="44" height="44" style="border-radius:8px;display:block;"></td>
      <td style="padding-left:14px;vertical-align:middle;">
        <div style="font-size:13px;font-weight:700;color:#1e293b;">Career Solutions for Today</div>
        <div style="font-size:12px;color:#64748b;margin-top:2px;">Empowering careers, one project at a time.</div>
        <div style="font-size:12px;margin-top:2px;"><a href="https://careersolutionsfortoday.com" style="color:#2563eb;text-decoration:none;">careersolutionsfortoday.com</a></div>
      </td>
    </tr></table>
    <p style="margin:0;color:#94a3b8;font-size:12px;line-height:1.6;">If you didn't expect this invitation, you can safely ignore this email. The link expires in 24 hours.</p>
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
    <p style="margin:0;color:#94a3b8;font-size:12px;line-height:1.6;">If you did not request this, you can safely ignore this email. The link expires in 1 hour.</p>
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
    const { email, displayName, inviterName, companyName } = req.body;
    if (!email) return res.status(400).json({ error: 'email is required' });
    try {
        const link = await auth.generatePasswordResetLink(email, { url: 'https://notebookpm.com', handleCodeInApp: false });
        await sendCustomEmail({ to: email, subject: `You've been invited to join NotebookPM`, html: buildInviteEmailHtml({ displayName, inviterName, companyName, link }) });
        res.json({ success: true });
    } catch (err) {
        console.error('[Email] Invite failed:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Send password reset email to an existing member (admin only)
app.post('/api/tenant/members/:uid/send-reset', requireAuth, async (req, res) => {
    if (req.userDoc.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    const { uid } = req.params;
    try {
        const doc = await db.collection('users').doc(uid).get();
        if (!doc.exists || doc.data().tenantId !== req.userDoc.tenantId) return res.status(404).json({ error: 'Member not found' });
        const { email, displayName } = doc.data();
        const link = await auth.generatePasswordResetLink(email, { url: 'https://notebookpm.com', handleCodeInApp: false });
        await sendCustomEmail({ to: email, subject: 'Reset your NotebookPM password', html: buildResetEmailHtml({ displayName, link }) });
        res.json({ success: true });
    } catch (err) {
        console.error('[Email] Reset failed:', err.message);
        res.status(500).json({ error: err.message });
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

                // 4. Generate a password-reset link so the buyer sets their own password
                //    (send via your email provider: SendGrid, Resend, etc.)
                const resetLink = await auth.generatePasswordResetLink(adminEmail);
                console.log('[Billing] Provisioned:', tenantId, '| Admin:', adminEmail, '| Reset:', resetLink);

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
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
