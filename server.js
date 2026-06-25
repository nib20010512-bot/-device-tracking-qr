'use strict';
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const ASSETS_FILE = path.join(DATA_DIR, 'assets.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

// ─── Data layer ───────────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

function readAssets() {
  try { return JSON.parse(fs.readFileSync(ASSETS_FILE, 'utf8')); } catch { return []; }
}
function writeAssets(assets) {
  fs.writeFileSync(ASSETS_FILE, JSON.stringify(assets, null, 2), 'utf8');
}

function readSettings() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch { return {}; }
}
function writeSettings(s) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(s, null, 2), 'utf8');
}

// ─── Users helpers ────────────────────────────────────────────────────────────
function getUsers() {
  const s = readSettings();
  // Migrate from old single-password format
  if (!s.users) {
    s.users = [{
      id: uuidv4(),
      username: 'admin',
      displayName: 'Administrator',
      role: 'admin',
      passwordHash: s.adminPasswordHash || bcrypt.hashSync('admin123', 10),
    }];
    delete s.adminPasswordHash;
    writeSettings(s);
    if (!s.users[0].passwordHash || s.adminPasswordHash) {
      console.log('\n  Default admin password: admin123');
      console.log('  Change it after first login!\n');
    }
  }
  return s.users;
}

function saveUsers(users) {
  const s = readSettings();
  s.users = users;
  writeSettings(s);
}

function findUser(username) {
  return getUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
}

// Ensure admin exists on startup
(function seedAdmin() {
  const users = getUsers();
  if (!users.length) {
    users.push({
      id: uuidv4(),
      username: 'admin',
      displayName: 'Administrator',
      role: 'admin',
      passwordHash: bcrypt.hashSync('admin123', 10),
    });
    saveUsers(users);
    console.log('\n  Default admin: username=admin  password=admin123');
    console.log('  Change it after first login!\n');
  }
})();

// ─── Network ─────────────────────────────────────────────────────────────────
function getLocalIP() {
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const iface of ifaces) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return '127.0.0.1';
}
const LOCAL_IP = getLocalIP();
const BASE_URL = `http://${LOCAL_IP}:${PORT}`;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: uuidv4(),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 },
}));
app.use(express.static(path.join(__dirname, 'public')));

const requireAuth = (req, res, next) =>
  req.session.userId ? next() : res.status(401).json({ error: 'Unauthorized' });

const requireAdmin = (req, res, next) =>
  req.session.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required' });

// ─── Auth routes ─────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ authenticated: false });
  res.json({
    authenticated: true,
    userId: req.session.userId,
    username: req.session.username,
    displayName: req.session.displayName,
    role: req.session.role,
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = findUser(username.trim());
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: 'Incorrect username or password' });

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.displayName = user.displayName;
  req.session.role = user.role;
  res.json({ ok: true, role: user.role, displayName: user.displayName });
});

app.post('/api/logout', (req, res) =>
  req.session.destroy(() => res.json({ ok: true })));

app.post('/api/change-password', requireAuth, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const users = getUsers();
  const idx = users.findIndex(u => u.id === req.session.userId);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  users[idx].passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);
  res.json({ ok: true });
});

// ─── User management (admin only) ────────────────────────────────────────────
app.get('/api/users', requireAuth, requireAdmin, (_req, res) => {
  const safe = getUsers().map(({ id, username, displayName, role }) => ({ id, username, displayName, role }));
  res.json(safe);
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { username, displayName, role, password } = req.body;
  if (!username?.trim() || !password || !role)
    return res.status(400).json({ error: 'Username, password, and role are required' });
  if (!['admin', 'manager'].includes(role))
    return res.status(400).json({ error: 'Role must be admin or manager' });

  const users = getUsers();
  if (users.some(u => u.username.toLowerCase() === username.trim().toLowerCase()))
    return res.status(409).json({ error: 'Username already exists' });

  const newUser = {
    id: uuidv4(),
    username: username.trim(),
    displayName: displayName?.trim() || username.trim(),
    role,
    passwordHash: bcrypt.hashSync(password, 10),
  };
  users.push(newUser);
  saveUsers(users);
  res.json({ ok: true, id: newUser.id });
});

app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const users = getUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  const { displayName, role, password } = req.body;
  if (displayName) users[idx].displayName = displayName.trim();
  if (role && ['admin', 'manager'].includes(role)) users[idx].role = role;
  if (password && password.length >= 6) users[idx].passwordHash = bcrypt.hashSync(password, 10);
  saveUsers(users);
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === req.session.userId)
    return res.status(400).json({ error: 'You cannot delete your own account' });
  const users = getUsers().filter(u => u.id !== req.params.id);
  saveUsers(users);
  res.json({ ok: true });
});

// ─── Asset routes ─────────────────────────────────────────────────────────────
app.get('/api/assets', requireAuth, (_req, res) => {
  const assets = readAssets().sort((a, b) => a.asset_tag.localeCompare(b.asset_tag));
  res.json(assets);
});

// Public — scan page
app.get('/api/assets/:id', (req, res) => {
  const asset = readAssets().find(a => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset not found' });
  res.json(asset);
});

// Add: admin only
app.post('/api/assets', requireAuth, requireAdmin, (req, res) => {
  const { asset_tag, asset_type, brand, model, serial_number, date_purchased, location, status, notes } = req.body;
  if (!asset_tag?.trim() || !asset_type?.trim())
    return res.status(400).json({ error: 'Asset Tag and Type are required' });

  const assets = readAssets();
  if (assets.some(a => a.asset_tag === asset_tag.trim()))
    return res.status(409).json({ error: 'Asset tag already exists' });

  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const newAsset = {
    id: uuidv4(),
    asset_tag: asset_tag.trim(),
    asset_type,
    brand: brand || '',
    model: model || '',
    serial_number: serial_number || '',
    date_purchased: date_purchased || '',
    location: location || '',
    status: status || 'Active',
    notes: notes || '',
    created_at: now,
    updated_at: now,
  };
  assets.push(newAsset);
  writeAssets(assets);
  res.json({ ok: true, id: newAsset.id });
});

// Edit: any logged-in user
app.put('/api/assets/:id', requireAuth, (req, res) => {
  const assets = readAssets();
  const idx = assets.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const { asset_tag, asset_type, brand, model, serial_number, date_purchased, location, status, notes } = req.body;
  assets[idx] = {
    ...assets[idx],
    asset_tag, asset_type,
    brand: brand || '',
    model: model || '',
    serial_number: serial_number || '',
    date_purchased: date_purchased || '',
    location: location || '',
    status: status || 'Active',
    notes: notes || '',
    updated_at: new Date().toISOString().replace('T', ' ').slice(0, 19),
  };
  writeAssets(assets);
  res.json({ ok: true });
});

// Delete: admin only
app.delete('/api/assets/:id', requireAuth, requireAdmin, (req, res) => {
  writeAssets(readAssets().filter(a => a.id !== req.params.id));
  res.json({ ok: true });
});

// Public QR image
app.get('/api/assets/:id/qr.png', async (req, res) => {
  const asset = readAssets().find(a => a.id === req.params.id);
  if (!asset) return res.status(404).send('Not found');
  const url = `${BASE_URL}/asset.html?id=${asset.id}`;
  const png = await QRCode.toBuffer(url, {
    width: 300, margin: 2,
    color: { dark: '#0f172a', light: '#ffffff' },
  });
  res.type('image/png').send(png);
});

app.get('/api/server-info', requireAuth, (_req, res) =>
  res.json({ ip: LOCAL_IP, port: PORT, base: BASE_URL }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n  IT Asset Tracker is running');
  console.log(`  Local:   http://localhost:${PORT}`);
  console.log(`  Network: ${BASE_URL}`);
  console.log('\n  Keep this computer on for QR scanning to work.\n');
});
