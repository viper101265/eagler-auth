// index.js
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// In-memory user storage (replace with DB for production)
const users = {};

// --- Helper: generate device key from client info ---
function generateDeviceKey(clientInfo) {
    return crypto.createHash('sha256').update(clientInfo).digest('hex');
}

// --- Registration ---
app.post('/register', async (req, res) => {
    const { username, email, password, clientInfo } = req.body;
    if (!username || !email || !password || !clientInfo) {
        return res.status(400).send({ error: 'Missing fields' });
    }
    if (users[username]) {
        return res.status(400).send({ error: 'User exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const deviceKey = generateDeviceKey(clientInfo);

    users[username] = { hash, email, deviceKey, token: null };
    res.send({ status: 'ok', deviceKey });
});

// --- Login ---
app.post('/login', async (req, res) => {
    const { username, password, clientInfo } = req.body;
    const user = users[username];
    if (!user) return res.status(400).send({ error: '
