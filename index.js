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

// Serve frontend
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// In-memory storage (replace with DB for production)
const users = {};

// --- Helper: generate device key ---
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
        return res.status(400).send({ error: 'Username already taken' });
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        const deviceKey = generateDeviceKey(clientInfo);
        users[username] = { hash, email, deviceKey, token: null };
        res.send({ status: 'ok', deviceKey });
    } catch (err) {
        res.status(500).send({ error: 'Server error' });
    }
});

// --- Login (generate token for frontend) ---
app.post('/login', async (req, res) => {
    const { username, password, clientInfo } = req.body;
    const user = users[username];
    if (!user) return res.status(400).send({ error: 'User not found' });

    try {
        const match = await bcrypt.compare(password, user.hash);
        if (!match) return res.status(401).send({ error: 'Wrong password' });

        const deviceKey = generateDeviceKey(clientInfo);
        if (deviceKey !== user.deviceKey)
            return res.status(401).send({ error: 'Invalid device' });

        const token = crypto.randomBytes(16).toString('hex');
        user.token = { value: token, expires: Date.now() + 5 * 60 * 1000 };
        res.send({ token });
    } catch (err) {
        res.status(500).send({ error: 'Server error' });
    }
});

// --- Verify token (used by plugin, invalidates after use) ---
app.post('/verify-token', (req, res) => {
    const { username, token, clientInfo } = req.body;
    const user = users[username];
    if (!user || !user.token) return res.status(400).send({ error: 'Invalid token' });

    const deviceKey = generateDeviceKey(clientInfo);
    if (deviceKey !== user.deviceKey)
        return res.status(401).send({ error: 'Invalid device' });

    if (user.token.value === token && user.token.expires > Date.now()) {
        user.token = null; // invalidate token
        return res.send({ status: 'ok' });
    } else {
        return res.status(401).send({ error: 'Token invalid or expired' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
