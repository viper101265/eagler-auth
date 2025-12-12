// index.js
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());

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
    if (!user) return res.status(400).send({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.hash);
    if (!match) return res.status(401).send({ error: 'Wrong password' });

    const deviceKey = generateDeviceKey(clientInfo);
    if (deviceKey !== user.deviceKey) return res.status(401).send({ error: 'Invalid device' });

    // Generate token valid for 5 minutes
    const token = crypto.randomBytes(16).toString('hex');
    user.token = { value: token, expires: Date.now() + 5 * 60 * 1000 };

    res.send({ token });
});

// --- Verify token ---
app.post('/verify-token', (req, res) => {
    const { username, token, clientInfo } = req.body;
    const user = users[username];
    if (!user || !user.token) return res.status(400).send({ error: 'Invalid token' });

    const deviceKey = generateDeviceKey(clientInfo);
    if (deviceKey !== user.deviceKey) return res.status(401).send({ error: 'Invalid device' });

    if (user.token.value === token && user.token.expires > Date.now()) {
        return res.send({ status: 'ok' });
    } else {
        return res.status(401).send({ error: 'Token invalid or expired' });
    }
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
