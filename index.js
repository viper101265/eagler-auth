// index.js
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const users = {}; // simple in-memory storage (replace with DB later)

// --- Registration ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ error: 'Missing fields' });
    if (users[username]) return res.status(400).send({ error: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    users[username] = { hash };
    res.send({ status: 'ok' });
});

// --- Login & token generation ---
app.post('/login', async (req, res) => {
    const { username, password, deviceId } = req.body;
    const user = users[username];
    if (!user) return res.status(400).send({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.hash);
    if (!match) return res.status(401).send({ error: 'Wrong password' });

    const token = crypto.randomBytes(16).toString('hex');
    user.token = { value: token, deviceId, expires: Date.now() + 5*60*1000 }; // 5 min expiry
    res.send({ token });
});

// --- Token verification ---
app.post('/verify-token', (req, res) => {
    const { username, token, deviceId } = req.body;
    const user = users[username];
    if (!user || !user.token) return res.status(400).send({ error: 'Invalid token' });

    if (user.token.value === token && user.token.deviceId === deviceId && user.token.expires > Date.now()) {
        return res.send({ status: 'ok' });
    } else {
        return res.status(401).send({ error: 'Token invalid or expired' });
    }
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
