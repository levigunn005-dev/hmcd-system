const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to PostgreSQL database using environment variable
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'hmcd-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Initialize PostgreSQL Tables and Seed Data
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance DOUBLE PRECISION NOT NULL,
        is_admin INT DEFAULT 0,
        must_change_password INT DEFAULT 1
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        sender VARCHAR(100) NOT NULL,
        receiver VARCHAR(100) NOT NULL,
        amount DOUBLE PRECISION NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const userCheck = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const initialPassword = bcrypt.hashSync('SHP', 10);
      await client.query(`
        INSERT INTO users (username, password, balance, is_admin, must_change_password) VALUES
        ('HM', $1, 700.5, 1, 1),
        ('Matthew', $1, 1709.5, 0, 1),
        ('Katharine', $1, 1297.0, 0, 1),
        ('Emma', $1, 2209.5, 0, 1);
      `, [initialPassword]);
    }
  } finally {
    client.release();
  }
}
initDB().catch(console.error);

// Middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

async function requireAdmin(req, res, next) {
  const { rows } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.session.userId]);
  if (!rows[0] || !rows[0].is_admin) {
    return res.status(403).send('Access denied: Admin required. <a href="/">Back</a>');
  }
  next();
}

// Routes
app.get('/', requireAuth, async (req, res) => {
  const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
  const user = userRes.rows[0];
  
  if (user.must_change_password) return res.redirect('/change-password');

  const allUsersRes = await pool.query('SELECT username, balance, is_admin FROM users ORDER BY username ASC');
  const allUsers = allUsersRes.rows;
  const otherUsers = allUsers.filter(u => u.username !== user.username);

  const totalRes = await pool.query('SELECT SUM(balance) as total FROM users');
  const totalSupply = totalRes.rows[0].total;

  const historyRes = await pool.query('SELECT * FROM transactions ORDER BY timestamp DESC');
  const history = historyRes.rows;

  res.send(`
    <h2>Welcome, ${user.username} ${user.is_admin ? '(Admin)' : ''}</h2>
    <p><strong>Your Balance:</strong> ${user.balance} HMCD</p>
    <p><strong>Total System Supply:</strong> ${totalSupply} HMCD</p>
    <hr>
    <h3>Standard Transfer</h3>
    <form action="/transfer" method="POST">
      <label>Recipient:</label>
      <select name="receiver" required>
        ${otherUsers.map(u => `<option value="${u.username}">${u.username}</option>`).join('')}
      </select>
      <input type="number" step="0.5" name="amount" placeholder="Amount" min="0.1" max="${user.balance}" required>
      <button type="submit">Send</button>
    </form>

    ${user.is_admin ? `
      <hr>
      <div style="background-color: #f4f4f4; padding: 15px; border-radius: 5px;">
        <h3>Admin Tools</h3>
        <h4>1. Force Transfer Between Accounts</h4>
        <form action="/admin/force-transfer" method="POST">
          <label>From:</label>
          <select name="fromUser" required>
            ${allUsers.map(u => `<option value="${u.username}">${u.username} (${u.balance} HMCD)</option>`).join('')}
          </select>
          <label>To:</label>
          <select name="toUser" required>
            ${allUsers.map(u => `<option value="${u.username}">${u.username}</option>`).join('')}
          </select>
          <input type="number" step="0.5" name="amount" placeholder="Amount" min="0.1" required>
          <button type="submit">Execute Transfer</button>
        </form>

        <h4>2. Grant / Mint New HMCD</h4>
        <form action="/admin/mint" method="POST">
          <label>Target Account:</label>
          <select name="targetUser" required>
            ${allUsers.map(u => `<option value="${u.username}">${u.username} (${u.balance} HMCD)</option>`).join('')}
          </select>
          <input type="number" step="0.5" name="amount" placeholder="Amount to Add" min="0.5" required>
          <button type="submit">Mint HMCD</button>
        </form>

        <h4>3. Create New User Account</h4>
        <form action="/admin/create-user" method="POST">
          <input type="text" name="newUsername" placeholder="Username" required>
          <input type="number" step="0.5" name="initialBalance" placeholder="Initial Balance" min="0" required>
          <button type="submit">Create Account</button>
        </form>
      </div>
    ` : ''}

    <hr>
    <h3>System Transaction Log</h3>
    <ul>
      ${history.map(t => `<li>[${t.timestamp.toLocaleString()}] <strong>${t.sender}</strong> ➔ <strong>${t.receiver}</strong>: ${t.amount} HMCD</li>`).join('')}
    </ul>
    <br><a href="/logout">Logout</a>
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <h2>HMCD Login</h2>
    <form action="/login" method="POST">
      <input type="text" name="username" placeholder="Username" required><br><br>
      <input type="password" name="password" placeholder="Password" required><br><br>
      <button type="submit">Sign In</button>
    </form>
  `);
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = rows[0];

    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      return res.redirect('/');
    }
    res.send('Invalid credentials. <a href="/login">Try again</a>');
  } catch (err) {
    console.error('Database query error on login:', err);
    res.status(500).send('Database connection error. Please check your DATABASE_URL in Render.');
  }
});

app.get('/change-password', requireAuth, (req, res) => {
  res.send(`
    <h2>First Time Login - Change Password</h2>
    <form action="/change-password" method="POST">
      <input type="password" name="newPassword" placeholder="New Password" required><br><br>
      <button type="submit">Update Password</button>
    </form>
  `);
});

app.post('/change-password', requireAuth, async (req, res) => {
  const hashedPassword = bcrypt.hashSync(req.body.newPassword, 10);
  await pool.query('UPDATE users SET password = $1, must_change_password = 0 WHERE id = $2', [hashedPassword, req.session.userId]);
  res.redirect('/');
});

app.post('/transfer', requireAuth, async (req, res) => {
  const { receiver, amount } = req.body;
  const transferAmount = parseFloat(amount);

  const senderRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
  const recipientRes = await pool.query('SELECT * FROM users WHERE username = $1', [receiver]);
  const sender = senderRes.rows[0];
  const recipient = recipientRes.rows[0];

  if (!recipient || transferAmount <= 0 || sender.balance < transferAmount) {
    return res.send('Invalid transaction details. <a href="/">Back</a>');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [transferAmount, sender.id]);
    await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [transferAmount, recipient.id]);
    await client.query('INSERT INTO transactions (sender, receiver, amount) VALUES ($1, $2, $3)', [sender.username, recipient.username, transferAmount]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    return res.send('Transfer failed.');
  } finally {
    client.release();
  }
  res.redirect('/');
});

app.post('/admin/force-transfer', requireAuth, requireAdmin, async (req, res) => {
  const { fromUser, toUser, amount } = req.body;
  const transferAmount = parseFloat(amount);

  const senderRes = await pool.query('SELECT * FROM users WHERE username = $1', [fromUser]);
  const recipientRes = await pool.query('SELECT * FROM users WHERE username = $1', [toUser]);
  const sender = senderRes.rows[0];
  const recipient = recipientRes.rows[0];

  if (!sender || !recipient || transferAmount <= 0 || sender.balance < transferAmount) {
    return res.send('Transfer failed: Check balance or parameters. <a href="/">Back</a>');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [transferAmount, sender.id]);
    await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [transferAmount, recipient.id]);
    await client.query('INSERT INTO transactions (sender, receiver, amount) VALUES ($1, $2, $3)', [`${sender.username} (via Admin)`, recipient.username, transferAmount]);
    await client.query('COMMIT');
  } finally {
    client.release();
  }
  res.redirect('/');
});

app.post('/admin/mint', requireAuth, requireAdmin, async (req, res) => {
  const { targetUser, amount } = req.body;
  const mintAmount = parseFloat(amount);
  const adminRes = await pool.query('SELECT username FROM users WHERE id = $1', [req.session.userId]);

  await pool.query('UPDATE users SET balance = balance + $1 WHERE username = $2', [mintAmount, targetUser]);
  await pool.query('INSERT INTO transactions (sender, receiver, amount) VALUES ($1, $2, $3)', [`[SYSTEM/ADMIN: ${adminRes.rows[0].username}]`, targetUser, mintAmount]);
  res.redirect('/');
});

app.post('/admin/create-user', requireAuth, requireAdmin, async (req, res) => {
  const { newUsername, initialBalance } = req.body;
  const startingBalance = parseFloat(initialBalance) || 0;
  const initialPassword = bcrypt.hashSync('SHP', 10);
  const adminRes = await pool.query('SELECT username FROM users WHERE id = $1', [req.session.userId]);

  try {
    await pool.query('INSERT INTO users (username, password, balance, is_admin, must_change_password) VALUES ($1, $2, $3, 0, 1)', [newUsername, initialPassword, startingBalance]);
    if (startingBalance > 0) {
      await pool.query('INSERT INTO transactions (sender, receiver, amount) VALUES ($1, $2, $3)', [`[SYSTEM/ADMIN: ${adminRes.rows[0].username}]`, newUsername, startingBalance]);
    }
    res.redirect('/');
  } catch (err) {
    res.send('User creation failed. <a href="/">Back</a>');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(PORT, () => console.log(`Server active on port ${PORT}`));
