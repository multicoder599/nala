// ============================================================
//  Nala Bank – Express API Server
//  User routes  +  Admin routes  +  Atomic transaction engine
// ============================================================

require('dotenv').config();
const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');

// ── Models ───────────────────────────────────────────────────
const User        = require('./models/User');
const Account     = require('./models/Account');
const Transaction = require('./models/Transaction');

// ── App ──────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(cors());

// ── MongoDB ──────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err  => console.error('❌ MongoDB error:', err.message));


// ============================================================
//  MIDDLEWARE
// ============================================================

/** Protect any route with a valid user JWT */
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token – please sign in.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Token expired or invalid – please sign in again.' });
  }
}

/**
 * Protect admin-only routes.
 * Admin credentials live in .env:
 *   ADMIN_USERNAME=admin
 *   ADMIN_PASSWORD=your_strong_password
 *
 * The admin logs in via POST /api/admin/login which returns a
 * short-lived admin JWT signed with ADMIN_JWT_SECRET.
 */
function adminAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Admin token required.' });
  try {
    const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET || process.env.JWT_SECRET + '_admin');
    if (decoded.role !== 'admin') throw new Error('Not admin');
    req.admin = decoded;
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid or expired admin token.' });
  }
}


// ============================================================
//  HELPERS
// ============================================================

/** Unique reference like NL-2025-AB3X */
function genRef() {
  return 'NL-' + new Date().getFullYear() + '-' +
    Math.random().toString(36).substring(2, 6).toUpperCase();
}

/**
 * ATOMIC transaction engine.
 * – Validates the account exists and (for debits) has enough balance.
 * – Updates balance with $inc to avoid race conditions.
 * – Writes the Transaction document.
 * Returns the updated Account.
 */
async function recordTransaction(accountId, type, amount, description, meta = {}) {
  const CREDIT_TYPES = ['credit', 'deposit', 'received', 'airtime_received', 'savings_interest', 'admin_credit'];
  const isCredit     = CREDIT_TYPES.includes(type);
  const absAmount    = Math.abs(amount);
  const sign         = isCredit ? 1 : -1;

  // For debits — check balance first (read-modify-write inside MongoDB)
  if (!isCredit) {
    const current = await Account.findById(accountId);
    if (!current) throw new Error('Account not found');
    if (current.balance < absAmount)
      throw new Error(`Insufficient balance. Available: KES ${current.balance.toFixed(2)}`);
  }

  // Atomically update balance
  const updated = await Account.findByIdAndUpdate(
    accountId,
    { $inc: { balance: sign * absAmount } },
    { new: true }
  );
  if (!updated) throw new Error('Account not found');

  // Record the transaction
  await Transaction.create({
    accountId,
    type,
    amount:      sign * absAmount,   // stored as negative for debits
    description,
    reference:   meta.reference || genRef(),
    balanceAfter: updated.balance,   // snapshot for audit trail
    ...meta
  });

  return updated;
}


// ============================================================
//  PUBLIC ROUTES
// ============================================================

app.get('/api/status', (req, res) =>
  res.json({ status: 'ok', message: 'Nala Bank backend is running.' })
);


// ── REGISTER ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, username: rawUsername, email, phone, password } = req.body;

    if (!fullName || !phone || !password)
      return res.status(400).json({ message: 'Full name, phone and password are required.' });

    // Clean username
    let username = rawUsername
      ? rawUsername.toLowerCase().replace(/[^a-z0-9_]/g, '')
      : (() => {
          const parts = fullName.toLowerCase().split(' ');
          const base  = parts.length > 1 ? parts[0][0] + parts[parts.length - 1] : parts[0];
          return base.replace(/[^a-z0-9_]/g, '') + Math.floor(Math.random() * 1000);
        })();

    // Uniqueness
    const [existPhone, existUser, existEmail] = await Promise.all([
      User.findOne({ phone }),
      User.findOne({ username }),
      email ? User.findOne({ email }) : null
    ]);
    if (existPhone) return res.status(400).json({ message: 'Phone number already registered.' });
    if (existUser)  return res.status(400).json({ message: 'Username already taken.' });
    if (existEmail) return res.status(400).json({ message: 'Email already registered.' });

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      fullName, username, email: email || '', phone, password: hashedPassword
    });

    const accountNumber = '0123' + Math.floor(10000000 + Math.random() * 90000000);
    const newAccount = await Account.create({
      userId: newUser._id, accountNumber, balance: 0
    });

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Account created successfully',
      token, username: newUser.username, fullName: newUser.fullName,
      accountNumber: newAccount.accountNumber
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});


// ── LOGIN ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: 'Username and password are required.' });

    const user = await User.findOne({ username: username.toLowerCase().trim() });
    if (!user) return res.status(400).json({ message: 'Invalid username or password.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid username or password.' });

    // Check if suspended
    if (user.status === 'suspended')
      return res.status(403).json({ message: 'Your account has been suspended. Contact support.' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful', token,
      username: user.username, fullName: user.fullName
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login.' });
  }
});


// ============================================================
//  USER PROTECTED ROUTES
// ============================================================

// ── BALANCE ──────────────────────────────────────────────────
app.get('/api/account/balance', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    res.json({
      balance: account.balance, accountNumber: account.accountNumber, currency: 'KES'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not fetch balance.' });
  }
});


// ── TRANSACTIONS (paginated) ──────────────────────────────────
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const page  = Math.max(parseInt(req.query.page)  || 1, 1);

    const [transactions, total] = await Promise.all([
      Transaction.find({ accountId: account._id })
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      Transaction.countDocuments({ accountId: account._id })
    ]);

    res.json({ transactions, page, limit, total, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not fetch transactions.' });
  }
});


// ── TRANSFER (send money) ─────────────────────────────────────
app.post('/api/transfer', auth, async (req, res) => {
  try {
    const { recipient, amount, note } = req.body;

    if (!recipient || !amount || amount <= 0)
      return res.status(400).json({ message: 'Recipient and a positive amount are required.' });

    const parsedAmount = parseFloat(amount);
    const senderUser   = await User.findById(req.user.id);
    const senderAcc    = await Account.findOne({ userId: req.user.id });
    if (!senderAcc) return res.status(404).json({ message: 'Your account was not found.' });

    const reference = genRef();
    const desc      = note || `Transfer to @${recipient}`;

    // ── Debit sender (throws if insufficient) ──
    const updatedSender = await recordTransaction(
      senderAcc._id, 'debit', parsedAmount, desc,
      { recipient, reference }
    );

    // ── Credit recipient if internal account exists ──
    const recipUser = await User.findOne({ username: recipient.toLowerCase().trim() });
    const recipAcc  = recipUser ? await Account.findOne({ userId: recipUser._id }) : null;

    if (recipAcc) {
      await recordTransaction(
        recipAcc._id, 'credit', parsedAmount,
        `Transfer from @${senderUser.username}`,
        { sender: senderUser.username, reference }
      );
    }

    res.json({
      message:    `KES ${parsedAmount.toFixed(2)} sent to @${recipient}` + (recipAcc ? '.' : ' (external – pending).'),
      reference,
      newBalance: updatedSender.balance
    });
  } catch (err) {
    console.error('Transfer error:', err);
    const status = err.message.startsWith('Insufficient') ? 400 : 500;
    res.status(status).json({ message: err.message || 'Transfer failed.' });
  }
});


// ── M-PESA ───────────────────────────────────────────────────
app.post('/api/mpesa', auth, async (req, res) => {
  try {
    const { type, phone, amount } = req.body;
    if (!type || !phone || !amount || amount <= 0)
      return res.status(400).json({ message: 'type, phone and amount are required.' });

    const parsedAmount = parseFloat(amount);
    const account      = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    const txType = type === 'deposit' ? 'credit' : 'debit';
    const desc   = type === 'deposit'
      ? `M-Pesa deposit from ${phone}`
      : `M-Pesa withdrawal to ${phone}`;

    const updated = await recordTransaction(account._id, txType, parsedAmount, desc, { phone });

    res.json({
      message:    `M-Pesa ${type} of KES ${parsedAmount.toFixed(2)} processed.`,
      reference:  genRef(),
      newBalance: updated.balance
    });
  } catch (err) {
    console.error('M-Pesa error:', err);
    const status = err.message.startsWith('Insufficient') ? 400 : 500;
    res.status(status).json({ message: err.message || 'M-Pesa transaction failed.' });
  }
});


// ── AIRTIME ──────────────────────────────────────────────────
app.post('/api/airtime', auth, async (req, res) => {
  try {
    const { network, phone, amount } = req.body;
    if (!phone || !amount || amount <= 0)
      return res.status(400).json({ message: 'Phone and amount are required.' });

    const parsedAmount = parseFloat(amount);
    const account      = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    const updated = await recordTransaction(
      account._id, 'debit', parsedAmount,
      `${network || 'Airtime'} purchase for ${phone}`,
      { phone, network }
    );

    res.json({
      message:    `KES ${parsedAmount.toFixed(2)} airtime sent to ${phone}.`,
      reference:  genRef(),
      newBalance: updated.balance
    });
  } catch (err) {
    console.error('Airtime error:', err);
    const status = err.message.startsWith('Insufficient') ? 400 : 500;
    res.status(status).json({ message: err.message || 'Airtime failed.' });
  }
});


// ── BILL PAYMENT ─────────────────────────────────────────────
app.post('/api/bills/pay', auth, async (req, res) => {
  try {
    const { biller, account: billAccount, amount } = req.body;
    if (!biller || !billAccount || !amount || amount <= 0)
      return res.status(400).json({ message: 'Biller, account number and amount are required.' });

    const parsedAmount = parseFloat(amount);
    const account      = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    const updated = await recordTransaction(
      account._id, 'debit', parsedAmount,
      `${biller} – A/C ${billAccount}`,
      { biller, billAccount }
    );

    res.json({
      message:    `${biller} payment of KES ${parsedAmount.toFixed(2)} processed.`,
      reference:  genRef(),
      newBalance: updated.balance
    });
  } catch (err) {
    console.error('Bill error:', err);
    const status = err.message.startsWith('Insufficient') ? 400 : 500;
    res.status(status).json({ message: err.message || 'Bill payment failed.' });
  }
});


// ── SAVINGS DEPOSIT ───────────────────────────────────────────
app.post('/api/savings/deposit', auth, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount < 100)
      return res.status(400).json({ message: 'Minimum savings deposit is KES 100.' });

    const parsedAmount = parseFloat(amount);
    const account      = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    // Debit main balance
    const updated = await recordTransaction(
      account._id, 'debit', parsedAmount,
      'Smart Savings deposit',
      { category: 'savings' }
    );

    // Increment savings sub-balance
    await Account.findByIdAndUpdate(account._id, { $inc: { savingsBalance: parsedAmount } });

    const final = await Account.findById(account._id);
    res.json({
      message:        `KES ${parsedAmount.toFixed(2)} moved to Smart Savings.`,
      reference:      genRef(),
      newBalance:     final.balance,
      savingsBalance: final.savingsBalance
    });
  } catch (err) {
    console.error('Savings error:', err);
    const status = err.message.startsWith('Insufficient') ? 400 : 500;
    res.status(status).json({ message: err.message || 'Savings deposit failed.' });
  }
});


// ── SAVINGS BALANCE ───────────────────────────────────────────
app.get('/api/savings', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    res.json({ savingsBalance: account.savingsBalance || 0, interestRate: 12, currency: 'KES' });
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch savings.' });
  }
});


// ── PROFILE GET ───────────────────────────────────────────────
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user    = await User.findById(req.user.id).select('-password');
    const account = await Account.findOne({ userId: req.user.id });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({
      fullName: user.fullName, username: user.username,
      email: user.email, phone: user.phone,
      accountNumber: account?.accountNumber, createdAt: user.createdAt
    });
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch profile.' });
  }
});


// ── PROFILE UPDATE ────────────────────────────────────────────
app.post('/api/profile', auth, async (req, res) => {
  try {
    const { fullName, phone, email } = req.body;
    const updates = {};
    if (fullName) updates.fullName = fullName.trim();
    if (phone)    updates.phone    = phone.trim();
    if (email)    updates.email    = email.trim().toLowerCase();

    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password');
    res.json({ message: 'Profile updated.', fullName: user.fullName });
  } catch (err) {
    res.status(500).json({ message: 'Profile update failed.' });
  }
});


// ── CHANGE PASSWORD ───────────────────────────────────────────
app.post('/api/account/password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: 'Both passwords are required.' });
    if (newPassword.length < 8)
      return res.status(400).json({ message: 'New password must be at least 8 characters.' });

    const user    = await User.findById(req.user.id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect.' });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Password change failed.' });
  }
});


// ── CARD ROUTES ───────────────────────────────────────────────
app.post('/api/card/freeze', auth, async (req, res) => {
  try {
    const account = await Account.findOneAndUpdate(
      { userId: req.user.id }, { cardFrozen: true }, { new: true }
    );
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    res.json({ message: 'Card frozen.', frozen: true });
  } catch (err) { res.status(500).json({ message: 'Could not freeze card.' }); }
});

app.post('/api/card/unfreeze', auth, async (req, res) => {
  try {
    const account = await Account.findOneAndUpdate(
      { userId: req.user.id }, { cardFrozen: false }, { new: true }
    );
    res.json({ message: 'Card unfrozen.', frozen: false });
  } catch (err) { res.status(500).json({ message: 'Could not unfreeze card.' }); }
});

app.post('/api/card/pin', auth, async (req, res) => {
  try {
    const { newPin } = req.body;
    if (!newPin || !/^\d{4}$/.test(newPin))
      return res.status(400).json({ message: 'PIN must be exactly 4 digits.' });
    await Account.findOneAndUpdate(
      { userId: req.user.id }, { cardPin: await bcrypt.hash(newPin, 10) }
    );
    res.json({ message: 'Card PIN updated.' });
  } catch (err) { res.status(500).json({ message: 'PIN update failed.' }); }
});

app.post('/api/card/limits', auth, async (req, res) => {
  try {
    const { dailyLimit, transactionLimit } = req.body;
    const updates = {};
    if (dailyLimit)       updates.dailyLimit       = parseFloat(dailyLimit);
    if (transactionLimit) updates.transactionLimit = parseFloat(transactionLimit);
    await Account.findOneAndUpdate({ userId: req.user.id }, updates);
    res.json({ message: 'Spending limits updated.' });
  } catch (err) { res.status(500).json({ message: 'Could not update limits.' }); }
});

app.get('/api/card/details', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    const user = await User.findById(req.user.id);
    res.json({
      cardNumber: account.cardNumber || '4000 0000 0000 0000',
      expiryDate: account.cardExpiry || '12/28',
      cvv:        account.cardCvv    || '000',
      cardHolder: user.fullName,
      frozen:     account.cardFrozen || false
    });
  } catch (err) { res.status(500).json({ message: 'Could not fetch card details.' }); }
});


// ============================================================
//  ADMIN ROUTES
//  All under /api/admin/* and protected by adminAuth
//
//  .env required:
//    ADMIN_USERNAME=admin
//    ADMIN_PASSWORD=your_strong_admin_password
//    ADMIN_JWT_SECRET=a_different_secret_from_JWT_SECRET
// ============================================================

// ── ADMIN LOGIN ───────────────────────────────────────────────
// Returns a short-lived admin JWT (8h).
// The admin.html page should POST here and store the token separately.
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (
      username !== process.env.ADMIN_USERNAME ||
      password !== process.env.ADMIN_PASSWORD
    ) {
      return res.status(401).json({ message: 'Invalid admin credentials.' });
    }

    const token = jwt.sign(
      { role: 'admin', username },
      process.env.ADMIN_JWT_SECRET || process.env.JWT_SECRET + '_admin',
      { expiresIn: '8h' }
    );

    res.json({ message: 'Admin login successful.', token });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});


// ── ADMIN – ALL USERS ─────────────────────────────────────────
// Returns every user with their linked account balance.
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users    = await User.find().select('-password').sort({ createdAt: -1 });
    const accounts = await Account.find();

    // Map account data onto each user
    const accMap = {};
    accounts.forEach(a => { accMap[a.userId.toString()] = a; });

    const result = users.map(u => ({
      _id:           u._id,
      fullName:      u.fullName,
      username:      u.username,
      email:         u.email,
      phone:         u.phone,
      status:        u.status || 'active',
      createdAt:     u.createdAt,
      balance:       accMap[u._id.toString()]?.balance        || 0,
      savingsBalance:accMap[u._id.toString()]?.savingsBalance || 0,
      accountNumber: accMap[u._id.toString()]?.accountNumber  || '',
      cardFrozen:    accMap[u._id.toString()]?.cardFrozen     || false
    }));

    res.json({ users: result, total: result.length });
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({ message: 'Could not fetch users.' });
  }
});


// ── ADMIN – SINGLE USER ───────────────────────────────────────
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const user    = await User.findById(req.params.id).select('-password');
    const account = await Account.findOne({ userId: req.params.id });
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const transactions = await Transaction
      .find({ accountId: account?._id })
      .sort({ createdAt: -1 })
      .limit(50);

    res.json({ user, account, transactions });
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch user.' });
  }
});


// ── ADMIN – SUSPEND / REINSTATE USER ─────────────────────────
app.post('/api/admin/users/:id/suspend', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, { status: 'suspended' }, { new: true }
    ).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found.' });
    console.log(`🔒 Admin suspended user @${user.username}`);
    res.json({ message: `User @${user.username} suspended.`, user });
  } catch (err) {
    res.status(500).json({ message: 'Could not suspend user.' });
  }
});

app.post('/api/admin/users/:id/reinstate', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, { status: 'active' }, { new: true }
    ).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found.' });
    console.log(`✅ Admin reinstated user @${user.username}`);
    res.json({ message: `User @${user.username} reinstated.`, user });
  } catch (err) {
    res.status(500).json({ message: 'Could not reinstate user.' });
  }
});


// ── ADMIN – ALL TRANSACTIONS ──────────────────────────────────
// Across all accounts, paginated, filterable by type / date.
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
    const page   = Math.max(parseInt(req.query.page)  || 1, 1);
    const filter = {};
    if (req.query.type) filter.type = req.query.type;
    if (req.query.from || req.query.to) {
      filter.createdAt = {};
      if (req.query.from) filter.createdAt.$gte = new Date(req.query.from);
      if (req.query.to)   filter.createdAt.$lte = new Date(req.query.to);
    }

    const [transactions, total] = await Promise.all([
      Transaction.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate('accountId', 'accountNumber'),
      Transaction.countDocuments(filter)
    ]);

    // Aggregate totals for the filtered set
    const agg = await Transaction.aggregate([
      { $match: filter },
      { $group: {
        _id: null,
        totalCredits: { $sum: { $cond: [{ $gt: ['$amount', 0] }, '$amount', 0] } },
        totalDebits:  { $sum: { $cond: [{ $lt: ['$amount', 0] }, '$amount', 0] } }
      }}
    ]);
    const totals = agg[0] || { totalCredits: 0, totalDebits: 0 };

    res.json({
      transactions, total, page, limit,
      pages: Math.ceil(total / limit),
      totalCredits: totals.totalCredits,
      totalDebits:  Math.abs(totals.totalDebits)
    });
  } catch (err) {
    console.error('Admin txns error:', err);
    res.status(500).json({ message: 'Could not fetch transactions.' });
  }
});


// ── ADMIN – ALL ACCOUNTS ──────────────────────────────────────
app.get('/api/admin/accounts', adminAuth, async (req, res) => {
  try {
    const accounts = await Account.find().populate('userId', 'fullName username phone status');
    const result   = accounts.map(a => ({
      _id:              a._id,
      accountNumber:    a.accountNumber,
      balance:          a.balance,
      savingsBalance:   a.savingsBalance || 0,
      cardFrozen:       a.cardFrozen     || false,
      dailyLimit:       a.dailyLimit     || 300000,
      transactionLimit: a.transactionLimit || 50000,
      mpesaLinked:      a.mpesaLinked    || false,
      owner:            a.userId          // populated
    }));
    res.json({ accounts: result, total: result.length });
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch accounts.' });
  }
});


// ── ADMIN – FREEZE / UNFREEZE A SPECIFIC CARD ─────────────────
app.post('/api/admin/accounts/:id/freeze', adminAuth, async (req, res) => {
  try {
    const account = await Account.findByIdAndUpdate(
      req.params.id, { cardFrozen: true }, { new: true }
    );
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    console.log(`🔒 Admin froze card for account ${account.accountNumber}`);
    res.json({ message: 'Card frozen.', accountNumber: account.accountNumber });
  } catch (err) {
    res.status(500).json({ message: 'Could not freeze card.' });
  }
});

app.post('/api/admin/accounts/:id/unfreeze', adminAuth, async (req, res) => {
  try {
    const account = await Account.findByIdAndUpdate(
      req.params.id, { cardFrozen: false }, { new: true }
    );
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    res.json({ message: 'Card unfrozen.', accountNumber: account.accountNumber });
  } catch (err) {
    res.status(500).json({ message: 'Could not unfreeze card.' });
  }
});


// ── ADMIN – MANUAL CREDIT / DEBIT ────────────────────────────
// Lets admin manually adjust a user's balance (e.g. welcome bonus, refund, correction).
app.post('/api/admin/accounts/:id/credit', adminAuth, async (req, res) => {
  try {
    const { amount, description } = req.body;
    if (!amount || amount <= 0)
      return res.status(400).json({ message: 'A positive amount is required.' });

    const updated = await recordTransaction(
      req.params.id, 'admin_credit', parseFloat(amount),
      description || 'Admin credit',
      { adminUser: req.admin.username }
    );

    console.log(`💰 Admin credited KES ${amount} to account ${req.params.id}`);
    res.json({ message: `KES ${amount} credited.`, newBalance: updated.balance });
  } catch (err) {
    console.error('Admin credit error:', err);
    res.status(500).json({ message: err.message || 'Credit failed.' });
  }
});

app.post('/api/admin/accounts/:id/debit', adminAuth, async (req, res) => {
  try {
    const { amount, description } = req.body;
    if (!amount || amount <= 0)
      return res.status(400).json({ message: 'A positive amount is required.' });

    const updated = await recordTransaction(
      req.params.id, 'debit', parseFloat(amount),
      description || 'Admin debit',
      { adminUser: req.admin.username }
    );

    console.log(`🔻 Admin debited KES ${amount} from account ${req.params.id}`);
    res.json({ message: `KES ${amount} debited.`, newBalance: updated.balance });
  } catch (err) {
    console.error('Admin debit error:', err);
    const status = err.message.startsWith('Insufficient') ? 400 : 500;
    res.status(status).json({ message: err.message || 'Debit failed.' });
  }
});


// ── ADMIN – FREEZE ALL CARDS ──────────────────────────────────
app.post('/api/admin/freeze-all-cards', adminAuth, async (req, res) => {
  try {
    const result = await Account.updateMany({}, { cardFrozen: true });
    console.log(`🔒 Admin froze ALL cards (${result.modifiedCount} accounts)`);
    res.json({ message: `All cards frozen. (${result.modifiedCount} accounts affected)` });
  } catch (err) {
    res.status(500).json({ message: 'Could not freeze all cards.' });
  }
});


// ── ADMIN – FLUSH ALL SESSIONS ────────────────────────────────
// Bumps a tokenVersion on the User model so all existing JWTs are rejected.
// Requires tokenVersion field in User schema and a check in the auth middleware.
app.post('/api/admin/flush-sessions', adminAuth, async (req, res) => {
  try {
    const result = await User.updateMany({}, { $inc: { tokenVersion: 1 } });
    console.log(`🔄 Admin flushed all sessions (${result.modifiedCount} users)`);
    res.json({ message: `All user sessions invalidated. (${result.modifiedCount} users signed out)` });
  } catch (err) {
    res.status(500).json({ message: 'Could not flush sessions.' });
  }
});


// ── ADMIN – PLATFORM STATS ────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const today    = new Date(); today.setHours(0,0,0,0);
    const tomorrow = new Date(today); tomorrow.setDate(today.getDate() + 1);

    const [
      totalUsers, newToday, totalAccounts, frozenCards, suspendedUsers,
      todayTxns, allTimeTxns, balanceAgg
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ createdAt: { $gte: today, $lt: tomorrow } }),
      Account.countDocuments(),
      Account.countDocuments({ cardFrozen: true }),
      User.countDocuments({ status: 'suspended' }),
      Transaction.countDocuments({ createdAt: { $gte: today, $lt: tomorrow } }),
      Transaction.countDocuments(),
      Account.aggregate([{ $group: { _id: null, total: { $sum: '$balance' }, savings: { $sum: '$savingsBalance' } } }])
    ]);

    // Today's transaction volume
    const todayVolumeAgg = await Transaction.aggregate([
      { $match: { createdAt: { $gte: today, $lt: tomorrow }, amount: { $gt: 0 } } },
      { $group: { _id: null, volume: { $sum: '$amount' } } }
    ]);

    res.json({
      users:           totalUsers,
      newUsersToday:   newToday,
      totalAccounts,
      frozenCards,
      suspendedUsers,
      transactionsToday:  todayTxns,
      transactionsAllTime: allTimeTxns,
      totalBalance:    balanceAgg[0]?.total   || 0,
      totalSavings:    balanceAgg[0]?.savings  || 0,
      todayVolume:     todayVolumeAgg[0]?.volume || 0
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ message: 'Could not fetch stats.' });
  }
});


// ── ADMIN – UPDATE USER DETAILS ───────────────────────────────
app.patch('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const allowed  = ['fullName', 'email', 'phone'];
    const updates  = {};
    allowed.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });

    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'User updated.', user });
  } catch (err) {
    res.status(500).json({ message: 'Could not update user.' });
  }
});


// ── ADMIN – RESET USER PASSWORD ───────────────────────────────
app.post('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    console.log(`🔑 Admin reset password for @${user.username}`);
    res.json({ message: `Password reset for @${user.username}.` });
  } catch (err) {
    res.status(500).json({ message: 'Password reset failed.' });
  }
});


// ── ADMIN – DELETE USER (soft delete) ────────────────────────
app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status: 'deleted', deletedAt: new Date() },
      { new: true }
    ).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found.' });
    console.log(`🗑️  Admin soft-deleted user @${user.username}`);
    res.json({ message: `User @${user.username} deleted.` });
  } catch (err) {
    res.status(500).json({ message: 'Could not delete user.' });
  }
});


// ============================================================
//  START SERVER
// ============================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Nala Bank server running on port ${PORT}`);
  console.log(`   User API:  http://localhost:${PORT}/api/status`);
  console.log(`   Admin API: http://localhost:${PORT}/api/admin/login`);
});