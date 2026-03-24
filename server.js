// ============================================================
//  Nala Bank – Express API Server
//  All routes consumed by the dashboard, login and register
// ============================================================

require('dotenv').config();
const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');

// ── Models ──────────────────────────────────────────────────
const User        = require('./models/User');
const Account     = require('./models/Account');
const Transaction = require('./models/Transaction');   // NEW – see schema below

// ── App ─────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(cors());

// ── MongoDB ──────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err.message));


// ============================================================
//  MIDDLEWARE – protect routes with JWT
// ============================================================
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


// ============================================================
//  HELPERS
// ============================================================

/** Generate a reference code like NL-2025-AB3X */
function genRef() {
  return 'NL-' + new Date().getFullYear() + '-' +
    Math.random().toString(36).substring(2,6).toUpperCase();
}

/** Record a transaction and update account balance atomically */
async function recordTransaction(accountId, type, amount, description, meta = {}) {
  const isCredit = ['credit', 'deposit', 'received', 'airtime_received', 'savings_interest'].includes(type);
  const sign     = isCredit ? 1 : -1;

  const account = await Account.findByIdAndUpdate(
    accountId,
    { $inc: { balance: sign * Math.abs(amount) } },
    { new: true }
  );

  if (!account) throw new Error('Account not found');

  await Transaction.create({
    accountId,
    type,
    amount: sign * Math.abs(amount),   // negative for debits, positive for credits
    description,
    reference: genRef(),
    ...meta
  });

  return account;
}


// ============================================================
//  PUBLIC ROUTES
// ============================================================

// Health check
app.get('/api/status', (req, res) =>
  res.json({ message: 'Nala Bank Backend is running smoothly!' })
);


// ── REGISTER ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, username: rawUsername, email, phone, password } = req.body;

    // Validate required fields
    if (!fullName || !phone || !password)
      return res.status(400).json({ message: 'Full name, phone and password are required.' });

    // Build a clean username
    let username = rawUsername
      ? rawUsername.toLowerCase().replace(/[^a-z0-9_]/g, '')
      : '';

    if (!username) {
      const parts = fullName.toLowerCase().split(' ');
      const base  = parts.length > 1
        ? parts[0][0] + parts[parts.length - 1]
        : parts[0];
      username = base.replace(/[^a-z0-9_]/g, '') + Math.floor(Math.random() * 1000);
    }

    // Uniqueness checks
    const [existPhone, existUser, existEmail] = await Promise.all([
      User.findOne({ phone }),
      User.findOne({ username }),
      email ? User.findOne({ email }) : Promise.resolve(null)
    ]);

    if (existPhone) return res.status(400).json({ message: 'Phone number already registered.' });
    if (existUser)  return res.status(400).json({ message: 'Username already taken. Please choose another.' });
    if (existEmail) return res.status(400).json({ message: 'Email address already registered.' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const newUser = await User.create({
      fullName,
      username,
      email:    email || '',
      phone,
      password: hashedPassword
    });

    // Create account with welcome balance KES 0
    const accountNumber = '0123' + Math.floor(10000000 + Math.random() * 90000000);
    const newAccount = await Account.create({
      userId:        newUser._id,
      accountNumber,
      balance:       0
    });

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message:       'Account created successfully',
      token,
      username:      newUser.username,
      fullName:      newUser.fullName,
      accountNumber: newAccount.accountNumber
    });

  } catch (err) {
    console.error('Registration error:', err);
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

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message:  'Login successful',
      token,
      username: user.username,
      fullName: user.fullName
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login.' });
  }
});


// ============================================================
//  PROTECTED ROUTES  (all require a valid JWT)
// ============================================================

// ── ACCOUNT BALANCE ──────────────────────────────────────────
app.get('/api/account/balance', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    res.json({
      balance:       account.balance,
      accountNumber: account.accountNumber,
      currency:      'KES'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not fetch balance.' });
  }
});


// ── TRANSACTIONS (list) ──────────────────────────────────────
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    const limit = parseInt(req.query.limit) || 20;
    const page  = parseInt(req.query.page)  || 1;

    const transactions = await Transaction
      .find({ accountId: account._id })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({ transactions, page, limit });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not fetch transactions.' });
  }
});


// ── TRANSFER (send money) ────────────────────────────────────
app.post('/api/transfer', auth, async (req, res) => {
  try {
    const { recipient, amount, note } = req.body;

    if (!recipient || !amount || amount <= 0)
      return res.status(400).json({ message: 'Recipient and a valid amount are required.' });

    const senderAccount = await Account.findOne({ userId: req.user.id });
    if (!senderAccount) return res.status(404).json({ message: 'Your account was not found.' });

    if (senderAccount.balance < amount)
      return res.status(400).json({ message: 'Insufficient balance.' });

    // Debit sender
    await recordTransaction(
      senderAccount._id, 'debit', amount,
      note || `Transfer to ${recipient}`,
      { recipient }
    );

    // Credit recipient if their account exists (internal transfer)
    const recipUser    = await User.findOne({ username: recipient });
    const recipAccount = recipUser ? await Account.findOne({ userId: recipUser._id }) : null;

    if (recipAccount) {
      await recordTransaction(
        recipAccount._id, 'credit', amount,
        `Transfer from @${(await User.findById(req.user.id)).username}`,
        { sender: req.user.id }
      );
    }

    const updated = await Account.findById(senderAccount._id);
    res.json({
      message:    'Transfer successful',
      reference:  genRef(),
      newBalance: updated.balance
    });

  } catch (err) {
    console.error('Transfer error:', err);
    res.status(500).json({ message: 'Transfer failed. Please try again.' });
  }
});


// ── M-PESA DEPOSIT / WITHDRAW ────────────────────────────────
app.post('/api/mpesa', auth, async (req, res) => {
  try {
    const { type, phone, amount } = req.body;

    if (!type || !phone || !amount || amount <= 0)
      return res.status(400).json({ message: 'Type, phone and amount are required.' });

    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    if (type === 'withdraw' && account.balance < amount)
      return res.status(400).json({ message: 'Insufficient balance for withdrawal.' });

    const txType      = type === 'deposit' ? 'credit' : 'debit';
    const description = type === 'deposit'
      ? `M-Pesa deposit from ${phone}`
      : `M-Pesa withdrawal to ${phone}`;

    await recordTransaction(account._id, txType, amount, description, { phone });

    const updated = await Account.findById(account._id);
    res.json({
      message:    `M-Pesa ${type} of KES ${amount} processed successfully.`,
      reference:  genRef(),
      newBalance: updated.balance
    });

  } catch (err) {
    console.error('M-Pesa error:', err);
    res.status(500).json({ message: 'M-Pesa transaction failed.' });
  }
});


// ── AIRTIME ──────────────────────────────────────────────────
app.post('/api/airtime', auth, async (req, res) => {
  try {
    const { network, phone, amount } = req.body;

    if (!phone || !amount || amount <= 0)
      return res.status(400).json({ message: 'Phone and amount are required.' });

    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    if (account.balance < amount)
      return res.status(400).json({ message: 'Insufficient balance.' });

    await recordTransaction(
      account._id, 'debit', amount,
      `${network || 'Airtime'} purchase for ${phone}`,
      { phone, network }
    );

    const updated = await Account.findById(account._id);
    res.json({
      message:    `KES ${amount} airtime sent to ${phone}.`,
      reference:  genRef(),
      newBalance: updated.balance
    });

  } catch (err) {
    console.error('Airtime error:', err);
    res.status(500).json({ message: 'Airtime purchase failed.' });
  }
});


// ── BILL PAYMENT ─────────────────────────────────────────────
app.post('/api/bills/pay', auth, async (req, res) => {
  try {
    const { biller, account: billAccount, amount } = req.body;

    if (!biller || !billAccount || !amount || amount <= 0)
      return res.status(400).json({ message: 'Biller, account number and amount are required.' });

    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    if (account.balance < amount)
      return res.status(400).json({ message: 'Insufficient balance.' });

    await recordTransaction(
      account._id, 'debit', amount,
      `${biller} – A/C ${billAccount}`,
      { biller, billAccount }
    );

    const updated = await Account.findById(account._id);
    res.json({
      message:    `${biller} payment of KES ${amount} processed.`,
      reference:  genRef(),
      newBalance: updated.balance
    });

  } catch (err) {
    console.error('Bill payment error:', err);
    res.status(500).json({ message: 'Bill payment failed.' });
  }
});


// ── SAVINGS DEPOSIT ───────────────────────────────────────────
app.post('/api/savings/deposit', auth, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount < 100)
      return res.status(400).json({ message: 'Minimum savings deposit is KES 100.' });

    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    if (account.balance < amount)
      return res.status(400).json({ message: 'Insufficient balance.' });

    await recordTransaction(
      account._id, 'debit', amount,
      `Smart Savings deposit`,
      { type: 'savings' }
    );

    // Update or create savings record on the account
    await Account.findByIdAndUpdate(account._id, {
      $inc: { savingsBalance: amount }
    });

    const updated = await Account.findById(account._id);
    res.json({
      message:        `KES ${amount} moved to Smart Savings.`,
      reference:      genRef(),
      newBalance:     updated.balance,
      savingsBalance: updated.savingsBalance || amount
    });

  } catch (err) {
    console.error('Savings error:', err);
    res.status(500).json({ message: 'Savings deposit failed.' });
  }
});


// ── PROFILE – GET ─────────────────────────────────────────────
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user    = await User.findById(req.user.id).select('-password');
    const account = await Account.findOne({ userId: req.user.id });
    if (!user) return res.status(404).json({ message: 'User not found.' });

    res.json({
      fullName:      user.fullName,
      username:      user.username,
      email:         user.email,
      phone:         user.phone,
      accountNumber: account?.accountNumber,
      createdAt:     user.createdAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not fetch profile.' });
  }
});


// ── PROFILE – UPDATE ─────────────────────────────────────────
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
    console.error(err);
    res.status(500).json({ message: 'Profile update failed.' });
  }
});


// ── CHANGE PASSWORD ───────────────────────────────────────────
app.post('/api/account/password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: 'Both current and new password are required.' });

    if (newPassword.length < 8)
      return res.status(400).json({ message: 'New password must be at least 8 characters.' });

    const user = await User.findById(req.user.id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect.' });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Password change failed.' });
  }
});


// ── FREEZE CARD ───────────────────────────────────────────────
app.post('/api/card/freeze', auth, async (req, res) => {
  try {
    const account = await Account.findOneAndUpdate(
      { userId: req.user.id },
      { cardFrozen: true },
      { new: true }
    );
    if (!account) return res.status(404).json({ message: 'Account not found.' });
    res.json({ message: 'Card frozen successfully.', frozen: true });
  } catch (err) {
    res.status(500).json({ message: 'Could not freeze card.' });
  }
});

// Unfreeze card
app.post('/api/card/unfreeze', auth, async (req, res) => {
  try {
    const account = await Account.findOneAndUpdate(
      { userId: req.user.id },
      { cardFrozen: false },
      { new: true }
    );
    res.json({ message: 'Card unfrozen.', frozen: false });
  } catch (err) {
    res.status(500).json({ message: 'Could not unfreeze card.' });
  }
});


// ── CARD PIN ──────────────────────────────────────────────────
app.post('/api/card/pin', auth, async (req, res) => {
  try {
    const { currentPin, newPin } = req.body;
    if (!newPin || newPin.length !== 4 || !/^\d{4}$/.test(newPin))
      return res.status(400).json({ message: 'PIN must be exactly 4 digits.' });

    const hashedPin = await bcrypt.hash(newPin, 10);
    await Account.findOneAndUpdate({ userId: req.user.id }, { cardPin: hashedPin });
    res.json({ message: 'Card PIN updated successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'PIN update failed.' });
  }
});


// ── SPENDING LIMITS ───────────────────────────────────────────
app.post('/api/card/limits', auth, async (req, res) => {
  try {
    const { dailyLimit, transactionLimit } = req.body;
    const updates = {};
    if (dailyLimit)       updates.dailyLimit       = parseFloat(dailyLimit);
    if (transactionLimit) updates.transactionLimit = parseFloat(transactionLimit);

    await Account.findOneAndUpdate({ userId: req.user.id }, updates);
    res.json({ message: 'Spending limits updated.' });
  } catch (err) {
    res.status(500).json({ message: 'Could not update limits.' });
  }
});


// ── CARD DETAILS (reveal number) ──────────────────────────────
app.get('/api/card/details', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    // In production use a vault / tokenisation service.
    // Here we return the stored virtual card number.
    res.json({
      cardNumber:  account.cardNumber  || '4000 0000 0000 0000',
      expiryDate:  account.cardExpiry  || '12/28',
      cvv:         account.cardCvv     || '000',
      cardHolder:  (await User.findById(req.user.id)).fullName,
      frozen:      account.cardFrozen  || false
    });
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch card details.' });
  }
});


// ── SAVINGS BALANCE ───────────────────────────────────────────
app.get('/api/savings', auth, async (req, res) => {
  try {
    const account = await Account.findOne({ userId: req.user.id });
    if (!account) return res.status(404).json({ message: 'Account not found.' });

    res.json({
      savingsBalance: account.savingsBalance || 0,
      interestRate:   12,
      currency:       'KES'
    });
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch savings.' });
  }
});


// ============================================================
//  Transaction model schema  (create this file if it doesn't exist)
//  File: models/Transaction.js
// ============================================================
/*
const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  accountId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Account', required: true },
  type:        { type: String, required: true },    // 'credit' | 'debit'
  amount:      { type: Number, required: true },    // positive = credit, negative = debit
  description: { type: String, default: 'Transaction' },
  reference:   { type: String },
  recipient:   { type: String },
  phone:       { type: String },
  biller:      { type: String },
  network:     { type: String },
  sender:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

module.exports = mongoose.model('Transaction', transactionSchema);
*/


// ============================================================
//  Account model  – ADD these fields to your existing schema
// ============================================================
/*
  savingsBalance:     { type: Number, default: 0 },
  cardFrozen:         { type: Boolean, default: false },
  cardNumber:         { type: String, default: '' },
  cardExpiry:         { type: String, default: '' },
  cardCvv:            { type: String, default: '' },
  cardPin:            { type: String, default: '' },
  dailyLimit:         { type: Number, default: 300000 },
  transactionLimit:   { type: Number, default: 50000 },
*/


// ── START SERVER ──────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Nala Bank server running on port ${PORT}`));