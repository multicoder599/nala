const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  // ── Core fields ───────────────────────────────────────────
  accountId: {
    type:     mongoose.Schema.Types.ObjectId,
    ref:      'Account',
    required: true,
    index:    true
  },
  type: {
    type:     String,
    required: true   // 'credit' | 'debit'
  },
  amount: {
    type:     Number,
    required: true   // positive = credit, negative = debit
  },
  description: {
    type:    String,
    default: 'Transaction'
  },
  reference: {
    type:    String,
    default: ''
  },

  // ── Party IDs (required by live DB schema) ────────────────
  // senderId  = the Account._id that initiated the transaction
  // receiverId = the Account._id that received funds (same as accountId for credits)
  // Both default to the accountId so existing routes don't break.
  senderId: {
    type:    mongoose.Schema.Types.ObjectId,
    ref:     'Account',
    default: null
  },
  receiverId: {
    type:    mongoose.Schema.Types.ObjectId,
    ref:     'Account',
    default: null
  },

  // ── Audit / balance snapshot ──────────────────────────────
  balanceAfter: {
    type:    Number,
    default: null
  },

  // ── Optional metadata ─────────────────────────────────────
  recipient:   { type: String, default: '' },
  phone:       { type: String, default: '' },
  biller:      { type: String, default: '' },
  billAccount: { type: String, default: '' },
  network:     { type: String, default: '' },
  category:    { type: String, default: '' },
  adminUser:   { type: String, default: '' }

}, {
  timestamps: true   // createdAt + updatedAt
});

// Compound index for fast per-account history queries
transactionSchema.index({ accountId: 1, createdAt: -1 });

module.exports = mongoose.model('Transaction', transactionSchema);