const mongoose = require('mongoose');

const accountSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', // Links this account to a specific User
        required: true 
    },
    accountNumber: { 
        type: String, 
        required: true, 
        unique: true 
    },
    balance: { 
        type: Number, 
        default: 0.00 // Everyone starts with 0
    }
}, { timestamps: true });

module.exports = mongoose.model('Account', accountSchema);