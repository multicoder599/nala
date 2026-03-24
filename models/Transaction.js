const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    senderId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    receiverId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    amount: { 
        type: Number, 
        required: true 
    },
    reference: { 
        type: String, 
        default: "Funds Transfer" 
    },
    status: { 
        type: String, 
        enum: ['pending', 'completed', 'failed'], 
        default: 'completed' 
    }
}, { timestamps: true });

module.exports = mongoose.model('Transaction', transactionSchema);