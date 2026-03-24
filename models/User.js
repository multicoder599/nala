const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    fullName: { 
        type: String, 
        required: true 
    },
    username: { 
        type: String, 
        required: true, 
        unique: true // No two users can have the same username
    },
    phone: { 
        type: String, 
        required: true 
    },
    password: { 
        type: String, 
        required: true 
    },
    biometricEnabled: { 
        type: Boolean, 
        default: false 
    }
}, { timestamps: true }); // Automatically adds createdAt and updatedAt dates

module.exports = mongoose.model('User', userSchema);