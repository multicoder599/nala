// 1. Import Dependencies
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Import Database Models
const User = require('./models/User');
const Account = require('./models/Account');

// 2. Initialize the Express App
const app = express();

// 3. Middleware
app.use(express.json()); 
app.use(cors());         

// 4. Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Successfully connected to MongoDB'))
  .catch((error) => console.error('❌ Error connecting to MongoDB:', error.message));

// ==========================================
// API ROUTES
// ==========================================

// Basic Health Check Route
app.get('/api/status', (req, res) => {
    res.json({ message: "Nala Bank Backend is running smoothly!" });
});

// --- 1. REGISTER ROUTE ---
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, phone, password } = req.body;

        // Check if a user with this phone already exists
        const existingUser = await User.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ message: "Phone number already registered." });
        }

        // Generate a unique username (e.g., "Kevin Mutua" -> "kmutua" + random number)
        const nameParts = fullName.toLowerCase().split(' ');
        const baseUsername = nameParts.length > 1 ? nameParts[0][0] + nameParts[nameParts.length - 1] : nameParts[0];
        const username = baseUsername + Math.floor(Math.random() * 1000);

        // Hash the password securely
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the new User in the database
        const newUser = new User({
            fullName,
            username,
            phone,
            password: hashedPassword
        });
        await newUser.save();

        // Create a linked Bank Account with a Welcome Bonus!
        const newAccount = new Account({
            userId: newUser._id,
            accountNumber: '0123' + Math.floor(10000000 + Math.random() * 90000000), // Random 12-digit account
            balance: 0 // KES 0 Welcome Bonus
        });
        await newAccount.save();

        // Generate a Login Token
        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        // Send success response back to frontend
        res.status(201).json({
            message: "Account created successfully",
            token,
            username: newUser.username,
            fullName: newUser.fullName
        });

    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Server error during registration." });
    }
});

// --- 2. LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: "Invalid username or password." });
        }

        // Check if the password matches the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid username or password." });
        }

        // Generate a Login Token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        // Send success response
        res.json({
            message: "Login successful",
            token,
            username: user.username,
            fullName: user.fullName
        });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error during login." });
    }
});

// 6. Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});