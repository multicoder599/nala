// 1. Import Dependencies
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

// 2. Initialize the Express App
const app = express();

// 3. Middleware
app.use(express.json()); // Allows the server to accept JSON data from frontend forms
app.use(cors());         // Allows your frontend HTML files to communicate with this backend

// 4. Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
      console.log('✅ Successfully connected to MongoDB');
  })
  .catch((error) => {
      console.error('❌ Error connecting to MongoDB:', error.message);
  });

// 5. Basic Health Check Route (Just to test if it works)
app.get('/api/status', (req, res) => {
    res.json({ message: "Nala Bank Backend is running smoothly!" });
});

// 6. Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});