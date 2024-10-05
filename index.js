// index.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const morgan = require('morgan');
const crypto = require('crypto');
const User = require('./models/User');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(morgan('combined')); // Logging middleware

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Middleware to protect routes
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(403).send({ message: 'Access denied. No token provided.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ message: 'Invalid token.' });
        req.user = user;
        next();
    });
};

// User validation schema
const userSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid('user', 'admin').optional(), // Allow 'role' field with validation
});

// Error handling middleware
const errorHandler = (err, req, res, next) => {
    console.error(err.message || err);
    res.status(500).send({ message: 'An unexpected error occurred.' });
};

// CRUD Endpoints
// Create User
app.post('/users', async (req, res) => {
    const { error } = userSchema.validate(req.body);
    if (error) return res.status(400).send({ message: error.details[0].message });

    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) return res.status(400).send({ message: 'Email already exists.' });

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
        role: req.body.role || 'user', // Default to 'user' if no role is provided
    });

    try {
        const savedUser = await user.save();
        const token = jwt.sign({ _id: savedUser._id, role: savedUser.role }, process.env.JWT_SECRET);
        res.status(201).json({ token });
    } catch (err) {
        res.status(500).send({ message: 'Error saving user: ' + err.message });
    }
});


// Read Users
app.get('/users', authenticateJWT, async (req, res) => {
    try {
        const { role } = req.query;
        const users = role === 'admin' ? await User.find({ role: 'admin' }) : await User.find();
        res.json(users);
    } catch (err) {
        res.status(500).send({ message: 'Error retrieving users: ' + err.message });
    }
});

// Update User
app.put('/users/:id', authenticateJWT, async (req, res) => {
    if (req.user._id !== req.params.id && req.user.role !== 'admin') {
        return res.status(403).send({ message: 'Access denied. Admins only can update other users.' });
    }

    const updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.email) updates.email = req.body.email;
    if (req.body.role && req.user.role === 'admin') updates.role = req.body.role; // Allow admin to change role

    try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, updates, { new: true });
        if (!updatedUser) return res.status(404).send({ message: 'User not found.' });
        res.json(updatedUser);
    } catch (err) {
        res.status(400).send({ message: 'Error updating user: ' + err.message });
    }
});


// Delete User
app.delete('/users/:id', authenticateJWT, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).send({ message: 'Access denied. Admins only.' });

    try {
        const deletedUser = await User.findByIdAndDelete(req.params.id);
        if (!deletedUser) return res.status(404).send({ message: 'User not found.' });
        res.sendStatus(204);
    } catch (err) {
        res.status(500).send({ message: 'Error deleting user: ' + err.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send({ message: 'User not found.' });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send({ message: 'Invalid password.' });

    const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token });
});

// Request Password Reset
app.post('/reset-password', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send({ message: 'User not found.' });

    const token = crypto.randomBytes(20).toString('hex');
    user.passwordResetToken = token;
    user.passwordResetExpires = Date.now() + 3600000; // Token valid for 1 hour

    try {
        await user.save();
        // Simulating sending an email
        console.log(`Password reset link: http://localhost:5000/reset-password/${token}`);
        res.send('Password reset link has been sent to your email address (simulated).');
    } catch (err) {
        res.status(500).send({ message: 'Error saving password reset token: ' + err.message });
    }
});

// Reset Password
app.post('/reset-password/:token', async (req, res) => {
    const user = await User.findOne({
        passwordResetToken: req.params.token,
        passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).send({ message: 'Password reset token is invalid or has expired.' });

    const { error } = Joi.object({
        password: Joi.string().min(6).required(),
    }).validate(req.body);

    if (error) return res.status(400).send({ message: error.details[0].message });

    try {
        user.password = await bcrypt.hash(req.body.password, 10);
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save();
        res.send('Password has been successfully reset.');
    } catch (err) {
        res.status(500).send({ message: 'Error resetting password: ' + err.message });
    }
});

// Error Handling Middleware
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
