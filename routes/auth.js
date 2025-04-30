const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const user = require('./models/user');

// Home page
router.get('/', (req, res) => {
    res.render('index');
});

// Register page
router.get('/register', (req, res) => {
    res.render('register');
});

// Handle register
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.redirect('/login');
    } catch (err) {
        res.send('Error: User already exists or invalid input.');
    }
});

// Login page
router.get('/login', (req, res) => {
    res.render('login');
});

// Handle login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.send('No user found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.send('Incorrect password');

    if (user.isAdmin) {
        const allUsers = await User.find({ isAdmin: false });
        res.render('admin', { users: allUsers });
    } else {
        res.render('dashboard', { user });
    }
});

module.exports = router;
