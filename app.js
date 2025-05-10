const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const userModel = require('./models/User.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Secret key for JWT
const JWT_SECRET = "Scode";

// Middleware to check authentication
const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.redirect('/login');
    }
};

// Middleware to check admin status
const adminMiddleware = (req, res, next) => {
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        res.status(403).send("Access denied. Admins only.");
    }
};

app.get('/', (req, res) => {
    res.render("index");
});
// app.get('/', (req, res) => {
//     res.send("Hello from Home Route");
// });


app.get('/login', (req, res) => {
    res.render("login");
});

app.get('/register', (req, res) => {
    res.render("register");
});

app.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await userModel.findById(req.user.userId);
        res.render("dashboard", { user });
    } catch (err) {
        res.redirect('/dashboard');
    }
});

app.get('/admin', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await userModel.find({}, 'name email');
        res.render("admin", { users });
    } catch (err) {
        res.status(500).send("Error fetching users");
    }
});

app.post('/register', async (req, res) => {
    try {
        let { name, username, password, email } = req.body;

        // Check if user already exists
        let existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).send("User already exists");
        }

        // Hash password
        let salt = await bcrypt.genSalt(10);
        let hashedPassword = await bcrypt.hash(password, salt);

        // Create new user (first user is admin)
        const isFirstUser = (await userModel.countDocuments({})) === 0;
        let newUser = await userModel.create({
            name,
            username,
            email,
            password: hashedPassword,
            isAdmin: isFirstUser
        });

        // Create token
        const token = jwt.sign(
            { userId: newUser._id, email: email, isAdmin: newUser.isAdmin },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Set cookie and redirect
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send("Error during registration");
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(400).send("Invalid email or password");
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send("Invalid email or password");
        }

        // Create token
        const token = jwt.sign(
            { userId: user._id, email: user.email, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Set cookie and redirect
        res.cookie('token', token, { httpOnly: true });
        if (user.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } catch (err) {
        res.status(500).send("Error during login");
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

app.listen(5000, () => {
    console.log('Server running on port 5000');
});

