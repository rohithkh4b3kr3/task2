const mongoose = require('mongoose');

mongoose.connect ('mongodb://localhost:27017/webopsappdatabase')
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }
});

module.exports = mongoose.model('User', userSchema);