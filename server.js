require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
const PORT = 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB!'))
    .catch((err) => console.error('MongoDB connection error:', err));

// Define the structure (schema) of a Post
const postSchema = new mongoose.Schema({
    title: String,
    content: String
});

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

const User = mongoose.model('User', userSchema);
// Create a Model to interact with the Posts collection
const Post = mongoose.model('Post', postSchema);

// Middleware to verify JWT token
function authMiddleware(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid token" });
    }
}

app.post('/signup', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
        username: req.body.username,
        password: hashedPassword
    });

    await newUser.save();
    res.json({ message: "User created successfully" });
});

app.post('/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }

    const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);

    if (!isPasswordCorrect) {
        return res.status(400).json({ message: "Incorrect password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
});

app.get('/posts', async (req, res) => {
    const posts = await Post.find();
    res.json(posts);
});

app.post('/posts', authMiddleware, async (req, res) => {
    const newPost = new Post({
        title: req.body.title,
        content: req.body.content
    });
    await newPost.save();
    res.json(newPost);
});

app.put('/posts/:id', authMiddleware, async (req, res) => {
    const updatedPost = await Post.findByIdAndUpdate(
        req.params.id,
        { title: req.body.title, content: req.body.content },
        { new: true }
    );
    res.json(updatedPost);
});

app.delete('/posts/:id', authMiddleware, async (req, res) => {
    await Post.findByIdAndDelete(req.params.id);
    res.json({ message: "Post deleted successfully" });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});