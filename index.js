const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

app.use(bodyParser.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => console.error('Failed to connect to MongoDB:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
    title: String,
    description: String,
    priority: String,
    status: String,
    assignee: { type: mongoose.Schema.Types.ObjectId, ref: 'User',default:null },
    createdAt: { type: Date, default: Date.now },
});

const Task = mongoose.model('Task', taskSchema);

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(`${username} + ${password}`);
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        
        res.json({ success: true, message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error registering user' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid username or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ success: false, message: 'Invalid username or password' });

    const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ success: true, token });
});

const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Access Denied' });
    
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid Token' });
    }
};

app.post('/api/tasks',authenticate, async (req, res) => {
    try {
        const { title, description, priority, status, assignee } = req.body;
        const newTask = new Task({ title, description, priority, status, assignee });
        await newTask.save();
        
        res.json({ success: true, task: newTask });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error creating task' });
    }
});

app.put('/api/tasks/:id',authenticate, async (req, res) => {
    try {
        const { title, description, priority, status, assignee } = req.body;
        const task = await Task.findByIdAndUpdate(
            req.params.id,
            { title, description, priority, status, assignee },
            { new: true }
        );
        
        if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
        res.json({ success: true, task });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating task' });
    }
});

app.delete('/api/tasks/:id', authenticate, async (req, res) => {
    try {
        const task = await Task.findByIdAndDelete(req.params.id);
        if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
        
        res.json({ success: true, message: 'Task deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error deleting task' });
    }
});

app.put('/api/tasks/assign/:id',authenticate, async (req, res) => {
    try {
        const { assignee } = req.body;
        const task = await Task.findByIdAndUpdate(
            req.params.id,
            { assignee },
            { new: true }
        );

        if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
        res.json({ success: true, task });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error assigning task' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
