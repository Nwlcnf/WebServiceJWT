const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

const users = [];
const tasks = {};

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).send('Access Denied');
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], 'secretkey');
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).send('Invalid Token');
    }
};

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });

    if (!tasks[username]) {
        tasks[username] = [];
    }

    res.status(201).send('User registered successfully');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).send('Invalid username or password');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).send('Invalid username or password');
    }

    const token = jwt.sign({ username: user.username }, 'secretkey', { expiresIn: '1h' });
    res.json({ token });
});

app.route('/tasks')
    .get(authenticateJWT, (req, res) => {
        res.json(tasks[req.user.username]);
    })
    .post(authenticateJWT, (req, res) => {
        const task = req.body.task;
        if (!task) {
            return res.status(400).send('Task is required');
        }
        tasks[req.user.username].push(task);
        res.status(201).send('Task added successfully');
    })
    .put(authenticateJWT, (req, res) => {
        const { taskId, newTask } = req.body;
        if (taskId === undefined || !newTask) {
            return res.status(400).send('Task ID and new task are required');
        }
        if (tasks[req.user.username][taskId] === undefined) {
            return res.status(400).send('Task not found');
        }
        tasks[req.user.username][taskId] = newTask;
        res.send('Task updated successfully');
    })
    .delete(authenticateJWT, (req, res) => {
        const { taskId } = req.body;
        if (taskId === undefined) {
            return res.status(400).send('Task ID is required');
        }
        if (tasks[req.user.username][taskId] === undefined) {
            return res.status(400).send('Task not found');
        }
        tasks[req.user.username].splice(taskId, 1);
        res.send('Task deleted successfully');
    });

app.get('/users', authenticateJWT, (req, res) => {
    res.json(users.map(user => ({ username: user.username })));
});


app.get('/protected', authenticateJWT, (req, res) => {
    res.send('This is a protected route');
});
