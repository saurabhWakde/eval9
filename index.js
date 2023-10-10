const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const { connection } = require("./config/config");


require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 3000;

const User = mongoose.model('User', {
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  ipAddress: { type: String },
});

const Todo = mongoose.model('Todo', {
  taskname: { type: String, required: true },
  status: { type: String, enum: ['pending', 'done'], required: true },
  tag: { type: String, enum: ['personal', 'official', 'family'], required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

// Middleware
const authMiddleware = (req, res, next) => {
  // Get the token from the request headers
  const token = req.headers.authorization;
  console.log('Received token:', token);

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Verify the token
  jwt.verify(token, process.env.jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Attach the user ID to the request for use in controllers
    req.userId = decoded.userId;

    next(); // Proceed to the next middleware or route handler
  });
};

app.use(cors());
app.use(bodyParser.json());

// Routes
app.get('/',(req,res)=>
{
    res.send("welcome to homepage")
})
app.post('/signup', async (req, res) => {
  try {
    const { email, password, ipAddress } = req.body;

    // Validate user input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, ipAddress });
    await user.save();

    // Create a JWT token
    const token = jwt.sign({ userId: user._id },process.env.jwtSecret);

    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if the password is valid
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.jwtSecret);

    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/todos', authMiddleware, async (req, res) => {
  try {
    const todos = await Todo.find({ user: req.userId });
    res.status(200).json(todos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/todos', authMiddleware, async (req, res) => {
  try {
    const { taskname, status, tag } = req.body;

    // Validate user input
    if (!taskname || !status || !tag) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const newTodo = new Todo({
      taskname,
      status,
      tag,
      user: req.userId,
    });

    const savedTodo = await newTodo.save();
    res.status(201).json(savedTodo);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/todos/:todoID', authMiddleware, async (req, res) => {
  try {
    const { taskname, status, tag } = req.body;
    const { todoID } = req.params;

    // Validate user input
    if (!taskname || !status || !tag) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Find the todo by ID and user
    const todo = await Todo.findOne({ _id: todoID, user: req.userId });

    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    // Update todo fields
    todo.taskname = taskname;
    todo.status = status;
    todo.tag = tag;

    const updatedTodo = await todo.save();
    res.status(200).json(updatedTodo);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/todos/:todoID', authMiddleware, async (req, res) => {
  try {
    const { todoID } = req.params;

    // Find the todo by ID and user
    const todo = await Todo.findOne({ _id: todoID, user: req.userId });

    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    // Delete the todo
    await todo.remove();
    res.status(204).end(); // 204 No Content response
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server
app.listen(port, async () => {
  try {
    await connection;
    console.log("Connection established successfully");
  } catch (error) {
    console.log("Error connecting with mongoose db", error);
  }
  console.log(`listening to server http://localhost:${port
}`);
});
