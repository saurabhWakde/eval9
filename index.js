
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



const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  ipAddress: { type: String }
});

const TodoSchema = new mongoose.Schema({
  taskname: { type: String, required: true },
  status: { type: String, enum: ['pending', 'done'], required: true },
  tag: { type: String, enum: ['personal', 'official', 'family'], required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

const User = mongoose.model('User', UserSchema);
const Todo = mongoose.model('Todo', TodoSchema);


const authMiddleware = (req, res, next) => {
  const token = req.header('x-auth-token');

  if (!token) {
    return res.status(401).json({ msg: 'Authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.jwtSecret);
    req.user = decoded.userId; 
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};



app.get('/',(req,res)=>
{
  res.send("Welcome to homepage")
})


app.post('/signup', async (req, res) => {
  try {
    const { email, password, ipAddress } = req.body;

 
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }


    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }


    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ email, password: hashedPassword, ipAddress });
    await newUser.save();


    const token = jwt.sign({ userId: newUser._id }, process.env.jwtSecret);

    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

 
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

  
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

   
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

 
    const token = jwt.sign({ userId: user._id }, process.env.jwtSecret);

    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});






app.post('/todos', authMiddleware, async (req, res) => {
  try {
    const { taskname, status, tag } = req.body;
    const userId = req.user; 

  
    if (!taskname || !status || !tag) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const newTodo = new Todo({
      taskname,
      status,
      tag,
      user: userId,
    });

    const savedTodo = await newTodo.save();
    res.status(201).json(savedTodo);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




app.get('/todos', authMiddleware, async (req, res) => {
  try {
    const todos = await Todo.find({ user: req.user.id });
    res.status(200).json(todos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.patch('/todos/:id', authMiddleware, async (req, res) => {
  try {
    const { taskname, status, tag } = req.body;
    const { id } = req.params;


    if (!taskname && !status && !tag) {
      return res.status(400).json({ error: 'At least one field is required for the update' });
    }


    const todo = await Todo.findOne({ _id: id, user: req.user.id });

    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    if (taskname) {
      todo.taskname = taskname;
    }
    if (status) {
      todo.status = status;
    }
    if (tag) {
      todo.tag = tag;
    }

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
    const userId = req.user.id;

    console.log('Deleting todo for user:', userId);
    console.log('Deleting todo with ID:', todoID);

  
    const deletedTodo = await Todo.findOneAndRemove({ _id: todoID, user: userId });

    if (!deletedTodo) {
      console.error('Todo not found for deletion:', todoID);
      return res.status(404).json({ error: 'Todo not found' });
    }

    console.log('Todo deleted successfully:', deletedTodo);

    res.status(204).end(); 
  } catch (error) {
    console.error('Error deleting todo:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});






app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
