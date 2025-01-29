require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const users = [];
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY;

// User Registration Endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  if (users.some((user) => user.username === username)) {
    return res.status(409).send("User already exists");
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create new user
  const newUser = { username, password: hashedPassword };
  users.push(newUser);

  res.status(201).send("User registered");
});

// User Login Endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Find user by username
  const user = users.find((user) => user.username === username);

  // Validate user and password
  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ username: user.username }, secretKey);
    res.json({ token });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

// Check if the server is running
app.get("/ping", (req, res) => {
  res.send("pong");
});

app.listen(port, () => {
  console.log(
    `User Authentication Service running at http://localhost:${port}/`
  );
});
