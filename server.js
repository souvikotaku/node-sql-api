require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(express.json());

// Connect to PostgreSQL database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render will provide this
  ssl: { rejectUnauthorized: false }, // Required for Render's PostgreSQL
});

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid Token" });
  }
};

// Create Tables
const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100) UNIQUE,
        password VARCHAR(255)
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        product VARCHAR(100),
        amount DECIMAL(10,2)
      );
    `);
    console.log("Tables created");
  } catch (err) {
    console.error(err);
  }
};
createTables();

// GET API to fetch users
app.get("/api/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST API to add a user
app.post("/api/users", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login User
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (user.rows.length === 0)
      return res.status(400).json({ message: "User not found" });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Create Order (Protected Route)
app.post("/api/orders", authenticateToken, async (req, res) => {
  try {
    const { product, amount } = req.body;
    const newOrder = await pool.query(
      "INSERT INTO orders (user_id, product, amount) VALUES ($1, $2, $3) RETURNING *",
      [req.user.id, product, amount]
    );
    res.json(newOrder.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get User Orders (Protected & With JOIN Query)
app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const orders = await pool.query(
      "SELECT orders.id, users.name, orders.product, orders.amount FROM orders JOIN users ON users.id = orders.user_id WHERE users.id = $1",
      [req.user.id]
    );
    res.json(orders.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get Total Order Amount (Aggregation Example)
app.get("/api/orders/total", authenticateToken, async (req, res) => {
  try {
    const total = await pool.query(
      "SELECT SUM(amount) as total_spent FROM orders WHERE user_id = $1",
      [req.user.id]
    );
    res.json(total.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
