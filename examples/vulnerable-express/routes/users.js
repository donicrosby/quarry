'use strict';

const express = require('express');
const router = express.Router();

// In-memory user store (for demonstration purposes only)
const users = {
  1: { id: 1, name: 'Alice', email: 'alice@example.com', role: 'admin' },
  2: { id: 2, name: 'Bob', email: 'bob@example.com', role: 'user' },
  3: { id: 3, name: 'Carol', email: 'carol@example.com', role: 'user' },
};

// GET /users/:id — return user record by ID
router.get('/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const user = users[id];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  // Returns the full user record to the requester
  return res.json(user);
});

// GET /users — list all users
router.get('/', (req, res) => {
  return res.json(Object.values(users));
});

module.exports = router;
