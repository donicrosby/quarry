'use strict';

const { exec } = require('child_process');
const express = require('express');
const router = express.Router();

// POST /admin/exec — run a system command from the request body. Body: { "cmd": "..." }
router.post('/exec', (req, res) => {
  const { cmd } = req.body;
  if (!cmd || typeof cmd !== 'string') {
    return res.status(400).json({ error: 'cmd field required' });
  }

  exec(cmd, { timeout: 5000 }, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message, stderr });
    }
    return res.json({ stdout, stderr });
  });
});

// GET /admin/status — basic admin status check
router.get('/status', (req, res) => {
  return res.json({ admin: true, uptime: process.uptime() });
});

module.exports = router;
