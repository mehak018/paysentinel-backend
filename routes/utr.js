// routes/utr.js
// Defines the URL endpoints for UTR verification
// The actual logic lives in the controller

const express = require('express');
const router  = express.Router();
const { verifyUTR, getUTRHistory } = require('../controllers/utrController.js');

// POST /api/utr/verify
// Body: { utrNumber, paymentMethod, expectedAmount }
router.post('/verify', verifyUTR);

// GET /api/utr/history
// Returns recent UTR checks (simulated)
router.get('/history', getUTRHistory);

module.exports = router;