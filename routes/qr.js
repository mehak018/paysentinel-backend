// routes/qr.js
const express = require('express');
const router  = express.Router();
const { checkQR } = require('../controllers/qrController.js');

// POST /api/qr/check
// Body: { qrContent } — the raw text decoded from a QR code
router.post('/check', checkQR);

module.exports = router;