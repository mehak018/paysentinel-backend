// routes/screenshot.js
const express = require('express');
const router  = express.Router();
const upload  = require('../config/multer.js');
const { analyzeScreenshot } = require('../controllers/screenshotController.js');

// POST /api/screenshot/analyze
// 'screenshot' is the field name from the frontend form
router.post('/analyze', upload.single('screenshot'), analyzeScreenshot);

module.exports = router;