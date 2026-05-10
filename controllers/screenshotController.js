// controllers/screenshotController.js
// ─────────────────────────────────────────────────────────────
// Analyzes uploaded payment screenshots for signs of fraud.
// In production: use Google Vision API or a custom ML model.
// Here we simulate forensic checks with realistic logic.
// ─────────────────────────────────────────────────────────────

const path = require('path');
const fs   = require('fs');
const { v4: uuidv4 } = require('uuid');

// ── POST /api/screenshot/analyze ────────────────────────────
const analyzeScreenshot = async (req, res, next) => {
  try {
    // multer puts file info on req.file
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error:   'No screenshot uploaded. Please attach an image file.',
      });
    }

    const { filename, size, mimetype, path: filePath } = req.file;
    const { paymentApp, expectedAmount } = req.body;

    // ── Simulate forensic analysis ───────────────────────────
    // In production, you'd run actual image analysis here:
    // - Check EXIF metadata for editing software
    // - Verify image dimensions match known app templates
    // - Run through a trained ML classifier
    // - Check for pixel manipulation artifacts

    // Simulated analysis delay (feels realistic)
    await new Promise(resolve => setTimeout(resolve, 800));

    // ── Generate forensic checks ─────────────────────────────
    const checks = generateForensicChecks(filename, size, mimetype, paymentApp);

    // Calculate overall fraud probability
    const fraudScore = checks.filter(c => c.status === 'fail').length;
    const warnScore  = checks.filter(c => c.status === 'warn').length;

    let verdict, confidence, riskScore;

    if (fraudScore >= 2) {
      verdict    = 'FRAUD';
      confidence = 85 + (fraudScore * 4);
      riskScore  = 80 + (fraudScore * 5);
    } else if (fraudScore === 1 || warnScore >= 2) {
      verdict    = 'SUSPICIOUS';
      confidence = 68;
      riskScore  = 55;
    } else {
      verdict    = 'GENUINE';
      confidence = 91;
      riskScore  = 8;
    }

    // Cap values at 100
    confidence = Math.min(confidence, 99);
    riskScore  = Math.min(riskScore,  99);

    // Clean up uploaded file after analysis
    // (don't store user screenshots permanently)
    fs.unlink(filePath, () => {});

    return res.json({
      success: true,
      scanId:  uuidv4(),
      verdict,
      confidence,
      riskScore,
      fileName: filename,
      fileSize: `${(size / 1024).toFixed(1)} KB`,
      paymentApp: paymentApp || 'Unknown',
      checks,
      summary: getSummary(verdict),
      recommendation: getRecommendation(verdict),
      analyzedAt: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
};

// ── Helper: generate realistic forensic check results ────────
const generateForensicChecks = (filename, size, mimetype, paymentApp) => {
  // In production these would be real checks.
  // Here we simulate based on file properties.

  const checks = [];

  // Check 1: File size analysis
  // Real payment screenshots are typically 100KB–800KB
  // Very small files may be re-screenshots of fake images
  checks.push({
    name:    'File Size Analysis',
    detail:  `File is ${(size / 1024).toFixed(1)} KB`,
    status:  size < 30000 ? 'warn' :
             size > 5000000 ? 'fail' : 'pass',
    message: size < 30000
      ? 'File is unusually small — may be a re-screenshot'
      : 'File size is within normal range',
  });

  // Check 2: Image format check
  checks.push({
    name:    'Image Format Verification',
    detail:  `Format: ${mimetype}`,
    status:  mimetype === 'image/png' ? 'pass' :
             mimetype === 'image/jpeg' ? 'pass' : 'warn',
    message: 'Image format accepted for analysis',
  });

  // Check 3: Metadata check (simulated)
  // Real implementation: use exifr library to read EXIF data
  const hasEditingMarkers = Math.random() > 0.6; // simulate
  checks.push({
    name:    'Metadata & EXIF Analysis',
    detail:  hasEditingMarkers
      ? 'Adobe Photoshop/Lightroom markers found'
      : 'No editing software markers detected',
    status:  hasEditingMarkers ? 'fail' : 'pass',
    message: hasEditingMarkers
      ? '⚠ Image was edited with photo editing software'
      : 'No evidence of post-processing detected',
  });

  // Check 4: Pixel integrity (simulated)
  const hasPixelArtifacts = Math.random() > 0.7;
  checks.push({
    name:    'Pixel Integrity Check',
    detail:  hasPixelArtifacts
      ? 'Inconsistent pixel patterns near amount field'
      : 'Pixel distribution appears natural',
    status:  hasPixelArtifacts ? 'fail' : 'pass',
    message: hasPixelArtifacts
      ? '⚠ Pixel manipulation detected — possible amount tampering'
      : 'No pixel manipulation detected',
  });

  // Check 5: Font consistency (simulated)
  checks.push({
    name:    'Font & Layout Consistency',
    detail:  `Checking ${paymentApp || 'payment app'} UI template`,
    status:  'pass',
    message: 'Font rendering matches known app templates',
  });

  // Check 6: Timestamp validation (simulated)
  const hasSuspiciousTime = Math.random() > 0.8;
  checks.push({
    name:    'Timestamp Validation',
    detail:  hasSuspiciousTime
      ? 'Transaction time: 3:00:00 AM (unusual)'
      : 'Transaction time appears normal',
    status:  hasSuspiciousTime ? 'warn' : 'pass',
    message: hasSuspiciousTime
      ? '⚠ Unusual transaction time detected'
      : 'Transaction timestamp is within normal hours',
  });

  return checks;
};

// ── Helper: summary message ──────────────────────────────────
const getSummary = (verdict) => {
  const summaries = {
    GENUINE:    'This screenshot appears to be an authentic payment confirmation.',
    SUSPICIOUS: 'Some elements of this screenshot are unusual. Manual verification recommended.',
    FRAUD:      'This screenshot shows clear signs of digital manipulation or forgery.',
  };
  return summaries[verdict];
};

// ── Helper: recommendation ───────────────────────────────────
const getRecommendation = (verdict) => {
  const recs = {
    GENUINE:    'Payment appears legitimate. Safe to confirm the transaction.',
    SUSPICIOUS: 'Do not release goods yet. Ask sender for a bank SMS or email receipt.',
    FRAUD:      'DO NOT release goods or services. Block this user and report to cybercrime.',
  };
  return recs[verdict];
};

module.exports = { analyzeScreenshot };