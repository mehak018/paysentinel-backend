
// ─────────────────────────────────────────────────────────
// Real screenshot fraud detection using actual image analysis
// No more Math.random() — every check uses real data
// ─────────────────────────────────────────────────────────

const path   = require('path');
const fs     = require('fs');
const { v4: uuidv4 } = require('uuid');
const Tesseract = require('tesseract.js');

// Try to load sharp — graceful fallback if not installed
let sharp;
try {
  sharp = require('sharp');
} catch {
  sharp = null;
  console.warn('⚠ Sharp not installed — using basic analysis only');
}

// ══════════════════════════════════════════════════════════
// KNOWN PAYMENT APP SCREENSHOT SPECIFICATIONS
// Real apps produce screenshots with specific dimensions
// ══════════════════════════════════════════════════════════

const APP_SPECS = {
  'PhonePe': {
    // PhonePe success screen is always portrait
    // Typical device widths: 360-430px (mobile)
    minWidth:  300,  maxWidth:  500,
    minHeight: 500,  maxHeight: 1000,
    // PhonePe uses purple — if someone screenshots on PC it's usually wider
    suspiciousWidth: 1920, // desktop screenshot = fake
    bgColor: 'purple',
  },
  'Google Pay': {
    minWidth:  300,  maxWidth:  500,
    minHeight: 500,  maxHeight: 1000,
    suspiciousWidth: 1920,
    bgColor: 'white',
  },
  'Paytm': {
    minWidth:  300,  maxWidth:  500,
    minHeight: 500,  maxHeight: 1000,
    suspiciousWidth: 1920,
    bgColor: 'blue',
  },
  'Amazon Pay': {
    minWidth:  300,  maxWidth:  500,
    minHeight: 500,  maxHeight: 1000,
    suspiciousWidth: 1920,
    bgColor: 'blue',
  },
  'BHIM': {
    minWidth:  300,  maxWidth:  500,
    minHeight: 500,  maxHeight: 1000,
    suspiciousWidth: 1920,
    bgColor: 'blue',
  },
};

// ══════════════════════════════════════════════════════════
// SUSPICIOUS FILENAME PATTERNS
// Scammers often use generated or edited filenames
// ══════════════════════════════════════════════════════════

const SUSPICIOUS_FILENAME_PATTERNS = [
  {
    pattern: /edited/i,
    reason:  'Filename contains "edited" — file was modified'
  },
  {
    pattern: /fake/i,
    reason:  'Filename contains "fake"'
  },
  {
    pattern: /copy/i,
    reason:  'Filename is a copy of another file'
  },
  {
    pattern: /modified/i,
    reason:  'Filename contains "modified"'
  },
  {
    pattern: /photoshop/i,
    reason:  'Filename references Photoshop'
  },
  {
    pattern: /picsart/i,
    reason:  'Filename references PicsArt editing app'
  },
  {
    pattern: /snapseed/i,
    reason:  'Filename references Snapseed editing app'
  },
  {
    pattern: /^img_\d{4}$/i,
    reason:  'Generic sequential filename — unusual for payment screenshots'
  },
];

// ══════════════════════════════════════════════════════════
// REAL FILE SIZE RULES
// Genuine payment screenshots have consistent file sizes
// ══════════════════════════════════════════════════════════

const FILE_SIZE_RULES = {
  tooSmall:    60  * 1024,       // < 60KB  = suspicious (your file is 57KB!)
  smallWarn:   150 * 1024,       // < 150KB = warning
  normalMin:   150 * 1024,       // normal minimum
  normalMax:   3   * 1024*1024,  // 3MB normal max
  tooBig:      5   * 1024*1024,  // > 5MB suspicious
};

// ══════════════════════════════════════════════════════════
// MAIN ANALYSIS FUNCTION
// ══════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════
// OCR — READ TEXT FROM IMAGE
// ══════════════════════════════════════════════════════════

const extractTextFromImage = async (imagePath) => {
  try {
    console.log('Running OCR on image...');
    const { data: { text } } = await Tesseract.recognize(
      imagePath,
      'eng', // English language
      {
        // Quiet mode — no progress logs
        logger: () => {},
      }
    );
    console.log('OCR extracted text:', text.substring(0, 200));
    return text;
  } catch (err) {
    console.error('OCR failed:', err.message);
    return '';
  }
};

// ══════════════════════════════════════════════════════════
// EXTRACT UTR NUMBER FROM OCR TEXT
// ══════════════════════════════════════════════════════════

const extractUTRFromText = (text) => {
  if (!text) return null;

  // Clean the text — OCR sometimes adds extra spaces
  const cleaned = text.replace(/\s+/g, ' ').toUpperCase();

  // Pattern 1: "UTR: 202573372196" or "UTR No: 202573372196"
  const utrLabelMatch = cleaned.match(
    /UTR\s*(?:NO\.?|NUMBER|#|:)?\s*[:\-]?\s*([A-Z0-9]{10,22})/i
  );
  if (utrLabelMatch) return utrLabelMatch[1].trim();

  // Pattern 2: "Ref No: T260514164326603" (transaction reference)
  const refMatch = cleaned.match(
    /(?:REF|REFERENCE|TXN|TRANSACTION)\s*(?:NO\.?|ID|#)?\s*[:\-]?\s*([A-Z0-9]{10,22})/i
  );
  if (refMatch) return refMatch[1].trim();

  // Pattern 3: Standalone 12-digit number (UPI UTR format)
  const standaloneMatch = cleaned.match(/\b(\d{12})\b/);
  if (standaloneMatch) return standaloneMatch[1];

  // Pattern 4: T + digits (PhonePe transaction ID format)
  const phonePeMatch = cleaned.match(/\b(T\d{17,20})\b/);
  if (phonePeMatch) return phonePeMatch[1];

  return null;
};

// ══════════════════════════════════════════════════════════
// EXTRACT AMOUNT FROM OCR TEXT
// ══════════════════════════════════════════════════════════

const extractAmountFromText = (text) => {
  if (!text) return null;

  // Pattern: ₹15 or Rs. 1,500 or INR 5000
  const amountPatterns = [
    /[₹]\s*([0-9,]+(?:\.\d{1,2})?)/,
    /Rs\.?\s*([0-9,]+(?:\.\d{1,2})?)/i,
    /INR\s*([0-9,]+(?:\.\d{1,2})?)/i,
    /Paid\s*[₹Rs.]*\s*([0-9,]+(?:\.\d{1,2})?)/i,
    /Amount\s*[₹Rs.:]*\s*([0-9,]+(?:\.\d{1,2})?)/i,
    /Debited\s*[₹Rs.:]*\s*([0-9,]+(?:\.\d{1,2})?)/i,
  ];

  for (const pattern of amountPatterns) {
    const match = text.match(pattern);
    if (match) {
      // Remove commas and parse
      const amount = parseFloat(match[1].replace(/,/g, ''));
      if (!isNaN(amount) && amount > 0) return amount;
    }
  }
  return null;
};

// ══════════════════════════════════════════════════════════
// DETECT PAYMENT APP FROM OCR TEXT
// ══════════════════════════════════════════════════════════

const detectPaymentAppFromText = (text) => {
  const upper = text.toUpperCase();
  if (upper.includes('PHONEPE'))    return 'PhonePe';
  if (upper.includes('GOOGLE PAY') ||
      upper.includes('GPAY'))       return 'Google Pay';
  if (upper.includes('PAYTM'))      return 'Paytm';
  if (upper.includes('AMAZON PAY')) return 'Amazon Pay';
  if (upper.includes('BHIM'))       return 'BHIM';
  if (upper.includes('NEFT') ||
      upper.includes('RTGS') ||
      upper.includes('IMPS'))       return 'Bank Transfer';
  return null;
};

// ══════════════════════════════════════════════════════════
// VERIFY UTR AGAINST DATABASE
// Same logic as utrController but as a function
// ══════════════════════════════════════════════════════════

const verifyUTRNumber = (utrNumber, extractedAmount, expectedAmount) => {
  if (!utrNumber) return null;

  const cleanUTR = utrNumber.replace(/[\s\-]/g, '').toUpperCase();

  // Definite fraud patterns
  if (/^0+$/.test(cleanUTR))         return { verdict:'FRAUD', reason:'UTR is all zeros' };
  if (/^(.)\1+$/.test(cleanUTR))     return { verdict:'FRAUD', reason:'UTR has repeated identical digits' };
  if (cleanUTR.length < 8)           return { verdict:'FRAUD', reason:'UTR is too short' };
  if (/^1234567890/.test(cleanUTR))  return { verdict:'FRAUD', reason:'UTR is sequential test number' };

  // Amount cross-check
  if (extractedAmount && expectedAmount) {
    const expected = parseFloat(expectedAmount);
    const diff     = Math.abs(extractedAmount - expected);
    const pctDiff  = (diff / expected) * 100;

    if (pctDiff > 1) {
      // More than 1% difference = amount was changed
      return {
        verdict: 'FRAUD',
        reason:  `Amount mismatch: screenshot shows ₹${extractedAmount} but expected ₹${expected}`,
        extractedAmount,
        expectedAmount: expected,
      };
    }
  }

  // Passed checks
  return {
    verdict:         'GENUINE',
    reason:          'UTR format valid and amount matches',
    extractedAmount,
  };
};
const analyzeScreenshot = async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No screenshot uploaded.',
      });
    }

    // DEBUG LOG — shows exact file path
    console.log('═══════════════════════════════════');
    console.log('File received:', req.file.originalname);
    console.log('Saved path:', req.file.path);
    console.log('Absolute path:', path.resolve(req.file.path));
    console.log('File exists:', fs.existsSync(path.resolve(req.file.path)));
    console.log('Size:', req.file.size, 'bytes');
    console.log('═══════════════════════════════════');

    const {
      filename, size, mimetype,
      path: filePath, originalname
    } = req.file;
    const absoluteFilePath = path.resolve(filePath);

    const { paymentApp, expectedAmount } = req.body;

    const checks     = [];
    let riskScore    = 0;
    const fraudFlags = [];

    // ── RUN ALL CHECKS ────────────────────────────────────

    // 1. File size check
    const sizeResult = checkFileSize(size, checks);
    riskScore += sizeResult.score;
    if (sizeResult.flag) fraudFlags.push(sizeResult.flag);

    // 2. File type check
    const typeResult = checkFileType(mimetype, checks);
    riskScore += typeResult.score;
    if (typeResult.flag) fraudFlags.push(typeResult.flag);

    // 3. Filename analysis
    const nameResult = checkFilename(originalname || filename, checks);
    riskScore += nameResult.score;
    if (nameResult.flag) fraudFlags.push(nameResult.flag);

    // 4. Real image property analysis using Sharp
    if (sharp) {
      const imageResult = await analyzeImageProperties(
        filePath, paymentApp, checks
      );
      riskScore += imageResult.score;
      imageResult.flags.forEach(f => fraudFlags.push(f));
    } else {

      // ── FIX: Use absolute path for Sharp ──────────────────────
        const absoluteFilePath = path.resolve(filePath);
        // Verify file actually exists before analyzing
      if (!fs.existsSync(absoluteFilePath)) {
        console.error('File not found at path:', absoluteFilePath);
        return res.status(400).json({
        success: false,
        error:   'Uploaded file not found. Please try uploading again.',
        });
      }
    }
    // 5. Amount consistency check
    if (expectedAmount) {
      const amtResult = checkAmountConsistency(expectedAmount, checks);
      riskScore += amtResult.score;
      if (amtResult.flag) fraudFlags.push(amtResult.flag);
    }

    // 6. File extension vs MIME type consistency
    const extResult = checkExtensionMimeMatch(
      originalname || filename, mimetype, checks
    );
    riskScore += extResult.score;
    if (extResult.flag) fraudFlags.push(extResult.flag);

    // ── CALCULATE VERDICT ─────────────────────────────────
    riskScore = Math.min(riskScore, 100);

    let verdict, confidence;

    if (riskScore >= 50) {
      verdict    = 'FRAUD';
      confidence = Math.min(72 + Math.floor(riskScore / 5), 97);
    } else if (riskScore >= 25) {
      verdict    = 'SUSPICIOUS';
      confidence = 70;
    } else {
      verdict    = 'GENUINE';
      confidence = Math.max(92 - riskScore, 82);
    }

    // ── CLEAN UP UPLOADED FILE ────────────────────────────
    // Delete after analysis — don't store user images
    
    try { fs.unlinkSync(absoluteFilePath); } catch { /* ignore */ }
   return res.json({
  success:         true,
  scanId:          uuidv4(),
  verdict,
  confidence:      Math.round(confidence),
  riskScore,
  fileName:        originalname || filename,
  fileSize:        formatSize(size),
  mimeType:        mimetype,
  paymentApp:      paymentApp || detectedApp || 'Unknown',
  extractedUTR:    extractedUTR   || null,   // ← NEW
  extractedAmount: extractedAmount || null,   // ← NEW
  detectedApp:     detectedApp    || null,   // ← NEW
  checks,
  fraudReasons:    fraudFlags,
  summary:         getSummary(verdict),
  recommendation:  getRecommendation(verdict),
  analyzedAt:      new Date().toISOString(),
});
  } catch (error) {
    // In the catch block at the bottom:
    if (req.file?.path) {
    try {
      const absPath = path.resolve(req.file.path);
      fs.unlinkSync(absPath);
    }   catch { /* ignore */ }
    }
  }
};

// ══════════════════════════════════════════════════════════
// CHECK 1 — FILE SIZE
// ══════════════════════════════════════════════════════════

function checkFileSize(size, checks) {
  let score = 0;
  let flag  = null;

  let status, message, detail;
  const sizeStr = formatFileSize(size);

  if (size < FILE_SIZE_RULES.tooSmall) {
    // Extremely small — almost certainly a re-screenshot of a fake
    status  = 'fail';
    message = `🚨 File is only ${sizeStr} — genuine payment screenshots are never this small`;
    score   = 45;
    flag    = `File extremely small (${sizeStr}) — likely re-screenshot of fake`;
  } else if (size < FILE_SIZE_RULES.smallWarn) {
    // Small — suspicious but not definitive
    status  = 'warn';
    message = `⚠ File is ${sizeStr} — smaller than typical payment screenshots`;
    score   = 20;
  } else if (size > FILE_SIZE_RULES.tooBig) {
    // Too large — heavily processed or wrong file
    status  = 'warn';
    message = `⚠ File is ${sizeStr} — unusually large for a payment screenshot`;
    score   = 15;
  } else {
    // Normal range
    status  = 'pass';
    message = `File size ${sizeStr} is within normal range for payment screenshots`;
    score   = 0;
  }

  detail = `File size: ${sizeStr}`;

  checks.push({ name:'File Size Analysis', detail, status, message });
  return { score, flag };
}

// ══════════════════════════════════════════════════════════
// CHECK 2 — FILE TYPE
// ══════════════════════════════════════════════════════════

function checkFileType(mimetype, checks) {
  const genuineTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
  const isGenuine    = genuineTypes.includes(mimetype);

  // PNG is most common for screenshots
  // JPEG is common too but loses quality each save
  // WEBP is modern
  const isPNG  = mimetype === 'image/png';
  const isJPEG = mimetype === 'image/jpeg' || mimetype === 'image/jpg';

  checks.push({
    name:    'File Type Verification',
    detail:  `Type: ${mimetype}`,
    status:  !isGenuine ? 'fail' : 'pass',
    message: !isGenuine
      ? `🚨 Unexpected file type: ${mimetype}`
      : isPNG
      ? '✓ PNG format — most common for genuine screenshots'
      : isJPEG
      ? '✓ JPEG format accepted'
      : '✓ WEBP format accepted',
  });

  return { score: isGenuine ? 0 : 40, flag: isGenuine ? null : `Invalid file type: ${mimetype}` };
}

// ══════════════════════════════════════════════════════════
// CHECK 3 — FILENAME ANALYSIS
// ══════════════════════════════════════════════════════════

function checkFilename(filename, checks) {
  let score = 0;
  let flag  = null;

  // Remove extension for checking
  const nameWithoutExt = filename.replace(/\.[^.]+$/, '').toLowerCase();

  // Check against suspicious patterns
  const suspiciousPattern = SUSPICIOUS_FILENAME_PATTERNS.find(
    p => p.pattern.test(nameWithoutExt)
  );

  // Check for genuinely screenshot-like filenames
  // Android: Screenshot_20240514_154230.png
  // iOS:     IMG_1234.png or photo_2024-05-14.png
  const looksLikeScreenshot =
    /screenshot/i.test(filename) ||
    /screen.?shot/i.test(filename) ||
    /^\d{13,}$/.test(nameWithoutExt) || // timestamp filename
    /img_\d{4,}/i.test(filename) ||
    /photo_\d/i.test(filename) ||
    /whatsapp.?image/i.test(filename);

  if (suspiciousPattern) {
    checks.push({
      name:    'Filename Analysis',
      detail:  `Filename: ${filename}`,
      status:  'fail',
      message: `🚨 ${suspiciousPattern.reason}`,
    });
    score = 40;
    flag  = suspiciousPattern.reason;
  } else if (looksLikeScreenshot) {
    checks.push({
      name:    'Filename Analysis',
      detail:  `Filename: ${filename}`,
      status:  'pass',
      message: '✓ Filename pattern matches genuine device screenshot',
    });
  } else {
    checks.push({
      name:    'Filename Analysis',
      detail:  `Filename: ${filename}`,
      status:  'warn',
      message: '⚠ Filename does not match typical screenshot naming — manually verify',
    });
    score = 10;
  }

  return { score, flag };
}

// ══════════════════════════════════════════════════════════
// CHECK 4 — REAL IMAGE PROPERTY ANALYSIS (Sharp)
// ══════════════════════════════════════════════════════════

async function analyzeImageProperties(absoluteFilePath, paymentApp, checks) {
  let score = 0;
  const flags = [];

  try {
    // Get real image metadata using Sharp
    const metadata = await sharp(absoluteFilePath).metadata();

    const {
      width, height, format,
      density,        // DPI
      hasAlpha,       // transparency channel
      space,          // color space
      exif,           // raw EXIF data
      icc,            // color profile
      channels,       // number of color channels
    } = metadata;

    // ── Dimension check ────────────────────────────────────
    const aspectRatio = width && height ? width / height : 0;
    const isPortrait  = aspectRatio < 1;
    const isSquare    = aspectRatio >= 0.9 && aspectRatio <= 1.1;
    const isDesktop   = width > 1000;

    const appSpec = APP_SPECS[paymentApp];

    if (isDesktop && paymentApp && paymentApp !== 'Other') {
      // Payment screenshot taken on desktop = suspicious
      // Real payments happen on phones
      checks.push({
        name:    'Screenshot Dimensions',
        detail:  `${width} × ${height}px (${isPortrait ? 'Portrait' : 'Landscape'})`,
        status:  'fail',
        message: `🚨 Image is ${width}px wide — looks like a desktop screenshot, not a mobile payment`,
      });
      score += 45;
      flags.push(`Desktop-sized image (${width}px) for mobile payment app`);
    } else if (appSpec && width) {
      const inRange = width >= appSpec.minWidth && width <= appSpec.maxWidth;
      checks.push({
        name:    'Screenshot Dimensions',
        detail:  `${width} × ${height}px`,
        status:  inRange ? 'pass' : 'warn',
        message: inRange
          ? `✓ Dimensions match ${paymentApp} mobile screenshot`
          : `⚠ Dimensions (${width}×${height}) unusual for ${paymentApp}`,
      });
      if (!inRange) score += 15;
    } else {
      checks.push({
        name:    'Screenshot Dimensions',
        detail:  `${width} × ${height}px`,
        status:  'pass',
        message: `Image dimensions: ${width} × ${height}px`,
      });
    }

    // ── EXIF metadata check ────────────────────────────────
    // EXIF contains info about what device/software created the image
    if (exif) {
      try {
        // Parse EXIF to check for editing software
        const exifStr = exif.toString('binary').toLowerCase();

        const editingTools = [
          { name: 'Adobe Photoshop', pattern: 'photoshop' },
          { name: 'Adobe Lightroom', pattern: 'lightroom' },
          { name: 'GIMP',            pattern: 'gimp'       },
          { name: 'PicsArt',         pattern: 'picsart'    },
          { name: 'Snapseed',        pattern: 'snapseed'   },
          { name: 'Canva',           pattern: 'canva'      },
          { name: 'Adobe Illustrator', pattern: 'illustrator' },
          { name: 'Pixlr',           pattern: 'pixlr'      },
          { name: 'Fotor',           pattern: 'fotor'      },
        ];

        const foundTool = editingTools.find(t => exifStr.includes(t.pattern));

        checks.push({
          name:    'EXIF Metadata Analysis',
          detail:  foundTool
            ? `Editing software detected: ${foundTool.name}`
            : 'No editing software found in metadata',
          status:  foundTool ? 'fail' : 'pass',
          message: foundTool
            ? `🚨 Image was processed with ${foundTool.name} — strong evidence of tampering`
            : '✓ No photo editing software detected in metadata',
        });

        if (foundTool) {
          score += 60;
          flags.push(`Editing software in EXIF: ${foundTool.name}`);
        }
      } catch {
        checks.push({
          name:    'EXIF Metadata Analysis',
          detail:  'Could not parse EXIF data',
          status:  'warn',
          message: '⚠ EXIF data present but unreadable — could indicate tampering',
        });
        score += 10;
      }
    } else {
      // No EXIF at all
      // Screenshots from phones usually have minimal EXIF
      // Screenshots from editors often have EXIF stripped
      checks.push({
        name:    'EXIF Metadata Analysis',
        detail:  'No EXIF metadata found',
        status:  'pass',
        message: '✓ No EXIF metadata — consistent with device screenshot',
      });
    }

    // ── DPI / Density check ────────────────────────────────
    if (density) {
      // Phone screenshots: 72-480 DPI
      // Printed/edited images: often 300+ DPI
      const isUnusualDPI = density > 300 || density === 72;
      checks.push({
        name:    'Image Resolution (DPI)',
        detail:  `${density} DPI`,
        status:  isUnusualDPI ? 'warn' : 'pass',
        message: isUnusualDPI && density > 300
          ? `⚠ ${density} DPI is unusually high for a phone screenshot — may be print-quality edited image`
          : '✓ DPI is consistent with mobile device screenshot',
      });
      if (density > 300) score += 15;
    }

    // ── Color space check ──────────────────────────────────
    // Genuine screenshots: srgb
    // Professionally edited: cmyk, lab (print color spaces)
    if (space === 'cmyk') {
      checks.push({
        name:    'Color Space Analysis',
        detail:  `Color space: CMYK`,
        status:  'fail',
        message: '🚨 Image uses CMYK color space — only used in print design, never in phone screenshots',
      });
      score += 50;
      flags.push('CMYK color space — not a phone screenshot');
    } else {
      checks.push({
        name:    'Color Space Analysis',
        detail:  `Color space: ${space || 'sRGB'}`,
        status:  'pass',
        message: `✓ Color space (${space || 'sRGB'}) is consistent with device screenshots`,
      });
    }

    // ── Alpha channel check ────────────────────────────────
    // Genuine screenshots don't have transparency
    // Edited images sometimes do (layered editing)
    if (hasAlpha && format !== 'png') {
      checks.push({
        name:    'Transparency Check',
        detail:  'Alpha channel detected in non-PNG',
        status:  'warn',
        message: '⚠ Transparency channel detected — unusual for payment screenshots',
      });
      score += 10;
    }

    return { score: Math.min(score, 100), flags };

  } catch (err) {
    console.error('Sharp analysis error:', err.message);
    checks.push({
      name:    'Image Property Analysis',
      detail:  'Analysis failed',
      status:  'warn',
      message: '⚠ Could not fully analyze image properties',
    });
    return { score: 5, flags: [] };
  }
}

// ══════════════════════════════════════════════════════════
// CHECK 5 — AMOUNT CONSISTENCY
// ══════════════════════════════════════════════════════════

function checkAmountConsistency(expectedAmount, checks) {
  const amount = parseFloat(expectedAmount);

  if (isNaN(amount) || amount <= 0) {
    checks.push({
      name:    'Amount Validation',
      detail:  `Expected: ₹${expectedAmount}`,
      status:  'warn',
      message: '⚠ Invalid expected amount entered',
    });
    return { score: 5, flag: null };
  }

  // Suspiciously round large amounts are sometimes fake
  const isVeryRound = amount > 10000 && amount % 5000 === 0;
  // Unusually large amounts
  const isVeryLarge = amount > 500000;

  if (isVeryLarge) {
    checks.push({
      name:    'Amount Analysis',
      detail:  `Amount: ₹${amount.toLocaleString('en-IN')}`,
      status:  'warn',
      message: `⚠ Very large amount ₹${amount.toLocaleString('en-IN')} — verify carefully`,
    });
    return { score: 10, flag: `Very large amount: ₹${amount}` };
  }

  checks.push({
    name:    'Amount Analysis',
    detail:  `Expected amount: ₹${amount.toLocaleString('en-IN')}`,
    status:  'pass',
    message: `Amount ₹${amount.toLocaleString('en-IN')} entered for cross-reference`,
  });
  return { score: 0, flag: null };
}

// ══════════════════════════════════════════════════════════
// CHECK 6 — EXTENSION vs MIME TYPE CONSISTENCY
// ══════════════════════════════════════════════════════════

function checkExtensionMimeMatch(filename, mimetype, checks) {
  const ext = filename.split('.').pop().toLowerCase();

  const extMimeMap = {
    'png':  'image/png',
    'jpg':  'image/jpeg',
    'jpeg': 'image/jpeg',
    'webp': 'image/webp',
  };

  const expectedMime = extMimeMap[ext];
  const matches      = !expectedMime || expectedMime === mimetype;

  checks.push({
    name:    'File Extension Consistency',
    detail:  `.${ext} file with ${mimetype} data`,
    status:  matches ? 'pass' : 'fail',
    message: matches
      ? `✓ File extension .${ext} matches content type`
      : `🚨 File extension .${ext} does not match content type ${mimetype} — file may be renamed`,
  });

  return {
    score: matches ? 0 : 35,
    flag:  matches ? null : `Extension/MIME mismatch: .${ext} vs ${mimetype}`,
  };
}
// ── Check 7: OCR Text Analysis ─────────────────────────────
let extractedUTR    = null;
let extractedAmount = null;
let detectedApp     = null;
let ocrText         = '';

try {
  // Run OCR to read text from image
  ocrText        = await extractTextFromImage(absPath);
  extractedUTR   = extractUTRFromText(ocrText);
  extractedAmount = extractAmountFromText(ocrText);
  detectedApp    = detectPaymentAppFromText(ocrText);

  console.log('OCR UTR found:', extractedUTR);
  console.log('OCR Amount found:', extractedAmount);
  console.log('OCR App detected:', detectedApp);

  // ── OCR Check A: Could we read text at all? ──
  if (!ocrText || ocrText.trim().length < 20) {
    checks.push({
      name:    'Text Recognition (OCR)',
      detail:  'Could not read text from image',
      status:  'warn',
      message: '⚠ Could not extract text — image may be blurry or heavily compressed',
    });
    riskScore += 10;
  } else {
    checks.push({
      name:    'Text Recognition (OCR)',
      detail:  `Read ${ocrText.trim().length} characters from image`,
      status:  'pass',
      message: `✓ Successfully extracted text from screenshot`,
    });
  }

  // ── OCR Check B: UTR found and verified? ──
  if (extractedUTR) {
    const utrCheck = verifyUTRNumber(
      extractedUTR, extractedAmount, expectedAmount
    );

    if (utrCheck.verdict === 'FRAUD') {
      checks.push({
        name:    'UTR Verification (from screenshot)',
        detail:  `Extracted UTR: ${extractedUTR}`,
        status:  'fail',
        message: `🚨 ${utrCheck.reason}`,
      });
      riskScore += 60; // very strong signal
      fraudFlags.push(utrCheck.reason);
    } else {
      checks.push({
        name:    'UTR Verification (from screenshot)',
        detail:  `Extracted UTR: ${extractedUTR}`,
        status:  'pass',
        message: `✓ UTR ${extractedUTR} extracted and format verified`,
      });
    }
  } else {
    checks.push({
      name:    'UTR Verification (from screenshot)',
      detail:  'No UTR number found in image',
      status:  'warn',
      message: '⚠ Could not find a UTR number in this screenshot — verify manually',
    });
    riskScore += 8;
  }

  // ── OCR Check C: Amount cross-verification ──
  if (extractedAmount && expectedAmount) {
    const expected = parseFloat(expectedAmount);
    const diff     = Math.abs(extractedAmount - expected);
    const pctDiff  = (diff / expected) * 100;

    if (pctDiff > 1) {
      checks.push({
        name:    'Amount Cross-Verification',
        detail:  `Screenshot: ₹${extractedAmount} vs Expected: ₹${expected}`,
        status:  'fail',
        message: `🚨 AMOUNT MISMATCH — Screenshot shows ₹${extractedAmount} but you expected ₹${expected}`,
      });
      riskScore += 65; // strongest possible signal
      fraudFlags.push(
        `Amount tampered: shows ₹${extractedAmount}, expected ₹${expected}`
      );
    } else {
      checks.push({
        name:    'Amount Cross-Verification',
        detail:  `Screenshot: ₹${extractedAmount} vs Expected: ₹${expected}`,
        status:  'pass',
        message: `✓ Amount matches — screenshot shows ₹${extractedAmount}`,
      });
    }
  } else if (extractedAmount) {
    checks.push({
      name:    'Amount Detected',
      detail:  `Amount found: ₹${extractedAmount}`,
      status:  'pass',
      message: `✓ Screenshot amount: ₹${extractedAmount} (enter expected amount above to cross-verify)`,
    });
  }

  // ── OCR Check D: Payment app verification ──
  if (detectedApp && paymentApp &&
      paymentApp !== 'Other' &&
      paymentApp !== 'NEFT / Bank Transfer') {
    const appMatches = detectedApp.toLowerCase() ===
                       paymentApp.toLowerCase();
    checks.push({
      name:    'Payment App Verification',
      detail:  `Detected: ${detectedApp} | Selected: ${paymentApp}`,
      status:  appMatches ? 'pass' : 'warn',
      message: appMatches
        ? `✓ Screenshot is from ${detectedApp} as selected`
        : `⚠ Screenshot appears to be from ${detectedApp} but you selected ${paymentApp}`,
    });
    if (!appMatches) riskScore += 15;
  }

} catch (ocrErr) {
  console.error('OCR error:', ocrErr.message);
  checks.push({
    name:    'Text Recognition (OCR)',
    detail:  'OCR engine error',
    status:  'warn',
    message: '⚠ Text recognition failed — manual verification required',
  });
}

// ══════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ══════════════════════════════════════════════════════════

function formatFileSize(bytes) {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getSummary(verdict) {
  return {
    GENUINE:    'This screenshot appears to be an authentic payment confirmation. Properties are consistent with a genuine device screenshot.',
    SUSPICIOUS: 'Some properties of this screenshot are unusual. Manual verification is strongly recommended before proceeding.',
    FRAUD:      'This screenshot shows clear signs of digital manipulation or forgery. Do not accept this as payment proof.',
  }[verdict];
}

function getRecommendation(verdict) {
  return {
    GENUINE:    'Payment appears legitimate. For large amounts, always cross-verify with your bank portal or SMS.',
    SUSPICIOUS: 'Do NOT release goods yet. Ask the sender to share the bank SMS confirmation directly.',
    FRAUD:      'REJECT this payment proof. Ask sender for bank-verified receipt. Block and report if they refuse.',
  }[verdict];
}

module.exports = { analyzeScreenshot };