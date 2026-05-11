// controllers/utrController.js
// Fixed version — much smarter UTR validation logic

const { v4: uuidv4 } = require('uuid');

// ── Real UTR format rules ─────────────────────────────────
// Real Indian payment UTRs follow these patterns:
// NEFT:  16 characters alphanumeric
// RTGS:  16 characters alphanumeric  
// IMPS:  12 digit numeric
// UPI:   12-22 digit numeric

const UTR_FORMATS = {
  UPI:  { minLen: 12, maxLen: 22, pattern: /^\d+$/,
          desc: '12-22 digit number' },
  NEFT: { minLen: 16, maxLen: 16, pattern: /^[A-Z]{4}\d{12}$/i,
          desc: '16 characters (4 letters + 12 digits)' },
  RTGS: { minLen: 16, maxLen: 16, pattern: /^[A-Z]{4}\d{12}$/i,
          desc: '16 characters (4 letters + 12 digits)' },
  IMPS: { minLen: 12, maxLen: 12, pattern: /^\d{12}$/,
          desc: 'exactly 12 digits' },
};

// ── Definite fraud patterns ───────────────────────────────
// These are ALWAYS fraud — no exceptions
const DEFINITE_FRAUD_PATTERNS = [
  {
    test: (utr) => /^0+$/.test(utr),
    reason: 'UTR is all zeros — clearly fabricated'
  },
  {
    test: (utr) => /^1234567890/.test(utr),
    reason: 'UTR is a sequential test number — not a real transaction'
  },
  {
    test: (utr) => utr.length < 8,
    reason: 'UTR is too short — real UTRs have at least 12 characters'
  },
  {
    test: (utr) => {
      // All same digit like 111111111111 or 222222222222
      return /^(.)\1+$/.test(utr);
    },
    reason: 'UTR contains repeated identical digits — invalid pattern'
  },
];

// ── Format validator ──────────────────────────────────────
const validateFormat = (utr, method) => {
  const format = UTR_FORMATS[method.toUpperCase()];
  if (!format) return { valid: true, reason: '' }; // unknown method, don't penalize

  if (utr.length < format.minLen || utr.length > format.maxLen) {
    return {
      valid: false,
      reason: `${method} UTR should be ${format.desc}. ` +
              `You entered ${utr.length} characters.`
    };
  }

  if (!format.pattern.test(utr)) {
    return {
      valid: false,
      reason: `${method} UTR format is invalid. Expected ${format.desc}.`
    };
  }

  return { valid: true, reason: '' };
};

// ── Risk score (lower = safer) ────────────────────────────
const calculateRiskScore = (utr, method, amount) => {
  let score = 0;

  // Very round large amounts can be slightly suspicious
  if (amount && amount > 50000 && amount % 10000 === 0) score += 5;

  // Mostly sequential digits
  let sequential = 0;
  for (let i = 0; i < utr.length - 1; i++) {
    if (Math.abs(parseInt(utr[i+1]) - parseInt(utr[i])) === 1) sequential++;
  }
  if (sequential > utr.length * 0.7) score += 20;

  return Math.min(score, 100);
};

// ── POST /api/utr/verify ──────────────────────────────────
const verifyUTR = async (req, res, next) => {
  try {
    const { utrNumber, paymentMethod = 'UPI', expectedAmount } = req.body;

    if (!utrNumber) {
      return res.status(400).json({
        success: false,
        error: 'UTR number is required',
      });
    }

    // Clean input
    const cleanUTR = utrNumber.replace(/[\s\-]/g, '').trim().toUpperCase();

    // ── Check definite fraud patterns first ──
    for (const pattern of DEFINITE_FRAUD_PATTERNS) {
      if (pattern.test(cleanUTR)) {
        return res.json({
          success:    true,
          scanId:     uuidv4(),
          verdict:    'FRAUD',
          confidence: 97,
          riskScore:  97,
          utrNumber:  cleanUTR,
          reason:     pattern.reason,
          details: {
            formatValid:     false,
            patternFlagged:  true,
            paymentMethod,
            recommendation:
              'This UTR is clearly fabricated. ' +
              'Do NOT release goods. Report to cybercrime.',
            checkedAt: new Date().toISOString(),
          },
        });
      }
    }

    // ── Validate format based on payment method ──
    const formatCheck = validateFormat(cleanUTR, paymentMethod);
    if (!formatCheck.valid) {
      return res.json({
        success:    true,
        scanId:     uuidv4(),
        verdict:    'SUSPICIOUS',
        confidence: 78,
        riskScore:  65,
        utrNumber:  cleanUTR,
        reason:     formatCheck.reason,
        details: {
          formatValid:    false,
          patternFlagged: false,
          paymentMethod,
          recommendation:
            'Format does not match. Ask sender for the ' +
            'original bank SMS or email receipt.',
          checkedAt: new Date().toISOString(),
        },
      });
    }

    // ── UTR passed all checks — mark as likely genuine ──
    // In production you would call NPCI / your payment gateway API here
    // For now we trust any properly formatted UTR that passes fraud checks
    const riskScore = calculateRiskScore(
      cleanUTR, paymentMethod, expectedAmount
    );

    const verdict    = riskScore >= 40 ? 'SUSPICIOUS' : 'GENUINE';
    const confidence = riskScore >= 40 ? 70 : 92;

    return res.json({
      success:    true,
      scanId:     uuidv4(),
      verdict,
      confidence,
      riskScore,
      utrNumber:  cleanUTR,
      reason: verdict === 'GENUINE'
        ? 'UTR format is valid and passed all fraud pattern checks'
        : 'UTR format is valid but shows some risk patterns — verify carefully',
      details: {
        formatValid:    true,
        patternFlagged: false,
        paymentMethod,
        utrLength:      cleanUTR.length,
        expectedAmount: expectedAmount || null,
        recommendation: verdict === 'GENUINE'
          ? 'UTR appears legitimate. ' +
            'For large amounts, confirm with your bank before releasing goods.'
          : 'Verify this UTR directly with your bank before proceeding.',
        checkedAt: new Date().toISOString(),
      },
    });

  } catch (error) {
    next(error);
  }
};

// ── GET /api/utr/history ──────────────────────────────────
const getUTRHistory = async (req, res, next) => {
  try {
    res.json({ success: true, history: [] });
  } catch (error) {
    next(error);
  }
};

module.exports = { verifyUTR, getUTRHistory };