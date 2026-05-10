// controllers/utrController.js
// ─────────────────────────────────────────────────────────────
// This controller handles UTR (Unique Transaction Reference)
// verification. In production you'd connect to a real banking
// API (NPCI, Razorpay, etc.). Here we simulate the logic
// with realistic rules so you understand the structure.
// ─────────────────────────────────────────────────────────────

const { v4: uuidv4 } = require('uuid');

// ── Simulated UTR database ───────────────────────────────────
// In production: query NPCI API or your payment gateway
const VALID_UTRS = {
  '412938001122': {
    amount: 5000, bank: 'State Bank of India',
    timestamp: '2025-05-14T10:24:00Z',
    sender: 'Rahul S.', receiver: 'Raj Electronics',
    status: 'SUCCESS'
  },
  '519827364011': {
    amount: 800,  bank: 'HDFC Bank',
    timestamp: '2025-05-14T11:02:00Z',
    sender: 'Priya M.', receiver: 'Priya Stores',
    status: 'SUCCESS'
  },
  '623819204756': {
    amount: 2300, bank: 'ICICI Bank',
    timestamp: '2025-05-14T12:10:00Z',
    sender: 'Amazon Pay', receiver: 'Customer',
    status: 'SUCCESS'
  },
};

// ── Fraud pattern rules ──────────────────────────────────────
// These patterns flag suspicious UTR numbers
const FRAUD_PATTERNS = [
  {
    // All zeros or sequential numbers are never real UTRs
    test: (utr) => /^0+$/.test(utr) || /^123456/.test(utr),
    reason: 'UTR contains invalid sequential or zero pattern'
  },
  {
    // Too short — real UTRs are 12-22 digits
    test: (utr) => utr.length < 12,
    reason: 'UTR is too short — real UTRs have 12-22 digits'
  },
  {
    // Contains letters — UTRs are numeric only
    test: (utr) => /[a-zA-Z]/.test(utr),
    reason: 'UTR contains letters — real UTRs are numeric only'
  },
];

// ── Risk score calculator ────────────────────────────────────
// Returns 0–100. Higher = more suspicious.
const calculateRiskScore = (utrNumber, paymentMethod, expectedAmount) => {
  let score = 0;

  // Repeated digits (e.g. 111111111111) — suspicious
  const uniqueDigits = new Set(utrNumber.split('')).size;
  if (uniqueDigits <= 2) score += 40;

  // Very round amounts are sometimes suspicious
  if (expectedAmount && expectedAmount % 1000 === 0
      && expectedAmount > 10000) score += 10;

  // Unknown payment method
  const validMethods = ['upi', 'neft', 'rtgs', 'imps'];
  if (paymentMethod &&
      !validMethods.includes(paymentMethod.toLowerCase())) score += 20;

  return Math.min(score, 100);
};

// ── POST /api/utr/verify ─────────────────────────────────────
const verifyUTR = async (req, res, next) => {
  try {
    const { utrNumber, paymentMethod, expectedAmount } = req.body;

    // ── Input validation ──
    if (!utrNumber) {
      return res.status(400).json({
        success: false,
        error:   'UTR number is required',
      });
    }

    // Clean the UTR — remove spaces and dashes
    const cleanUTR = utrNumber.replace(/[\s-]/g, '').trim();

    // ── Check fraud patterns first ──
    for (const pattern of FRAUD_PATTERNS) {
      if (pattern.test(cleanUTR)) {
        return res.json({
          success:    true,
          scanId:     uuidv4(),
          verdict:    'FRAUD',
          confidence: 96,
          riskScore:  95,
          utrNumber:  cleanUTR,
          reason:     pattern.reason,
          details: {
            foundInDatabase:  false,
            patternMatch:     true,
            recommendation:   'Do NOT release goods or services. Report this transaction.',
            checkedAt:        new Date().toISOString(),
          },
        });
      }
    }

    // ── Check against known valid UTRs ──
    const utrRecord = VALID_UTRS[cleanUTR];

    if (utrRecord) {
      // Found in database — genuine
      const amountMatch = !expectedAmount ||
        Math.abs(utrRecord.amount - Number(expectedAmount)) < 1;

      return res.json({
        success:    true,
        scanId:     uuidv4(),
        verdict:    amountMatch ? 'GENUINE' : 'SUSPICIOUS',
        confidence: amountMatch ? 99 : 72,
        riskScore:  amountMatch ? 2 : 45,
        utrNumber:  cleanUTR,
        reason:     amountMatch
          ? 'UTR found and verified in payment records'
          : 'UTR found but amount does not match — verify carefully',
        details: {
          foundInDatabase:  true,
          bank:             utrRecord.bank,
          processedAt:      utrRecord.timestamp,
          sender:           utrRecord.sender,
          receiver:         utrRecord.receiver,
          amount:           utrRecord.amount,
          expectedAmount:   expectedAmount || null,
          amountMatch,
          paymentStatus:    utrRecord.status,
          recommendation:   amountMatch
            ? 'Payment verified. Safe to release goods/services.'
            : 'Amount mismatch detected. Verify with sender before proceeding.',
          checkedAt:        new Date().toISOString(),
        },
      });
    }

    // ── Not in database ──
    // Calculate risk score for unknown UTRs
    const riskScore = calculateRiskScore(
      cleanUTR, paymentMethod, expectedAmount
    );

    const isHighRisk = riskScore >= 50;

    return res.json({
      success:    true,
      scanId:     uuidv4(),
      verdict:    isHighRisk ? 'FRAUD' : 'SUSPICIOUS',
      confidence: isHighRisk ? 88 : 65,
      riskScore,
      utrNumber:  cleanUTR,
      reason:     isHighRisk
        ? 'UTR not found in payment records and shows high-risk patterns'
        : 'UTR not found in our database — could not be verified',
      details: {
        foundInDatabase: false,
        patternMatch:    false,
        riskFactors: [
          riskScore > 30 ? 'UTR not in NPCI records' : null,
          riskScore > 50 ? 'Suspicious digit pattern detected' : null,
        ].filter(Boolean),
        recommendation: isHighRisk
          ? 'HIGH RISK: Do NOT release goods. Contact your bank immediately.'
          : 'Could not verify. Ask sender for bank-generated payment receipt.',
        checkedAt: new Date().toISOString(),
      },
    });

  } catch (error) {
    // Pass error to global error handler
    next(error);
  }
};

// ── GET /api/utr/history ─────────────────────────────────────
const getUTRHistory = async (req, res, next) => {
  try {
    // Simulated history — in production, fetch from database
    const history = [
      { utr: '412938001122', verdict: 'GENUINE',    time: '10:24 AM', amount: 5000  },
      { utr: '412938764502', verdict: 'FRAUD',      time: '10:31 AM', amount: 12500 },
      { utr: '519827364011', verdict: 'GENUINE',    time: '11:02 AM', amount: 800   },
      { utr: '000000000001', verdict: 'FRAUD',      time: '11:45 AM', amount: 45000 },
      { utr: '623819204756', verdict: 'GENUINE',    time: '12:10 PM', amount: 2300  },
    ];

    res.json({ success: true, history });
  } catch (error) {
    next(error);
  }
};

module.exports = { verifyUTR, getUTRHistory };