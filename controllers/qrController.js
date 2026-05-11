// controllers/qrController.js
// Fixed version — much more accurate, no false positives on real QRs

const { v4: uuidv4 } = require('uuid');

// ── Trusted UPI bank handles ──────────────────────────────
// These are OFFICIAL bank UPI handles — always safe
const TRUSTED_UPI_HANDLES = [
  '@ybl',          // Yes Bank (PhonePe)
  '@okhdfcbank',   // HDFC (Google Pay)
  '@okicici',      // ICICI (Google Pay)
  '@okaxis',       // Axis (Google Pay)
  '@oksbi',        // SBI (Google Pay)
  '@paytm',        // Paytm
  '@apl',          // Amazon Pay
  '@axl',          // Axis
  '@ibl',          // IndusInd
  '@upi',          // Generic UPI
  '@icici',        // ICICI direct
  '@sbi',          // SBI direct
  '@hdfcbank',     // HDFC direct
  '@axisbank',     // Axis direct
  '@kotak',        // Kotak
  '@indus',        // IndusInd
  '@airtel',       // Airtel Payments Bank
  '@jio',          // Jio Payments Bank
  '@boi',          // Bank of India
  '@pnb',          // Punjab National Bank
  '@unionbank',    // Union Bank
  '@federal',      // Federal Bank
  '@rbl',          // RBL Bank
  '@idbi',         // IDBI Bank
  '@bob',          // Bank of Baroda
  '@citi',         // Citibank
  '@sc',           // Standard Chartered
  '@hsbc',         // HSBC
  '@pingpay',      // Samsung Pay
  '@freecharge',   // Freecharge
  '@mobikwik',     // Mobikwik
  '@timecosmos',   // ICICI merchant
  '@rajgovind',    // common merchant handle
];

// ── CONFIRMED malicious domains ───────────────────────────
// Only domains CONFIRMED to be scam/phishing
const MALICIOUS_DOMAINS = [
  'free-prize.in',
  'win-now.com',
  'lucky-draw.net',
  'payment-verify.com',
  'upi-refund.in',
  'bank-update.com',
  'secure-pay.xyz',
  'verify-upi.net',
  'claim-reward.in',
  'refund-process.com',
  'upi-cashback.net',
  'paytm-offer.in',
  'gpay-reward.com',
];

// ── High-risk keyword COMBINATIONS ───────────────────────
// Single words like 'secure' or 'bank' are NOT enough
// We look for COMBINATIONS that together indicate fraud
const FRAUD_COMBOS = [
  ['free', 'click'],
  ['win', 'prize'],
  ['lucky', 'draw'],
  ['refund', 'verify'],
  ['otp', 'enter'],
  ['pin', 'confirm'],
  ['reward', 'claim'],
  ['cashback', 'click'],
  ['offer', 'limited'],
];

// ── Analyse a URL QR ─────────────────────────────────────
const analyzeURL = (content, checks) => {
  let riskScore = 0;

  let hostname = '';
  try {
    hostname = new URL(content).hostname.toLowerCase();
  } catch {
    checks.push({
      name: 'URL Format', status: 'fail',
      detail: 'Cannot parse URL',
      message: 'Invalid URL — not a standard web address'
    });
    return 60; // malformed URL is risky
  }

  // 1. Known malicious domain check
  const isMalicious = MALICIOUS_DOMAINS.some(d => hostname.includes(d));
  checks.push({
    name:    'Domain Reputation',
    detail:  `Domain: ${hostname}`,
    status:  isMalicious ? 'fail' : 'pass',
    message: isMalicious
      ? '🚨 Domain is on confirmed threat list'
      : 'Domain not on any known threat list',
  });
  if (isMalicious) riskScore += 80;

  // 2. HTTPS check — http is a warning but NOT fraud on its own
  const isHTTPS = content.startsWith('https://');
  checks.push({
    name:    'Security Protocol',
    detail:  isHTTPS ? 'HTTPS (encrypted)' : 'HTTP (unencrypted)',
    status:  isHTTPS ? 'pass' : 'warn',
    message: isHTTPS
      ? 'Connection uses HTTPS encryption'
      : 'Connection is not encrypted — use caution on payment pages',
  });
  if (!isHTTPS) riskScore += 10; // small penalty, not automatic fraud

  // 3. Fraud keyword COMBINATION check
  const lowerContent = content.toLowerCase();
  const foundCombo = FRAUD_COMBOS.find(
    combo => combo.every(word => lowerContent.includes(word))
  );
  checks.push({
    name:    'Content Analysis',
    detail:  foundCombo
      ? `Suspicious phrase: "${foundCombo.join(' + ')}"`
      : 'No suspicious keyword combinations',
    status:  foundCombo ? 'fail' : 'pass',
    message: foundCombo
      ? `⚠ Phishing phrase pattern detected: ${foundCombo.join(', ')}`
      : 'No phishing phrases detected',
  });
  if (foundCombo) riskScore += 50;

  // 4. Suspicious TLD check
  const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq'];
  const hasSuspiciousTLD = suspiciousTLDs.some(t => hostname.endsWith(t));
  checks.push({
    name:    'Domain Extension',
    detail:  `TLD: .${hostname.split('.').pop()}`,
    status:  hasSuspiciousTLD ? 'warn' : 'pass',
    message: hasSuspiciousTLD
      ? '⚠ Unusual domain extension — often used in scam sites'
      : 'Domain extension appears normal',
  });
  if (hasSuspiciousTLD) riskScore += 20;

  return Math.min(riskScore, 100);
};

// ── Analyse a UPI QR ─────────────────────────────────────
const analyzeUPI = (content, checks) => {
  let riskScore = 0;

  // 1. Extract UPI ID
  const upiMatch  = content.match(/pa=([^&]+)/);
  const upiId     = upiMatch ? decodeURIComponent(upiMatch[1]).toLowerCase() : null;

  if (!upiId) {
    checks.push({
      name: 'UPI ID', status: 'fail',
      detail: 'No UPI ID found in QR',
      message: 'Malformed UPI QR — cannot extract payment address'
    });
    return 70;
  }

  // 2. Check if UPI handle is from a trusted bank
  const trustedHandle = TRUSTED_UPI_HANDLES.find(h =>
    upiId.endsWith(h.toLowerCase())
  );

  checks.push({
    name:    'UPI Bank Handle',
    detail:  `UPI ID: ${upiId}`,
    status:  trustedHandle ? 'pass' : 'warn',
    message: trustedHandle
      ? `✓ Registered with trusted bank handle (${trustedHandle})`
      : '⚠ Unrecognized bank handle — verify merchant identity',
  });
  if (!trustedHandle) riskScore += 15; // warn but not fraud

  // 3. Merchant name check
  const nameMatch    = content.match(/pn=([^&]+)/);
  const merchantName = nameMatch
    ? decodeURIComponent(nameMatch[1]) : null;

  checks.push({
    name:    'Merchant Name',
    detail:  merchantName ? `Name: ${merchantName}` : 'No merchant name',
    status:  merchantName ? 'pass' : 'warn',
    message: merchantName
      ? `Merchant: ${merchantName}`
      : '⚠ No merchant name in QR — verify who you are paying',
  });
  if (!merchantName) riskScore += 10;

  // 4. Hardcoded amount — minor warning only
  const amountMatch = content.match(/am=([^&]+)/);
  checks.push({
    name:    'Payment Amount',
    detail:  amountMatch ? `Fixed: ₹${amountMatch[1]}` : 'No fixed amount',
    status:  amountMatch ? 'warn' : 'pass',
    message: amountMatch
      ? '⚠ Amount is fixed in QR — confirm this matches what you expect'
      : 'No hardcoded amount — you enter the amount manually',
  });
  if (amountMatch) riskScore += 5; // very minor

  // 5. Check UPI ID for suspicious patterns
  const suspiciousUPIPatterns = [
    { test: /refund/i,  msg: 'UPI ID contains "refund" — very suspicious' },
    { test: /prize/i,   msg: 'UPI ID contains "prize" — likely scam'      },
    { test: /reward/i,  msg: 'UPI ID contains "reward" — likely scam'     },
    { test: /free/i,    msg: 'UPI ID contains "free" — suspicious'        },
    { test: /win/i,     msg: 'UPI ID contains "win" — suspicious'         },
  ];

  const suspiciousPattern = suspiciousUPIPatterns.find(
    p => p.test.test(upiId)
  );
  checks.push({
    name:    'UPI ID Pattern',
    detail:  suspiciousPattern ? 'Suspicious word in UPI ID' : 'UPI ID looks normal',
    status:  suspiciousPattern ? 'fail' : 'pass',
    message: suspiciousPattern
      ? `🚨 ${suspiciousPattern.msg}`
      : 'No suspicious words in UPI ID',
  });
  if (suspiciousPattern) riskScore += 60;

  return Math.min(riskScore, 100);
};

// ── POST /api/qr/check ───────────────────────────────────
const checkQR = async (req, res, next) => {
  try {
    const { qrContent } = req.body;

    if (!qrContent || !qrContent.trim()) {
      return res.status(400).json({
        success: false,
        error: 'QR content is required',
      });
    }

    const content = qrContent.trim();
    const checks  = [];
    let riskScore = 0;

    // Detect type
    const isUPI  = content.toLowerCase().startsWith('upi://');
    const isURL  = content.startsWith('http://') ||
                   content.startsWith('https://');

    if (isUPI) {
      riskScore = analyzeUPI(content, checks);
    } else if (isURL) {
      riskScore = analyzeURL(content, checks);
    } else {
      // Plain text — very low risk
      checks.push({
        name:    'Content Type',
        detail:  `Plain text: "${content.substring(0, 60)}"`,
        status:  'pass',
        message: 'Plain text QR — not a payment or URL',
      });
      riskScore = 0;
    }

    // ── Verdict thresholds (more lenient) ──
    // < 20  = SAFE
    // 20-49 = SUSPICIOUS
    // 50+   = MALICIOUS
    let verdict, confidence;

    if (riskScore >= 50) {
      verdict    = 'MALICIOUS';
      confidence = Math.min(70 + riskScore / 5, 99);
    } else if (riskScore >= 20) {
      verdict    = 'SUSPICIOUS';
      confidence = 72;
    } else {
      verdict    = 'SAFE';
      confidence = Math.max(95 - riskScore, 85);
    }

    return res.json({
      success:    true,
      scanId:     uuidv4(),
      verdict,
      confidence: Math.round(confidence),
      riskScore,
      qrType:     isUPI ? 'UPI Payment' : isURL ? 'URL / Website' : 'Plain Text',
      content:    content.length > 120
        ? content.substring(0, 120) + '...' : content,
      checks,
      recommendation: getRecommendation(verdict, isUPI),
      scannedAt: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
};

const getRecommendation = (verdict, isUPI) => {
  if (verdict === 'SAFE') {
    return isUPI
      ? 'QR code looks safe. Verify the merchant name matches before paying.'
      : 'Link appears safe. Always double-check the URL before entering details.';
  }
  if (verdict === 'SUSPICIOUS') {
    return isUPI
      ? 'Verify the UPI ID with the merchant verbally before paying.'
      : 'Proceed carefully. Do not enter passwords or payment details.';
  }
  return 'DO NOT pay or click this link. This QR shows signs of fraud. Report it.';
};

module.exports = { checkQR };