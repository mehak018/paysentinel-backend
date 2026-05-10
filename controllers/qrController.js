// controllers/qrController.js
// ─────────────────────────────────────────────────────────────
// Analyzes QR code content for threats.
// Checks UPI IDs, URLs, and known malicious patterns.
// ─────────────────────────────────────────────────────────────

const { v4: uuidv4 } = require('uuid');

// ── Known safe UPI handles ───────────────────────────────────
const TRUSTED_UPI_HANDLES = [
  '@ybl', '@okhdfcbank', '@okicici', '@okaxis', '@oksbi',
  '@paytm', '@apl', '@axl', '@ibl', '@upi'
];

// ── Known malicious domains ──────────────────────────────────
const MALICIOUS_DOMAINS = [
  'free-prize.in', 'win-now.com', 'lucky-draw.net',
  'payment-verify.com', 'upi-refund.in', 'bank-update.com',
  'secure-pay.xyz', 'verify-upi.net'
];

// ── Suspicious keywords in URLs ──────────────────────────────
const SUSPICIOUS_KEYWORDS = [
  'free', 'win', 'prize', 'lucky', 'refund', 'cashback',
  'verify', 'update', 'secure', 'login', 'password',
  'otp', 'pin', 'reward', 'offer', 'click', 'claim'
];

// ── POST /api/qr/check ───────────────────────────────────────
const checkQR = async (req, res, next) => {
  try {
    const { qrContent } = req.body;

    if (!qrContent || qrContent.trim() === '') {
      return res.status(400).json({
        success: false,
        error:   'QR content is required',
      });
    }

    const content = qrContent.trim();
    const checks  = [];
    let riskScore = 0;

    // ── Detect QR type ───────────────────────────────────────
    const isUPI  = content.startsWith('upi://');
    const isURL  = content.startsWith('http://') ||
                   content.startsWith('https://');
    const isText = !isUPI && !isURL;

    // ── Run checks based on type ─────────────────────────────

    if (isUPI) {
      // ── UPI QR Code checks ──

      // 1. Extract UPI ID
      const upiMatch = content.match(/pa=([^&]+)/);
      const upiId    = upiMatch ? upiMatch[1] : null;

      if (!upiId) {
        checks.push({
          name: 'UPI ID Extraction', status: 'fail',
          detail: 'Could not extract UPI ID from QR',
          message: '⚠ Malformed UPI QR code'
        });
        riskScore += 40;
      } else {
        // 2. Check UPI handle is from a known bank
        const trustedHandle = TRUSTED_UPI_HANDLES.some(h =>
          upiId.toLowerCase().endsWith(h)
        );
        checks.push({
          name:    'UPI Handle Verification',
          detail:  `UPI ID: ${upiId}`,
          status:  trustedHandle ? 'pass' : 'warn',
          message: trustedHandle
            ? `Registered with a trusted bank handle`
            : '⚠ Unrecognized UPI bank handle',
        });
        if (!trustedHandle) riskScore += 25;

        // 3. Check for suspicious merchant name
        const nameMatch = content.match(/pn=([^&]+)/);
        const merchantName = nameMatch
          ? decodeURIComponent(nameMatch[1]) : 'Unknown';

        checks.push({
          name:    'Merchant Name Check',
          detail:  `Merchant: ${merchantName}`,
          status:  'pass',
          message: `Merchant name present: ${merchantName}`,
        });
      }

      // 4. Check for hardcoded amount (suspicious — merchants shouldn't hardcode)
      const amountMatch = content.match(/am=([^&]+)/);
      if (amountMatch) {
        checks.push({
          name:    'Amount Check',
          detail:  `Hardcoded amount: ₹${amountMatch[1]}`,
          status:  'warn',
          message: '⚠ Amount is hardcoded in QR — verify before paying',
        });
        riskScore += 15;
      } else {
        checks.push({
          name:    'Amount Check',
          detail:  'No hardcoded amount',
          status:  'pass',
          message: 'You will enter the amount manually — good practice',
        });
      }

    } else if (isURL) {
      // ── URL QR Code checks ──

      let hostname = '';
      try {
        hostname = new URL(content).hostname.toLowerCase();
      } catch {
        checks.push({
          name: 'URL Parsing', status: 'fail',
          detail: 'Cannot parse URL', message: 'Invalid URL format'
        });
        riskScore += 50;
      }

      if (hostname) {
        // 1. Check against known malicious domains
        const isMalicious = MALICIOUS_DOMAINS.some(d =>
          hostname.includes(d)
        );
        checks.push({
          name:    'Domain Reputation',
          detail:  `Domain: ${hostname}`,
          status:  isMalicious ? 'fail' : 'pass',
          message: isMalicious
            ? '🚨 Domain is on our threat list!'
            : 'Domain not on known malicious list',
        });
        if (isMalicious) riskScore += 70;

        // 2. Check for suspicious keywords
        const lowerContent = content.toLowerCase();
        const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k =>
          lowerContent.includes(k)
        );
        checks.push({
          name:    'Keyword Analysis',
          detail:  foundKeywords.length > 0
            ? `Found: ${foundKeywords.join(', ')}` : 'No suspicious keywords',
          status:  foundKeywords.length > 1 ? 'fail' :
                   foundKeywords.length === 1 ? 'warn' : 'pass',
          message: foundKeywords.length > 0
            ? `⚠ Suspicious keywords detected: ${foundKeywords.join(', ')}`
            : 'No suspicious keywords found',
        });
        if (foundKeywords.length > 0) riskScore += foundKeywords.length * 15;

        // 3. HTTPS check
        checks.push({
          name:    'Security Protocol',
          detail:  content.startsWith('https') ? 'HTTPS' : 'HTTP (insecure)',
          status:  content.startsWith('https') ? 'pass' : 'warn',
          message: content.startsWith('https')
            ? 'Connection is encrypted (HTTPS)'
            : '⚠ Insecure HTTP connection — data not encrypted',
        });
        if (!content.startsWith('https')) riskScore += 20;
      }

    } else {
      // ── Plain text QR ──
      checks.push({
        name:    'Content Type',
        detail:  `Text content: "${content.substring(0, 50)}..."`,
        status:  'pass',
        message: 'Plain text QR code — low risk',
      });
    }

    // ── Calculate final verdict ──────────────────────────────
    riskScore = Math.min(riskScore, 100);

    let verdict, confidence;
    if (riskScore >= 60) {
      verdict    = 'MALICIOUS';
      confidence = Math.min(75 + riskScore / 5, 99);
    } else if (riskScore >= 25) {
      verdict    = 'SUSPICIOUS';
      confidence = 70;
    } else {
      verdict    = 'SAFE';
      confidence = 94;
    }

    return res.json({
      success:    true,
      scanId:     uuidv4(),
      verdict,
      confidence: Math.round(confidence),
      riskScore,
      qrType:     isUPI ? 'UPI Payment' : isURL ? 'URL/Link' : 'Plain Text',
      content:    content.length > 100
        ? content.substring(0, 100) + '...' : content,
      checks,
      recommendation: getQRRecommendation(verdict),
      scannedAt:  new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
};

const getQRRecommendation = (verdict) => {
  const recs = {
    SAFE:      'QR code appears safe. Verify merchant name matches before paying.',
    SUSPICIOUS:'Proceed with caution. Confirm UPI ID with the merchant verbally.',
    MALICIOUS: 'DO NOT scan or pay. This QR code leads to a known scam. Report it.',
  };
  return recs[verdict];
};

module.exports = { checkQR };