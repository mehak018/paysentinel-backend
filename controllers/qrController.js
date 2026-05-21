// controllers/qrController.js

const { v4: uuidv4 } = require('uuid');

// ── Trusted UPI bank handles ──────────────────────────────
const TRUSTED_UPI_HANDLES = [
  '@ybl',
  '@okhdfcbank',
  '@okicici',
  '@okaxis',
  '@oksbi',
  '@paytm',
  '@apl',
  '@axl',
  '@ibl',
  '@upi',
  '@icici',
  '@sbi',
  '@hdfcbank',
  '@axisbank',
  '@kotak','@indus','@airtel','@jio','@boi',
  '@pnb','@unionbank','@federal','@rbl','@idbi','@bob',
  '@citi','@sc','@hsbc','@pingpay','@freecharge','@mobikwik',
  '@timecosmos','@rajgovind',
];

// ── CONFIRMED malicious domains ───────────────────────────
const MALICIOUS_DOMAINS = [
  'sca-atl.com',         
  'scam-of-the-week.com',
  'fake-qr-codes.com',
  'qr-scam.com',
  'fraud-alert.in',
  'phishing-test.com',
  'free-prize.in','win-now.com','lucky-draw.net',
  'payment-verify.com','upi-refund.in','bank-update.com',
  'secure-pay.xyz','verify-upi.net','claim-reward.in',
  'refund-process.com','upi-cashback.net','paytm-offer.in',
  'gpay-reward.com',
];

// ── Suspicious words ──────────────────────────────────────
const SINGLE_SUSPICIOUS_WORDS = [
  'scam','fake','fraud','phishing','hack','steal','cheat','trick',
  'trap','malware','virus','ransomware','spyware','exploit',
  'free','win','prize','lucky','lottery','refund','cashback',
  'reward','claim','verify','update','suspend','blocked',
  'urgent','alert','warning','confirm','otp','pin','password','credential',
];

// ── Word combinations ─────────────────────────────────────
const FRAUD_COMBOS = [
  ['free','click'], ['win','prize'], ['lucky','draw'],
  ['refund','verify'], ['otp','enter'], ['pin','confirm'],
  ['reward','claim'], ['cashback','click'],
  ['scam','week'], ['fake','qr'], ['fraud','alert'],
];

// ── Analyse a URL QR ──────────────────────────────────────
const analyzeURL = (content, checks) => {
  let riskScore = 0;

  let hostname = '';
  try {
    hostname = new URL(content).hostname.toLowerCase();
  } catch {
    checks.push({
      name: 'URL Format',
      status: 'fail',
      detail: 'Cannot parse URL',
      message: 'Invalid URL — not a standard web address'
    });
    return 60;
  }

  // 1. Domain reputation
  const isMalicious = MALICIOUS_DOMAINS.some(d => hostname.includes(d));
  checks.push({
    name: 'Domain Reputation',
    detail: `Domain: ${hostname}`,
    status: isMalicious ? 'fail' : 'pass',
    message: isMalicious
      ? '🚨 Domain is on confirmed threat list'
      : 'Domain not on known threat list',
  });
  if (isMalicious) riskScore += 80;

  // 2. HTTPS check
  const isHTTPS = content.startsWith('https://');
  checks.push({
    name: 'Security Protocol',
    detail: isHTTPS ? 'HTTPS (encrypted)' : 'HTTP (unencrypted)',
    status: isHTTPS ? 'pass' : 'warn',
    message: isHTTPS
      ? 'Secure HTTPS connection'
      : '⚠ Not secure (HTTP)',
  });
  if (!isHTTPS) riskScore += 10;

  // 3. Content analysis (NEW LOGIC)
  const lowerContent = content.toLowerCase();

  const foundSingleWord = SINGLE_SUSPICIOUS_WORDS.find(
    word => lowerContent.includes(word)
  );

  const foundCombo = FRAUD_COMBOS.find(
    combo => combo.every(w => lowerContent.includes(w))
  );

  checks.push({
    name: 'Content Analysis',
    detail: foundCombo
      ? `Fraud phrase: "${foundCombo.join(' + ')}"`
      : foundSingleWord
      ? `Suspicious word: "${foundSingleWord}"`
      : 'No suspicious content detected',
    status: foundCombo || foundSingleWord ? 'fail' : 'pass',
    message: foundCombo
      ? `🚨 Fraud phrase detected: ${foundCombo.join(', ')}`
      : foundSingleWord
      ? `⚠ Suspicious word "${foundSingleWord}" detected`
      : 'No suspicious words found',
  });

  if (foundCombo) {
    riskScore += 70;
  } else if (foundSingleWord) {
    riskScore += 55;
  }

  // 4. Suspicious TLD
  const suspiciousTLDs = ['.xyz','.tk','.ml','.ga','.cf','.gq'];
  const hasSuspiciousTLD = suspiciousTLDs.some(t => hostname.endsWith(t));

  checks.push({
    name: 'Domain Extension',
    detail: `.${hostname.split('.').pop()}`,
    status: hasSuspiciousTLD ? 'warn' : 'pass',
    message: hasSuspiciousTLD
      ? '⚠ Suspicious domain extension'
      : 'Normal domain extension',
  });

  if (hasSuspiciousTLD) riskScore += 20;

  return Math.min(riskScore, 100);
};

// ── Analyse UPI QR ────────────────────────────────────────
const analyzeUPI = (content, checks) => {
  let riskScore = 0;

  const upiMatch = content.match(/pa=([^&]+)/);
  const upiId = upiMatch ? decodeURIComponent(upiMatch[1]).toLowerCase() : null;

  if (!upiId) {
    checks.push({
      name: 'UPI ID',
      status: 'fail',
      detail: 'Missing',
      message: 'Invalid UPI QR'
    });
    return 70;
  }

  const trustedHandle = TRUSTED_UPI_HANDLES.find(h =>
    upiId.endsWith(h)
  );

  checks.push({
    name: 'UPI Handle',
    detail: upiId,
    status: trustedHandle ? 'pass' : 'warn',
    message: trustedHandle
      ? 'Trusted bank handle'
      : 'Unknown handle',
  });

  if (!trustedHandle) riskScore += 15;

  // Suspicious words in UPI ID
  const suspicious = SINGLE_SUSPICIOUS_WORDS.find(w => upiId.includes(w));

  checks.push({
    name: 'UPI Pattern',
    detail: suspicious || 'Clean',
    status: suspicious ? 'fail' : 'pass',
    message: suspicious
      ? `🚨 Suspicious word "${suspicious}" in UPI ID`
      : 'UPI ID looks normal',
  });

  if (suspicious) riskScore += 60;

  return Math.min(riskScore, 100);
};

// ── MAIN CONTROLLER ───────────────────────────────────────
const checkQR = async (req, res, next) => {
  try {
    const { qrContent } = req.body;

    if (!qrContent) {
      return res.status(400).json({
        success: false,
        error: 'QR content required'
      });
    }

    const content = qrContent.trim();
    const checks = [];
    let riskScore = 0;

    const isUPI = content.startsWith('upi://');
    const isURL = content.startsWith('http');

    if (isUPI) {
      riskScore = analyzeUPI(content, checks);
    } else if (isURL) {
      riskScore = analyzeURL(content, checks);
    }

    let verdict = 'SAFE';
    if (riskScore >= 35) {
  verdict    = 'MALICIOUS';
  confidence = Math.min(75 + Math.floor(riskScore / 5), 99);
} else if (riskScore >= 10) {
  verdict    = 'SUSPICIOUS';
  confidence = 74;
} else {
  verdict    = 'SAFE';
  confidence = Math.max(94 - riskScore, 85);
}

    return res.json({
      success: true,
      scanId: uuidv4(),
      verdict,
      riskScore,
      checks,
      scannedAt: new Date(),
    });

  } catch (err) {
    next(err);
  }
};

module.exports = { checkQR };