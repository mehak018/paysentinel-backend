// config/multer.js
const multer = require('multer');
const path   = require('path');
const { v4: uuidv4 } = require('uuid');
const fs     = require('fs');

// ── Create uploads folder if it doesn't exist ─────────────
// Use ABSOLUTE path — works on any system
const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  console.log('✅ Created uploads directory:', UPLOADS_DIR);
}

// ── Storage engine ─────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Always use absolute path
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    // Give unique name: uuid + original extension
    const ext      = path.extname(file.originalname).toLowerCase();
    const safeName = `${uuidv4()}${ext}`;
    cb(null, safeName);
  },
});

// ── File filter ────────────────────────────────────────────
const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp',
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error('Only JPG, PNG, and WEBP images are allowed'),
      false
    );
  }
};

// ── Export upload handler ──────────────────────────────────
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
  },
});

module.exports = upload;