// config/multer.js
// ─────────────────────────────────────────────────────────────
// Multer handles file uploads. This config controls:
// - Where files are saved
// - What file types are allowed
// - Maximum file size
// ─────────────────────────────────────────────────────────────

const multer = require('multer');
const path   = require('path');
const { v4: uuidv4 } = require('uuid');

// Storage engine — controls where and how files are saved
const storage = multer.diskStorage({
  // Save to the 'uploads' folder
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },

  // Give each file a unique name to prevent overwrites
  // Example: a3f9c2d1-xxxx.png
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  },
});

// File filter — only allow image files
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);  // Accept the file
  } else {
    // Reject with an error
    cb(new Error('Only JPG, PNG, and WEBP images are allowed'), false);
  }
};

// Create the multer upload handler
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
  },
});

module.exports = upload;