// middleware/errorHandler.js
// ─────────────────────────────────────────────────────────────
// This catches ANY unhandled error from any route and
// sends a clean JSON error response instead of crashing.
// ─────────────────────────────────────────────────────────────

const errorHandler = (err, req, res, next) => {
  // Log the error to the server console for debugging
  console.error('❌ Error:', err.message);

  // Multer errors (file upload problems)
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      success: false,
      error:   'File too large. Maximum size is 5MB.',
    });
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({
      success: false,
      error:   'Unexpected file field.',
    });
  }

  // Default error response
  res.status(err.status || 500).json({
    success: false,
    error:   err.message || 'Internal server error',
    // Only show stack trace in development (not in production)
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};

module.exports = errorHandler;