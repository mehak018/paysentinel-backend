// server.js
// ─────────────────────────────────────────────────────────────
// This is the entry point of your backend server.
// It starts Express, connects all routes, and listens for requests.
// ─────────────────────────────────────────────────────────────

const express = require('express');
const cors    = require('cors');
const dotenv  = require('dotenv');
const path    = require('path');

// Load environment variables from .env file
// Must be called before anything else uses process.env
dotenv.config();

// Import our route files (we'll create these next)
const utrRoutes        = require('./routes/utr.js');
const screenshotRoutes = require('./routes/screenshot.js');
const qrRoutes         = require('./routes/qr.js');
const errorHandler     = require('./middleware/errorHandler.js');

// Create the Express app
const app  = express();
const PORT = process.env.PORT || 5000;

// ── Middleware ───────────────────────────────────────────────
// Middleware runs on EVERY request before it hits your routes.
// Think of it as a series of checkpoints.

// 1. CORS — allows your React app to make requests to this server
//    Without this, browsers block cross-origin requests for security
app.use(cors({
  origin:      process.env.FRONTEND_URL || 'http://localhost:3000',
  methods:     ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));

// 2. JSON parser — lets Express read JSON request bodies
//    Without this, req.body would be undefined
app.use(express.json({ limit: '10mb' }));

// 3. URL encoded parser — for form submissions
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. Serve uploaded files statically
//    (so frontend can display uploaded screenshots)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ── Routes ───────────────────────────────────────────────────
// Each route file handles a group of related endpoints

// Health check — visit http://localhost:5000/api/health to confirm server is up
app.get('/api/health', (req, res) => {
  res.json({
    status:    'online',
    message:   '🛡️ PaySentinel API is running',
    timestamp: new Date().toISOString(),
    version:   '1.0.0',
  });
});

// Mount route files at their base paths
app.use('/api/utr',        utrRoutes);        // /api/utr/verify
app.use('/api/screenshot', screenshotRoutes); // /api/screenshot/analyze
app.use('/api/qr',         qrRoutes);         // /api/qr/check

// 404 handler — catches requests to routes that don't exist
app.use( (req, res) => {
  res.status(404).json({
    success: false,
    error:   `Route ${req.originalUrl} not found`,
  });
});

// Global error handler — must be LAST, after all routes
app.use(errorHandler);

// ── Start the server ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  🛡️  PaySentinel Backend API');
  console.log(`  ✅  Server running on http://localhost:${PORT}`);
  console.log(`  📡  Health check: http://localhost:${PORT}/api/health`);
  console.log('');
});

module.exports = app;