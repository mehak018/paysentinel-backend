# 🛡️ PaySentinel — AI Guardian (Backend API)

Node.js + Express REST API powering the PaySentinel fraud detection platform.

## 🌐 Live API
[Coming soon — deploying to Render]

## 📡 API Endpoints

| Method | Endpoint                   | Description                    |
|--------|----------------------------|--------------------------------|
| GET    | /api/health                | Server health check            |
| POST   | /api/utr/verify            | Verify UTR transaction number  |
| GET    | /api/utr/history           | Get recent UTR check history   |
| POST   | /api/screenshot/analyze    | Analyze payment screenshot     |
| POST   | /api/qr/check              | Check QR code for threats      |

## 🛠️ Tech Stack
- **Runtime:** Node.js
- **Framework:** Express.js
- **File Uploads:** Multer
- **Security:** CORS, dotenv, input validation
- **Dev Tools:** Nodemon

## 🚀 Run Locally

1. Clone the repo
   git clone https://github.com/YOUR_USERNAME/paysentinel-backend.git

2. Install dependencies
   cd paysentinel-backend
   npm install

3. Create .env file
   PORT=5000
   FRONTEND_URL=http://localhost:3000
   NODE_ENV=development

4. Start the server
   npm run dev

5. Test health check
   http://localhost:5000/api/health

## 📁 Project Structure
├── routes/        API route definitions
├── controllers/   Business logic for each endpoint
├── middleware/    Error handler
├── config/        Multer file upload config
└── server.js      Entry point