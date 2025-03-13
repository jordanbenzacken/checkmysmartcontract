import express from 'express';
import cors from 'cors';
import { analyzeContract } from './smartcheck-service.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Configure CORS to only allow requests from our frontend
const allowedOrigins = [
  'http://localhost:5173',  // Local development
  'http://localhost:3000',  // Local production build
  'https://smartcheck-web.netlify.app', // Your Netlify domain
  'https://smartcheck-web.up.railway.app' // Railway domain (update this with your actual domain)
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('CORS policy violation'), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// API routes
app.post('/api/analyze', async (req, res) => {
  try {
    const { sourceCode } = req.body;
    if (!sourceCode) {
      return res.status(400).json({ error: 'Source code is required' });
    }

    const results = await analyzeContract(sourceCode);
    res.json({ results });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze contract' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});