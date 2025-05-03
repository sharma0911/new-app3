// index.js - Main Express server file
const express = require('express');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Event storage - In a production app, you'd use a database
let lastEvent = null;

// Middleware to parse JSON with raw body
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Function to verify Periskope webhook signature
function verifySignature(rawBody, signature) {
  // Skip verification if no secret is set (for development only)
  if (!process.env.PERISKOPE_SIGNING_SECRET) {
    console.warn('Warning: PERISKOPE_SIGNING_SECRET not set, skipping signature verification');
    return true;
  }

  if (!signature) {
    return false;
  }

  const hmac = crypto.createHmac('sha256', process.env.PERISKOPE_SIGNING_SECRET);
  hmac.update(rawBody);
  const digest = hmac.digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(signature)
  );
}

// Webhook endpoint
app.post('/webhook', (req, res) => {
  const signature = req.headers['x-periskope-signature'];
  
  try {
    // Verify the signature if in production mode
    if (process.env.NODE_ENV === 'production') {
      if (!verifySignature(req.rawBody, signature)) {
        console.log('Invalid signature received');
        return res.status(401).send('Invalid signature');
      }
    }
    
    // Process the webhook data
    const eventData = req.body;
    console.log('Received webhook event:', eventData);
    
    // Check if this is a ticket creation event
    if (eventData.event && eventData.event.includes('ticket.created')) {
      // Store the last event
      lastEvent = eventData;
      console.log('Ticket created event received and stored');
    }
    
    // Acknowledge receipt
    res.status(200).send('Event received');
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).send('Error processing webhook');
  }
});

// API endpoint to get the last event
app.get('/api/last-event', (req, res) => {
  res.json(lastEvent || { message: 'No events received yet' });
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
