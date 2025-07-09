const crypto = require('crypto');

// Get your 32-byte AES encryption key from .env
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // must be 64 hex characters

// Encrypt function
function encrypt(text) {
  const iv = crypto.randomBytes(16); // Initialization Vector (makes encryption random each time)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

  // Output format: iv:data (both in hex)
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}


module.exports = encrypt;
// This module provides functions to encrypt and decrypt text using AES-256-CBC.
// It uses a 32-byte key defined in the environment variable ENCRYPTION_KEY.