const crypto = require('crypto');

// Get the same 32-byte key from .env
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

function decrypt(encryptedData) {
  const [ivHex, encryptedHex] = encryptedData.split(':');

  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([
    decipher.update(encryptedText),
    decipher.final()
  ]);

  return decrypted.toString('utf8');
}

module.exports = decrypt;
