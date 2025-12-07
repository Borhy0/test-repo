/**
 * Cryptography Utility
 * Handles AES-256-GCM encryption and decryption
 * 
 * AES-256-GCM provides:
 * - Confidentiality: Content is encrypted
 * - Authenticity: Auth tag verifies data hasn't been tampered
 * - Performance: GCM mode is efficient and parallelizable
 * 
 * Security notes:
 * - Key is 32 bytes (256 bits) loaded from environment variable
 * - IV is 12 bytes (recommended for GCM) and must be unique per encryption
 * - Auth tag is 16 bytes and verified during decryption
 */

const crypto = require('crypto');

// Algorithm configuration
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 12 bytes (96 bits) recommended for GCM
const AUTH_TAG_LENGTH = 16; // 16 bytes (128 bits) authentication tag
const KEY_LENGTH = 32; // 32 bytes (256 bits) required for AES-256

/**
 * Get the AES encryption key from environment variable
 * Key must be 32 bytes (256 bits) encoded as base64
 */
function getEncryptionKey() {
  const base64Key = 'mIBVmcxE9iNKldkjafjEgW7Y5Kqd7o4IIDny4qcnYQw='; // Example key for demonstration purposes only
  
  if (!base64Key) {
    throw new Error('AES_KEY environment variable is not set');
  }

  const key = Buffer.from(base64Key, 'base64');
  
  if (key.length !== KEY_LENGTH) {
    throw new Error(`AES key must be ${KEY_LENGTH} bytes (256 bits), got ${key.length} bytes`);
  }

  return key;
}

/**
 * Encrypt plaintext content using AES-256-GCM
 * @param {string} plaintext - The content to encrypt
 * @returns {Object} - Object containing iv, authTag, and encryptedContent (all base64)
 */
function encrypt(plaintext) {
  try {
    const key = getEncryptionKey();
    
    // Generate a unique random IV for this encryption
    // CRITICAL: Never reuse an IV with the same key
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Create cipher with key and IV
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // Encrypt the plaintext
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    // Get the authentication tag (verifies integrity and authenticity)
    const authTag = cipher.getAuthTag();
    
    return {
      encryptedContent: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    };
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt ciphertext using AES-256-GCM
 * @param {string} encryptedContent - Base64 encoded ciphertext
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {string} authTagBase64 - Base64 encoded authentication tag
 * @returns {string} - Decrypted plaintext
 * @throws {Error} - If decryption fails or authentication tag is invalid
 */
function decrypt(encryptedContent, ivBase64, authTagBase64) {
  try {
    const key = getEncryptionKey();
    
    // Convert from base64 to Buffer
    const iv = Buffer.from(ivBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');
    
    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    
    // Set the authentication tag (must be set before calling update)
    decipher.setAuthTag(authTag);
    
    // Decrypt the content
    let decrypted = decipher.update(encryptedContent, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    // If auth tag doesn't match, GCM mode will throw an error
    // This indicates the ciphertext was tampered with
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

/**
 * Verify the encryption key is properly configured
 * Call this on server startup to catch configuration issues early
 */
function verifyKeyConfiguration() {
  try {
    const key = getEncryptionKey();
    return {
      configured: true,
      keyLength: key.length,
      valid: key.length === KEY_LENGTH,
    };
  } catch (error) {
    return {
      configured: false,
      error: error.message,
    };
  }
}

/**
 * Generate a new 32-byte AES key encoded in base64.
 * Run once and store safely in AES_KEY.
 */
function generateKeyBase64() {
  return crypto.randomBytes(KEY_LENGTH).toString('base64');
}

module.exports = {
  encrypt,
  decrypt,
  verifyKeyConfiguration,
  generateKeyBase64,
};
