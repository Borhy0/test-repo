/**
 * Hash Utility
 * Provides SHA-256 hashing for integrity verification
 * 
 * Purpose:
 * - Compute SHA-256 hash of plaintext content before encryption
 * - Store this hash alongside encrypted content
 * - After decryption, recompute hash and compare to detect tampering
 * - If hashes don't match, content was modified (integrity breach)
 */

const crypto = require('crypto');

/**
 * Compute SHA-256 hash of content
 * @param {string} content - Content to hash
 * @returns {string} - Hex-encoded SHA-256 hash
 */
function computeSHA256(content) {
  return crypto
    .createHash('sha256')
    .update(content, 'utf8')
    .digest('hex');
}

/**
 * Verify integrity by comparing hashes
 * @param {string} content - Current content
 * @param {string} storedHash - Previously computed hash
 * @returns {boolean} - True if hashes match (integrity verified)
 */
function verifyIntegrity(content, storedHash) {
  const currentHash = computeSHA256(content);
  return currentHash === storedHash;
}

module.exports = {
  computeSHA256,
  verifyIntegrity,
};
