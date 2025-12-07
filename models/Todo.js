/**
 * Todo Model
 * Stores encrypted to-do items with integrity verification
 * 
 * Security features:
 * - Content is encrypted with AES-256-GCM
 * - Each encryption uses a unique random IV (Initialization Vector)
 * - Auth tag from GCM mode ensures authenticity
 * - SHA-256 integrity hash of plaintext stored to detect tampering
 * - All encrypted data stored as base64 strings
 */

const mongoose = require('mongoose');

const todoSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true, // Index for faster queries by user
  },
  // Encrypted content (base64 encoded ciphertext)
  encryptedContent: {
    type: String,
    required: true,
  },
  // Initialization Vector (12 bytes for GCM, base64 encoded)
  // Must be unique for each encryption operation
  iv: {
    type: String,
    required: true,
  },
  // Authentication tag from AES-GCM (16 bytes, base64 encoded)
  // Provides authenticated encryption - detects if ciphertext was tampered
  authTag: {
    type: String,
    required: true,
  },
  // SHA-256 hash of the original plaintext content (hex string)
  // Used to verify integrity after decryption
  integrityHash: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Compound index for efficient queries
todoSchema.index({ userId: 1, createdAt: -1 });

// Update the updatedAt timestamp on save
todoSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Todo', todoSchema);
