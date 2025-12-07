/**
 * User Model
 * Stores user authentication information
 * - Supports both traditional email/password and Google OAuth
 * - Passwords are hashed with bcrypt (12 rounds)
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address'],
  },
  passwordHash: {
    type: String,
    // Not required because Google OAuth users won't have a password
  },
  googleId: {
    type: String,
    // Only set for users who sign up via Google OAuth
    sparse: true, // Allows multiple null values but unique non-null values
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Indexes are defined in schema fields (unique: true, sparse: true)

/**
 * Hash password before saving
 * Uses bcrypt with 12 rounds as specified
 */
userSchema.pre('save', async function (next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('passwordHash')) {
    return next();
  }

  try {
    // Generate salt and hash with 12 rounds (security requirement)
    const salt = await bcrypt.genSalt(12);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Compare provided password with stored hash
 * @param {string} candidatePassword - Plain text password to verify
 * @returns {Promise<boolean>} - True if password matches
 */
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.passwordHash) {
    return false; // Google OAuth users have no password
  }
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

/**
 * Remove sensitive data from JSON output
 */
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
