/**
 * Authentication Middleware
 * Verifies JWT tokens and protects routes
 * 
 * Security features:
 * - Validates JWT signature using secret from environment
 * - Checks token expiration
 * - Supports tokens from Authorization header or HTTP-only cookies
 * - Attaches user information to request object
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

/**
 * Middleware to verify JWT and authenticate user
 * Usage: Add to routes that require authentication
 */
const authenticate = async (req, res, next) => {
  try {
    // Get token from Authorization header or cookie
    let token;

    // Check Authorization header: "Bearer <token>"
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    // If no header token, check for HTTP-only cookie
    if (!token && req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required. No token provided.',
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: 'Token expired. Please login again.',
        });
      }
      if (error.name === 'JsonWebTokenError') {
        logger.securityEvent('Invalid JWT token attempt', {
          ip: req.ip,
          error: error.message,
        });
        return res.status(401).json({
          error: 'Invalid token.',
        });
      }
      throw error;
    }

    // Get user from database
    const user = await User.findById(decoded.userId);

    if (!user) {
      logger.securityEvent('Token for non-existent user', {
        userId: decoded.userId,
        ip: req.ip,
      });
      return res.status(401).json({
        error: 'User not found.',
      });
    }

    // Attach user to request object
    req.user = user;
    req.userId = user._id;

    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    res.status(500).json({
      error: 'Authentication failed.',
    });
  }
};

/**
 * Generate JWT access token
 * @param {string} userId - User ID to encode in token
 * @returns {string} - Signed JWT
 */
const generateAccessToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );
};

/**
 * Generate JWT refresh token
 * @param {string} userId - User ID to encode in token
 * @returns {string} - Signed JWT refresh token
 */
const generateRefreshToken = (userId) => {
  return jwt.sign(
    { userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );
};

/**
 * Verify refresh token
 * @param {string} token - Refresh token to verify
 * @returns {Object} - Decoded token payload
 */
const verifyRefreshToken = (token) => {
  return jwt.verify(
    token,
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
  );
};

module.exports = {
  authenticate,
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
};
