/**
 * Input Validation Middleware
 * Uses express-validator to validate and sanitize all user inputs
 * 
 * Protects against:
 * - NoSQL injection (by validating data types and formats)
 * - XSS (by sanitizing inputs)
 * - Invalid data that could crash the application
 * 
 * Note: Always validate on server-side even if client validates
 */

const { body, param, validationResult } = require('express-validator');

/**
 * Middleware to check validation results
 * Call this after validation rules to return errors
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.path || err.param,
        message: err.msg,
      })),
    });
  }
  next();
};

/**
 * Validation rules for user registration
 */
const validateRegistration = [
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number'),
  
  validate,
];

/**
 * Validation rules for login
 */
const validateLogin = [
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  
  validate,
];

/**
 * Validation rules for creating/updating a todo
 */
const validateTodo = [
  body('content')
    .trim()
    .notEmpty()
    .withMessage('Todo content is required')
    .isLength({ max: 5000 })
    .withMessage('Todo content must not exceed 5000 characters')
    // Sanitize to prevent XSS (remove HTML tags)
    .escape(),
  
  validate,
];

/**
 * Validation rules for MongoDB ObjectId parameters
 */
const validateObjectId = [
  param('id')
    .matches(/^[0-9a-fA-F]{24}$/)
    .withMessage('Invalid ID format'),
  
  validate,
];

/**
 * Validation rules for refresh token
 */
const validateRefreshToken = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
    .isString()
    .withMessage('Refresh token must be a string'),
  
  validate,
];

module.exports = {
  validate,
  validateRegistration,
  validateLogin,
  validateTodo,
  validateObjectId,
  validateRefreshToken,
};
