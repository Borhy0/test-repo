/**
 * Authentication Routes
 * Handles user registration, login, and Google OAuth
 */

const express = require('express');
const passport = require('passport');
const router = express.Router();

const authController = require('../controllers/authController');
const {
  validateRegistration,
  validateLogin,
  validateRefreshToken,
} = require('../middleware/validation');

// Traditional email/password authentication
router.post('/register', validateRegistration, authController.register);
router.post('/login', validateLogin, authController.login);
router.post('/refresh', validateRefreshToken, authController.refresh);
router.post('/logout', authController.logout);

// Google OAuth routes
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false, // We use JWT, not sessions
  })
);

router.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: '/?error=google_auth_failed',
  }),
  authController.googleCallback
);

module.exports = router;
