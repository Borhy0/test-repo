/**
 * Authentication Controller
 * Handles user registration, login, and Google OAuth
 */

const User = require('../models/User');
const logger = require('../utils/logger');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require('../middleware/auth');

/**
 * Register a new user
 * POST /api/auth/register
 */
const register = async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.securityEvent('Registration attempt with existing email', { email });
      return res.status(400).json({
        error: 'User with this email already exists',
      });
    }

    // Create new user (password will be hashed by the pre-save hook)
    const user = await User.create({
      email,
      username,
      passwordHash: password, // Will be hashed by model
    });

    logger.info(`New user registered: ${email}`);

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Set HTTP-only cookie for access token (more secure than localStorage)
    res.cookie('token', accessToken, {
      httpOnly: true, // Prevents JavaScript access (XSS protection)
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
      },
      accessToken, // Also send in body for flexibility
      refreshToken,
    });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: error.message,
    });
  }
};

/**
 * Login with email and password
 * POST /api/auth/login
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      logger.loginFailure(email, 'User not found', req.ip);
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    // Check if user registered with Google (no password)
    if (!user.passwordHash) {
      logger.loginFailure(email, 'Google OAuth user attempted password login', req.ip);
      return res.status(401).json({
        error: 'This account uses Google Sign-In. Please login with Google.',
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.loginFailure(email, 'Invalid password', req.ip);
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    logger.loginSuccess(email, 'password');

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Set HTTP-only cookie
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
      },
      accessToken,
      refreshToken,
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      message: error.message,
    });
  }
};

/**
 * Refresh access token using refresh token
 * POST /api/auth/refresh
 */
const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token is required',
      });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (error) {
      logger.securityEvent('Invalid refresh token attempt', { ip: req.ip });
      return res.status(401).json({
        error: 'Invalid or expired refresh token',
      });
    }

    // Check if user still exists
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        error: 'User not found',
      });
    }

    // Generate new access token
    const accessToken = generateAccessToken(user._id);

    // Set new cookie
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
    });

    res.json({
      message: 'Token refreshed successfully',
      accessToken,
    });
  } catch (error) {
    logger.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Token refresh failed',
    });
  }
};

/**
 * Logout user
 * POST /api/auth/logout
 */
const logout = (req, res) => {
  // Clear the cookie
  res.clearCookie('token');
  
  res.json({
    message: 'Logout successful',
  });
};

/**
 * Google OAuth callback handler
 * This is called after successful Google authentication
 */
const googleCallback = (req, res) => {
  try {
    // User is attached by passport
    const user = req.user;

    if (!user) {
      logger.error('Google OAuth: No user in callback');
      return res.redirect('/?error=authentication_failed');
    }

    logger.loginSuccess(user.email, 'google');

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Set HTTP-only cookie
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
    });

    // Redirect to frontend with success (token is in cookie)
    // Could also redirect with token in URL, but that's less secure
    res.redirect('/?login=success');
  } catch (error) {
    logger.error('Google callback error:', error);
    res.redirect('/?error=authentication_failed');
  }
};

module.exports = {
  register,
  login,
  refresh,
  logout,
  googleCallback,
};
