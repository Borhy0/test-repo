/**
 * Rate Limiting Middleware
 * Implements anti-DoS protection using express-rate-limit
 * 
 * Two rate limiters:
 * 1. General limiter: 60 requests per minute per IP for all endpoints
 * 2. Auth limiter: Stricter limits for authentication endpoints (10 req/min)
 * 
 * Prevents brute force attacks and resource exhaustion
 */

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

// General rate limiter for all requests
// 60 requests per minute per IP
const generalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per window
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  handler: (req, res) => {
    logger.securityEvent('Rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({
      error: 'Too many requests, please try again later.',
    });
  },
});

// Stricter rate limiter for authentication endpoints
// 10 requests per minute per IP
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per window
  message: {
    error: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false, // Count successful requests too
  handler: (req, res) => {
    logger.securityEvent('Auth rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({
      error: 'Too many authentication attempts, please try again later.',
    });
  },
});

module.exports = {
  generalLimiter,
  authLimiter,
};
