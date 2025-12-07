/**
 * Logger Utility
 * Uses Winston for structured logging
 * 
 * Logs important security events:
 * - User logins (successful and failed)
 * - Registration attempts
 * - Suspicious activity
 * - Server errors
 * 
 * SECURITY: Never log passwords, tokens, or encryption keys
 */

const winston = require('winston');
const path = require('path');

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
    
    // Add metadata if present (but filter out sensitive data)
    if (Object.keys(meta).length > 0) {
      // Remove sensitive fields
      const safeMeta = { ...meta };
      delete safeMeta.password;
      delete safeMeta.token;
      delete safeMeta.jwt;
      delete safeMeta.secret;
      
      if (Object.keys(safeMeta).length > 0) {
        log += ` ${JSON.stringify(safeMeta)}`;
      }
    }
    
    return log;
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports: [
    // Console output (for development)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        logFormat
      ),
    }),
    // File output for errors
    new winston.transports.File({
      filename: path.join(__dirname, '..', 'logs', 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    // File output for all logs
    new winston.transports.File({
      filename: path.join(__dirname, '..', 'logs', 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
});

// Security event logging helpers
logger.securityEvent = (event, details = {}) => {
  logger.warn(`[SECURITY] ${event}`, details);
};

logger.loginSuccess = (email, method = 'password') => {
  logger.info(`Login successful: ${email} (${method})`);
};

logger.loginFailure = (email, reason, ip) => {
  logger.securityEvent(`Login failed: ${email} - ${reason}`, { ip });
};

logger.suspiciousActivity = (description, details = {}) => {
  logger.securityEvent(`Suspicious activity: ${description}`, details);
};

module.exports = logger;
