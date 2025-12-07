# Team Member Individual Questions

This document contains individual questions for each team member to answer. Each person should select one question and provide a detailed answer (2-3 paragraphs minimum).

## Instructions

1. Each team member should answer ONE question from the list below
2. Write your name next to the question you're answering
3. Provide a comprehensive answer (minimum 200 words)
4. Include specific examples from the codebase where applicable
5. Explain WHY we made certain security decisions, not just WHAT we did

---

## Question 1: AES-256-GCM Encryption Implementation

**Answered by:** [Your Name Here]

**Question:** Explain how AES-256-GCM encryption is implemented in this application. Why do we use GCM mode instead of CBC? What is the purpose of the Initialization Vector (IV) and why must it be unique for each encryption? How does the authentication tag work, and what happens if someone tampers with the encrypted data?

**Answer:**

[Write your answer here. Include:
- What AES-256-GCM is and how it works
- Why GCM mode over CBC mode (authenticated encryption)
- IV purpose and uniqueness requirement
- Authentication tag verification
- What happens when tampering is detected
- Code references from utils/crypto.js]

---

## Question 2: SHA-256 Integrity Verification

**Answered by:** [Your Name Here]

**Question:** Describe the role of SHA-256 hashing in our integrity verification system. Why do we need both the GCM authentication tag AND a separate SHA-256 hash? Walk through the complete process: when is the hash computed, where is it stored, when is it verified, and what happens if verification fails? How does this protect against different types of attacks?

**Answer:**

[Write your answer here. Include:
- SHA-256 basics and properties
- Difference between auth tag and integrity hash
- Complete flow: create, store, verify
- Attack scenarios prevented
- Code references from utils/hash.js and controllers/todoController.js]

---

## Question 3: JWT Authentication and Token Management

**Answered by:** [Your Name Here]

**Question:** Explain how JWT (JSON Web Token) authentication works in this application. What information is stored in the token? Why do we have both access tokens and refresh tokens? Compare the security of storing JWTs in HTTP-only cookies versus localStorage. What are the trade-offs, and why did we choose our implementation?

**Answer:**

[Write your answer here. Include:
- JWT structure and contents
- Access vs refresh tokens
- HTTP-only cookies vs localStorage security
- CSRF and XSS considerations
- Token expiration and renewal
- Code references from middleware/auth.js]

---

## Question 4: Password Security with bcrypt

**Answered by:** [Your Name Here]

**Question:** Explain how password hashing works in this application using bcrypt. What is a "salt" and why is it important? Why do we use 12 rounds specifically? How does bcrypt compare to other hashing algorithms like SHA-256 or MD5 for passwords? What happens during login when a password needs to be verified?

**Answer:**

[Write your answer here. Include:
- bcrypt algorithm and work factor
- Salt generation and storage
- Why 12 rounds (security vs performance)
- Comparison to SHA-256 (why SHA-256 is BAD for passwords)
- Login verification process
- Code references from models/User.js]

---

## Question 5: Google OAuth SSO Integration

**Answered by:** [Your Name Here]

**Question:** Describe how Google OAuth 2.0 Single Sign-On (SSO) is implemented in this application. Walk through the complete OAuth flow from when a user clicks "Sign in with Google" to when they receive a JWT. How do we handle users who sign up with Google versus those who already have an email/password account? What security benefits does OAuth provide?

**Answer:**

[Write your answer here. Include:
- OAuth 2.0 flow (redirect, authorization, callback)
- Passport.js strategy configuration
- Account linking logic
- JWT issuance after OAuth
- Security benefits of OAuth
- Code references from config/passport.js and controllers/authController.js]

---

## Question 6: Rate Limiting and DoS Protection

**Answered by:** [Your Name Here]

**Question:** Explain how rate limiting protects this application against Denial of Service (DoS) attacks. Why do authentication endpoints have stricter limits than other endpoints? What happens when a user exceeds the rate limit? What are the limitations of the current implementation, and how would you improve it for a production environment?

**Answer:**

[Write your answer here. Include:
- How express-rate-limit works
- Window size and max requests
- Different limits for auth vs general endpoints
- Current limitations (memory-based, per-instance)
- Production improvements (Redis, distributed)
- Code references from middleware/rateLimiter.js]

---

## Question 7: Input Validation and Injection Prevention

**Answered by:** [Your Name Here]

**Question:** Describe how input validation and sanitization prevent NoSQL injection and XSS attacks in this application. Give specific examples of validation rules we apply to different inputs (email, password, todo content). Why is server-side validation crucial even when we have client-side validation? How does express-validator help prevent attacks?

**Answer:**

[Write your answer here. Include:
- NoSQL injection attack examples
- express-validator rules and sanitization
- Server-side vs client-side validation
- Specific validation rules (email, password strength, etc.)
- How Mongoose prevents injection
- Code references from middleware/validation.js]

---

## Question 8: XSS Prevention and Content Security Policy

**Answered by:** [Your Name Here]

**Question:** Explain Cross-Site Scripting (XSS) attacks and how this application prevents them. Compare the use of `textContent` vs `innerHTML` in the frontend code. How does the Content Security Policy (CSP) help? What role does Helmet.js play? Describe a specific scenario where XSS could occur without our protections.

**Answer:**

[Write your answer here. Include:
- What XSS is and types (reflected, stored, DOM-based)
- textContent vs innerHTML security
- CSP headers and directives
- Helmet.js security headers
- Input sanitization on server
- Code references from public/js/app.js and server.js]

---

## Question 9: Security Logging and Monitoring

**Answered by:** [Your Name Here]

**Question:** Discuss the importance of security logging in this application. What events are logged and why? What information should NEVER be logged and why? How does Winston help structure our logs? In a production environment, what additional monitoring and alerting would you implement?

**Answer:**

[Write your answer here. Include:
- Purpose of security logging
- Events logged (logins, failures, suspicious activity)
- Sensitive data that must NOT be logged
- Winston configuration and log levels
- Log rotation and storage
- Production monitoring improvements
- Code references from utils/logger.js]

---

## Question 10: Complete Security Architecture

**Answered by:** [Your Name Here]

**Question:** Provide a comprehensive overview of how all security components in this application work together. Describe the complete lifecycle of a todo item from creation to retrieval, highlighting every security measure applied. Then discuss the defense-in-depth strategy: how multiple layers of security protect against various attack vectors.

**Answer:**

[Write your answer here. Include:
- Todo creation: validation → hashing → encryption → storage
- Todo retrieval: fetch → decrypt → verify integrity
- Defense-in-depth layers
- How components complement each other
- Attack scenarios and defenses
- Overall security architecture]

---

## Submission Guidelines

1. **Individual Work:** Each team member must answer their own question independently
2. **Depth Required:** Answers should be 200+ words with technical detail
3. **Code References:** Include specific file and function names
4. **Examples:** Provide concrete examples from the codebase
5. **Understanding:** Demonstrate WHY security decisions were made, not just WHAT was implemented

## Grading Rubric (2 points total)

- **Completeness (0.5 pts):** Answer addresses all parts of the question
- **Technical Accuracy (0.5 pts):** Information is correct and well-explained
- **Code References (0.5 pts):** Specific references to implementation
- **Understanding (0.5 pts):** Demonstrates deep understanding of security concepts

---

## Example Answer Format

**Question:** [Question text]

**Answered by:** Jane Doe

**Answer:**

[First paragraph: Define the concept and explain basics]

[Second paragraph: Describe specific implementation in our code with examples]

[Third paragraph: Discuss security implications, trade-offs, and production considerations]

**Code References:**
- `utils/crypto.js` - `encrypt()` and `decrypt()` functions
- `controllers/todoController.js` - Lines 45-60

---

**Note:** This is an individual assignment. Each team member should complete their answer independently to demonstrate understanding of the security concepts implemented in the project.
