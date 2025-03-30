# 🛡️ SecureShield

[![npm version](https://img.shields.io/npm/v/secure-shield.svg)](https://www.npmjs.com/package/secure-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/npm/dm/secure-shield.svg)](https://www.npmjs.com/package/secure-shield)
[![Security Rating](https://img.shields.io/security-headers?url=https%3A%2F%2Fsecure-shield.dev)](https://secure-shield.dev)

> A comprehensive security middleware package for Node.js applications providing real-time protection against common web vulnerabilities and attacks.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Security Features](#-security-features)
- [API Reference](#-api-reference)
- [Examples](#-examples)
- [Best Practices](#-best-practices)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [Security Policy](#-security-policy)
- [License](#-license)

## ✨ Features

### Core Protection
- 🔍 SQL Injection Detection & Prevention
- 🛡️ XSS (Cross-Site Scripting) Protection
- 🚫 NoSQL Injection Detection
- 🕵️ Malicious Payload Detection
- ⚡ Rate Limiting & Brute Force Protection
- 🧹 Input Sanitization

### Advanced Security
- 📜 Security Headers Management
  - HSTS
  - CSP
  - XSS Protection
  - And more...
- 🔐 Cryptographic Utilities
  - Password Hashing
  - Data Encryption
  - Token Generation
- ✅ Request Validation
- 📝 Automatic Security Logging

## 📦 Installation

### 🛠️ Installation

```bash
# Using npm
npm install secure-shield

# Using yarn
yarn add secure-shield

# Using pnpm
pnpm add secure-shield
```

## 🚀 Quick Start

```javascript
const express = require('express');
const { SecureShield } = require('secure-shield');

const app = express();

// Initialize with default settings
const shield = new SecureShield();
app.use(shield.middleware());

// Or with custom configuration
const shield = new SecureShield({
    sqlProtection: true,
    xssProtection: true,
    rateLimit: {
        maxRequests: 100,
        windowMs: 15 * 60 * 1000
    }
});
```

## 🔧 Configuration

### Basic Configuration

```javascript
const shield = new SecureShield({
    // Core Protection
    sqlProtection: true,
    xssProtection: true,
    noSqlProtection: true,
    payloadProtection: true,

    // Rate Limiting
    rateLimit: {
        enabled: true,
        maxRequests: 100,
        windowMs: 15 * 60 * 1000,
        bruteForceProtection: true
    }
});
```

### Advanced Configuration

```javascript
const shield = new SecureShield({
    // Security Headers
    securityHeaders: {
        enabled: true,
        hsts: true,
        noSniff: true,
        xssFilter: true,
        frameguard: 'SAMEORIGIN',
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
            }
        }
    },

    // Cryptographic Settings
    crypto: {
        enabled: true,
        algorithm: 'aes-256-gcm',
        secretKey: process.env.SECRET_KEY
    },

    // Logging
    logging: {
        enabled: true,
        logLevel: 'info',
        logPath: './security.log',
        format: 'json'
    }
});
```

## 🔒 Security Features

### Cryptographic Utilities

```javascript
// Password Hashing
const { hash, salt } = await shield.hashPassword('userPassword');

// Password Verification
const isValid = await shield.verifyPassword('userPassword', hash, salt);

// Data Encryption
const encrypted = shield.encrypt('sensitive data');
const decrypted = shield.decrypt(encrypted);
```

### Request Validation

```javascript
shield.requestValidation({
    maxBodySize: 1024 * 1024, // 1MB
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedContentTypes: [
        'application/json',
        'application/x-www-form-urlencoded'
    ]
});
```

### Security Headers

```javascript
shield.securityHeaders({
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    csp: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"]
    }
});
```

## 📖 API Reference

### Core Methods

- `shield.middleware()` - Express/Koa middleware
- `shield.scan(input)` - Scan input for threats
- `shield.sanitize(input)` - Sanitize input
- `shield.encrypt(data)` - Encrypt sensitive data
- `shield.decrypt(data)` - Decrypt data
- `shield.generateToken()` - Generate secure token

### Event Handling

```javascript
shield.on('threat', (threat) => {
    console.log('Security threat detected:', threat);
});

shield.on('rateLimit', (info) => {
    console.log('Rate limit exceeded:', info);
});
```

## 🎯 Examples

### Express.js Integration

```javascript
const express = require('express');
const { SecureShield } = require('secure-shield');

const app = express();
const shield = new SecureShield();

// Apply middleware
app.use(shield.middleware());

// Protected route
app.post('/api/data', (req, res) => {
    res.json({ success: true });
});
```

### Standalone Usage

```javascript
const { SecureShield } = require('secure-shield');
const shield = new SecureShield();

// Scan for threats
const threats = shield.scan(userInput);

// Sanitize input
const clean = shield.sanitize(userInput);
```

## 🏆 Best Practices

1. **Environment Configuration**
   - Use environment variables for sensitive settings
   - Never commit security keys to version control

2. **Rate Limiting**
   - Adjust limits based on your application's needs
   - Implement IP-based and user-based limits

3. **Logging**
   - Enable security logging in production
   - Regularly review security logs
   - Implement log rotation

4. **Updates**
   - Keep the package updated
   - Subscribe to security advisories

## ❓ FAQ

<details>
<summary>How does rate limiting work?</summary>
Rate limiting tracks requests using a sliding window algorithm and can be configured per IP or user basis.
</details>

<details>
<summary>Is it production-ready?</summary>
Yes, SecureShield is production-ready and is used by many companies in production environments.
</details>

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 🔏 Security Policy

Please report security vulnerabilities to security@secure-shield.dev instead of creating public issues.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by the SecureShield Team 