const SQLInjectionDetector = require('./detectors/sqlInjection');
const XSSDetector = require('./detectors/xss');
const NoSQLInjectionDetector = require('./detectors/noSqlInjection');
const RateLimiter = require('./utils/rateLimiter');
const SecurityLogger = require('./utils/logger');
const SecurityHeaders = require('./utils/securityHeaders');
const CryptoUtils = require('./utils/cryptoUtils');
const RequestValidator = require('./utils/requestValidator');

class SecureShield {
    constructor(options = {}) {
        this.options = {
            sqlProtection: true,
            xssProtection: true,
            noSqlProtection: true,
            rateLimit: {
                enabled: true,
                maxRequests: 100,
                windowMs: 15 * 60 * 1000 // 15 minutes
            },
            logging: {
                enabled: true,
                logLevel: 'warn'
            },
            securityHeaders: {
                enabled: true,
                hsts: true,
                noSniff: true,
                xssFilter: true
            },
            requestValidation: {
                enabled: true,
                maxBodySize: 1024 * 1024
            },
            crypto: {
                enabled: true,
                algorithm: 'aes-256-gcm'
            },
            ...options
        };

        this.sqlDetector = new SQLInjectionDetector(options.sqlOptions);
        this.xssDetector = new XSSDetector(options.xssOptions);
        this.noSqlDetector = new NoSQLInjectionDetector(options.noSqlOptions);
        this.rateLimiter = new RateLimiter(this.options.rateLimit);
        this.logger = new SecurityLogger(this.options.logging);
        this.securityHeaders = new SecurityHeaders(this.options.securityHeaders);
        this.cryptoUtils = new CryptoUtils(this.options.crypto);
        this.requestValidator = new RequestValidator(this.options.requestValidation);
    }

    middleware() {
        return async (req, res, next) => {
            try {
                // Apply security headers first
                if (this.options.securityHeaders.enabled) {
                    this.securityHeaders.middleware()(req, res, () => {});
                }

                // Validate request
                if (this.options.requestValidation.enabled) {
                    this.requestValidator.middleware()(req, res, () => {});
                }

                // Rate limiting check
                if (this.options.rateLimit.enabled) {
                    const rateLimitResult = await this.rateLimiter.check(req);
                    if (!rateLimitResult.allowed) {
                        this.logger.warn('Rate limit exceeded', { ip: req.ip });
                        return res.status(429).json({ error: 'Too many requests' });
                    }
                }

                // Scan request body, query parameters, and headers
                const scanTarget = {
                    body: req.body,
                    query: req.query,
                    headers: req.headers
                };

                const threats = this.scan(scanTarget);

                if (threats.length > 0) {
                    this.logger.warn('Security threats detected', { threats });
                    return res.status(400).json({ 
                        error: 'Malicious input detected',
                        threats: threats.map(t => t.type)
                    });
                }

                next();
            } catch (error) {
                this.logger.error('Security middleware error', { error });
                next(error);
            }
        };
    }

    scan(input) {
        const threats = [];

        if (this.options.sqlProtection) {
            const sqlThreats = this.sqlDetector.detect(input);
            threats.push(...sqlThreats);
        }

        if (this.options.xssProtection) {
            const xssThreats = this.xssDetector.detect(input);
            threats.push(...xssThreats);
        }

        if (this.options.noSqlProtection) {
            const noSqlThreats = this.noSqlDetector.detect(input);
            threats.push(...noSqlThreats);
        }

        return threats;
    }

    // Add utility methods for easy access to crypto functions
    async hashPassword(password) {
        return this.cryptoUtils.hashPassword(password);
    }

    async verifyPassword(password, hash, salt) {
        return this.cryptoUtils.verifyPassword(password, hash, salt);
    }

    encrypt(data) {
        return this.cryptoUtils.encrypt(data);
    }

    decrypt(encryptedData) {
        return this.cryptoUtils.decrypt(encryptedData);
    }

    generateToken(length) {
        return this.cryptoUtils.generateToken(length);
    }
}

module.exports = function(options) {
    const shield = new SecureShield(options);
    return shield.middleware();
};

module.exports.SecureShield = SecureShield; 