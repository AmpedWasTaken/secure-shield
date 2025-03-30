const crypto = require('crypto');

class RateLimiter {
    constructor(options = {}) {
        this.options = {
            windowMs: 15 * 60 * 1000,  // 15 minutes
            maxRequests: 100,
            bruteForceProtection: true,
            bruteForceThreshold: 5,
            bruteForceWindowMs: 5 * 60 * 1000,  // 5 minutes
            ...options
        };

        this.requests = new Map();
        this.blockedIPs = new Map();
        this.suspiciousAttempts = new Map();

        // Cleanup old entries periodically
        setInterval(() => this.cleanup(), this.options.windowMs);
    }

    async check(req) {
        const ip = this.getClientIP(req);
        const path = req.path;
        const now = Date.now();

        // Check if IP is blocked
        if (this.isBlocked(ip)) {
            return {
                allowed: false,
                bruteForceDetected: true,
                remainingTime: this.getBlockTimeRemaining(ip)
            };
        }

        // Generate request identifier
        const identifier = this.generateRequestIdentifier(req);
        
        // Get or create request record
        const record = this.requests.get(identifier) || {
            count: 0,
            firstRequest: now,
            lastRequest: now,
            paths: new Set()
        };

        // Update record
        record.count++;
        record.lastRequest = now;
        record.paths.add(path);
        this.requests.set(identifier, record);

        // Check for brute force attempts
        if (this.options.bruteForceProtection) {
            const isBruteForce = this.checkBruteForce(ip, path);
            if (isBruteForce) {
                this.blockIP(ip);
                return {
                    allowed: false,
                    bruteForceDetected: true,
                    remainingTime: this.options.bruteForceWindowMs
                };
            }
        }

        // Check rate limit
        const isRateLimited = record.count > this.options.maxRequests &&
            (now - record.firstRequest) < this.options.windowMs;

        if (isRateLimited) {
            this.trackSuspiciousAttempt(ip, path);
        }

        return {
            allowed: !isRateLimited,
            bruteForceDetected: false,
            currentCount: record.count,
            maxRequests: this.options.maxRequests,
            remainingRequests: Math.max(0, this.options.maxRequests - record.count),
            resetTime: record.firstRequest + this.options.windowMs
        };
    }

    checkBruteForce(ip, path) {
        const key = `${ip}:${path}`;
        const attempts = this.suspiciousAttempts.get(key) || {
            count: 0,
            firstAttempt: Date.now()
        };

        const now = Date.now();
        if (now - attempts.firstAttempt > this.options.bruteForceWindowMs) {
            attempts.count = 1;
            attempts.firstAttempt = now;
        } else {
            attempts.count++;
        }

        this.suspiciousAttempts.set(key, attempts);
        return attempts.count >= this.options.bruteForceThreshold;
    }

    blockIP(ip) {
        this.blockedIPs.set(ip, Date.now() + this.options.bruteForceWindowMs);
    }
} 