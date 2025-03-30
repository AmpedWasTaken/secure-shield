import { RateLimitOptions } from '../types';
import crypto from 'crypto';

interface RequestRecord {
    count: number;
    lastRequest: number;
    firstRequest: number;
}

interface SuspiciousAttempt {
    count: number;
    firstAttempt: number;
}

export class RateLimiter {
    private options: Required<RateLimitOptions>;
    private requests: Map<string, RequestRecord>;
    private blockedIPs: Map<string, number>;
    private suspiciousAttempts: Map<string, SuspiciousAttempt>;

    constructor(options: RateLimitOptions = {}) {
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

        const cleanupInterval = setInterval(() => this.cleanup(), this.options.windowMs);
        // Prevent the interval from keeping the process alive
        cleanupInterval.unref();
    }

    async check(req: any): Promise<boolean> {
        const ip = this.getClientIP(req);
        const path = req.path;
        const now = Date.now();

        // Check if IP is blocked
        if (this.blockedIPs.has(ip)) {
            const blockUntil = this.blockedIPs.get(ip)!;
            if (now < blockUntil) {
                return false;
            }
            this.blockedIPs.delete(ip);
        }

        const key = this.generateKey(ip, path);
        const record = this.requests.get(key) || {
            count: 0,
            lastRequest: now,
            firstRequest: now
        };

        // Update request count
        record.count++;
        record.lastRequest = now;
        this.requests.set(key, record);

        // Check rate limit
        if (record.count > this.options.maxRequests) {
            if (this.options.bruteForceProtection) {
                this.trackSuspiciousAttempt(ip);
            }
            return false;
        }

        return true;
    }

    private getClientIP(req: any): string {
        return req.ip || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress || 
               req.connection.socket.remoteAddress;
    }

    private generateKey(ip: string, path: string): string {
        return crypto
            .createHash('sha256')
            .update(`${ip}:${path}`)
            .digest('hex');
    }

    private trackSuspiciousAttempt(ip: string): void {
        const now = Date.now();
        const attempt = this.suspiciousAttempts.get(ip) || {
            count: 0,
            firstAttempt: now
        };

        attempt.count++;

        if (attempt.count >= this.options.bruteForceThreshold) {
            // Block IP for twice the brute force window
            this.blockedIPs.set(ip, now + (this.options.bruteForceWindowMs * 2));
            this.suspiciousAttempts.delete(ip);
        } else {
            this.suspiciousAttempts.set(ip, attempt);
        }
    }

    private cleanup(): void {
        const now = Date.now();

        // Cleanup requests
        for (const [key, record] of this.requests.entries()) {
            if (now - record.lastRequest > this.options.windowMs) {
                this.requests.delete(key);
            }
        }

        // Cleanup blocked IPs
        for (const [ip, blockUntil] of this.blockedIPs.entries()) {
            if (now > blockUntil) {
                this.blockedIPs.delete(ip);
            }
        }

        // Cleanup suspicious attempts
        for (const [ip, attempt] of this.suspiciousAttempts.entries()) {
            if (now - attempt.firstAttempt > this.options.bruteForceWindowMs) {
                this.suspiciousAttempts.delete(ip);
            }
        }
    }
} 