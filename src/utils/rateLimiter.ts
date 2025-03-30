import { Request } from 'express';
import type { RateLimitConfig as ImportedRateLimitConfig, RateLimitInfo as ImportedRateLimitInfo } from '../types';
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

interface RateLimitOptions extends ImportedRateLimitConfig {
    bruteForceProtection?: boolean;
    bruteForceThreshold?: number;
    bruteForceWindowMs?: number;
}

const DEFAULT_OPTIONS: Required<RateLimitOptions> = {
    windowMs: 15 * 60 * 1000,  // 15 minutes
    maxRequests: 100,
    message: 'Too many requests, please try again later.',
    bruteForceProtection: true,
    bruteForceThreshold: 5,
    bruteForceWindowMs: 15 * 60 * 1000
};

export interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
    message?: string;
}

export interface RateLimitInfo {
    remaining: number;
    reset: number;
    limit: number;
}

export class RateLimiter {
    private store: Map<string, { count: number; resetTime: number }>;
    private blockedIPs: Map<string, number>;
    private options: Required<RateLimitOptions> = DEFAULT_OPTIONS;
    private cleanupInterval: NodeJS.Timeout;
    private requests: Map<string, RequestRecord>;
    private suspiciousAttempts: Map<string, SuspiciousAttempt>;

    constructor(options: Partial<RateLimitOptions> = {}) {
        this.store = new Map();
        this.blockedIPs = new Map();
        this.requests = new Map();
        this.suspiciousAttempts = new Map();
        this.options = { ...DEFAULT_OPTIONS, ...options };
        this.cleanupInterval = setInterval(() => this.cleanup(), this.options.windowMs);
    }

    async check(req: Request): Promise<boolean | RateLimitInfo> {
        const ip = this.getClientIP(req);
        const path = req.path;
        const now = Date.now();
    
        // Check if IP is blocked
        if (this.blockedIPs.has(ip)) {
            const blockUntil = this.blockedIPs.get(ip)!;
            if (now < blockUntil) {
                return {
                    remaining: 0,
                    reset: blockUntil,
                    limit: this.options.maxRequests
                };
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
            return {
                remaining: 0,
                reset: record.firstRequest + this.options.windowMs,
                limit: this.options.maxRequests
            };
        }
    
        const remaining = this.options.maxRequests - record.count;
        const reset = record.firstRequest + this.options.windowMs;
    
        return {
            remaining,
            reset,
            limit: this.options.maxRequests
        };
    }
    

    private getClientIP(req: Request): string {
        const xForwardedFor = req.headers['x-forwarded-for'];
        const xRealIp = req.headers['x-real-ip'];
        
        if (Array.isArray(xForwardedFor)) {
            return xForwardedFor[0];
        }
        
        return xForwardedFor as string || 
               xRealIp as string || 
               req.socket?.remoteAddress || 
               'unknown';
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
        for (const [key, value] of this.store.entries()) {
            if (now > value.resetTime) {
                this.store.delete(key);
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

    checkLimit(clientId: string): boolean {
        const now = Date.now();
        const record = this.store.get(clientId);

        if (!record) {
            this.store.set(clientId, {
                count: 1,
                resetTime: now + this.options.windowMs
            });
            return true;
        }

        if (now > record.resetTime) {
            this.store.set(clientId, {
                count: 1,
                resetTime: now + this.options.windowMs
            });
            return true;
        }

        if (record.count < this.options.maxRequests) {
            record.count++;
            return true;
        }

        return false;
    }

    getLimitInfo(clientId: string): ImportedRateLimitInfo {
        const now = Date.now();
        const record = this.store.get(clientId);

        if (!record) {
            return {
                remaining: this.options.maxRequests,
                reset: now + this.options.windowMs,
                limit: this.options.maxRequests
            };
        }

        return {
            remaining: Math.max(0, this.options.maxRequests - record.count),
            reset: record.resetTime,
            limit: this.options.maxRequests
        };
    }

    getClientId(req: Request): string {
        const xForwardedFor = req.headers['x-forwarded-for'];
        const xRealIp = req.headers['x-real-ip'];
        
        if (Array.isArray(xForwardedFor)) {
            return xForwardedFor[0];
        }
        
        return xForwardedFor as string || 
               xRealIp as string || 
               req.socket?.remoteAddress || 
               'unknown';
    }

    destroy(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
    }
} 