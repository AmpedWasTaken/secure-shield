import { Request } from 'express';

export interface SecurityOptions {
    enabled?: boolean;
    mode?: 'block' | 'sanitize';
}

export interface RateLimitOptions {
    windowMs?: number;
    maxRequests?: number;
    bruteForceProtection?: boolean;
    bruteForceThreshold?: number;
    bruteForceWindowMs?: number;
}

export interface LoggerOptions {
    enabled?: boolean;
    logLevel?: string;
    logPath?: string;
    maxSize?: number;
    maxFiles?: number;
    format?: string;
}

export interface ThreatDetection {
    type: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
    pattern: string;
    value: string;
    timestamp: string;
}

export interface SecurityReport {
    period: {
        start: string;
        end: string;
    };
    summary: {
        totalThreats: number;
        threatsByType: { [key: string]: number };
        threatsBySeverity: { [key: string]: number };
        topAttackers: { [key: string]: number };
        blockedRequests: number;
    };
    details: ThreatDetection[];  // Specifiek getypt als een array van 'ThreatDetection' objecten
}

export interface LogOptions {
    enabled?: boolean;
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
    logPath?: string;
    format?: string;
}

export interface SecurityHeadersOptions {
    enabled?: boolean;
    xssProtection?: boolean;
    noSniff?: boolean;
    frameOptions?: 'DENY' | 'SAMEORIGIN';
    hsts?: boolean;
    hstsMaxAge?: number;
    referrerPolicy?: string;
    contentSecurityPolicy?: {
        directives?: { [key: string]: string[] }
    } | boolean;
}

export interface XSSOptions {
    stripTags?: boolean;
    allowedTags?: string[];
    allowedAttributes?: Record<string, string[]>;
}

export interface SQLOptions {
    maxQueryLength?: number;
    blockComments?: boolean;
    blockUnions?: boolean;
}

export interface NoSQLOptions {
    blockOperators?: boolean;
    allowedOperators?: string[];
}

export interface PayloadOptions {
    maxSize?: number;
    allowedTypes?: string[];
}

export interface SecureShieldOptions {
    enabled?: boolean;
    xssOptions?: XSSOptions;
    sqlOptions?: SQLOptions;
    noSqlOptions?: NoSQLOptions;
    payloadOptions?: PayloadOptions;
    rateLimit?: RateLimitOptions;
    logging?: LogOptions;
    securityHeaders?: SecurityHeadersOptions;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogMessage = string | Error;
export type LogContext = Record<string, unknown>;

export interface LogEntry {
    timestamp: string;
    level: LogLevel;
    message: string;
    context?: LogContext;
}

// Base interface for all threats
export interface BaseThreat {
    type: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
    value?: string;
}

// Interface for initial threat detections
export interface ThreatDetection extends BaseThreat {
    matchedPattern?: RegExp;  // Changed from 'pattern' to avoid conflicts
    confidence: number;
}

// Interface for processed security threats
export interface SecurityThreat extends BaseThreat {
    description: string;
    location?: string;
    confidence?: number;
    detectionPattern?: string;  // Store pattern as string in final threat
}

export interface EncryptedData {
    encrypted: string;
    iv: string;
    authTag: string;
}

export interface DetectorOptions {
    customRules?: RegExp[];
    sensitivity?: 'LOW' | 'MEDIUM' | 'HIGH';
    maxLength?: number;
    allowedPatterns?: RegExp[];
    blocklistPatterns?: RegExp[];
}

export interface SQLOptions extends DetectorOptions {
    maxQueryLength?: number;
    blockComments?: boolean;
    blockUnions?: boolean;
}

export interface NoSQLOptions extends DetectorOptions {
    blockOperators?: boolean;
    allowedOperators?: string[];
}

export interface PayloadOptions extends DetectorOptions {
    maxSize?: number;
    allowedTypes?: string[];
}

export interface SecurityHeadersOptions {
    enabled?: boolean;
    xssProtection?: boolean;
    noSniff?: boolean;
    frameOptions?: 'DENY' | 'SAMEORIGIN';
    hsts?: boolean;
    hstsMaxAge?: number;
    referrerPolicy?: string;
    contentSecurityPolicy?: {
        directives?: { [key: string]: string[] }
    } | boolean;
}

export interface SecurityRule {
    type: string;
    pattern: string | RegExp;
    action: 'block' | 'sanitize' | 'log';
    severity: 'low' | 'medium' | 'high';
}

export interface SecurityConfig {
    customRules: SecurityRule[];
    rateLimiting?: {
        windowMs: number;
        maxRequests: number;
        message?: string;
    };
    // ... other config options ...
}

export interface ExtendedRequest extends Request {
    clientIp?: string;
}

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