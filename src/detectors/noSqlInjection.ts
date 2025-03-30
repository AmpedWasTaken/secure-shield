import { SecurityThreat, DetectorOptions, QueryObject } from '../types/detector';

export class NoSQLInjectionDetector {
    private options: Required<DetectorOptions>;
    private readonly operatorPattern = /^\$[a-zA-Z]+$/;
    private readonly jsKeywords = new Set([
        'where', 'function', 'eval', 'exec', 'setTimeout', 'setInterval'
    ]);

    constructor(options: DetectorOptions = {}) {
        this.options = {
            customRules: [],
            sensitivity: 'MEDIUM',
            maxLength: 1000,
            allowedPatterns: [],
            blocklistPatterns: [],
            ...options
        };
    }

    detect(input: string | QueryObject): SecurityThreat[] {
        const threats: SecurityThreat[] = [];

        if (typeof input === 'string') {
            threats.push(...this.detectStringInjection(input));
        } else if (typeof input === 'object' && input !== null) {
            threats.push(...this.detectObjectInjection(input));
        }

        return threats;
    }

    private detectStringInjection(input: string): SecurityThreat[] {
        const threats: SecurityThreat[] = [];

        // Check for JavaScript injection attempts
        if (this.containsJavaScript(input)) {
            threats.push({
                type: 'NOSQL_INJECTION',
                severity: 'HIGH',
                description: 'JavaScript code detected in query string',
                value: input
            });
        }

        return threats;
    }

    private detectObjectInjection(obj: QueryObject): SecurityThreat[] {
        const threats: SecurityThreat[] = [];

        for (const [key, value] of Object.entries(obj)) {
            // Check for MongoDB operators
            if (this.operatorPattern.test(key)) {
                threats.push({
                    type: 'NOSQL_INJECTION',
                    severity: 'HIGH',
                    description: 'MongoDB operator detected',
                    location: key,
                    value: String(value)
                });
            }

            // Recursively check nested objects
            if (typeof value === 'object' && value !== null) {
                function isQueryObject(obj: unknown): obj is QueryObject {
                    return typeof obj === 'object' && obj !== null;
                }
                
                if (Array.isArray(value)) {
                    value.forEach((item) => {
                        if (isQueryObject(item)) {
                            threats.push(...this.detectObjectInjection(item));
                        }
                    });
                }                 else {
                    threats.push(...this.detectObjectInjection(value as QueryObject));
                }
            }
        }

        return threats;
    }

    private containsJavaScript(input: string): boolean {
        const lowerInput = input.toLowerCase();
        return this.jsKeywords.has(lowerInput) ||
               /\bfunction\s*\(.*\)/.test(input) ||
               /\beval\s*\(/.test(input);
    }
} 