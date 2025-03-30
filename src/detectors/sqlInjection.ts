import { SecurityThreat, DetectorOptions } from '../types/detector';

export class SQLInjectionDetector {
    private options: Required<DetectorOptions>;
    private readonly sqlPatterns: RegExp[];

    constructor(options: DetectorOptions = {}) {
        this.options = {
            customRules: [],
            sensitivity: 'MEDIUM',
            maxLength: 1000,
            allowedPatterns: [],
            blocklistPatterns: [],
            ...options
        };

        this.sqlPatterns = [
            /(\b)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)(\b)/gi,
            /(\b)(FROM|INTO|WHERE|TABLE)(\b)/gi,
            /(\b)(OR|AND)(\b)\s*\d+\s*=\s*\d+/gi,
            /(\b)(OR|AND)(\b)\s*['"].*?['"]\s*=\s*['"].*?['"]/gi,
            /--[^\n]*/gi,
            /;.*/gi,
            /\/\*.*?\*\//gi,
            /EXEC(\s|\+)+(XP|SP|MASTER)/gi,
            /INFORMATION_SCHEMA/gi,
            /CONCAT\s*\([^\)]*\)/gi
        ];
    }

    detect(input: string | Record<string, unknown>): SecurityThreat[] {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        const threats: SecurityThreat[] = [];

        // Check input length
        if (input.length > this.options.maxLength) {
            threats.push({
                type: 'SQL_INJECTION',
                severity: 'MEDIUM',
                description: 'Input exceeds maximum allowed length'
            });
            return threats;
        }

        // Check custom rules
        this.options.customRules.forEach(pattern => {
            if (pattern.test(input)) {
                threats.push({
                    type: 'SQL_INJECTION',
                    severity: 'HIGH',
                    description: 'Custom SQL injection pattern detected',
                    value: input
                });
            }
        });

        // Check predefined patterns
        this.sqlPatterns.forEach(pattern => {
            if (pattern.test(input)) {
                threats.push({
                    type: 'SQL_INJECTION',
                    severity: 'HIGH',
                    description: 'SQL injection pattern detected',
                    value: input
                });
            }
        });

        return threats;
    }
} 