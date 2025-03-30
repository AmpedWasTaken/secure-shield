import { SecurityThreat, DetectorOptions, DetectedPayload } from '../types/detector';

interface PayloadPattern {
    pattern: RegExp;
    type: string;
    confidence: number;
}

export class PayloadDetector {
    private options: Required<DetectorOptions>;
    private patterns: PayloadPattern[];

    constructor(options: DetectorOptions = {}) {
        this.options = {
            customRules: [],
            sensitivity: 'MEDIUM',
            maxLength: 1000,
            allowedPatterns: [],
            blocklistPatterns: [],
            ...options
        };

        this.patterns = [
            {
                pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
                type: 'XSS',
                confidence: 0.9
            },
            {
                pattern: /(\b)(on\w+\s*=)/gi,
                type: 'XSS',
                confidence: 0.8
            },
            {
                pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*?(\bFROM\b|\bINTO\b|\bTABLE\b)/gi,
                type: 'SQL_INJECTION',
                confidence: 0.9
            },
            {
                pattern: /\{\s*\$where\s*:/i,
                type: 'NOSQL_INJECTION',
                confidence: 0.9
            }
        ];
    }

    detect(input: string | Record<string, unknown>): SecurityThreat[] {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        const detectedPayloads = this.detectPayloads(input);
        return this.convertToThreats(detectedPayloads);
    }

    private detectPayloads(input: string): DetectedPayload[] {
        const payloads: DetectedPayload[] = [];

        // Check custom rules first
        this.options.customRules.forEach(pattern => {
            if (pattern.test(input)) {
                payloads.push({
                    type: 'CUSTOM_RULE',
                    value: input,
                    pattern,
                    confidence: 1.0
                });
            }
        });

        // Check predefined patterns
        this.patterns.forEach(({ pattern, type, confidence }) => {
            const matches = input.match(pattern);
            if (matches) {
                matches.forEach(match => {
                    payloads.push({
                        type,
                        value: match,
                        pattern,
                        confidence
                    });
                });
            }
        });

        return payloads;
    }

    private convertToThreats(payloads: DetectedPayload[]): SecurityThreat[] {
        return payloads.map(payload => ({
            type: payload.type,
            severity: this.determineSeverity(payload.confidence),
            description: `Detected potential ${payload.type} payload`,
            value: payload.value
        }));
    }

    private determineSeverity(confidence: number): 'LOW' | 'MEDIUM' | 'HIGH' {
        if (confidence >= 0.9) return 'HIGH';
        if (confidence >= 0.7) return 'MEDIUM';
        return 'LOW';
    }
} 