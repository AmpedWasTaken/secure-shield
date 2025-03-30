import DOMPurify from 'isomorphic-dompurify';
import sanitizeHtml from 'sanitize-html';

export interface XSSDetectorOptions {
    allowedTags?: string[];
    allowedAttributes?: {
        [key: string]: string[];
    };
    patterns?: RegExp[];
}

export interface ThreatDetection {
    type: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
    pattern: string;
    value: string;
    timestamp: string;
}

export class XSSDetector {
    private options: XSSDetectorOptions;
    private patterns: RegExp[];

    constructor(options: XSSDetectorOptions = {}) {
        this.options = {
            allowedTags: options.allowedTags || [
                'b', 'i', 'em', 'strong', 'p', 'br'
            ],
            allowedAttributes: options.allowedAttributes || {
                'a': ['href', 'title'],
                'img': ['src', 'alt']
            },
            ...options
        };

        this.patterns = [
            // Script injection
            /<script[^>]*>[\s\S]*?<\/script>/i,
            /(javascript|vbscript|expression|data):/i,
            /on\w+\s*=/i,

            // Event handlers
            /on(load|error|mouse|key|focus|blur|change|submit)\s*=/i,

            // Data URIs
            /data:\s*[^,]+\s*,/i,

            // JavaScript functions
            /eval\s*\(/i,
            /Function\s*\(/i,
            /setTimeout\s*\(/i,
            /setInterval\s*\(/i,
            /new\s+Function\s*\(/i,

            // DOM manipulation
            /document\.(cookie|write|location)/i,
            /window\.(location|open|eval)/i,
            /innerHTML|outerHTML/i,

            // Base64 encoded JavaScript
            /base64.*(?=<\/script>)/i,
            
            ...(options.patterns || [])
        ];
    }

    detect(input: string | object): ThreatDetection[] {
        const threats: ThreatDetection[] = [];
        const stringInput = this.convertToString(input);

        // Check for XSS patterns
        this.patterns.forEach(pattern => {
            if (pattern.test(stringInput)) {
                threats.push({
                    type: 'XSS',
                    severity: 'HIGH',
                    pattern: pattern.toString(),
                    value: stringInput,
                    timestamp: new Date().toISOString()
                });
            }
        });

        // Check for suspicious HTML attributes
        if (this.checkSuspiciousAttributes(stringInput)) {
            threats.push({
                type: 'XSS',
                severity: 'MEDIUM',
                pattern: 'Suspicious HTML attributes',
                value: stringInput,
                timestamp: new Date().toISOString()
            });
        }

        return threats;
    }

    sanitize(input: string, customOptions: XSSDetectorOptions = {}): string {
        const options = {
            ...this.options,
            ...customOptions
        };

        // First pass: DOMPurify for basic XSS protection
        let sanitized = DOMPurify.sanitize(input, {
            ALLOWED_TAGS: options.allowedTags,
            ALLOWED_ATTR: Object.keys(options.allowedAttributes || {}).reduce((acc, key) => 
                [...acc, ...(options.allowedAttributes?.[key] || [])], [] as string[]),
            KEEP_CONTENT: true,
            RETURN_DOM: false
        });

        // Second pass: sanitize-html for more granular control
        sanitized = sanitizeHtml(sanitized, {
            allowedTags: options.allowedTags,
            allowedAttributes: options.allowedAttributes,
            allowProtocolRelative: false
        });

        return sanitized;
    }

    private checkSuspiciousAttributes(input: string): boolean {
        const suspiciousAttributes = [
            /\sformaction\s*=/i,
            /\sxlink:href\s*=/i,
            /\saction\s*=/i,
            /\ssrc\s*=\s*["']?javascript:/i,
            /\shref\s*=\s*["']?javascript:/i
        ];

        return suspiciousAttributes.some(pattern => pattern.test(input));
    }

    private convertToString(input: string | object): string {
        if (typeof input === 'string') return input;
        if (typeof input === 'object') {
            return JSON.stringify(input);
        }
        return String(input);
    }
} 