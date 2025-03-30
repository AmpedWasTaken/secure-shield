const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const sanitizeHtml = require('sanitize-html');

class XSSDetector {
    constructor(options = {}) {
        const window = new JSDOM('').window;
        this.DOMPurify = createDOMPurify(window);
        
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
            /base64.*(?=<\/script>)/i
        ];
    }

    detect(input) {
        const threats = [];
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

    sanitize(input, customOptions = {}) {
        const options = {
            ...this.options,
            ...customOptions
        };

        // First pass: DOMPurify for basic XSS protection
        let sanitized = this.DOMPurify.sanitize(input, {
            ALLOWED_TAGS: options.allowedTags,
            ALLOWED_ATTR: Object.keys(options.allowedAttributes).reduce((acc, key) => 
                [...acc, ...options.allowedAttributes[key]], []),
            KEEP_CONTENT: true,
            RETURN_DOM: false,
            SANITIZE_DOM: true
        });

        // Second pass: sanitize-html for more granular control
        sanitized = sanitizeHtml(sanitized, {
            allowedTags: options.allowedTags,
            allowedAttributes: options.allowedAttributes,
            allowedSchemes: ['http', 'https', 'mailto'],
            allowProtocolRelative: false
        });

        return sanitized;
    }

    checkSuspiciousAttributes(input) {
        const suspiciousAttributes = [
            /\sformaction\s*=/i,
            /\sxlink:href\s*=/i,
            /\saction\s*=/i,
            /\ssrc\s*=\s*["']?javascript:/i,
            /\shref\s*=\s*["']?javascript:/i
        ];

        return suspiciousAttributes.some(pattern => pattern.test(input));
    }

    convertToString(input) {
        if (typeof input === 'string') return input;
        if (typeof input === 'object') {
            return JSON.stringify(input);
        }
        return String(input);
    }
}

module.exports = XSSDetector; 