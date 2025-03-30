class PayloadDetector {
    constructor(options = {}) {
        this.patterns = {
            // Command injection
            commandInjection: [
                /[\&\|\;\`\$](?:\s*(?:wget|curl|bash|cmd|powershell|exec|eval|ping|nc|ncat|netcat|nslookup|cat|more))/i,
                /\b(?:system|exec|eval|ping|curl|wget)\s*\(/i
            ],

            // File inclusion
            fileInclusion: [
                /(?:\.\.|\/|\\)(etc|proc|opt|tmp|prefix|home|root|dev|lib|bin)/i,
                /(?:file|php|glob|data|phar|ssh2|rar|ogg|expect):\/\//i
            ],

            // Directory traversal
            directoryTraversal: [
                /(?:\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)/i,
                /(?:%c0%ae|%c1%9c)/i
            ],

            // Serialization attacks
            serialization: [
                /O:[0-9]+:"[^"]+":[0-9]+:/i, // PHP serialized objects
                /__[A-Za-z]+__/              // Python magic methods
            ],

            // Template injection
            templateInjection: [
                /\{\{.*\}\}/i,               // Mustache/Handlebars
                /\$\{.*\}/i,                 // Template literals
                /<\%.*\%>/i                  // EJS/ASP
            ],

            // SSRF indicators
            ssrf: [
                /^(?:http|ftp|gopher|data|file):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[:0]|internal)/i,
                /^(?:http|ftp|gopher|data|file):\/\/(?:169\.254\.169\.254)/i // AWS metadata
            ]
        };

        // Add custom patterns if provided
        if (options.customPatterns) {
            Object.keys(options.customPatterns).forEach(key => {
                if (this.patterns[key]) {
                    this.patterns[key] = [
                        ...this.patterns[key],
                        ...options.customPatterns[key]
                    ];
                } else {
                    this.patterns[key] = options.customPatterns[key];
                }
            });
        }
    }

    detect(input) {
        const threats = [];
        const stringInput = this.convertToString(input);

        Object.entries(this.patterns).forEach(([category, patterns]) => {
            patterns.forEach(pattern => {
                if (pattern.test(stringInput)) {
                    threats.push({
                        type: 'MALICIOUS_PAYLOAD',
                        category,
                        severity: 'HIGH',
                        pattern: pattern.toString(),
                        value: stringInput,
                        timestamp: new Date().toISOString()
                    });
                }
            });
        });

        // Additional heuristic checks
        if (this.checkEncodedPayloads(stringInput)) {
            threats.push({
                type: 'MALICIOUS_PAYLOAD',
                category: 'encodedPayload',
                severity: 'MEDIUM',
                pattern: 'Encoded payload detection',
                value: stringInput,
                timestamp: new Date().toISOString()
            });
        }

        return threats;
    }

    checkEncodedPayloads(input) {
        // Check for suspicious encoding patterns
        const encodingPatterns = [
            /%[0-9a-f]{2}/i,           // URL encoding
            /\\u[0-9a-f]{4}/i,         // Unicode escape
            /\\x[0-9a-f]{2}/i,         // Hex escape
            /base64[^]*/i,             // Base64
            /&#x[0-9a-f]+;/i           // HTML hex encoding
        ];

        // Calculate the ratio of encoded characters
        let encodedCount = 0;
        encodingPatterns.forEach(pattern => {
            const matches = input.match(pattern) || [];
            encodedCount += matches.length;
        });

        // If more than 25% of the input appears to be encoded, flag it
        return (encodedCount * 4) > input.length;
    }

    convertToString(input) {
        if (typeof input === 'string') return input;
        if (typeof input === 'object') {
            return JSON.stringify(input);
        }
        return String(input);
    }
}

module.exports = PayloadDetector; 