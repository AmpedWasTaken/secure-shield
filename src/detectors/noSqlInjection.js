class NoSQLInjectionDetector {
    constructor(options = {}) {
        this.patterns = [
            // MongoDB operators
            /\$where/i,
            /\$ne/i,
            /\$gt/i,
            /\$lt/i,
            /\$gte/i,
            /\$lte/i,
            /\$in/i,
            /\$nin/i,
            /\$regex/i,
            /\$exists/i,

            // JavaScript execution
            /\{\s*\$function\s*:/i,
            /function\s*\(/i,
            /eval\s*\(/i,

            // Array operators
            /\$all/i,
            /\$elemMatch/i,
            /\$size/i,

            // Logical operators
            /\$or/i,
            /\$and/i,
            /\$not/i,
            /\$nor/i
        ];

        this.customPatterns = options?.patterns || [];
        this.patterns = [...this.patterns, ...this.customPatterns];
    }

    detect(input) {
        const threats = [];
        const stringInput = this.convertToString(input);

        // Check for MongoDB operators and injection patterns
        this.patterns.forEach(pattern => {
            if (pattern.test(stringInput)) {
                threats.push({
                    type: 'NOSQL_INJECTION',
                    severity: 'HIGH',
                    pattern: pattern.toString(),
                    value: stringInput,
                    timestamp: new Date().toISOString()
                });
            }
        });

        // Check for type confusion attacks
        if (this.checkTypeConfusion(input)) {
            threats.push({
                type: 'NOSQL_INJECTION',
                severity: 'MEDIUM',
                pattern: 'Type confusion attack',
                value: stringInput,
                timestamp: new Date().toISOString()
            });
        }

        return threats;
    }

    checkTypeConfusion(input) {
        if (typeof input !== 'object' || input === null) return false;

        // Check for arrays or objects where strings are expected
        return Object.values(input).some(value => 
            Array.isArray(value) || 
            (typeof value === 'object' && value !== null)
        );
    }

    convertToString(input) {
        if (typeof input === 'string') return input;
        if (typeof input === 'object') {
            return JSON.stringify(input);
        }
        return String(input);
    }
}

module.exports = NoSQLInjectionDetector; 