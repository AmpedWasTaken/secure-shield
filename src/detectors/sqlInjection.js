class SQLInjectionDetector {
    constructor(options = {}) {
        this.patterns = [
            /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
            /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
            /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
            /union\s+select/i,
            /exec(\s|\+)+(s|x)p\w+/i
        ];
    }

    detect(input) {
        const threats = [];
        const stringInput = this.convertToString(input);

        this.patterns.forEach(pattern => {
            if (pattern.test(stringInput)) {
                threats.push({
                    type: 'SQL_INJECTION',
                    pattern: pattern.toString(),
                    value: stringInput
                });
            }
        });

        return threats;
    }

    convertToString(input) {
        if (typeof input === 'string') return input;
        if (typeof input === 'object') {
            return JSON.stringify(input);
        }
        return String(input);
    }
}

module.exports = SQLInjectionDetector; 