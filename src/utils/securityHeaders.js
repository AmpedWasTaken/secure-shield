class SecurityHeaders {
    constructor(options = {}) {
        this.options = {
            hsts: true,
            noSniff: true,
            xssFilter: true,
            frameguard: 'SAMEORIGIN',
            referrerPolicy: 'strict-origin-when-cross-origin',
            contentSecurityPolicy: true,
            ...options
        };
    }

    middleware() {
        return (req, res, next) => {
            // HTTP Strict Transport Security
            if (this.options.hsts) {
                res.setHeader(
                    'Strict-Transport-Security',
                    'max-age=31536000; includeSubDomains; preload'
                );
            }

            // Prevent MIME type sniffing
            if (this.options.noSniff) {
                res.setHeader('X-Content-Type-Options', 'nosniff');
            }

            // XSS Protection Header
            if (this.options.xssFilter) {
                res.setHeader('X-XSS-Protection', '1; mode=block');
            }

            // Clickjacking Protection
            if (this.options.frameguard) {
                res.setHeader('X-Frame-Options', this.options.frameguard);
            }

            // Referrer Policy
            if (this.options.referrerPolicy) {
                res.setHeader('Referrer-Policy', this.options.referrerPolicy);
            }

            // Content Security Policy
            if (this.options.contentSecurityPolicy) {
                res.setHeader('Content-Security-Policy', this.getCSP());
            }

            // Remove sensitive headers
            res.removeHeader('X-Powered-By');
            res.removeHeader('Server');

            next();
        };
    }

    getCSP() {
        return [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self'",
            "media-src 'self'",
            "object-src 'none'",
            "frame-src 'self'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'self'",
            "upgrade-insecure-requests"
        ].join('; ');
    }
}

module.exports = SecurityHeaders; 