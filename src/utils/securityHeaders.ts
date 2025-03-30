import { Request, Response, NextFunction } from 'express';

export interface SecurityHeadersOptions {
    hsts?: boolean;
    noSniff?: boolean;
    xssFilter?: boolean;
    frameguard?: 'DENY' | 'SAMEORIGIN' | false;
    referrerPolicy?: string;
    contentSecurityPolicy?: boolean | {
        directives?: {
            [key: string]: string[];
        };
    };
}

export class SecurityHeaders {
    private options: Required<SecurityHeadersOptions>;

    constructor(options: SecurityHeadersOptions = {}) {
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
        return (req: Request, res: Response, next: NextFunction): void => {
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

            // Frameguard
            if (this.options.frameguard) {
                res.setHeader('X-Frame-Options', this.options.frameguard);
            }

            // Referrer Policy
            res.setHeader('Referrer-Policy', this.options.referrerPolicy);

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

    private getCSP(): string {
        const defaultDirectives = {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "media-src": ["'self'"],
            "object-src": ["'none'"],
            "frame-src": ["'self'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'self'"]
        };

        const directives = typeof this.options.contentSecurityPolicy === 'object'
            ? { ...defaultDirectives, ...this.options.contentSecurityPolicy.directives }
            : defaultDirectives;

        return Object.entries(directives)
            .map(([key, values]) => `${key} ${values.join(' ')}`)
            .join('; ');
    }
} 