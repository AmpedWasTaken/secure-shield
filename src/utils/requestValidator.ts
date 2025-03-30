import { Request, Response, NextFunction } from 'express';

export interface RequestValidatorOptions {
    maxBodySize?: number;
    allowedMethods?: string[];
    allowedContentTypes?: string[];
    validateContentLength?: boolean;
    validateHost?: boolean;
}

export class RequestValidator {
    private options: Required<RequestValidatorOptions>;

    constructor(options: RequestValidatorOptions = {}) {
        this.options = {
            maxBodySize: 1024 * 1024, // 1MB
            allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
            allowedContentTypes: [
                'application/json',
                'application/x-www-form-urlencoded',
                'multipart/form-data'
            ],
            validateContentLength: true,
            validateHost: true,
            ...options
        };
    }

    middleware() {
        return (req: Request, res: Response, next: NextFunction): void => {
            try {
                // Validate HTTP method
                if (!this.options.allowedMethods.includes(req.method)) {
                    res.status(405).json({
                        error: 'Method Not Allowed'
                    });
                    return;
                }

                // Validate Content-Type
                const contentType = req.get('content-type');
                if (contentType && !this.options.allowedContentTypes.some(
                    allowed => contentType.includes(allowed)
                )) {
                    res.status(415).json({
                        error: 'Unsupported Media Type'
                    });
                    return;
                }

                // Validate Content-Length
                if (this.options.validateContentLength) {
                    const contentLength = parseInt(req.get('content-length') || '0', 10);
                    if (contentLength > this.options.maxBodySize) {
                        res.status(413).json({
                            error: 'Payload Too Large'
                        });
                        return;
                    }
                }

                // Validate Host header
                if (this.options.validateHost && !req.get('host')) {
                    res.status(400).json({
                        error: 'Host Header Required'
                    });
                    return;
                }

                // Check for invalid characters
                if (this.hasInvalidCharacters(req.url) ||
                    this.hasInvalidCharacters(req.get('host') || '')) {
                    res.status(400).json({
                        error: 'Invalid Characters Detected'
                    });
                    return;
                }

                next();
            } catch (error) {
                next(error);
            }
        };
    }

    private hasInvalidCharacters(str: string): boolean {
        if (!str) return false;
        // Check for NULL bytes, control characters, etc.
        return /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
    }
} 