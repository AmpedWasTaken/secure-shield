class RequestValidator {
    constructor(options = {}) {
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
        return (req, res, next) => {
            try {
                // Validate HTTP method
                if (!this.options.allowedMethods.includes(req.method)) {
                    return res.status(405).json({
                        error: 'Method Not Allowed',
                        allowed: this.options.allowedMethods
                    });
                }

                // Validate Content-Type
                if (req.method !== 'GET' && req.headers['content-type']) {
                    const contentType = req.headers['content-type'].split(';')[0];
                    if (!this.options.allowedContentTypes.includes(contentType)) {
                        return res.status(415).json({
                            error: 'Unsupported Media Type',
                            allowed: this.options.allowedContentTypes
                        });
                    }
                }

                // Validate Content-Length
                if (this.options.validateContentLength && req.headers['content-length']) {
                    const size = parseInt(req.headers['content-length']);
                    if (size > this.options.maxBodySize) {
                        return res.status(413).json({
                            error: 'Payload Too Large',
                            maxSize: this.options.maxBodySize
                        });
                    }
                }

                // Validate Host header
                if (this.options.validateHost && !req.headers.host) {
                    return res.status(400).json({
                        error: 'Missing Host Header'
                    });
                }

                // Additional security checks
                if (this.hasInvalidCharacters(req.url) ||
                    this.hasInvalidCharacters(req.headers.host)) {
                    return res.status(400).json({
                        error: 'Invalid Characters Detected'
                    });
                }

                next();
            } catch (error) {
                next(error);
            }
        };
    }

    hasInvalidCharacters(str) {
        if (!str) return false;
        // Check for NULL bytes, control characters, etc.
        return /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
    }
}

module.exports = RequestValidator; 