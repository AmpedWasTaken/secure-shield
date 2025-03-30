import { Request, Response, NextFunction } from 'express';
import { XSSDetector } from './detectors/xss';
import { SQLInjectionDetector } from './detectors/sqlInjection';
import { NoSQLInjectionDetector } from './detectors/noSqlInjection';
import { PayloadDetector } from './detectors/payloadDetector';
import { RateLimiter } from './utils/rateLimiter';
import Logger from './utils/logger';
import { SecurityHeaders } from './utils/securityHeaders';
import { RequestValidator } from './utils/requestValidator';
import { InputSanitizer, DefaultInputSanitizer } from './utils/inputSanitizer';
import { ConfigManager } from './utils/configManager';
import { CryptoUtils } from './utils/cryptoUtils';
import { 
    SecureShieldOptions, 
    SecurityThreat,
    ThreatDetection,
    EncryptedData,
    SQLOptions,
    NoSQLOptions,
    PayloadOptions,
    SecurityConfig,
    ExtendedRequest
} from './types';

export interface RequestHandler {
    (req: Request, res: Response, next: NextFunction): Promise<void> | void;
}

export class SecureShield {
    private options: Required<SecureShieldOptions>;
    private xssDetector: XSSDetector = new XSSDetector();
    private sqlDetector: SQLInjectionDetector = new SQLInjectionDetector();
    private noSqlDetector: NoSQLInjectionDetector = new NoSQLInjectionDetector();
    private payloadDetector: PayloadDetector = new PayloadDetector();
    private rateLimiter: RateLimiter;
    private logger: Logger = new Logger();
    private securityHeaders: SecurityHeaders = new SecurityHeaders();
    private requestValidator: RequestValidator = new RequestValidator();
    private inputSanitizer: DefaultInputSanitizer;
    private configManager = ConfigManager.getInstance();
    private cryptoUtils: CryptoUtils = new CryptoUtils();

    constructor(config?: SecurityConfig) {
        this.options = {
            enabled: true,
            xssOptions: {},
            sqlOptions: {},
            noSqlOptions: {},
            payloadOptions: {},
            rateLimit: {
                windowMs: config?.rateLimiting?.windowMs || 60000,
                maxRequests: config?.rateLimiting?.maxRequests || 100
            },
            logging: {},
            securityHeaders: {},
        };

        this.inputSanitizer = new DefaultInputSanitizer();
        this.rateLimiter = new RateLimiter({
            windowMs: config?.rateLimiting?.windowMs || 60000,
            maxRequests: config?.rateLimiting?.maxRequests || 100
        });

        this.initializeComponents();
    }

    private initializeComponents(): void {
        this.xssDetector = new XSSDetector(this.options.xssOptions);
        this.sqlDetector = new SQLInjectionDetector(this.options.sqlOptions as SQLOptions);
        this.noSqlDetector = new NoSQLInjectionDetector(this.options.noSqlOptions as NoSQLOptions);
        this.payloadDetector = new PayloadDetector(this.options.payloadOptions as PayloadOptions);
        this.logger = new Logger(this.options.logging);
        this.securityHeaders = new SecurityHeaders(this.options.securityHeaders);
        this.requestValidator = new RequestValidator();
        this.cryptoUtils = new CryptoUtils();
    }

    private processThreats(detections: ThreatDetection[]): SecurityThreat[] {
        return detections.map(detection => ({
            type: detection.type,
            severity: detection.severity,
            value: detection.value,
            confidence: detection.confidence,
            description: `Detected ${detection.type} threat with ${detection.confidence * 100}% confidence`,
            detectionPattern: detection.matchedPattern?.toString(),
            location: detection.value ? `Found in: ${detection.value}` : undefined
        }));
    }

    private async validateRequest(req: Request): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            const nextFn: NextFunction = (error: unknown) => {
                if (error instanceof Error) {
                    reject(new Error(typeof error === 'string' ? error : error.message));
                } else {
                    resolve();
                }
            };
            this.requestValidator.middleware()(req, {} as Response, nextFn);
        });
    }

    middleware(): RequestHandler {
        return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
            if (!this.options.enabled) {
                next();
                return;
            }

            try {
                // Apply security headers
                this.securityHeaders.middleware()(req, res, () => {});

                // Rate limiting check
                const rateLimit = await this.asyncCheckRateLimit(req as ExtendedRequest);
                if (!rateLimit) {
                    this.logger.warn('Rate limit exceeded', { ip: req.ip });
                    res.status(429).json({ error: 'Too Many Requests' });
                    return;
                }

                // Request validation
                try {
                    await this.validateRequest(req);
                } catch (error) {
                    this.logger.error('Request validation failed', { error });
                    res.status(400).json({ error: 'Invalid Request' });
                    return;
                }

                // Threat detection
                const detections: ThreatDetection[] = [
                    ...this.xssDetector.detect(req.body),
                    ...this.sqlDetector.detect(req.query),
                    ...this.noSqlDetector.detect(req.body),
                    ...this.payloadDetector.detect(req.body)
                ] as ThreatDetection[];

                const threats = this.processThreats(detections);

                if (threats.length > 0) {
                    this.logger.warn('Security threats detected', { threats });
                    res.status(403).json({ error: 'Security Threat Detected' });
                    return;
                }

                next();
            } catch (error) {
                this.logger.error('Security middleware error', { error });
                next(error);
            }
        };
    }

    sanitizeInput(input: string | number | boolean | Record<string, unknown>): string {
        return this.inputSanitizer.sanitize(input);
    }

    validateInput(input: string | number | boolean | Record<string, unknown>): boolean {
        return this.inputSanitizer.validate(input);
    }

    encrypt(data: string | Record<string, unknown>): EncryptedData {
        return this.cryptoUtils.encrypt(data);
    }

    decrypt(encryptedData: EncryptedData): string {
        return this.cryptoUtils.decrypt(encryptedData);
    }

    async checkRequest(req: Request): Promise<boolean> {
        return new Promise((resolve) => {
            this.requestValidator.middleware()(req, {} as Response, () => {
                resolve(true);
            });
        });
    }

    private async asyncCheckRateLimit(req: ExtendedRequest): Promise<boolean> {
        const clientId = this.rateLimiter.getClientId(req);
        return this.rateLimiter.checkLimit(clientId);
    }
}

// Export all components for individual use
export {
    XSSDetector,
    SQLInjectionDetector,
    NoSQLInjectionDetector,
    PayloadDetector,
    RateLimiter,
    Logger,
    SecurityHeaders,
    RequestValidator,
    InputSanitizer,
    ConfigManager,
    CryptoUtils
}; 