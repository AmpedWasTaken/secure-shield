import { SecurityOptions, RateLimitOptions, LoggerOptions } from '../types';

export interface ConfigOptions {
    security?: SecurityOptions;
    rateLimit?: RateLimitOptions;
    logging?: LoggerOptions;
    environment?: string;
}

export class ConfigManager {
    private config: Required<ConfigOptions>;
    private static instance: ConfigManager;

    private constructor(options: ConfigOptions = {}) {
        this.config = {
            security: {
                enabled: true,
                mode: 'block',
                ...options.security
            },
            rateLimit: {
                windowMs: 15 * 60 * 1000,
                maxRequests: 100,
                bruteForceProtection: true,
                bruteForceThreshold: 5,
                bruteForceWindowMs: 5 * 60 * 1000,
                ...options.rateLimit
            },
            logging: {
                enabled: true,
                logLevel: 'info',
                logPath: './logs/security.log',
                ...options.logging
            },
            environment: options.environment || process.env.NODE_ENV || 'development'
        };
    }

    static getInstance(options?: ConfigOptions): ConfigManager {
        if (!ConfigManager.instance) {
            ConfigManager.instance = new ConfigManager(options);
        }
        return ConfigManager.instance;
    }

    get<K extends keyof ConfigOptions>(key: K): Required<ConfigOptions>[K] {
        return this.config[key];
    }

    set<K extends keyof ConfigOptions>(key: K, value: Required<ConfigOptions>[K]): void {
        this.config[key] = value;
    }

    update(options: Partial<ConfigOptions>): void {
        this.config = {
            ...this.config,
            ...options,
            security: { ...this.config.security, ...options.security },
            rateLimit: { ...this.config.rateLimit, ...options.rateLimit },
            logging: { ...this.config.logging, ...options.logging }
        };
    }

    isDevelopment(): boolean {
        return this.config.environment === 'development';
    }

    isProduction(): boolean {
        return this.config.environment === 'production';
    }

    isTest(): boolean {
        return this.config.environment === 'test';
    }
} 