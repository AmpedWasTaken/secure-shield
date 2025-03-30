import { LogOptions, LogLevel, LogMessage, LogContext, LogEntry } from '../types';
import * as fs from 'fs';
import * as path from 'path';

export class Logger {
    private options: Required<LogOptions>;
    private logStream: fs.WriteStream | null = null;

    constructor(options: LogOptions = {}) {
        this.options = {
            enabled: true,
            logLevel: 'info',
            logPath: './logs/security.log',
            format: 'json',
            ...options
        };

        if (this.options.enabled && this.options.logPath) {
            this.initializeLogStream();
        }
    }

    private initializeLogStream(): void {
        try {
            const logDir = path.dirname(this.options.logPath);
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }
            this.logStream = fs.createWriteStream(this.options.logPath, { flags: 'a' });
        } catch (error) {
            console.error('Failed to initialize log stream:', error);
        }
    }

    private shouldLog(level: LogLevel): boolean {
        const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
        const configuredLevel = levels.indexOf(this.options.logLevel);
        const messageLevel = levels.indexOf(level);
        return this.options.enabled && messageLevel >= configuredLevel;
    }

    private formatMessage(level: LogLevel, message: LogMessage, context?: LogContext): LogEntry {
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level,
            message: message instanceof Error ? message.message : message,
            context: context || {}
        };

        if (message instanceof Error) {
            entry.context = {
                ...entry.context,
                stack: message.stack,
                name: message.name
            };
        }

        return entry;
    }

    private write(entry: LogEntry): void {
        if (!this.options.enabled) return;

        const logMessage = JSON.stringify(entry) + '\n';

        if (this.logStream) {
            this.logStream.write(logMessage);
        }

        // Also log to console in development
        if (process.env.NODE_ENV !== 'production') {
            const consoleMethod = entry.level === 'error' ? 'error' : 'log';
            console[consoleMethod](logMessage);
        }
    }

    debug(message: LogMessage, context?: LogContext): void {
        if (this.shouldLog('debug')) {
            this.write(this.formatMessage('debug', message, context));
        }
    }

    info(message: LogMessage, context?: LogContext): void {
        if (this.shouldLog('info')) {
            this.write(this.formatMessage('info', message, context));
        }
    }

    warn(message: LogMessage, context?: LogContext): void {
        if (this.shouldLog('warn')) {
            this.write(this.formatMessage('warn', message, context));
        }
    }

    error(message: LogMessage, context?: LogContext): void {
        if (this.shouldLog('error')) {
            this.write(this.formatMessage('error', message, context));
        }
    }

    close(): void {
        if (this.logStream) {
            this.logStream.end();
            this.logStream = null;
        }
    }
}

export default Logger; 