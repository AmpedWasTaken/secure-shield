const winston = require('winston');
const path = require('path');
const fs = require('fs');

class SecurityLogger {
    constructor(options = {}) {
        this.options = {
            enabled: true,
            logLevel: 'info',
            logPath: './logs/security.log',
            maxSize: 10 * 1024 * 1024, // 10MB
            maxFiles: 5,
            format: 'json',
            ...options
        };

        // Create logs directory if it doesn't exist
        const logDir = path.dirname(this.options.logPath);
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }

        this.logger = winston.createLogger({
            level: this.options.logLevel,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({
                    filename: this.options.logPath,
                    maxsize: this.options.maxSize,
                    maxFiles: this.options.maxFiles,
                    tailable: true
                })
            ]
        });

        // Add console transport in development
        if (process.env.NODE_ENV !== 'production') {
            this.logger.add(new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
            }));
        }
    }

    log(level, message, meta = {}) {
        if (!this.options.enabled) return;

        this.logger.log({
            level,
            message,
            ...meta,
            timestamp: new Date().toISOString()
        });
    }

    info(message, meta = {}) {
        this.log('info', message, meta);
    }

    warn(message, meta = {}) {
        this.log('warn', message, meta);
    }

    error(message, meta = {}) {
        this.log('error', message, meta);
    }

    generateReport(startDate, endDate) {
        // Implementation for generating security reports
        return new Promise((resolve, reject) => {
            const report = {
                period: {
                    start: startDate,
                    end: endDate
                },
                summary: {
                    totalThreats: 0,
                    threatsByType: {},
                    threatsBySeverity: {},
                    topAttackers: {},
                    blockedRequests: 0
                },
                details: []
            };

            const stream = fs.createReadStream(this.options.logPath, { encoding: 'utf8' });
            const rl = require('readline').createInterface({
                input: stream,
                crlfDelay: Infinity
            });

            rl.on('line', (line) => {
                try {
                    const log = JSON.parse(line);
                    if (log.timestamp >= startDate && log.timestamp <= endDate) {
                        this.processLogEntry(log, report);
                    }
                } catch (err) {
                    console.error('Error processing log line:', err);
                }
            });

            rl.on('close', () => {
                resolve(report);
            });

            rl.on('error', (err) => {
                reject(err);
            });
        });
    }

    processLogEntry(log, report) {
        if (log.threat) {
            report.summary.totalThreats++;
            
            // Count threats by type
            report.summary.threatsByType[log.threat.type] = 
                (report.summary.threatsByType[log.threat.type] || 0) + 1;
            
            // Count threats by severity
            report.summary.threatsBySeverity[log.threat.severity] = 
                (report.summary.threatsBySeverity[log.threat.severity] || 0) + 1;
            
            // Track attackers
            if (log.ip) {
                report.summary.topAttackers[log.ip] = 
                    (report.summary.topAttackers[log.ip] || 0) + 1;
            }

            report.details.push(log);
        }

        if (log.blocked) {
            report.summary.blockedRequests++;
        }
    }
}

module.exports = SecurityLogger; 