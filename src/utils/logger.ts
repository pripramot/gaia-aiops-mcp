import winston from 'winston';
import path from 'node:path';
import fs from 'node:fs';

const LOG_DIR = process.env['LOG_DIR'] ?? './logs';

// Ensure log directory exists before creating transports
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

export const logger = winston.createLogger({
  level: process.env['LOG_LEVEL'] ?? 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  defaultMeta: { service: 'gtsalpha-mcp' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...rest }) => {
          // Drop the "service" key from every console line to keep it clean
          const { service: _service, ...extra } = rest as Record<string, unknown>;
          const extraStr = Object.keys(extra).length
            ? `  ${JSON.stringify(extra)}`
            : '';
          return `${String(timestamp)} [${String(level)}] ${String(message)}${extraStr}`;
        }),
      ),
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'error.log'),
      level:    'error',
      maxsize:  10_485_760,   // 10 MB
      maxFiles: 10,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'combined.log'),
      maxsize:  10_485_760,
      maxFiles: 30,
    }),
  ],
});
