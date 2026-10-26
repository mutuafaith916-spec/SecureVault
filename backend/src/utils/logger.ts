import pino from 'pino'

export const logger = pino({
  level: 'info',
  base: { service: 'securevault-api' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      'password',
      'req.headers.authorization',
      'req.headers.cookie',
      'jwtAccessSecret',
      'jwtRefreshSecret',
      'encryptionMasterKey',
    ],
    censor: '[REDACTED]',
  },
})
