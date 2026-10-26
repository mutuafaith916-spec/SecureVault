import nodemailer from 'nodemailer'
import type { EnvironmentConfig } from '../config/environment.js'
import { logger } from '../utils/logger.js'

export function dispatchSecurityAlert(
  environment: EnvironmentConfig,
  subject: string,
  message: string,
  context: Record<string, string | number | null>,
): void {
  if (environment.securityAlertEmails.length === 0) {
    return
  }

  setImmediate(() => {
    void deliverSecurityAlert(environment, subject, message, context).catch((error: unknown) => {
      logger.error(
        {
          event: 'security.alert_delivery_failed',
          errorType: error instanceof Error ? error.name : 'UnknownError',
          alertType: subject,
        },
        'Security alert could not be delivered',
      )
    })
  })
}

async function deliverSecurityAlert(
  environment: EnvironmentConfig,
  subject: string,
  message: string,
  context: Record<string, string | number | null>,
): Promise<void> {
  const { smtpHost, smtpPort, smtpUser, smtpPassword, smtpFrom } = environment
  if (!smtpHost || !smtpPort || !smtpUser || !smtpPassword || !smtpFrom) {
    throw new Error('SMTP configuration is unavailable for security alert delivery')
  }

  const transport = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpPort === 465,
    requireTLS: smtpPort !== 465,
    auth: { user: smtpUser, pass: smtpPassword },
  })
  try {
    await transport.sendMail({
      from: smtpFrom,
      to: [...environment.securityAlertEmails],
      subject: `[SecureVault security] ${subject}`,
      text: [
        message,
        '',
        ...Object.entries(context).map(([key, value]) => `${key}: ${value ?? 'unknown'}`),
      ].join('\n'),
    })
  } finally {
    transport.close()
  }
}
