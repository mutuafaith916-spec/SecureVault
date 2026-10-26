export const requestBodyLimits = Object.freeze({
  json: '950kb',
  urlEncoded: '10kb',
})

export const apiRateLimit = Object.freeze({
  windowMs: 15 * 60 * 1000,
  limit: 100,
})

export const fileUploadRateLimit = Object.freeze({
  windowMs: 15 * 60 * 1000,
  limit: 10,
})

export const allowedCorsMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const
