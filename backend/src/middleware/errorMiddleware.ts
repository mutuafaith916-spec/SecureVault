import type { ErrorRequestHandler, RequestHandler } from 'express'
import { HttpError } from '../types/http.js'
import { logger } from '../utils/logger.js'

export const notFoundMiddleware: RequestHandler = (_request, response) => {
  response.status(404).json({
    success: false,
    message: 'Route not found',
  })
}

function isBodyParserError(error: unknown, type: string): boolean {
  if (typeof error !== 'object' || error === null || !('type' in error)) {
    return false
  }
  return error.type === type
}

export const errorMiddleware: ErrorRequestHandler = (error: unknown, request, response, _next) => {
  if (error instanceof HttpError) {
    if (error.statusCode === 400 || error.statusCode === 401 || error.statusCode === 403) {
      logger.warn(
        {
          event: 'security.request_rejected',
          statusCode: error.statusCode,
          method: request.method,
          path: request.path,
          ipAddress: request.ip,
        },
        'Request failed validation or authorization',
      )
    }
    response.status(error.statusCode).json({
      success: false,
      message: error.message,
    })
    return
  }

  if (isBodyParserError(error, 'entity.too.large')) {
    logger.warn(
      { event: 'security.request_body_too_large', method: request.method, path: request.path, ipAddress: request.ip },
      'Rejected oversized request body',
    )
    response.status(413).json({
      success: false,
      message: 'Request body is too large',
    })
    return
  }

  if (isBodyParserError(error, 'entity.parse.failed')) {
    logger.warn(
      { event: 'security.invalid_json', method: request.method, path: request.path, ipAddress: request.ip },
      'Rejected malformed JSON request body',
    )
    response.status(400).json({
      success: false,
      message: 'Invalid JSON request body',
    })
    return
  }

  logger.error({ err: error }, 'Unhandled API error')
  response.status(500).json({
    success: false,
    message: 'An unexpected error occurred',
  })
}
