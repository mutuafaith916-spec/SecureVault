import type { Request, RequestHandler } from 'express'
import jwt from 'jsonwebtoken'
import type { DataSource } from 'typeorm'
import { User } from '../entities/User.js'
import type { EnvironmentConfig } from '../config/environment.js'
import { HttpError } from '../types/http.js'
import { accessCookieName, getRequestCookie } from '../utils/authCookies.js'

export interface AuthenticatedUser {
  id: string
  role: 'USER' | 'ADMIN'
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser
}

interface AccessTokenPayload {
  sub: string
  role: 'USER' | 'ADMIN'
  tokenType: 'access'
  authVersion: number
}

export function createAuthMiddleware(
  environment: EnvironmentConfig,
  dataSource: DataSource,
): RequestHandler {
  return async (request, _response, next) => {
    if (!environment.jwtAccessSecret) {
      next(new HttpError(503, 'Authentication is not configured yet.'))
      return
    }

    let payload: jwt.JwtPayload & Partial<AccessTokenPayload>
    try {
      const authorization = request.headers.authorization
      const token = getRequestCookie(request, accessCookieName) ??
        (authorization?.startsWith('Bearer ') ? authorization.slice('Bearer '.length).trim() : '')
      if (!token) {
        throw new Error('Missing access token')
      }

      payload = jwt.verify(
        token,
        environment.jwtAccessSecret,
      ) as jwt.JwtPayload & Partial<AccessTokenPayload>

      if (
        typeof payload.sub !== 'string' ||
        !payload.sub ||
        (payload.role !== 'USER' && payload.role !== 'ADMIN') ||
        payload.tokenType !== 'access' ||
        typeof payload.authVersion !== 'number'
      ) {
        throw new Error('Invalid access token payload')
      }
    } catch {
      next(new HttpError(401, 'Your session is invalid or expired. Please log in again.'))
      return
    }

    try {
      const user = await dataSource.getRepository(User).findOne({
        where: { id: payload.sub },
        select: { id: true, role: true, authVersion: true },
      })
      if (!user || user.role !== payload.role || user.authVersion !== payload.authVersion) {
        next(new HttpError(401, 'Your session is invalid or expired. Please log in again.'))
        return
      }
      ;(request as AuthenticatedRequest).user = { id: user.id, role: user.role }
      next()
    } catch (error) {
      next(error)
    }
  }
}
