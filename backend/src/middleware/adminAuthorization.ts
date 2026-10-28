import type { Request } from 'express'
import { UserRole } from '../entities/User.js'
import type { AuthenticatedRequest } from './authMiddleware.js'
import { HttpError } from '../types/http.js'

export function requireAdminId(request: Request): string {
  const authenticatedUser = (request as AuthenticatedRequest).user
  if (!authenticatedUser) {
    throw new HttpError(401, 'Please sign in to continue.')
  }
  if (authenticatedUser.role !== UserRole.ADMIN) {
    throw new HttpError(403, 'Administrator access is required.')
  }
  return authenticatedUser.id
}
