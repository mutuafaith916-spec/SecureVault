import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import { User, UserRole } from '../entities/User.js'
import type { AuthenticatedRequest } from '../middleware/authMiddleware.js'
import { AuditLog } from '../entities/AuditLog.js'
import { HttpError } from '../types/http.js'

const auditHistoryLimit = 100

export function createListAuditLogsController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const authenticatedUser = (request as AuthenticatedRequest).user
    if (!authenticatedUser) {
      throw new HttpError(401, 'Please log in to view security activity.')
    }

    const actor = await dataSource.getRepository(User).findOne({
      where: { id: authenticatedUser.id },
      select: { id: true, role: true },
    })
    if (!actor) {
      throw new HttpError(401, 'Your session is invalid. Please sign in again.')
    }

    const isAdmin = actor.role === UserRole.ADMIN
    const auditLogs = await dataSource.getRepository(AuditLog).find({
      where: isAdmin ? {} : { userId: authenticatedUser.id },
      order: { createdAt: 'DESC' },
      take: auditHistoryLimit,
      relations: { user: true, file: true },
      select: {
        id: true,
        userId: true,
        action: true,
        fileId: true,
        ipAddress: true,
        userAgent: true,
        details: true,
        createdAt: true,
        user: { id: true, fullName: true, email: true },
        file: { id: true, originalName: true },
      },
    })

    response.status(200).json({
      success: true,
      auditLogs: auditLogs.map((log) => ({
        id: log.id,
        userId: log.userId,
        actor: log.user ? { fullName: log.user.fullName, email: log.user.email } : null,
        action: log.action,
        file: log.file ? { id: log.file.id, originalName: log.file.originalName } : null,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        details: log.details,
        createdAt: log.createdAt,
      })),
    })
  }
}
