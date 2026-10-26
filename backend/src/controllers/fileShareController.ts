import type { Request, RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import { AuditAction } from '../entities/AuditLog.js'
import { FileEntity } from '../entities/File.js'
import { FileShare, FileSharePermission } from '../entities/FileShare.js'
import { User } from '../entities/User.js'
import type { AuthenticatedRequest } from '../middleware/authMiddleware.js'
import { writeAuditLog } from '../services/auditLog.service.js'
import { HttpError } from '../types/http.js'

function getUserId(request: Request): string {
  const userId = (request as AuthenticatedRequest).user?.id
  if (!userId) {
    throw new HttpError(401, 'Please log in to manage file sharing.')
  }
  return userId
}

function getFileId(request: Request): string {
  const fileId = request.params.id
  if (typeof fileId !== 'string' || !fileId) {
    throw new HttpError(400, 'A valid file identifier is required.')
  }
  return fileId
}

function parseShareBody(body: unknown): {
  email: string
  permission: FileSharePermission
  expiresAt: Date | null
} {
  if (typeof body !== 'object' || body === null) {
    throw new HttpError(400, 'Provide the recipient email and permission.')
  }
  const { email, permission, expiresAt } = body as Record<string, unknown>
  if (
    typeof email !== 'string' ||
    email.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  ) {
    throw new HttpError(400, 'Please provide a valid recipient email address.')
  }
  if (permission !== FileSharePermission.VIEW && permission !== FileSharePermission.DOWNLOAD) {
    throw new HttpError(400, 'Permission must be VIEW or DOWNLOAD.')
  }
  if (expiresAt === undefined || expiresAt === null || expiresAt === '') {
    return { email: email.trim().toLowerCase(), permission, expiresAt: null }
  }
  if (typeof expiresAt !== 'string') {
    throw new HttpError(400, 'The share expiry date is invalid.')
  }
  const expiry = new Date(expiresAt)
  if (!Number.isFinite(expiry.getTime()) || expiry <= new Date()) {
    throw new HttpError(400, 'The share expiry must be a valid future date.')
  }
  return { email: email.trim().toLowerCase(), permission, expiresAt: expiry }
}

export function createFileShareController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const ownerId = getUserId(request)
    const fileId = getFileId(request)
    const { email, permission, expiresAt } = parseShareBody(request.body)

    const result = await dataSource.transaction(async (manager) => {
      const files = manager.getRepository(FileEntity)
      const file = await files.findOne({
        where: { id: fileId, ownerId },
        lock: { mode: 'pessimistic_write' },
      })
      if (!file) {
        throw new HttpError(404, 'The file could not be found.')
      }

      const recipient = await manager.getRepository(User).findOneBy({ email })
      if (!recipient) {
        throw new HttpError(404, 'No SecureVault account was found for that email.')
      }
      if (recipient.id === ownerId) {
        throw new HttpError(400, 'You already have access to your own file.')
      }

      const shares = manager.getRepository(FileShare)
      const existingShare = await shares.findOneBy({ fileId, sharedWith: recipient.id })
      const share = existingShare
        ? shares.merge(existingShare, { sharedBy: ownerId, permission, expiresAt })
        : shares.create({ fileId, sharedBy: ownerId, sharedWith: recipient.id, permission, expiresAt })
      const savedShare = await shares.save(share)
      await writeAuditLog(manager, request, AuditAction.FILE_SHARED, ownerId, fileId)
      return savedShare
    })

    response.status(200).json({
      success: true,
      message: 'File access was shared successfully.',
      share: {
        id: result.id,
        email,
        permission: result.permission,
        expiresAt: result.expiresAt,
        createdAt: result.createdAt,
      },
    })
  }
}

export function createListFileSharesController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const ownerId = getUserId(request)
    const fileId = getFileId(request)
    const file = await dataSource.getRepository(FileEntity).findOneBy({ id: fileId, ownerId })
    if (!file) {
      throw new HttpError(404, 'The file could not be found.')
    }

    const shares = await dataSource.getRepository(FileShare).find({
      where: { fileId },
      order: { createdAt: 'DESC' },
      relations: { sharedWithUser: true },
      select: {
        id: true,
        permission: true,
        expiresAt: true,
        createdAt: true,
        sharedWithUser: { email: true, fullName: true },
      },
    })
    response.status(200).json({
      success: true,
      shares: shares.map((share) => ({
        id: share.id,
        email: share.sharedWithUser.email,
        fullName: share.sharedWithUser.fullName,
        permission: share.permission,
        expiresAt: share.expiresAt,
        createdAt: share.createdAt,
        expired: share.expiresAt !== null && share.expiresAt <= new Date(),
      })),
    })
  }
}

export function createRevokeFileShareController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const ownerId = getUserId(request)
    const fileId = getFileId(request)
    const shareId = request.params.shareId
    if (typeof shareId !== 'string' || !shareId) {
      throw new HttpError(400, 'A valid share identifier is required.')
    }

    await dataSource.transaction(async (manager) => {
      const file = await manager.getRepository(FileEntity).findOneBy({ id: fileId, ownerId })
      if (!file) {
        throw new HttpError(404, 'The file could not be found.')
      }
      const share = await manager.getRepository(FileShare).findOneBy({ id: shareId, fileId })
      if (!share) {
        throw new HttpError(404, 'The file share could not be found.')
      }
      await manager.getRepository(FileShare).delete({ id: share.id })
      await writeAuditLog(manager, request, AuditAction.SHARE_REVOKED, ownerId, fileId)
    })

    response.status(200).json({ success: true, message: 'File access was revoked.' })
  }
}
