import type { Request, Response } from 'express'

export const accessCookieName = 'securevault_access'
export const refreshCookieName = 'securevault_refresh'
const accessCookieLifetimeMs = 15 * 60 * 1000

export function getRequestCookie(request: Request, name: string): string | undefined {
  const cookieHeader = request.headers.cookie
  if (!cookieHeader) {
    return undefined
  }

  const cookie = cookieHeader.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
  if (!cookie) {
    return undefined
  }

  try {
    return decodeURIComponent(cookie.slice(name.length + 1))
  } catch {
    return undefined
  }
}

export function setSessionCookies(
  response: Response,
  accessToken: string,
  refreshToken: string,
  secure: boolean,
  persistent: boolean,
  refreshExpiresAt: Date,
): void {
  const commonOptions = {
    httpOnly: true,
    secure,
    sameSite: 'strict' as const,
  }
  response.cookie(accessCookieName, accessToken, {
    ...commonOptions,
    path: '/api/v1',
    maxAge: accessCookieLifetimeMs,
  })
  response.cookie(refreshCookieName, refreshToken, {
    ...commonOptions,
    path: '/api/v1/auth',
    ...(persistent ? { maxAge: Math.max(0, refreshExpiresAt.getTime() - Date.now()) } : {}),
  })
}

export function clearSessionCookies(response: Response, secure: boolean): void {
  const commonOptions = {
    httpOnly: true,
    secure,
    sameSite: 'strict' as const,
  }
  response.clearCookie(accessCookieName, { ...commonOptions, path: '/api/v1' })
  response.clearCookie(refreshCookieName, { ...commonOptions, path: '/api/v1/auth' })
}
