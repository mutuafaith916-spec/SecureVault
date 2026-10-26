import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { Request, Response } from 'express'
import {
  accessCookieName,
  clearSessionCookies,
  getRequestCookie,
  refreshCookieName,
  setSessionCookies,
} from '../src/utils/authCookies.js'

test('session cookie parser reads encoded cookie values and ignores malformed encoding', () => {
  const request = {
    headers: { cookie: `${accessCookieName}=access%2Etoken; ${refreshCookieName}=bad%ZZ` },
  } as Request

  assert.equal(getRequestCookie(request, accessCookieName), 'access.token')
  assert.equal(getRequestCookie(request, refreshCookieName), undefined)
})

test('session credentials are HttpOnly, strict same-site cookies and only persistent refresh cookies get Max-Age', () => {
  const cookies: Array<{ name: string; value: string; options: Record<string, unknown> }> = []
  const response = {
    cookie(name: string, value: string, options: Record<string, unknown>) {
      cookies.push({ name, value, options })
      return this
    },
  } as unknown as Response
  const expiresAt = new Date(Date.now() + 60_000)

  setSessionCookies(response, 'access', 'refresh', true, false, expiresAt)
  assert.equal(cookies.length, 2)
  assert.equal(cookies[0].options.httpOnly, true)
  assert.equal(cookies[0].options.secure, true)
  assert.equal(cookies[0].options.sameSite, 'strict')
  assert.equal(cookies[0].options.path, '/api/v1')
  assert.equal(cookies[1].options.path, '/api/v1/auth')
  assert.equal(cookies[1].options.maxAge, undefined)

  cookies.length = 0
  setSessionCookies(response, 'access', 'refresh', false, true, expiresAt)
  assert.ok(typeof cookies[1].options.maxAge === 'number')
})

test('logout clears access and refresh cookies using their original paths', () => {
  const cleared: Array<{ name: string; options: Record<string, unknown> }> = []
  const response = {
    clearCookie(name: string, options: Record<string, unknown>) {
      cleared.push({ name, options })
      return this
    },
  } as unknown as Response

  clearSessionCookies(response, true)
  assert.deepEqual(cleared.map(({ name, options }) => [name, options.path]), [
    [accessCookieName, '/api/v1'],
    [refreshCookieName, '/api/v1/auth'],
  ])
})
