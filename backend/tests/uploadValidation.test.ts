import assert from 'node:assert/strict'
import { test } from 'node:test'
import { validateUploadFile } from '../src/services/uploadValidation.js'

test('upload validation accepts supported files with matching content signatures', () => {
  validateUploadFile('report.pdf', 'application/pdf', Buffer.from('%PDF-1.7 document'))
  validateUploadFile('notes.txt', 'text/plain', Buffer.from('hello SecureVault'))
  validateUploadFile('photo.png', 'image/png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
  validateUploadFile('book.xlsx', 'application/octet-stream', Buffer.from([0x50, 0x4b, 0x03, 0x04]))
})

test('upload validation rejects unsupported extensions, mismatched MIME types, and fake signatures', () => {
  assert.throws(
    () => validateUploadFile('payload.exe', 'application/octet-stream', Buffer.from('MZ')),
    /file type is not supported/,
  )
  assert.throws(
    () => validateUploadFile('photo.png', 'image/jpeg', Buffer.from('not a png')),
    /file type does not match its extension/,
  )
  assert.throws(
    () => validateUploadFile('document.pdf', 'application/pdf', Buffer.from('not a pdf')),
    /content does not match its declared type/,
  )
})

test('text uploads reject binary and malformed UTF-8 content', () => {
  assert.throws(
    () => validateUploadFile('data.csv', 'text/csv', Buffer.from([0x61, 0x00, 0x62])),
    /content does not match its declared type/,
  )
  assert.throws(
    () => validateUploadFile('data.txt', 'text/plain', Buffer.from([0xff, 0xfe])),
    /content does not match its declared type/,
  )
})
