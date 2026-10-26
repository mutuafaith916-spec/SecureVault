import { HttpError } from '../types/http.js'

const allowedMimeTypes: Readonly<Record<string, readonly string[]>> = {
  '.csv': ['text/csv', 'text/plain', 'application/vnd.ms-excel'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  '.gif': ['image/gif'],
  '.jpeg': ['image/jpeg'],
  '.jpg': ['image/jpeg'],
  '.pdf': ['application/pdf'],
  '.png': ['image/png'],
  '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  '.txt': ['text/plain'],
  '.webp': ['image/webp'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
}

const genericMimeType = 'application/octet-stream'

export function validateUploadFile(
  originalName: string,
  mimeType: string,
  contents: Buffer,
): void {
  const extension = originalName.slice(originalName.lastIndexOf('.')).toLowerCase()
  const acceptedMimeTypes = allowedMimeTypes[extension]
  if (!acceptedMimeTypes) {
    throw new HttpError(400, 'This file type is not supported.')
  }

  const normalizedMimeType = mimeType.toLowerCase()
  if (
    normalizedMimeType !== genericMimeType &&
    !acceptedMimeTypes.includes(normalizedMimeType)
  ) {
    throw new HttpError(400, 'The file type does not match its extension.')
  }

  if (!matchesFileSignature(extension, contents)) {
    throw new HttpError(400, 'The file content does not match its declared type.')
  }
}

function matchesFileSignature(extension: string, contents: Buffer): boolean {
  switch (extension) {
    case '.pdf':
      return contents.subarray(0, 5).toString('ascii') === '%PDF-'
    case '.png':
      return contents.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    case '.jpg':
    case '.jpeg':
      return contents.length >= 3 && contents[0] === 0xff && contents[1] === 0xd8 && contents[2] === 0xff
    case '.gif':
      return ['GIF87a', 'GIF89a'].includes(contents.subarray(0, 6).toString('ascii'))
    case '.webp':
      return contents.length >= 12 &&
        contents.subarray(0, 4).toString('ascii') === 'RIFF' &&
        contents.subarray(8, 12).toString('ascii') === 'WEBP'
    case '.docx':
    case '.pptx':
    case '.xlsx':
      return contents.length >= 4 &&
        contents[0] === 0x50 && contents[1] === 0x4b &&
        contents[2] === 0x03 && contents[3] === 0x04
    case '.txt':
    case '.csv':
      return isValidUtf8Text(contents)
    default:
      return false
  }
}

function isValidUtf8Text(contents: Buffer): boolean {
  if (contents.includes(0)) {
    return false
  }
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(contents)
    return true
  } catch {
    return false
  }
}
