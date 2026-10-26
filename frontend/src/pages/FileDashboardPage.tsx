import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

interface VaultFile {
  id: string
  originalName: string
  fileSize: string
  mimeType: string
  createdAt: string
  access: 'OWNER' | 'SHARED'
  permission: 'VIEW' | 'DOWNLOAD'
}

interface FileShareGrant {
  id: string
  email: string
  fullName: string
  permission: 'VIEW' | 'DOWNLOAD'
  expiresAt: string | null
  expired: boolean
}

interface FileBackup {
  id: string
  status: 'COMPLETED'
  createdAt: string
}

interface DeletedFile {
  id: string
  originalName: string
  fileSize: string
  deletedAt: string
  backupId: string | null
}

interface AuditEvent {
  id: string
  action: string
  createdAt: string
  actor: { fullName: string; email: string } | null
  file: { id: string; originalName: string } | null
}

interface ApiResult {
  success: boolean
  message?: string
  files?: VaultFile[]
  backups?: FileBackup[]
  deletedFiles?: DeletedFile[]
  shares?: FileShareGrant[]
  auditLogs?: AuditEvent[]
  share?: FileShareGrant
}

type Notice = { type: 'success' | 'error'; message: string }

async function fetchWithSession(url: string, init: RequestInit = {}): Promise<Response> {
  const request = () => fetch(url, { ...init, credentials: 'include' })
  let response = await request()
  if (response.status === 401) {
    const refresh = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'include',
    })
    if (refresh.ok) {
      response = await request()
    }
  }
  return response
}

function encodeBase64(data: ArrayBuffer): string {
  const bytes = new Uint8Array(data)
  const chunkSize = 0x8000
  let binary = ''
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize))
  }
  return btoa(binary)
}

function formatFileSize(fileSize: string): string {
  const bytes = Number(fileSize)
  if (!Number.isFinite(bytes) || bytes < 0) {
    return 'Size unavailable'
  }
  if (bytes < 1024) {
    return `${bytes} B`
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function FileDashboardPage() {
  const navigate = useNavigate()
  const fileInput = useRef<HTMLInputElement>(null)
  const [files, setFiles] = useState<VaultFile[]>([])
  const [fileSearch, setFileSearch] = useState('')
  const [fileTypeFilter, setFileTypeFilter] = useState('all')
  const [fileSort, setFileSort] = useState<'newest' | 'oldest' | 'name' | 'size'>('newest')
  const [isLoading, setIsLoading] = useState(true)
  const [busyFileId, setBusyFileId] = useState<string | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [sharingFile, setSharingFile] = useState<VaultFile | null>(null)
  const [shares, setShares] = useState<FileShareGrant[]>([])
  const [shareEmail, setShareEmail] = useState('')
  const [sharePermission, setSharePermission] = useState<'VIEW' | 'DOWNLOAD'>('VIEW')
  const [shareExpiry, setShareExpiry] = useState('')
  const [isLoadingShares, setIsLoadingShares] = useState(false)
  const [isSavingShare, setIsSavingShare] = useState(false)
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([])
  const [deletedFiles, setDeletedFiles] = useState<DeletedFile[]>([])
  const ownedFileCount = files.filter((file) => file.access === 'OWNER').length
  const sharedWithMeCount = files.filter((file) => file.access === 'SHARED').length
  const storageUsed = files
    .filter((file) => file.access === 'OWNER')
    .reduce((total, file) => total + (Number(file.fileSize) || 0), 0)
  const filteredFiles = files.filter((file) => {
    const matchesSearch = file.originalName
      .toLowerCase()
      .includes(fileSearch.trim().toLowerCase())

    const extension = file.originalName.split('.').pop()?.toLowerCase() ?? ''

    const imageTypes = ['gif', 'jpeg', 'jpg', 'png', 'webp']
    const documentTypes = ['doc', 'docx', 'pdf', 'ppt', 'pptx', 'txt']
    const spreadsheetTypes = ['csv', 'xls', 'xlsx']

    const matchesType =
      fileTypeFilter === 'all' ||
      (fileTypeFilter === 'images' && imageTypes.includes(extension)) ||
      (fileTypeFilter === 'documents' && documentTypes.includes(extension)) ||
      (fileTypeFilter === 'spreadsheets' && spreadsheetTypes.includes(extension)) ||
      (fileTypeFilter === 'other' &&
        !imageTypes.includes(extension) &&
        !documentTypes.includes(extension) &&
        !spreadsheetTypes.includes(extension))

    return matchesSearch && matchesType
  })
  const sortedFiles = [...filteredFiles].sort((first, second) => {
    if (fileSort === 'name') {
      return first.originalName.localeCompare(second.originalName, undefined, { sensitivity: 'base' })
    }
    if (fileSort === 'size') {
      return Number(first.fileSize) - Number(second.fileSize)
    }
    const dateOrder = new Date(first.createdAt).getTime() - new Date(second.createdAt).getTime()
    return fileSort === 'oldest' ? dateOrder : -dateOrder
  })

  const loadDeletedFiles = useCallback(async (): Promise<void> => {
    try {
      const response = await fetchWithSession('/api/v1/files/trash')
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success || !result.deletedFiles) {
        setNotice({
          type: 'error',
          message: result.message || 'Recently deleted files could not be loaded.',
        })
        return
      }
      setDeletedFiles(result.deletedFiles)
    } catch {
      setNotice({
        type: 'error',
        message: 'Recently deleted files could not be loaded. Check your connection.',
      })
    }
  }, [navigate])

  useEffect(() => {
    let isMounted = true
    async function loadInitialFiles() {
      try {
        const response = await fetchWithSession('/api/v1/files')
        if (response.status === 401) {
          navigate('/login', { replace: true })
          return
        }
        const result = await response.json() as ApiResult
        if (!isMounted) {
          return
        }
        if (!response.ok || !result.success || !result.files) {
          setNotice({
            type: 'error',
            message: result.message || 'Your files could not be loaded. Please try again.',
          })
          return
        }
        setFiles(result.files)
        await loadDeletedFiles()
        if (!isMounted) {
          return
        }
        const auditResponse = await fetchWithSession('/api/v1/audit')
        if (auditResponse.status === 401) {
          navigate('/login', { replace: true })
          return
        }
        const auditResult = await auditResponse.json() as ApiResult
        if (!isMounted) {
          return
        }
        if (auditResponse.ok && auditResult.success && auditResult.auditLogs) {
          setAuditEvents(auditResult.auditLogs)
        } else {
          setNotice({
            type: 'error',
            message: auditResult.message || 'Security activity could not be loaded. Please refresh to try again.',
          })
        }
      } catch {
        if (isMounted) {
          setNotice({
            type: 'error',
            message: 'We could not reach SecureVault. Check your connection and try again.',
          })
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }
    void loadInitialFiles()
    return () => {
      isMounted = false
    }
  }, [loadDeletedFiles, navigate])

  const loadFiles = useCallback(async (): Promise<boolean> => {
    try {
      const response = await fetchWithSession('/api/v1/files')
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return false
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success || !result.files) {
        setNotice({
          type: 'error',
          message: result.message || 'Your files could not be loaded. Please try again.',
        })
        return false
      }
      setFiles(result.files)
      return true
    } catch {
      setNotice({
        type: 'error',
        message: 'We could not reach SecureVault. Check your connection and try again.',
      })
      return false
    } finally {
      setIsLoading(false)
    }
  }, [navigate])

  const loadAuditEvents = useCallback(async (): Promise<void> => {
    try {
      const response = await fetchWithSession('/api/v1/audit')
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success || !result.auditLogs) {
        setNotice({
          type: 'error',
          message: result.message || 'Security activity could not be loaded. Please refresh to try again.',
        })
        return
      }
      setAuditEvents(result.auditLogs)
    } catch {
      setNotice({
        type: 'error',
        message: 'Security activity could not be loaded. Please check your connection and try again.',
      })
    }
  }, [navigate])

  async function handleUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0]
    event.currentTarget.value = ''
    if (!file) {
      return
    }
    if (file.size === 0) {
      setNotice({ type: 'error', message: 'Choose a file that is not empty.' })
      return
    }
    if (file.size > 700 * 1024) {
      setNotice({ type: 'error', message: 'Files must be 700 KB or smaller.' })
      return
    }

    setIsUploading(true)
    setNotice(null)
    try {
      const contentBase64 = encodeBase64(await file.arrayBuffer())
      const response = await fetchWithSession('/api/v1/files', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          originalName: file.name,
          mimeType: file.type || 'application/octet-stream',
          contentBase64,
        }),
      })
      const result = await response.json() as ApiResult
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      if (!response.ok || !result.success) {
        setNotice({
          type: 'error',
          message: result.message || 'The file could not be encrypted and uploaded.',
        })
        return
      }

      if (await loadFiles()) {
        setNotice({ type: 'success', message: result.message || 'File encrypted and uploaded.' })
      }
      void loadAuditEvents()
    } catch {
      setNotice({
        type: 'error',
        message: 'The file could not be uploaded. Check your connection and try again.',
      })
    } finally {
      setIsUploading(false)
    }
  }

  async function handleDownload(file: VaultFile) {
    setBusyFileId(file.id)
    setNotice(null)
    try {
      const response = await fetchWithSession(`/api/v1/files/${encodeURIComponent(file.id)}/download`)
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      if (!response.ok) {
        const result = await response.json() as ApiResult
        setNotice({
          type: 'error',
          message: result.message || `Could not download ${file.originalName}.`,
        })
        return
      }

      const objectUrl = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = objectUrl
      link.download = file.originalName
      document.body.append(link)
      link.click()
      link.remove()
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
      setNotice({ type: 'success', message: `${file.originalName} downloaded and decrypted.` })
    } catch {
      setNotice({
        type: 'error',
        message: `Could not download ${file.originalName}. Check your connection and try again.`,
      })
    } finally {
      setBusyFileId(null)
    }
  }

  async function handleRestoreBackup(file: VaultFile) {
    if (file.access !== 'OWNER') {
      setNotice({ type: 'error', message: 'Only the file owner can restore a backup.' })
      return
    }

    setBusyFileId(file.id)
    setNotice(null)
    try {
      const backupsResponse = await fetchWithSession(
        `/api/v1/files/${encodeURIComponent(file.id)}/backups`,
      )
      if (backupsResponse.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const backupsResult = await backupsResponse.json() as ApiResult
      if (!backupsResponse.ok || !backupsResult.success || !backupsResult.backups) {
        setNotice({
          type: 'error',
          message: backupsResult.message || 'The file backup could not be loaded.',
        })
        return
      }
      const backup = backupsResult.backups[0]
      if (!backup) {
        setNotice({ type: 'error', message: 'There is no completed backup available to restore.' })
        return
      }
      if (!window.confirm(`Restore the encrypted backup from ${new Date(backup.createdAt).toLocaleString()} for "${file.originalName}"?`)) {
        return
      }

      const response = await fetchWithSession(
        `/api/v1/files/${encodeURIComponent(file.id)}/backups/${encodeURIComponent(backup.id)}/restore`,
        { method: 'POST' },
      )
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({
          type: 'error',
          message: result.message || `Could not restore ${file.originalName}.`,
        })
        return
      }
      setNotice({ type: 'success', message: result.message || 'Encrypted backup restored.' })
      await loadFiles()
      await loadDeletedFiles()
      void loadAuditEvents()
    } catch {
      setNotice({
        type: 'error',
        message: `Could not restore ${file.originalName}. Check your connection and try again.`,
      })
    } finally {
      setBusyFileId(null)
    }
  }

  async function handleRestoreDeletedFile(file: DeletedFile) {
    if (!file.backupId) {
      setNotice({ type: 'error', message: 'No completed backup is available for this deleted file.' })
      return
    }
    if (!window.confirm(`Restore "${file.originalName}" from its encrypted backup?`)) {
      return
    }

    setBusyFileId(file.id)
    setNotice(null)
    try {
      const response = await fetchWithSession(
        `/api/v1/files/${encodeURIComponent(file.id)}/backups/${encodeURIComponent(file.backupId)}/restore`,
        { method: 'POST' },
      )
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({
          type: 'error',
          message: result.message || `Could not restore ${file.originalName}.`,
        })
        return
      }
      setNotice({ type: 'success', message: result.message || 'Deleted file restored.' })
      await loadFiles()
      await loadDeletedFiles()
      void loadAuditEvents()
    } catch {
      setNotice({
        type: 'error',
        message: `Could not restore ${file.originalName}. Check your connection and try again.`,
      })
    } finally {
      setBusyFileId(null)
    }
  }

  async function handleDelete(file: VaultFile) {
    if (file.access !== 'OWNER') {
      setNotice({ type: 'error', message: 'Only the file owner can delete this file.' })
      return
    }
    if (!window.confirm(`Move "${file.originalName}" to Recently deleted? You can restore it for 30 days before its files and backups are permanently deleted.`)) {
      return
    }
    setBusyFileId(file.id)
    setNotice(null)
    try {
      const response = await fetchWithSession(`/api/v1/files/${encodeURIComponent(file.id)}`, {
        method: 'DELETE',
      })
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({
          type: 'error',
          message: result.message || `Could not delete ${file.originalName}.`,
        })
        return
      }
      setFiles((currentFiles) => currentFiles.filter((currentFile) => currentFile.id !== file.id))
      void loadDeletedFiles()
      setNotice({ type: 'success', message: result.message || 'File deleted.' })
      void loadAuditEvents()
    } catch {
      setNotice({
        type: 'error',
        message: `Could not delete ${file.originalName}. Check your connection and try again.`,
      })
    } finally {
      setBusyFileId(null)
    }
  }

  async function handleExportData() {
    setIsExporting(true)
    setNotice(null)
    try {
      const response = await fetchWithSession('/api/v1/files/export')
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      if (!response.ok) {
        const result = await response.json() as ApiResult
        setNotice({ type: 'error', message: result.message || 'Your data export could not be created.' })
        return
      }
      const exportBlob = await response.blob()
      const downloadUrl = URL.createObjectURL(exportBlob)
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = 'securevault-data-export.json'
      document.body.append(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(downloadUrl)
      setNotice({ type: 'success', message: 'Your data export was downloaded.' })
      void loadAuditEvents()
    } catch {
      setNotice({ type: 'error', message: 'Could not reach SecureVault to export your data.' })
    } finally {
      setIsExporting(false)
    }
  }

  async function handleOpenShares(file: VaultFile) {
    setSharingFile(file)
    setShares([])
    setShareEmail('')
    setSharePermission('VIEW')
    setShareExpiry('')
    setIsLoadingShares(true)
    setNotice(null)
    try {
      const response = await fetchWithSession(`/api/v1/files/${encodeURIComponent(file.id)}/shares`)
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success || !result.shares) {
        setNotice({
          type: 'error',
          message: result.message || 'Sharing settings could not be loaded.',
        })
        setSharingFile(null)
        return
      }
      setShares(result.shares)
    } catch {
      setNotice({ type: 'error', message: 'Sharing settings could not be loaded. Check your connection.' })
      setSharingFile(null)
    } finally {
      setIsLoadingShares(false)
    }
  }

  async function handleShareSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!sharingFile) {
      return
    }
    setIsSavingShare(true)
    setNotice(null)
    try {
      const response = await fetchWithSession(
        `/api/v1/files/${encodeURIComponent(sharingFile.id)}/shares`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: shareEmail,
            permission: sharePermission,
            expiresAt: shareExpiry ? new Date(shareExpiry).toISOString() : null,
          }),
        },
      )
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({
          type: 'error',
          message: result.message || 'File access could not be shared.',
        })
        return
      }
      setShareEmail('')
      setShareExpiry('')
      const refreshed = await fetchWithSession(
        `/api/v1/files/${encodeURIComponent(sharingFile.id)}/shares`,
      )
      if (refreshed.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const refreshedResult = await refreshed.json() as ApiResult
      if (refreshed.ok && refreshedResult.success && refreshedResult.shares) {
        setShares(refreshedResult.shares)
        setNotice({ type: 'success', message: result.message || 'File access shared successfully.' })
        void loadAuditEvents()
      } else {
        setNotice({
          type: 'error',
          message: 'Access was shared, but the access list could not be refreshed.',
        })
      }
    } catch {
      setNotice({ type: 'error', message: 'File access could not be shared. Check your connection.' })
    } finally {
      setIsSavingShare(false)
    }
  }

  async function handleRevokeShare(share: FileShareGrant) {
    if (!sharingFile) {
      return
    }
    try {
      const response = await fetchWithSession(
        `/api/v1/files/${encodeURIComponent(sharingFile.id)}/shares/${encodeURIComponent(share.id)}`,
        { method: 'DELETE' },
      )
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({ type: 'error', message: result.message || 'File access could not be revoked.' })
        return
      }
      setShares((current) => current.filter((currentShare) => currentShare.id !== share.id))
      setNotice({ type: 'success', message: result.message || 'File access revoked.' })
      void loadAuditEvents()
    } catch {
      setNotice({ type: 'error', message: 'File access could not be revoked. Check your connection.' })
    }
  }

  async function handleLogout() {
    try {
      const response = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'include',
      })
      if (!response.ok) {
        const result = await response.json() as ApiResult
        setNotice({ type: 'error', message: result.message || 'Could not sign out. Please try again.' })
        return
      }
      navigate('/login', { replace: true })
    } catch {
      setNotice({ type: 'error', message: 'Could not reach SecureVault to sign out. Please try again.' })
    }
  }

  return (
    <main className="vault-page">
      <header className="vault-header">
        <Link className="brand" to="/" aria-label="SecureVault home">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32" fill="none">
              <path d="M16 3.5 27 8v7.1c0 7.1-4.7 11.7-11 14.4C9.7 26.8 5 22.2 5 15.1V8l11-4.5Z" />
              <path d="m11.7 16.1 2.8 2.8 6-6" />
            </svg>
          </span>
          <span>Secure<span className="brand-accent">Vault</span></span>
        </Link>
        <div className="vault-header-actions">
          <span className="vault-session-indicator"><span /> PRIVATE SESSION</span>
          <button className="vault-logout" type="button" onClick={handleLogout}>Sign out</button>
        </div>
      </header>

      <section className="vault-content">
        <div className="vault-heading">
          <div>
            <div className="section-kicker">YOUR PRIVATE SPACE</div>
            <h1>Your files, under lock.</h1>
            <p>Files are encrypted before they are saved to storage.</p>
          </div>
          <div className="vault-header-actions">
            <button
              className="vault-refresh"
              type="button"
              onClick={() => void handleExportData()}
              disabled={isExporting}
            >
              {isExporting ? 'Preparing export…' : 'Export my data'}
            </button>
            <button
              className="button vault-upload-button"
              type="button"
              onClick={() => fileInput.current?.click()}
              disabled={isUploading}
            >
              {isUploading ? 'Encrypting & uploading…' : 'Upload a file'}
              <span aria-hidden="true">↑</span>
            </button>
          </div>
          <input
            ref={fileInput}
            className="vault-file-input"
            type="file"
            accept=".csv,.docx,.gif,.jpeg,.jpg,.pdf,.png,.pptx,.txt,.webp,.xlsx"
            onChange={(event) => void handleUpload(event)}
            aria-label="Choose a file to encrypt and upload"
          />
        </div>

        {notice && (
          <p
            className={`form-feedback form-feedback-${notice.type} vault-notice`}
            role={notice.type === 'error' ? 'alert' : 'status'}
          >
            {notice.message}
          </p>
        )}
        <section className="vault-overview" aria-label="Vault overview">
          <article className="vault-overview-card">
            <span>Files you own</span>
            <strong>{ownedFileCount}</strong>
            <small>Active files in your vault</small>
          </article>
          <article className="vault-overview-card">
            <span>Shared with you</span>
            <strong>{sharedWithMeCount}</strong>
            <small>Active shares available to your account</small>
          </article>
          <article className="vault-overview-card">
            <span>Storage used</span>
            <strong>{formatFileSize(String(storageUsed))}</strong>
            <small>Owned file sizes only</small>
          </article>
          <article className="vault-overview-card">
            <span>Storage quota</span>
            <strong>Not configured</strong>
            <small>No capacity limit is configured</small>
          </article>
        </section>
        <div className="vault-file-filters">
  <label>
    <span>Search files</span>
    <input
      type="search"
      value={fileSearch}
      onChange={(event) => setFileSearch(event.target.value)}
      placeholder="Search by filename..."
      aria-label="Search files by filename"
    />
  </label>

  <label>
    <span>File type</span>
    <select
      value={fileTypeFilter}
      onChange={(event) => setFileTypeFilter(event.target.value)}
      aria-label="Filter files by type"
    >
      <option value="all">All file types</option>
      <option value="documents">Documents</option>
      <option value="images">Images</option>
      <option value="spreadsheets">Spreadsheets</option>
      <option value="other">Other files</option>
    </select>
  </label>
  <label>
    <span>Sort files</span>
    <select
      value={fileSort}
      onChange={(event) => setFileSort(event.target.value as typeof fileSort)}
      aria-label="Sort files"
    >
      <option value="newest">Newest first</option>
      <option value="oldest">Oldest first</option>
      <option value="name">Filename</option>
      <option value="size">File size</option>
    </select>
  </label>
</div>

        <div className="vault-list-heading">
          <h2>Your vault</h2>
          <button
            className="vault-refresh"
            type="button"
            onClick={() => {
              setIsLoading(true)
              setNotice(null)
              void (async () => {
                await loadFiles()
                await loadAuditEvents()
              })()
            }}
            disabled={isLoading}
          >
            Refresh
          </button>
        </div>

        {isLoading ? (
          <div className="vault-empty-state" role="status">Loading your encrypted files…</div>
        ) : filteredFiles.length === 0 ? (
          <div className="vault-empty-state">
            <span className="vault-empty-icon" aria-hidden="true">＋</span>
            <h3>{files.length === 0 ? 'Your vault is ready' : 'No matching files'}</h3>
            <p>
              {files.length === 0
                ? 'Upload a file to encrypt it and keep it in your private space.'
                : 'No files match your search or selected file type. Try adjusting your filters.'}
            </p>
            {files.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  setFileSearch('')
                  setFileTypeFilter('all')
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <div className="vault-file-list">
            {sortedFiles.map((file) => (
              <article className="vault-file-item" key={file.id}>
                <span className="vault-file-icon" aria-hidden="true">▤</span>
                <div className="vault-file-details">
                  <strong title={file.originalName}>{file.originalName}</strong>
                  <span>
                    {formatFileSize(file.fileSize)} · {file.access === 'OWNER' ? 'Encrypted' : `Shared · ${file.permission.toLowerCase()}`}
                  </span>
                </div>
                <time dateTime={file.createdAt}>
                  {new Date(file.createdAt).toLocaleDateString()}
                </time>
                <div className="vault-file-actions">
                  {file.access === 'OWNER' || file.permission === 'DOWNLOAD' ? (
                    <button
                      type="button"
                      onClick={() => void handleDownload(file)}
                      disabled={busyFileId === file.id}
                    >
                      Download
                    </button>
                  ) : (
                    <span className="vault-view-only">View only</span>
                  )}
                  {file.access === 'OWNER' && (
                    <>
                      <button
                        type="button"
                        onClick={() => void handleRestoreBackup(file)}
                        disabled={busyFileId === file.id}
                      >
                        Restore
                      </button>
                      <button type="button" onClick={() => void handleOpenShares(file)}>
                        Share
                      </button>
                      <button
                        className="vault-delete-button"
                        type="button"
                        onClick={() => void handleDelete(file)}
                        disabled={busyFileId === file.id}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}

        <section className="vault-activity" aria-labelledby="vault-trash-heading">
          <div className="vault-list-heading">
            <h2 id="vault-trash-heading">Recently deleted</h2>
          </div>
          {deletedFiles.length === 0 ? (
            <p className="vault-activity-empty">Files can be restored for 30 days. After that, encrypted copies and file metadata are permanently purged.</p>
          ) : (
            <div className="vault-file-list">
              {deletedFiles.map((file) => (
                <article className="vault-file-item" key={file.id}>
                  <span className="vault-file-icon" aria-hidden="true">▤</span>
                  <div className="vault-file-details">
                    <strong title={file.originalName}>{file.originalName}</strong>
                    <span>{formatFileSize(file.fileSize)} · Deleted {new Date(file.deletedAt).toLocaleDateString()}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleRestoreDeletedFile(file)}
                    disabled={!file.backupId || busyFileId === file.id}
                  >
                    {file.backupId ? 'Restore' : 'No backup'}
                  </button>
                </article>
              ))}
            </div>
          )}
        </section>

        <div className="vault-security-note">
          <span aria-hidden="true">✓</span>
          <p><strong>Encrypted at rest.</strong> Files are decrypted only when you download them.</p>
        </div>
        <section className="vault-encryption-details" aria-labelledby="vault-encryption-heading">
          <div>
            <div className="section-kicker">ENCRYPTION CENTRE</div>
            <h2 id="vault-encryption-heading">How your files are protected</h2>
          </div>
          <dl>
            <div><dt>Algorithm</dt><dd>AES-256-GCM authenticated encryption</dd></div>
            <div><dt>Encryption location</dt><dd>Backend, before encrypted bytes are stored</dd></div>
            <div><dt>Decryption location</dt><dd>Backend, after download authorization succeeds</dd></div>
            <div><dt>Integrity</dt><dd>GCM authentication tag verified before plaintext is returned</dd></div>
            <div><dt>Key management</dt><dd>Server-side ENCRYPTION_MASTER_KEY; key material is not shown here</dd></div>
            <div><dt>Architecture</dt><dd>Not end-to-end encrypted; the server can decrypt authorized files</dd></div>
            <div><dt>Upload limit</dt><dd>700 KB per file</dd></div>
          </dl>
        </section>

        <section className="vault-activity" aria-labelledby="vault-activity-heading">
          <div className="vault-list-heading">
            <h2 id="vault-activity-heading">Recent security activity</h2>
          </div>
          {auditEvents.length === 0 ? (
            <p className="vault-activity-empty">No recent security activity.</p>
          ) : (
            <ul className="vault-activity-list">
              {auditEvents.slice(0, 8).map((event) => (
                <li key={event.id}>
                  <span>
                    <strong>{event.action.replaceAll('_', ' ')}</strong>
                    {event.file && <span> · {event.file.originalName}</span>}
                  </span>
                  <time dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>

      {sharingFile && (
        <div className="vault-dialog-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) {
            setSharingFile(null)
          }
        }}>
          <section
            className="vault-share-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="vault-share-heading"
          >
            <div className="vault-share-dialog-heading">
              <div>
                <div className="section-kicker">FILE ACCESS</div>
                <h2 id="vault-share-heading">Share {sharingFile.originalName}</h2>
              </div>
              <button type="button" onClick={() => setSharingFile(null)} aria-label="Close sharing settings">
                ×
              </button>
            </div>
            <form className="vault-share-form" onSubmit={(event) => void handleShareSubmit(event)}>
              <label>
                Recipient email
                <input
                  type="email"
                  value={shareEmail}
                  onChange={(event) => setShareEmail(event.target.value)}
                  autoComplete="email"
                  required
                />
              </label>
              <div className="vault-share-form-row">
                <label>
                  Permission
                  <select
                    value={sharePermission}
                    onChange={(event) => setSharePermission(event.target.value as 'VIEW' | 'DOWNLOAD')}
                  >
                    <option value="VIEW">View details</option>
                    <option value="DOWNLOAD">Download file</option>
                  </select>
                </label>
                <label>
                  Optional expiry
                  <input
                    type="datetime-local"
                    value={shareExpiry}
                    onChange={(event) => setShareExpiry(event.target.value)}
                  />
                </label>
              </div>
              <button className="button" type="submit" disabled={isSavingShare}>
                {isSavingShare ? 'Saving access…' : 'Share file'}
              </button>
            </form>
            {notice && (
              <p
                className={`form-feedback form-feedback-${notice.type} vault-share-notice`}
                role={notice.type === 'error' ? 'alert' : 'status'}
              >
                {notice.message}
              </p>
            )}
            <h3>People with access</h3>
            {isLoadingShares ? (
              <p className="vault-activity-empty">Loading access list…</p>
            ) : shares.length === 0 ? (
              <p className="vault-activity-empty">No one else has access to this file.</p>
            ) : (
              <ul className="vault-share-list">
                {shares.map((share) => (
                  <li key={share.id}>
                    <span>
                      <strong>{share.fullName || share.email}</strong>
                      <small>{share.email} · {share.permission.toLowerCase()}{share.expired ? ' · expired' : ''}</small>
                    </span>
                    <button type="button" onClick={() => void handleRevokeShare(share)}>
                      Revoke
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </main>
  )
}

export default FileDashboardPage
