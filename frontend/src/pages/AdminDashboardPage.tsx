import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

type UserRole = 'USER' | 'ADMIN'

interface AdminUser {
  id: string
  fullName: string
  email: string
  role: UserRole
  mfaEnabled: boolean
  lockedUntil: string | null
  createdAt: string
}

interface AuditEvent {
  id: string
  action: string
  createdAt: string
  actor: { fullName: string; email: string } | null
  file: { id: string; originalName: string } | null
}

type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
type AlertStatus = 'OPEN' | 'REVIEWED' | 'RESOLVED'

interface SecurityAlert {
  id: string
  ruleId: string
  eventType: string
  severity: AlertSeverity
  status: AlertStatus
  sourceIp: string | null
  evidence: Record<string, string | number | boolean | null>
  occurrenceCount: number
  lastSeenAt: string
  createdAt: string
  actor: { fullName: string; email: string } | null
  reviewedBy: { fullName: string; email: string } | null
  reviewedAt: string | null
  resolvedAt: string | null
}

interface AdminOverview {
  users: number
  usersWithMfa: number
  activeFiles: number
  storageUsedBytes: string
  activeShares: number
  backups: { completed: number; pending: number; failed: number }
  health: {
    api: string
    database: string
    storage: {
      provider: string
      configuration: string
      connectivity: string
    }
  }
}

interface ApiResult {
  success: boolean
  message?: string
  currentAdminId?: string
  overview?: AdminOverview
  users?: AdminUser[]
  auditLogs?: AuditEvent[]
  alerts?: SecurityAlert[]
  integrity?: { valid: boolean; entriesChecked: number; firstInvalidId: string | null }
  pagination?: { page: number; pageSize: number; total: number }
  role?: UserRole
  data?: { api: string; database: string; timestamp: string }
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
    if (refresh.ok) response = await request()
  }
  return response
}

function formatBytes(value: string): string {
  const bytes = Number(value)
  if (!Number.isFinite(bytes) || bytes < 0) return 'Unavailable'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function AdminDashboardPage() {
  const navigate = useNavigate()
  const [overview, setOverview] = useState<AdminOverview | null>(null)
  const [currentAdminId, setCurrentAdminId] = useState('')
  const [users, setUsers] = useState<AdminUser[]>([])
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([])
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[]>([])
  const [alertStatus, setAlertStatus] = useState<'all' | AlertStatus>('OPEN')
  const [alertSeverity, setAlertSeverity] = useState<'all' | AlertSeverity>('all')
  const [alertPage, setAlertPage] = useState(1)
  const [alertTotal, setAlertTotal] = useState(0)
  const [liveHealth, setLiveHealth] = useState<ApiResult['data'] | null>(null)
  const [search, setSearch] = useState('')
  const [submittedSearch, setSubmittedSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [totalUsers, setTotalUsers] = useState(0)
  const [auditAction, setAuditAction] = useState('all')
  const [auditSearch, setAuditSearch] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busyUserId, setBusyUserId] = useState<string | null>(null)
  const [auditIntegrity, setAuditIntegrity] = useState<ApiResult['integrity'] | null>(null)
  const [isCheckingIntegrity, setIsCheckingIntegrity] = useState(false)

  const loadDashboard = useCallback(async () => {
    try {
      try {
        const healthResponse = await fetch('/api/v1/health', { credentials: 'include' })
        const healthResult = await healthResponse.json() as ApiResult
        setLiveHealth(healthResult.data ?? null)
      } catch {
        setLiveHealth(null)
      }
      const query = new URLSearchParams({ page: String(page), pageSize: String(pageSize) })
      if (submittedSearch) query.set('search', submittedSearch)
      const overviewResponse = await fetchWithSession('/api/v1/admin/overview')
      if (overviewResponse.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      if (overviewResponse.status === 403) {
        setNotice({ type: 'error', message: 'Administrator access is required to view this page.' })
        return
      }
      const overviewResult = await overviewResponse.json() as ApiResult
      if (!overviewResponse.ok || !overviewResult.success || !overviewResult.overview) {
        setNotice({ type: 'error', message: overviewResult.message || 'System overview could not be loaded.' })
        return
      }
      const usersResponse = await fetchWithSession(`/api/v1/admin/users?${query.toString()}`)
      if (usersResponse.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      if (usersResponse.status === 403) {
        setNotice({ type: 'error', message: 'Administrator access is required to list users.' })
        return
      }
      const usersResult = await usersResponse.json() as ApiResult
      if (!usersResponse.ok || !usersResult.success || !usersResult.users || !usersResult.pagination) {
        setNotice({ type: 'error', message: usersResult.message || 'User list could not be loaded.' })
        return
      }
      const auditResponse = await fetchWithSession('/api/v1/audit')
      if (auditResponse.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      if (auditResponse.status === 403) {
        setNotice({ type: 'error', message: 'Administrator access is required to read the system audit log.' })
        return
      }
      const auditResult = await auditResponse.json() as ApiResult
      if (!auditResponse.ok || !auditResult.success || !auditResult.auditLogs) {
        setNotice({ type: 'error', message: auditResult.message || 'Audit activity could not be loaded.' })
        return
      }
      const alertQuery = new URLSearchParams({ page: String(alertPage), pageSize: '10' })
      if (alertStatus !== 'all') alertQuery.set('status', alertStatus)
      if (alertSeverity !== 'all') alertQuery.set('severity', alertSeverity)
      const alertsResponse = await fetchWithSession(`/api/v1/admin/alerts?${alertQuery.toString()}`)
      if (alertsResponse.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const alertsResult = await alertsResponse.json() as ApiResult
      if (!alertsResponse.ok || !alertsResult.success || !alertsResult.alerts || !alertsResult.pagination) {
        setNotice({ type: 'error', message: alertsResult.message || 'Security alerts could not be loaded.' })
        return
      }
      setOverview(overviewResult.overview)
      setCurrentAdminId(overviewResult.currentAdminId || '')
      setUsers(usersResult.users)
      setTotalUsers(usersResult.pagination.total)
      setAuditLogs(auditResult.auditLogs)
      setSecurityAlerts(alertsResult.alerts)
      setAlertTotal(alertsResult.pagination.total)
      setPageSize(usersResult.pagination.pageSize)
      setNotice(null)
    } catch {
      setNotice({ type: 'error', message: 'SecureVault could not be reached. Check the connection and retry.' })
    }
  }, [alertPage, alertSeverity, alertStatus, navigate, page, pageSize, submittedSearch])

  useEffect(() => {
    const initialLoad = window.setTimeout(() => void loadDashboard(), 0)
    return () => window.clearTimeout(initialLoad)
  }, [loadDashboard])

  const filteredAudit = useMemo(() => auditLogs.filter((event) => {
    const matchesAction = auditAction === 'all' || event.action === auditAction
    const haystack = `${event.action} ${event.actor?.fullName ?? ''} ${event.actor?.email ?? ''} ${event.file?.originalName ?? ''}`
      .toLowerCase()
    return matchesAction && haystack.includes(auditSearch.trim().toLowerCase())
  }), [auditAction, auditLogs, auditSearch])
  const auditActions = useMemo(
    () => [...new Set(auditLogs.map((event) => event.action))].sort(),
    [auditLogs],
  )

  function handleSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const nextSearch = search.trim()
    if (page === 1 && submittedSearch === nextSearch) {
      void loadDashboard()
      return
    }
    setPage(1)
    setSubmittedSearch(nextSearch)
  }

  async function changeRole(user: AdminUser, role: UserRole) {
    if (user.id === currentAdminId || user.role === role) return
    const verb = role === 'ADMIN' ? 'promote' : 'demote'
    if (!window.confirm(`Are you sure you want to ${verb} ${user.fullName}? Their active sessions will be revoked.`)) {
      return
    }
    setBusyUserId(user.id)
    setNotice(null)
    try {
      const response = await fetchWithSession(`/api/v1/admin/users/${encodeURIComponent(user.id)}/role`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role }),
      })
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({ type: 'error', message: result.message || 'The account role could not be changed.' })
        return
      }
      await loadDashboard()
      setNotice({ type: 'success', message: result.message || 'Account role updated.' })
    } catch {
      setNotice({ type: 'error', message: 'The role change could not be completed. Check the connection.' })
    } finally {
      setBusyUserId(null)
    }
  }

  async function verifyAuditIntegrity() {
    setIsCheckingIntegrity(true)
    setAuditIntegrity(null)
    try {
      const response = await fetchWithSession('/api/v1/audit/integrity')
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success || !result.integrity) {
        setNotice({ type: 'error', message: result.message || 'Audit integrity could not be checked.' })
        return
      }
      setAuditIntegrity(result.integrity)
    } catch {
      setNotice({ type: 'error', message: 'Audit integrity could not be checked. Verify the connection and retry.' })
    } finally {
      setIsCheckingIntegrity(false)
    }
  }

  async function updateAlertStatus(alert: SecurityAlert, status: 'REVIEWED' | 'RESOLVED') {
    setBusyUserId(alert.id)
    setNotice(null)
    try {
      const response = await fetchWithSession(`/api/v1/admin/alerts/${encodeURIComponent(alert.id)}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      })
      if (response.status === 401) {
        navigate('/login', { replace: true })
        return
      }
      const result = await response.json() as ApiResult
      if (!response.ok || !result.success) {
        setNotice({ type: 'error', message: result.message || 'The security alert could not be updated.' })
        return
      }
      await loadDashboard()
      setNotice({ type: 'success', message: result.message || 'Security alert updated.' })
    } catch {
      setNotice({ type: 'error', message: 'The security alert could not be updated. Check the connection.' })
    } finally {
      setBusyUserId(null)
    }
  }

  return (
    <main className="vault-page">
      <header className="vault-header">
        <Link className="brand" to="/files" aria-label="SecureVault dashboard">
          <span>Secure<span className="brand-accent">Vault</span></span>
        </Link>
        <nav className="admin-nav" aria-label="Administrator navigation">
          <Link to="/files">My vault</Link>
          <span>Administrator console</span>
        </nav>
      </header>
      <section className="vault-content admin-content">
        <div className="vault-heading">
          <div>
            <div className="section-kicker">SECUREVAULT MANAGEMENT</div>
            <h1>Administrator console</h1>
            <p>System and account information from authenticated administrative APIs.</p>
          </div>
          <button type="button" className="vault-refresh" onClick={() => void loadDashboard()}>
            Refresh
          </button>
        </div>
        {notice && (
          <p className={`form-feedback form-feedback-${notice.type}`} role={notice.type === 'error' ? 'alert' : 'status'}>
            {notice.message}
          </p>
        )}
        <section className="vault-encryption-details admin-health" aria-labelledby="admin-health-heading">
          <h2 id="admin-health-heading">System health</h2>
          <dl>
            <div><dt>Backend API</dt><dd>{liveHealth?.api ?? overview?.health.api ?? 'Unavailable'}</dd></div>
            <div><dt>Database connectivity</dt><dd>{liveHealth?.database ?? overview?.health.database ?? 'Unavailable'}</dd></div>
            <div><dt>Storage provider</dt><dd>{overview ? `${overview.health.storage.provider} · ${overview.health.storage.configuration}` : 'Unavailable'}</dd></div>
            <div><dt>Storage connectivity</dt><dd>Not checked by this status endpoint</dd></div>
          </dl>
          <p>The API and database values come from the public health check. Storage configuration is only reported from application settings; bucket or disk connectivity has not been probed.</p>
        </section>
        {!overview && !notice ? (
          <div className="vault-empty-state" role="status">Loading protected administrator data…</div>
        ) : overview ? (
          <>
            <section className="vault-overview admin-overview" aria-label="System overview">
              <article className="vault-overview-card"><span>Registered users</span><strong>{overview.users}</strong><small>Email verification is required after each password</small></article>
              <article className="vault-overview-card"><span>Active files</span><strong>{overview.activeFiles}</strong><small>{formatBytes(overview.storageUsedBytes)} metadata-reported storage</small></article>
              <article className="vault-overview-card"><span>Active shares</span><strong>{overview.activeShares}</strong><small>Unexpired grants on active files</small></article>
              <article className="vault-overview-card"><span>Completed backups</span><strong>{overview.backups.completed}</strong><small>{overview.backups.pending} pending · {overview.backups.failed} failed</small></article>
            </section>

            <section className="admin-section" aria-labelledby="admin-users-heading">
              <div className="vault-list-heading">
                <div><h2 id="admin-users-heading">User management</h2><p>{totalUsers} matching accounts</p></div>
              </div>
              <form className="admin-search-form" onSubmit={handleSearch}>
                <label htmlFor="admin-user-search">Search by name or email</label>
                <input id="admin-user-search" type="search" maxLength={100} value={search} onChange={(event) => setSearch(event.target.value)} />
                <button type="submit" className="button">Search</button>
                <button type="button" onClick={() => {
                  setSearch('')
                  if (page === 1 && submittedSearch === '') {
                    void loadDashboard()
                    return
                  }
                  setSubmittedSearch('')
                  setPage(1)
                }}>Clear</button>
              </form>
              {users.length === 0 ? <p className="vault-activity-empty">No accounts match this search.</p> : (
                <div className="admin-table-wrap">
                  <table className="admin-table">
                    <thead><tr><th>Account</th><th>Role</th><th>Legacy authenticator</th><th>Login status</th><th>Created</th><th>Change role</th></tr></thead>
                    <tbody>
                      {users.map((user) => (
                        <tr key={user.id}>
                          <td><strong>{user.fullName}</strong><small>{user.email}</small></td>
                          <td>{user.role}</td>
                          <td>{user.mfaEnabled ? 'Enrolled (not used for sign-in)' : 'Not enrolled'}</td>
                          <td>{user.lockedUntil ? `Locked until ${new Date(user.lockedUntil).toLocaleString()}` : 'Available'}</td>
                          <td>{new Date(user.createdAt).toLocaleDateString()}</td>
                          <td>
                            <select
                              aria-label={`Change role for ${user.email}`}
                              value={user.role}
                              disabled={user.id === currentAdminId || busyUserId === user.id}
                              onChange={(event) => void changeRole(user, event.target.value as UserRole)}
                            >
                              <option value="USER">USER</option>
                              <option value="ADMIN">ADMIN</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="admin-pagination">
                <button type="button" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
                <span>Page {page} of {Math.max(1, Math.ceil(totalUsers / pageSize))}</span>
                <button type="button" disabled={page >= Math.ceil(totalUsers / pageSize)} onClick={() => setPage((value) => value + 1)}>Next</button>
              </div>
              <p className="admin-note">Account disabling is not supported by this backend. Role changes use the protected API and revoke the affected account’s active sessions.</p>
            </section>

            <section className="admin-section" aria-labelledby="admin-audit-heading">
              <div className="vault-list-heading">
                <div><h2 id="admin-audit-heading">Security and audit activity</h2><p>Latest 100 persisted audit events</p></div>
                <button type="button" className="vault-refresh" onClick={() => void verifyAuditIntegrity()} disabled={isCheckingIntegrity}>
                  {isCheckingIntegrity ? 'Checking…' : 'Verify audit chain'}
                </button>
              </div>
              {auditIntegrity && (
                <p className={`admin-integrity-result ${auditIntegrity.valid ? 'is-valid' : 'is-invalid'}`} role="status">
                  {auditIntegrity.valid
                    ? `Audit chain verified: ${auditIntegrity.entriesChecked} entries checked.`
                    : `Audit chain verification failed after ${auditIntegrity.entriesChecked} entries. First invalid entry: ${auditIntegrity.firstInvalidId || 'unknown'}.`}
                </p>
              )}
              <div className="admin-audit-filters">
                <label>Event type
                  <select value={auditAction} onChange={(event) => setAuditAction(event.target.value)}>
                    <option value="all">All events</option>
                    {auditActions.map((action) => <option value={action} key={action}>{action.replaceAll('_', ' ')}</option>)}
                  </select>
                </label>
                <label>Search events
                  <input type="search" value={auditSearch} onChange={(event) => setAuditSearch(event.target.value)} placeholder="Actor, email, or filename" />
                </label>
              </div>
              {filteredAudit.length === 0 ? <p className="vault-activity-empty">No recorded events match these filters.</p> : (
                <ul className="vault-activity-list">
                  {filteredAudit.map((event) => (
                    <li key={event.id}>
                      <span><strong>{event.action.replaceAll('_', ' ')}</strong>
                        <small>{event.actor ? `${event.actor.fullName} · ${event.actor.email}` : 'System or deleted account'}
                          {event.file ? ` · ${event.file.originalName}` : ''}
                        </small>
                      </span>
                      <time dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="admin-section" aria-labelledby="admin-alerts-heading">
              <div className="vault-list-heading">
                <div><h2 id="admin-alerts-heading">Detected security alerts</h2><p>{alertTotal} matching persisted alerts</p></div>
              </div>
              <div className="admin-audit-filters">
                <label>Alert status
                  <select value={alertStatus} onChange={(event) => {
                    setAlertStatus(event.target.value as 'all' | AlertStatus)
                    setAlertPage(1)
                  }}>
                    <option value="OPEN">Open</option>
                    <option value="REVIEWED">Reviewed</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="all">All statuses</option>
                  </select>
                </label>
                <label>Severity
                  <select value={alertSeverity} onChange={(event) => {
                    setAlertSeverity(event.target.value as 'all' | AlertSeverity)
                    setAlertPage(1)
                  }}>
                    <option value="all">All severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </label>
              </div>
              {securityAlerts.length === 0 ? (
                <p className="vault-activity-empty">No persisted alerts match these filters. This does not mean that no suspicious activity has occurred.</p>
              ) : (
                <div className="admin-table-wrap">
                  <table className="admin-table admin-alert-table">
                    <thead><tr><th>Severity / rule</th><th>Evidence</th><th>Source</th><th>Last seen</th><th>Status / actions</th></tr></thead>
                    <tbody>
                      {securityAlerts.map((alert) => (
                        <tr key={alert.id}>
                          <td>
                            <span className={`admin-alert-severity severity-${alert.severity.toLowerCase()}`}>{alert.severity}</span>
                            <small>{alert.ruleId.replaceAll('.', ' ')}</small>
                            <small>{alert.occurrenceCount} matching events</small>
                          </td>
                          <td>{Object.entries(alert.evidence).map(([key, value]) => `${key}: ${value ?? 'unknown'}`).join(' · ') || 'No additional evidence'}</td>
                          <td>{alert.actor ? `${alert.actor.fullName} · ${alert.actor.email}` : 'Unknown or deleted account'}
                            {alert.sourceIp ? <small>{alert.sourceIp}</small> : null}
                          </td>
                          <td><time dateTime={alert.lastSeenAt}>{new Date(alert.lastSeenAt).toLocaleString()}</time></td>
                          <td>
                            <strong>{alert.status}</strong>
                            {alert.reviewedBy && <small>Reviewed by {alert.reviewedBy.fullName}</small>}
                            <div className="admin-alert-actions">
                              {alert.status === 'OPEN' && (
                                <button type="button" disabled={busyUserId === alert.id} onClick={() => void updateAlertStatus(alert, 'REVIEWED')}>Mark reviewed</button>
                              )}
                              {alert.status !== 'RESOLVED' && (
                                <button type="button" disabled={busyUserId === alert.id} onClick={() => void updateAlertStatus(alert, 'RESOLVED')}>Resolve</button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="admin-pagination">
                <button type="button" disabled={alertPage <= 1} onClick={() => setAlertPage((value) => value - 1)}>Previous alerts</button>
                <span>Page {alertPage} of {Math.max(1, Math.ceil(alertTotal / 10))}</span>
                <button type="button" disabled={alertPage >= Math.ceil(alertTotal / 10)} onClick={() => setAlertPage((value) => value + 1)}>Next alerts</button>
              </div>
              <p className="admin-note">Alerts are generated from configured audit-event thresholds. They are not a complete intrusion-detection system and do not automatically block accounts or requests.</p>
            </section>
          </>
        ) : (
          <div className="vault-empty-state">Administrator data is unavailable. Use Refresh to try again.</div>
        )}
      </section>
    </main>
  )
}

export default AdminDashboardPage
