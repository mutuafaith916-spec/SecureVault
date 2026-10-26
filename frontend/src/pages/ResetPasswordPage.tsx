import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

type ResetResponse = {
  success: boolean
  message?: string
}

function ResetPasswordPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const token = searchParams.get('token') ?? ''
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isComplete, setIsComplete] = useState(false)
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    token ? null : { type: 'error', message: 'This password reset link is invalid or missing.' },
  )

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFeedback(null)
    if (password !== confirmPassword) {
      setFeedback({ type: 'error', message: 'Your passwords do not match.' })
      return
    }

    setIsSubmitting(true)
    try {
      const response = await fetch('/api/v1/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      })
      const result = await response.json() as ResetResponse
      if (!response.ok || !result.success) {
        setFeedback({
          type: 'error',
          message: result.message || 'We could not reset your password. Request a new reset link and try again.',
        })
        return
      }

      setIsComplete(true)
      setSearchParams({}, { replace: true })
      setPassword('')
      setConfirmPassword('')
      setFeedback({ type: 'success', message: result.message || 'Your password has been reset.' })
    } catch {
      setFeedback({
        type: 'error',
        message: 'We could not reach SecureVault. Please check your connection and try again.',
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="auth-page">
      <Link className="brand auth-brand" to="/" aria-label="SecureVault home">
        <span className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 32 32" fill="none">
            <path d="M16 3.5 27 8v7.1c0 7.1-4.7 11.7-11 14.4C9.7 26.8 5 22.2 5 15.1V8l11-4.5Z" />
            <path d="m11.7 16.1 2.8 2.8 6-6" />
          </svg>
        </span>
        <span>Secure<span className="brand-accent">Vault</span></span>
      </Link>
      <section className="auth-layout">
        <aside className="auth-aside">
          <div className="aside-content">
            <div className="eyebrow"><span className="status-dot" /> ACCOUNT RECOVERY</div>
            <h1>Secure your<br /><span>account.</span></h1>
            <p>Choose a new password to restore secure access to your files.</p>
          </div>
          <span className="aside-caption">PRIVATE BY DESIGN</span>
        </aside>
        <section className="auth-panel">
          <div className="auth-form-wrap">
            <div className="mobile-auth-kicker">ACCOUNT RECOVERY</div>
            <h2>{isComplete ? 'Password updated' : 'Create a new password'}</h2>
            <p className="auth-intro">Use at least 8 characters for your new password.</p>
            {feedback && (
              <p
                className={`form-feedback form-feedback-${feedback.type}`}
                role={feedback.type === 'error' ? 'alert' : 'status'}
              >
                {feedback.message}
              </p>
            )}
            {isComplete ? (
              <Link className="button auth-submit reset-finish-button" to="/login">
                Return to sign in <span aria-hidden="true">→</span>
              </Link>
            ) : (
              <form className="auth-form" onSubmit={handleSubmit}>
                <label className="form-field">
                  <span>New password</span>
                  <input
                    type="password"
                    name="password"
                    autoComplete="new-password"
                    minLength={8}
                    maxLength={128}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    disabled={!token}
                  />
                </label>
                <label className="form-field">
                  <span>Confirm new password</span>
                  <input
                    type="password"
                    name="confirmPassword"
                    autoComplete="new-password"
                    minLength={8}
                    maxLength={128}
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    required
                    disabled={!token}
                  />
                </label>
                <button className="button auth-submit" type="submit" disabled={!token || isSubmitting}>
                  {isSubmitting ? 'Updating password…' : 'Update password'}
                  <span aria-hidden="true">{isSubmitting ? '' : '→'}</span>
                </button>
              </form>
            )}
            <p className="auth-switch"><Link to="/login">Back to sign in</Link></p>
          </div>
        </section>
      </section>
      <footer className="auth-footer"><Link to="/">← Back to home</Link><span>SECUREVAULT · PRIVATE BY DESIGN</span></footer>
    </main>
  )
}

export default ResetPasswordPage
