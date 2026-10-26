import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

type AuthUser = {
  id: string
  fullName: string
  email: string
  role: string
}

type AuthResponse = {
  success: boolean
  message?: string
  user?: AuthUser
  mfaRequired?: boolean
  mfaSetupRequired?: boolean
  challengeToken?: string
  provisioningUri?: string
  manualSecret?: string
}

type Feedback = { type: 'success' | 'error'; message: string }

function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaChallenge, setMfaChallenge] = useState('')
  const [mfaSetupRequired, setMfaSetupRequired] = useState(false)
  const [restartMfaSetup, setRestartMfaSetup] = useState(false)
  const [mfaProvisioningUri, setMfaProvisioningUri] = useState('')
  const [mfaManualSecret, setMfaManualSecret] = useState('')
  const [forgotEmail, setForgotEmail] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [remember, setRemember] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSendingReset, setIsSendingReset] = useState(false)
  const [isCheckingSession, setIsCheckingSession] = useState(true)
  const [isForgotPasswordOpen, setIsForgotPasswordOpen] = useState(false)
  const [user, setUser] = useState<AuthUser | null>(null)
  const [feedback, setFeedback] = useState<Feedback | null>(null)
  const [resetFeedback, setResetFeedback] = useState<Feedback | null>(null)

  useEffect(() => {
    let isMounted = true

    async function restoreSession() {
      try {
        let response = await fetch('/api/v1/auth/session', { credentials: 'include' })
        if (response.status === 401) {
          const refreshResponse = await fetch('/api/v1/auth/refresh', {
            method: 'POST',
            credentials: 'include',
          })
          if (refreshResponse.ok) {
            response = await fetch('/api/v1/auth/session', { credentials: 'include' })
          } else if (refreshResponse.status >= 500 && isMounted) {
            setFeedback({
              type: 'error',
              message: 'SecureVault could not verify your session. You can still sign in below.',
            })
          }
        } else if (!response.ok && isMounted) {
          setFeedback({
            type: 'error',
            message: 'SecureVault could not verify your session. You can still sign in below.',
          })
        }

        if (response.ok) {
          const result = await response.json() as AuthResponse
          if (isMounted && result.success && result.user) {
            setUser(result.user)
          }
        }
      } catch {
        if (isMounted) {
          setFeedback({
            type: 'error',
            message: 'We could not check your saved session. You can still sign in below.',
          })
        }
      } finally {
        if (isMounted) {
          setIsCheckingSession(false)
        }
      }
    }

    void restoreSession()
    return () => {
      isMounted = false
    }
  }, [])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFeedback(null)
    setIsSubmitting(true)

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, rememberMe: remember, restartMfaSetup }),
      })
      const result = await response.json() as AuthResponse

      if (!response.ok || !result.success) {
        setFeedback({
          type: 'error',
          message: result.message || 'We could not sign you in. Please check your details and try again.',
        })
        return
      }

      if (result.mfaRequired && result.challengeToken) {
        setMfaChallenge(result.challengeToken)
        setMfaSetupRequired(result.mfaSetupRequired === true)
        setMfaProvisioningUri(result.provisioningUri || '')
        setMfaManualSecret(result.manualSecret || '')
        setRestartMfaSetup(false)
        setPassword('')
        setFeedback({ type: 'success', message: result.message || 'Verify your sign-in to continue.' })
        return
      }

      if (!result.user) {
        setFeedback({ type: 'error', message: 'The sign-in response was incomplete. Please try again.' })
        return
      }
      setUser(result.user)
      setPassword('')
      setFeedback({ type: 'success', message: result.message || 'You have signed in successfully.' })
    } catch {
      setFeedback({
        type: 'error',
        message: 'We could not reach SecureVault. Please check your connection and try again.',
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  async function handleMfaSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFeedback(null)
    setIsSubmitting(true)
    try {
      const response = await fetch('/api/v1/auth/mfa/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeToken: mfaChallenge, code: mfaCode }),
      })
      const result = await response.json() as AuthResponse
      if (!response.ok || !result.success || !result.user) {
        setFeedback({
          type: 'error',
          message: result.message || 'The verification code was not accepted. Please try again.',
        })
        return
      }
      setUser(result.user)
      setMfaChallenge('')
      setMfaCode('')
      setMfaManualSecret('')
      setMfaProvisioningUri('')
      setFeedback({ type: 'success', message: result.message || 'You have signed in successfully.' })
    } catch {
      setFeedback({
        type: 'error',
        message: 'We could not reach SecureVault. Please check your connection and try again.',
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  async function handleForgotPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setResetFeedback(null)
    setIsSendingReset(true)

    try {
      const response = await fetch('/api/v1/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotEmail }),
      })
      const result = await response.json() as AuthResponse
      if (!response.ok || !result.success) {
        setResetFeedback({
          type: 'error',
          message: result.message || 'We could not send a reset link. Please try again later.',
        })
        return
      }
      setResetFeedback({
        type: 'success',
        message: result.message || 'If an account exists for that email, a reset link will be sent shortly.',
      })
    } catch {
      setResetFeedback({
        type: 'error',
        message: 'We could not reach SecureVault. Please check your connection and try again.',
      })
    } finally {
      setIsSendingReset(false)
    }
  }

  async function handleLogout() {
    setFeedback(null)
    try {
      const response = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'include',
      })
      const result = await response.json() as AuthResponse
      if (!response.ok || !result.success) {
        setFeedback({ type: 'error', message: result.message || 'We could not sign you out. Please try again.' })
        return
      }
      setUser(null)
      setFeedback({ type: 'success', message: result.message || 'You have signed out successfully.' })
    } catch {
      setFeedback({
        type: 'error',
        message: 'We could not reach SecureVault to sign you out. Please try again.',
      })
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
            <div className="eyebrow"><span className="status-dot" /> YOUR PRIVATE SPACE</div>
            <h1>Good to have<br />you <span>back.</span></h1>
            <p>Your files are waiting in a safer place. Sign in to continue to your SecureVault.</p>
            <div className="aside-security">
              <span className="aside-security-icon">
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <rect x="4" y="10" width="16" height="11" rx="2" />
                  <path d="M8 10V7a4 4 0 0 1 8 0v3" />
                </svg>
              </span>
              <span><strong>Security comes first</strong><small>Your privacy is at the heart of SecureVault.</small></span>
            </div>
          </div>
          <span className="aside-caption">SECURE FILE ENCRYPTION &amp; CLOUD STORAGE</span>
        </aside>

        <section className="auth-panel">
          <div className="auth-form-wrap">
            <div className="mobile-auth-kicker">WELCOME BACK</div>
            <h2>{user ? 'Your vault session' : 'Sign in to your vault'}</h2>
            <p className="auth-intro">
              {user
                ? `Signed in as ${user.email}`
                : mfaChallenge
                  ? mfaSetupRequired
                    ? 'Set up an authenticator app to protect your account.'
                    : 'Enter the current code from your authenticator app.'
                  : 'Enter your details to access your secure space.'}
            </p>

            {isCheckingSession ? (
              <p className="form-feedback" role="status">Checking your secure session…</p>
            ) : user ? (
              <div className="auth-form">
                {feedback && (
                  <p className={`form-feedback form-feedback-${feedback.type}`} role="status">{feedback.message}</p>
                )}
                <Link className="button auth-submit" to="/files">
                  Open your file vault <span aria-hidden="true">→</span>
                </Link>
                <button className="button auth-submit" type="button" onClick={handleLogout}>
                  Sign out <span aria-hidden="true">→</span>
                </button>
              </div>
            ) : mfaChallenge ? (
              <form className="auth-form" onSubmit={handleMfaSubmit}>
                {mfaSetupRequired && (
                  <div className="form-feedback" role="status">
                    <strong>Set up an authenticator app</strong>
                    <p>Scan this setup link in your app, or enter the key manually:</p>
                    <p><code>{mfaManualSecret}</code></p>
                    <a href={mfaProvisioningUri}>Open authenticator setup</a>
                    <p>Enter the six-digit code shown by the app to finish setup. Starting over with your password creates a new key and invalidates this one.</p>
                  </div>
                )}
                <label className="form-field">
                  <span>Authenticator code</span>
                  <input
                    type="text"
                    name="mfaCode"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                    required
                  />
                </label>
                {feedback && (
                  <p
                    className={`form-feedback form-feedback-${feedback.type}`}
                    role={feedback.type === 'error' ? 'alert' : 'status'}
                  >
                    {feedback.message}
                  </p>
                )}
                <button className="button auth-submit" type="submit" disabled={isSubmitting}>
                  {isSubmitting ? 'Verifying…' : mfaSetupRequired ? 'Finish setup' : 'Verify and sign in'}
                  <span aria-hidden="true">{isSubmitting ? '' : '→'}</span>
                </button>
                <button
                  className="text-button"
                  type="button"
                  onClick={() => {
                    if (mfaSetupRequired) {
                      setRestartMfaSetup(true)
                    }
                    setMfaChallenge('')
                    setMfaCode('')
                    setMfaSetupRequired(false)
                    setMfaProvisioningUri('')
                    setMfaManualSecret('')
                    setFeedback(null)
                  }}
                >
                  {mfaSetupRequired ? 'Start over with a new key' : 'Back to password'}
                </button>
              </form>
            ) : (
              <>
                <form className="auth-form" onSubmit={handleSubmit}>
                  <label className="form-field">
                    <span>Email address</span>
                    <input
                      type="email"
                      name="email"
                      placeholder="you@example.com"
                      autoComplete="email"
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      required
                    />
                  </label>
                  <label className="form-field">
                    <span>Password</span>
                    <span className="password-input">
                      <input
                        type={passwordVisible ? 'text' : 'password'}
                        name="password"
                        placeholder="Enter your password"
                        autoComplete="current-password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        required
                      />
                      <button
                        className="password-toggle"
                        type="button"
                        onClick={() => setPasswordVisible((visible) => !visible)}
                        aria-label={passwordVisible ? 'Hide password' : 'Show password'}
                      >
                        {passwordVisible ? 'Hide' : 'Show'}
                      </button>
                    </span>
                  </label>
                  <div className="form-options">
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        name="remember"
                        checked={remember}
                        onChange={(event) => setRemember(event.target.checked)}
                      />
                      <span>Remember me</span>
                    </label>
                    <button
                      className="text-button"
                      type="button"
                      onClick={() => {
                        setForgotEmail(email)
                        setIsForgotPasswordOpen((isOpen) => !isOpen)
                        setResetFeedback(null)
                      }}
                    >
                      {isForgotPasswordOpen ? 'Back to sign in' : 'Forgot password?'}
                    </button>
                  </div>
                  {feedback && (
                    <p
                      className={`form-feedback form-feedback-${feedback.type}`}
                      role={feedback.type === 'error' ? 'alert' : 'status'}
                    >
                      {feedback.message}
                    </p>
                  )}
                  <button className="button auth-submit" type="submit" disabled={isSubmitting}>
                    {isSubmitting ? 'Signing in…' : 'Log in to SecureVault'}
                    <span aria-hidden="true">{isSubmitting ? '' : '→'}</span>
                  </button>
                </form>

                {isForgotPasswordOpen && (
                  <form className="auth-form reset-request-form" onSubmit={handleForgotPassword}>
                    <h3>Reset your password</h3>
                    <p className="auth-intro">Enter your account email and we’ll send a one-time reset link.</p>
                    <label className="form-field">
                      <span>Email address</span>
                      <input
                        type="email"
                        name="resetEmail"
                        autoComplete="email"
                        value={forgotEmail}
                        onChange={(event) => setForgotEmail(event.target.value)}
                        required
                      />
                    </label>
                    {resetFeedback && (
                      <p
                        className={`form-feedback form-feedback-${resetFeedback.type}`}
                        role={resetFeedback.type === 'error' ? 'alert' : 'status'}
                      >
                        {resetFeedback.message}
                      </p>
                    )}
                    <button className="button auth-submit" type="submit" disabled={isSendingReset}>
                      {isSendingReset ? 'Sending link…' : 'Send reset link'}
                      <span aria-hidden="true">{isSendingReset ? '' : '→'}</span>
                    </button>
                  </form>
                )}
              </>
            )}

            {!user && !mfaChallenge && !isCheckingSession && (
              <p className="auth-switch">New to SecureVault? <Link to="/register">Create an account</Link></p>
            )}
          </div>
        </section>
      </section>
      <footer className="auth-footer"><Link to="/">← Back to home</Link><span>SECUREVAULT · PRIVATE BY DESIGN</span></footer>
    </main>
  )
}

export default LoginPage
