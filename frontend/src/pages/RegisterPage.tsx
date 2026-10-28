import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

type RegistrationResponse = {
  success: boolean
  message: string
}

function getPasswordStrength(password: string) {
  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[a-z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ]
  const score = checks.filter(Boolean).length
  const label = !password ? 'Enter a password' : score < 3 ? 'Weak' : score < 5 ? 'Fair' : 'Strong'
  return { score, label }
}

function RegisterPage() {
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [confirmVisible, setConfirmVisible] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const strength = getPasswordStrength(password)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFeedback(null)

    if (password !== confirmPassword) {
      setFeedback({ type: 'error', message: 'Your passwords do not match.' })
      return
    }

    setIsSubmitting(true)
    try {
      const response = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullName, email, password }),
      })
      const result = await response.json() as RegistrationResponse

      if (!response.ok || !result.success) {
        setFeedback({
          type: 'error',
          message: result.message || 'We could not create your account. Please try again.',
        })
        return
      }

      setFeedback({ type: 'success', message: result.message })
      setPassword('')
      setConfirmPassword('')
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

      <section className="auth-layout register-layout">
        <aside className="auth-aside register-aside">
          <div className="aside-content">
            <div className="eyebrow"><span className="status-dot" /> START WITH SECURITY</div>
            <h1>Secure your data<br />in the <span>digital age.</span></h1>
            <p>Create your SecureVault and bring your important files into a more private, protected space.</p>
            <div className="privacy-points">
              <div><span>✓</span> Your files, in your control</div>
              <div><span>✓</span> Privacy-minded by design</div>
              <div><span>✓</span> A simpler way to stay secure</div>
            </div>
          </div>
          <span className="aside-caption">A SAFER PLACE FOR WHAT MATTERS</span>
        </aside>

        <section className="auth-panel register-panel">
          <div className="auth-form-wrap">
            <div className="mobile-auth-kicker">CREATE YOUR ACCOUNT</div>
            <h2>Create your account</h2>
            <p className="auth-intro">A few details to get your private space started.</p>
            <form className="auth-form register-form" onSubmit={handleSubmit}>
              <label className="form-field">
                <span>Full name</span>
                <input
                  type="text"
                  name="fullName"
                  placeholder="Your full name"
                  autoComplete="name"
                  maxLength={160}
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  required
                />
              </label>
              <label className="form-field">
                <span>Email address</span>
                <input
                  type="email"
                  name="email"
                  placeholder="you@example.com"
                  autoComplete="email"
                  maxLength={320}
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
                    placeholder="Create a strong password"
                    autoComplete="new-password"
                    minLength={8}
                    maxLength={128}
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
                <span className={`strength-meter strength-${strength.score}`}>
                  <span className="strength-bars" aria-label={`Password strength: ${strength.label}`}>
                    {[1, 2, 3, 4, 5].map((segment) => <span key={segment} />)}
                  </span>
                  <span>{strength.label}</span>
                </span>
              </label>
              <label className="form-field">
                <span>Confirm password</span>
                <span className="password-input">
                  <input
                    type={confirmVisible ? 'text' : 'password'}
                    name="confirmPassword"
                    placeholder="Enter your password again"
                    autoComplete="new-password"
                    minLength={8}
                    maxLength={128}
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    required
                  />
                  <button
                    className="password-toggle"
                    type="button"
                    onClick={() => setConfirmVisible((visible) => !visible)}
                    aria-label={confirmVisible ? 'Hide password' : 'Show password'}
                  >
                    {confirmVisible ? 'Hide' : 'Show'}
                  </button>
                </span>
              </label>
              <label className="checkbox-label terms-label">
                <input type="checkbox" name="terms" required />
                <span>I agree to the <a href="#terms" onClick={(event) => event.preventDefault()}>Terms and Conditions</a></span>
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
                {isSubmitting ? 'Creating your account…' : 'Create SecureVault account'}
                <span aria-hidden="true">{isSubmitting ? '' : '→'}</span>
              </button>
            </form>
            <p className="auth-switch">Already have an account? <Link to="/login">Log in</Link></p>
          </div>
        </section>
      </section>
      <footer className="auth-footer"><Link to="/">← Back to home</Link><span>SECUREVAULT · PRIVATE BY DESIGN</span></footer>
    </main>
  )
}

export default RegisterPage
