import { Link } from 'react-router-dom'

function Brand() {
  return (
    <Link className="brand" to="/" aria-label="SecureVault home">
      <span className="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 32 32" fill="none">
          <path d="M16 3.5 27 8v7.1c0 7.1-4.7 11.7-11 14.4C9.7 26.8 5 22.2 5 15.1V8l11-4.5Z" />
          <path d="m11.7 16.1 2.8 2.8 6-6" />
        </svg>
      </span>
      <span>Secure<span className="brand-accent">Vault</span></span>
    </Link>
  )
}

const features = [
  {
    number: '01',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <rect x="4" y="10" width="16" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
      </svg>
    ),
    title: 'Encrypted Files',
    description:
      'Your files are protected with strong encryption, designed to keep private data private.',
  },
  {
    number: '02',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 3 20 6v5.2c0 5.1-3.4 8.4-8 10.3-4.6-1.9-8-5.2-8-10.3V6l8-3Z" />
        <path d="M9 12h6m-3-3v6" />
      </svg>
    ),
    title: 'Controlled Access',
    description:
      'Stay in control of who can access your files and share sensitive content with confidence.',
  },
  {
    number: '03',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M3 12h4l2.5-7 5 14 2.5-7h4" />
      </svg>
    ),
    title: 'Security Monitoring',
    description:
      'Keep an eye on important account activity and get a clearer view of your security.',
  },
]

function LandingPage() {
  return (
    <main className="landing-page">
      <header className="site-header">
        <div className="header-inner">
          <Brand />
          <nav className="header-nav" aria-label="Main navigation">
            <a href="#features">Features</a>
            <Link className="nav-login" to="/login">Log in</Link>
            <Link className="button button-small" to="/register">Get started</Link>
          </nav>
        </div>
      </header>

      <section className="hero-section">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-content">
          <div className="eyebrow"><span className="status-dot" /> YOUR FILES. YOUR CONTROL.</div>
          <h1>Secure File Encryption<br />&amp; <span>Cloud Storage</span></h1>
          <p className="hero-copy">
            A safer place for the files that matter. SecureVault brings privacy,
            thoughtful access controls, and simple cloud storage together.
          </p>
          <div className="hero-actions">
            <Link className="button" to="/register">
              Get started <span aria-hidden="true">→</span>
            </Link>
            <Link className="button button-secondary" to="/login">Log in to your vault</Link>
          </div>
          <div className="hero-note">
            <svg viewBox="0 0 18 18" fill="none" aria-hidden="true">
              <path d="M9 2 15 4.5v4c0 3.9-2.6 6.4-6 7.9-3.4-1.5-6-4-6-7.9v-4L9 2Z" />
              <path d="m6.5 8.8 1.7 1.7 3.5-3.6" />
            </svg>
            Built with privacy and security in mind
          </div>
        </div>

        <div className="vault-visual" aria-label="SecureVault encrypted storage illustration">
          <div className="visual-orbit orbit-one" />
          <div className="visual-orbit orbit-two" />
          <div className="visual-glow" />
          <div className="vault-card">
            <div className="vault-card-top">
              <span className="vault-lock">
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <rect x="4" y="10" width="16" height="11" rx="2" />
                  <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
                </svg>
              </span>
              <span className="encrypted-label"><span /> VAULT ENCRYPTION</span>
            </div>
            <div className="vault-card-title">Your files, under lock.</div>
            <div className="vault-card-subtitle">Private by design. Protected at every step.</div>
            <div className="file-row">
              <span className="file-icon pdf-icon">PDF</span>
              <span className="file-meta"><strong>project-notes.pdf</strong><small>Encrypted file</small></span>
              <span className="file-check" aria-label="Protected">✓</span>
            </div>
            <div className="file-row">
              <span className="file-icon image-icon">
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <rect x="3" y="4" width="18" height="16" rx="3" />
                  <circle cx="9" cy="10" r="2" />
                  <path d="m4 17 5-4 3 2 3-3 5 5" />
                </svg>
              </span>
              <span className="file-meta"><strong>memories.jpg</strong><small>Encrypted file</small></span>
              <span className="file-check" aria-label="Protected">✓</span>
            </div>
            <div className="vault-card-foot"><span className="pulse-dot" /> YOUR PRIVATE SPACE</div>
          </div>
          <div className="floating-badge">
            <span className="badge-shield">✓</span>
            <span><strong>Privacy first</strong><small>Your data stays yours</small></span>
          </div>
          <div className="visual-spark spark-one" />
          <div className="visual-spark spark-two" />
        </div>
      </section>

      <section className="features-section" id="features">
        <div className="features-heading">
          <div>
            <div className="section-kicker">SECURITY, MADE SIMPLE</div>
            <h2>A more confident way to store</h2>
          </div>
          <p>Keep the important things protected without getting in your way.</p>
        </div>
        <div className="feature-grid">
          {features.map((feature) => (
            <article className="feature-card" key={feature.title}>
              <div className="feature-card-top">
                <span className="feature-icon">{feature.icon}</span>
                <span className="feature-number">{feature.number}</span>
              </div>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
              <span className="feature-rule" />
            </article>
          ))}
        </div>
      </section>

      <footer className="site-footer">
        <Brand />
        <span>Thoughtfully designed for a more secure digital life.</span>
        <span className="footer-year">SECUREVAULT · 2026</span>
      </footer>
    </main>
  )
}

export default LandingPage
