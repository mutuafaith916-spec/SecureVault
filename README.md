# SecureVault

SecureVault is a privacy-focused file storage demo. The browser sends file bytes to the API, which encrypts them with AES-256-GCM before writing ciphertext to local encrypted-file storage. PostgreSQL stores account, file metadata, session, permission, and audit records.

## Run locally

Requirements: Node.js and PostgreSQL. Local development can use the encrypted local-disk adapter. Production requires Cloudflare R2 (or another S3-compatible service) and two separate buckets.

1. Copy `backend/.env.example` to `backend/.env`.
2. Set `DATABASE_URL` to the PostgreSQL connection string, configure independent random `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` values of at least 32 characters, and set `ENCRYPTION_MASTER_KEY` to a base64-encoded 32-byte key. In production, retrieve secrets from a managed secret store or KMS-backed deployment secret integration; do not commit them or put them in the file backup bucket. Losing the encryption key makes encrypted files and stored MFA secrets unrecoverable. See [Key backup and recovery](#key-backup-and-recovery).
3. For Cloudflare R2, create a primary bucket and a different backup bucket. Set `STORAGE_PROVIDER=s3`, `CLOUD_STORAGE_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com`, `CLOUD_STORAGE_REGION=auto`, `CLOUD_STORAGE_BUCKET`, and `CLOUD_BACKUP_BUCKET`. Create an R2 API token with object read/write/delete access to both buckets and set its S3 access key and secret in `CLOUD_STORAGE_ACCESS_KEY_ID` and `CLOUD_STORAGE_SECRET_ACCESS_KEY`. The application sends only AES-256-GCM ciphertext to both buckets.
4. Local development defaults to `STORAGE_PROVIDER=local`, storing encrypted files and backups under `backend/storage`. Production refuses local storage. S3-compatible storage requires both buckets to exist before the application starts uploading.
5. To enable password reset and security alerts, set all of `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM`. Reset links are disabled until SMTP is configured.
6. Configure `SECURITY_ALERT_EMAILS` as a comma-separated list of administrator/security contacts. SMTP and at least one recipient are required in production for security notifications.
7. Run the schema migrations:

   ```sh
   cd backend
   npm install
   npm run migration:run
   npm run dev
   ```

8. In another terminal, start the frontend:

   ```sh
   cd frontend
   npm install
   npm run dev
   ```

Open the Vite URL printed in the terminal. The development server proxies `/api` to `http://localhost:3000`.
For a one-command development start from the project root, run `npm run dev`. It starts both services and reuses a healthy backend already listening on port 3000.

Never use the example values as production credentials. In production, use HTTPS and secret-manager supplied signing, encryption, cloud-storage, and SMTP credentials. Keep the backup bucket separate from the primary bucket, restrict its access, and separately back up PostgreSQL metadata; the file backup bucket does not contain user accounts or database records.

### Backup, export, deletion, and disaster recovery

The backend provides a PostgreSQL backup command, but it does not install a scheduler. Configure Windows Task Scheduler, cron, or an equivalent scheduler to run `npm run backup:database` from the `backend` directory at least daily, and alert on nonzero exit status or missing recent artifacts. Install PostgreSQL client tools (`pg_dump` and `pg_restore`) on the backup/restore host and ensure they are on `PATH`.

The backup command streams a PostgreSQL custom-format dump through AES-256-GCM using `DATABASE_BACKUP_ENCRYPTION_KEY`, writes a `.svdbak` artifact with owner-only permissions on platforms that enforce POSIX modes, and uploads it to the dedicated S3-compatible database backup bucket. Ensure the local backup directory is access-restricted with operating-system permissions/ACLs, especially on Windows. Configure `DATABASE_BACKUP_ENDPOINT`, `DATABASE_BACKUP_BUCKET`, `DATABASE_BACKUP_ACCESS_KEY_ID`, `DATABASE_BACKUP_SECRET_ACCESS_KEY`, and `DATABASE_BACKUP_ENCRYPTION_KEY` in the deployment secret manager. The backup key must be an independently generated base64-encoded 32-byte key, distinct from `ENCRYPTION_MASTER_KEY`; retain its encrypted recovery copy separately from both file and database backup storage. Production startup requires these settings. Local encrypted artifacts are retained for 35 days by default (`DATABASE_BACKUP_RETENTION_DAYS`); this retention does not configure remote-object expiration.

Configure and verify lifecycle retention, versioning, and—where supported—immutability/object-lock controls on the database backup bucket and file backup bucket. Keep backup credentials separate and more restrictive than routine application credentials. The application does not set remote lifecycle/immutability policies or install the backup schedule automatically.

For a recovery test or disaster, provision an isolated PostgreSQL database and point `DATABASE_URL` at that target before running `npm run restore:database -- "path\to\backup.svdbak"` from `backend`. The restore command authenticates and fully decrypts the artifact into a temporary file before invoking `pg_restore`; a failed authentication check will not start the restore. The temporary file is created with owner-only permissions on platforms that enforce POSIX modes, so ensure the operating system's temporary directory is access-restricted, especially on Windows. Restore the required application and encryption keys through the deployment secret manager, apply compatible application configuration, recover encrypted file objects and metadata, then verify file downloads with a non-sensitive canary before restoring service. Never test against the production database. Record the outcome and remove temporary databases and credentials. Run and document a restoration test regularly; no recovery-point or recovery-time objective is configured by the application.

Authenticated users can download a JSON export of account metadata and their owned files at `GET /api/v1/files/export` (the dashboard provides an “Export my data” action). File bytes are included as base64 after authenticated decryption. The export is capped at 50 MB; users must download larger files individually. Deleted files are retained for recovery for 30 days. Schedule `npm run purge:expired-files` daily (or at an appropriate cadence): it removes expired deleted-file objects and metadata, while retaining audit events. This is permanent deletion; ensure the deletion/retention policy and any provider-level backup retention are communicated to users and aligned with legal requirements.

### Key backup and recovery

The application consumes `ENCRYPTION_MASTER_KEY` as a base64-encoded 32-byte secret at startup. Supply it through a managed secret store (preferably backed by a KMS/HSM) with least-privilege access, access logging, and a controlled break-glass process. SecureVault does not currently call a cloud KMS directly or automatically back up, rotate, or recover this key; key custody and recovery remain deployment responsibilities. The same configured key currently protects file encryption and MFA secrets, so losing or replacing it without a planned migration makes both unreadable.

Maintain a recoverable copy of the exact key separately from the primary and file-backup buckets. Store the copy encrypted under an independent recovery key, with access restricted to designated operators; keep that recovery key under separate custody. Do not store a plaintext key beside file backups, database backups, or application source. Record key version/identity and recovery ownership in the organization’s secret-management system, not in the repository.

Before production and at regular intervals:

1. Create a small non-sensitive canary file, upload it through SecureVault, and retain its encrypted backup and metadata.
2. In an isolated recovery environment, retrieve the key through the documented break-glass process and restore a database snapshot plus the canary ciphertext and metadata.
3. Download the canary through SecureVault and compare it with the original. Confirm that changing a byte in the ciphertext or authentication tag causes decryption to fail.
4. Record the recovery result and remove the isolated test data and temporary credentials. Never use a real user file as a test fixture.

Key rotation is not currently an automatic feature. Do not replace `ENCRYPTION_MASTER_KEY` in place: existing encrypted files and MFA secrets would no longer decrypt. A future rotation must preserve old-key access while all affected data is re-encrypted and verified, then retire old key versions only after tested recovery.

## Application flow

- Register an account, then sign in.
- Every account must enroll a TOTP authenticator at first sign-in and provide a current six-digit code. The MFA secret is encrypted at rest with `ENCRYPTION_MASTER_KEY`; enrollment challenges expire after five minutes and a TOTP time-step cannot be reused.
- Successful MFA verification issues short-lived access and rotating refresh cookies. Both are `HttpOnly` and `SameSite=Strict`; cookies are `Secure` in production. “Remember me” controls whether the refresh cookie persists for up to seven days; otherwise it is a browser-session cookie with a 12-hour server-side lifetime. Logout revokes all active refresh sessions for the account and invalidates existing access tokens; password reset also invalidates sessions.
- Login is limited to five attempts per IP in 15 minutes, MFA verification to six attempts per IP in 15 minutes, and an account is locked for 15 minutes after five failed password attempts. Role and session-version claims are checked against the database on authenticated requests so role changes and revocation take effect immediately.
- Administrators can change another account's `USER`/`ADMIN` role at `PATCH /api/v1/admin/users/:userId/role`; the last administrator cannot be demoted and accounts whose role changes have their sessions revoked. Changes are recorded in the audit trail.
- The protected file vault supports encrypted upload, listing, download/decryption, and deletion. AES-256-GCM authentication tags and metadata are checked before plaintext is released; modified ciphertext, tags, or malformed metadata are rejected. Each successful upload is copied as authenticated ciphertext to the backup store; file owners can restore a verified backup from the vault. The API rejects noncanonical base64 and files larger than 700 KB.
- Owners can grant another registered account `VIEW` or `DOWNLOAD` access to a file, optionally with an expiry, and can revoke grants. Shared users see eligible files in their vault; only owners can manage permissions or delete files. Downloads are authorized against the current owner or an active, unexpired `DOWNLOAD` grant for that recipient; `VIEW` grants do not allow downloading.
- Security activity is available at `/api/v1/audit` and in the dashboard. Users see their own events; accounts with the `ADMIN` role see the latest 100 events across the system. Events include account/session and file/share actions.
- Audit events form a SHA-256 hash chain and the database rejects updates/deletes to audit rows. Administrators can check the chain at `GET /api/v1/audit/integrity`. This is tamper-evident and append-only for the application database role; it is not a substitute for exporting logs to independently controlled immutable storage.
- With SMTP and `SECURITY_ALERT_EMAILS` configured, SecureVault emails security contacts for repeated failed sign-ins, rapid downloads, administrator role changes, unauthorized resource access, and detected audit-chain damage. Failed-login alerts trigger at five events from an IP in ten minutes; download alerts trigger at ten files per account in five minutes. Alerts are rate-limited to one per category/key every 15 minutes.
- Password recovery sends a one-time, one-hour reset link via the configured SMTP server. Reset links are stored as hashes, and a successful reset revokes active refresh sessions.

## Security and resilience requirements

This section describes the target security framework for SecureVault. It is a set of requirements and a roadmap, not a claim that every control listed below is already implemented. Refer to the application flow and validation sections for currently documented behavior.

### Identity, access, and application security

- Require strong user authentication, least-privilege role-based authorization, and multi-factor authentication for accounts and privileged actions. TOTP enrollment and verification are implemented for sign-in; authenticated file access checks current role and session version.
- Protect sessions with secure cookie attributes, short-lived credentials, rotation and revocation, and defenses against session fixation and theft. Apply rate limits and progressive protections against brute-force login and password-reset attempts.
- Enforce authorization on every API operation and validate, normalize, and safely handle all untrusted input. Use parameterized database access and context-appropriate output encoding to mitigate injection, cross-site scripting, and related attacks.
- Require HTTPS/TLS for deployed services, apply secure HTTP headers, protect secrets through a managed secret store, and keep dependencies and runtime components patched. Run dependency and vulnerability scans as part of maintenance and deployment.
- Apply request and resource limits to reduce denial-of-service risk. Scan uploaded files for malware where appropriate, and do not treat scanning as a replacement for authorization or encryption.
- Configure a managed perimeter WAF (for example, a provider WAF in front of the API) with managed OWASP rules, bot and volumetric protections, and rate-based rules. The application provides Helmet headers, restrictive CORS, bounded JSON/form requests, API/login/MFA/admin rate limits, and server-side authorization, but does not include or replace a network-edge WAF.

### Implemented ongoing protections and deployment requirements

- **Uploads:** The API accepts PDF, DOCX, XLSX, PPTX, PNG, JPEG, GIF, WebP, UTF-8 plain text, and UTF-8 CSV only. SVG, HTML, legacy macro-enabled Office files, executables, and archives are rejected. It checks extensions, declared MIME types, basic content signatures, rejects empty files, and caps decoded content at 700 KB. Browser filters are convenience only; validation is enforced by the API.
- **Malware scanning:** Production startup requires `MALWARE_SCANNER_ENABLED=true`. Install ClamAV (`clamscan`) and keep its virus definitions updated; set `MALWARE_SCANNER_COMMAND` if the executable uses another path/name and `MALWARE_SCANNER_DATABASE` if signatures are outside ClamAV's default database directory. Each upload is scanned before encryption or storage. A detection rejects that upload; scanner errors or 120-second timeouts fail closed and block the upload. The CLI scanner starts for each upload and loads its signature database each time; a production deployment should use a managed, continuously running scanner if startup latency is significant. A scanner does not guarantee detection of all malicious files.
- **Dependency and source scanning:** `.github/workflows/security.yml` runs `npm audit --audit-level=high` for backend and frontend dependencies and CodeQL JavaScript/TypeScript analysis on pushes, pull requests, and weekly. Dependabot checks npm packages and GitHub Actions weekly. These checks require GitHub Actions, Dependabot, and repository code-scanning support to be enabled; review and remediate findings rather than treating a green scan as proof of security.
- **Transport and secrets:** Production configuration requires an HTTPS browser origin, HTTPS object-storage endpoints, PostgreSQL `sslmode=require` (prefer `verify-full`), secure session cookies, and Helmet security headers. SMTP transport requires TLS. Terminate web TLS at a maintained reverse proxy/load balancer, disable public access to the plaintext API listener, and configure HSTS there as well. The application does not itself operate a TLS listener. `.env` files are gitignored; production secrets must be injected from a secret manager and must never be placed in frontend `VITE_*` variables or committed. Frontend variables are public in the built bundle.
- **Rate limits and denial of service:** The API limits requests to 100 per IP per 15 minutes; sign-in, MFA, reset, and administrator operations have tighter limits. Uploads are additionally limited to 10 per IP per 15 minutes. The default limiter store is per process, not shared across instances; production deployments with multiple replicas need a shared rate-limit store or equivalent edge rules. Use a WAF/CDN/load balancer for distributed rate limiting, request/connection timeouts, bot filtering, and volumetric DDoS protection. These infrastructure controls are not provisioned by the application.

### Security testing and incident response

CI runs the automated build/tests plus the scheduled dependency and CodeQL checks when repository workflows are enabled. Before each release, test (in an authorized non-production environment) rejected file extensions and MIME/signature mismatches, oversize and empty uploads, malware test signatures, unauthenticated and cross-user file access, expired/revoked shares, repeated login/upload requests, session revocation, and modified ciphertext/authentication tags. Keep test accounts and harmless test fixtures; never use real user data. Schedule independent security assessments and penetration tests, record findings with owners and deadlines, and verify fixes with regression tests.

For a suspected incident: (1) page the designated security/operations contact and preserve relevant application, WAF, identity-provider, database, and object-store logs; (2) contain by blocking abusive traffic at the edge, disabling affected accounts/sessions or uploads, and isolating impacted hosts without destroying evidence; (3) rotate potentially exposed credentials/keys through the secret manager and assess access to encrypted data; (4) patch or remove the cause, restore from verified backups if needed, and validate integrity and access controls before reconnecting service; (5) determine affected users/data and meet applicable notification obligations; and (6) document the timeline, impact, decisions, and follow-up tests. Assign named on-call owners and maintain provider-specific contacts and recovery credentials outside the application.

### Attack detection and audit

- Validate request schemas at the API boundary, including canonical base64 and a 700 KB maximum decoded upload size. Database access uses TypeORM parameterized queries; file and role operations enforce owner, recipient, and administrator authorization on the server.
- Audit authentication, downloads, sharing, unauthorized file access, and administrator privilege changes. The append-only database trigger and ordered hash chain make edits/deletions detectable; administrators can verify the full chain using `/api/v1/audit/integrity`.
- Configure `SECURITY_ALERT_EMAILS` and SMTP for email notifications. Detection includes repeated failed logins, unusually rapid file downloads, role changes, unauthorized resource access, and detected audit integrity failures. Notification delivery depends on the configured SMTP service; an external monitoring/incident alert channel is recommended as an independent backup.

### Encryption, keys, and data protection

- Encrypt file contents with AES-256-GCM before upload. Use cryptographically secure key and nonce generation and verify the authentication tag before releasing decrypted content. The application rejects modified ciphertext or authentication metadata.
- Keep encryption keys separate from stored ciphertext and source code. Define controlled key access, rotation and versioning, encrypted and access-restricted key backups, and a tested recovery process; key loss must be treated as a data-recovery incident. Direct KMS integration, automated key backup, and automated key rotation are not currently implemented; follow the deployment recovery procedure above.
- Protect data in transit and at rest, minimize retained personal data, and provide controlled file sharing, data export and recovery, and documented deletion behavior.

### Availability, backup, and recovery

- The backend provides an encrypted PostgreSQL backup command and a 30-day deleted-file purge command; operators must schedule and monitor them. File uploads are redundantly backed up as encrypted objects. Configure remote retention, versioning, immutability, and independent access controls at the storage provider; these policies and the scheduler are not installed by the application.
- Document disaster-recovery responsibilities, recovery priorities, restoration procedures, and service shutdown and restart steps. Regularly test restoration of both database metadata and encrypted files, including verification that required keys remain recoverable.
- Verify file integrity on upload, backup, and recovery. Define and monitor recovery-point and recovery-time objectives appropriate to the deployment.

### Monitoring, audit, and incident response

- Maintain centralized, access-controlled, tamper-resistant audit records for authentication, file access and sharing, administrative changes, and security-sensitive operations. Avoid recording passwords, tokens, encryption keys, or unnecessary sensitive file data.
- Monitor for suspicious login patterns, unusual file access, unauthorized changes, and privilege escalation. Add anomaly and intrusion detection with actionable alerts and documented escalation paths.
- Maintain incident-response procedures for investigation, containment, recovery, and user notification, and perform regular security assessments and authorized penetration testing.

These safeguards reduce risk but cannot guarantee prevention or immediate detection of every attack. Deployment owners must review the implementation, operational procedures, and applicable legal requirements before using SecureVault with sensitive or production data.

## Validation

```sh
cd backend
npm run build
npm test
npm audit --audit-level=high

cd ../frontend
npm run build
npm run lint
npm audit --audit-level=high
```

The backend tests cover session cookie attributes and parsing, TOTP verification and encrypted MFA-secret storage, production environment requirements, authenticated encryption/decryption, ciphertext/tag/metadata tamper rejection, upload allowlist/content checks, audit-hash determinism, CORS security headers, and health-route behavior. Production also requires a working ClamAV scanner and up-to-date signatures. A full cloud-backed demonstration also requires a reachable PostgreSQL server, applied migrations, valid signing/encryption keys, two configured object-storage buckets, and SMTP credentials for password recovery and security alerts.

## Presentation walkthrough

1. Show the landing page and account registration.
2. Sign in and enroll a TOTP authenticator, then verify a code. Sign in again with “Remember me” both off and on; show that session credentials are not stored in browser local storage.
3. Upload a small file, confirm it appears in the vault, download it, and compare the downloaded content with the original.
4. Share a file with a second registered account as `VIEW` and then `DOWNLOAD`; verify that view-only recipients cannot download, and revoke access.
5. Review recent security activity, then delete a file and verify it disappears from the list.
6. Show password recovery using a configured SMTP inbox.
7. Show the backend test results and the PostgreSQL migration status.

Capture presentation screenshots from the running app with a configured database; screenshots of mocked browser responses are not evidence of database-backed operation.
