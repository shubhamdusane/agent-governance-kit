# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within **Agent Governance Kit**, please send an email to sdusane4@gmail.com. All reports will be promptly addressed.

**Please include the following in your report:**

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if applicable)
- Your contact information for follow-up

## Response Timeline

- **Acknowledgment:** Within 48 hours of report submission
- **Initial Assessment:** Within 72 hours
- **Fix Deployment:** Within 7 days for confirmed vulnerabilities

## Security Update Process

1. Vulnerability reports are triaged and prioritized
2. A fix is developed and tested in a private branch
3. Security patch is released as a minor or patch version bump
4. Affected users are notified via release notes
5. CVE is requested if applicable

## Security-Related Configuration

- Policy definitions are version-controlled and digitally signed
- Governance decisions are recorded in an append-only audit log
- Role-based access control is enforced on all policy management endpoints
- Agent capability grants require multi-party approval
- Policy evaluation engine runs in an isolated sandbox environment

## Known Security Gaps

- Policy hot-reload does not verify cryptographic signatures before activation
- Audit log entries are not encrypted at rest in the default configuration
- Emergency override mechanism lacks multi-factor authentication
