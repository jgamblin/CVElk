# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/jgamblin/CVElk/security/advisories)
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**
   - Send details to: security@gamblin.com
   - Use the subject line: "CVElk Security Vulnerability"
   - Include as much information as possible

### What to Include

Please include the following information:
- Type of vulnerability
- Full paths of affected source files
- Location of the vulnerable code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Depends on severity, typically:
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Safe Harbor

We support safe harbor for security researchers who:
- Make a good faith effort to avoid privacy violations and data destruction
- Only interact with accounts you own or with explicit permission
- Do not exploit vulnerabilities beyond what's necessary to demonstrate them
- Report vulnerabilities promptly

## Security Best Practices for Users

### Elasticsearch Security

1. **Always use authentication** in production
2. **Enable TLS/SSL** for all connections
3. **Use strong passwords** (minimum 16 characters)
4. **Restrict network access** to Elasticsearch ports

### Docker Security

1. **Don't run containers as root** (our images use non-root by default)
2. **Keep images updated** for security patches
3. **Use Docker secrets** for sensitive configuration
4. **Scan images for vulnerabilities** before deployment

### API Keys

1. **Never commit API keys** to version control
2. **Use environment variables** or secrets management
3. **Rotate keys regularly**
4. **Use minimal permissions** when possible

## Security Features

CVElk includes several security features:

- **TLS/SSL encryption** for Elasticsearch and Kibana
- **Authentication required** by default in production Docker setup
- **Non-root container user** for reduced attack surface
- **Automated dependency scanning** in CI/CD
- **CodeQL analysis** for code vulnerabilities
- **Container image scanning** with Trivy

## Acknowledgments

We appreciate security researchers who help keep CVElk secure. Contributors will be acknowledged (with permission) in release notes.
