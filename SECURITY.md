# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in TokenShield, please report it to us through coordinated disclosure.

Please include the following information:
- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the issue
- Location of affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

## Security Considerations

TokenShield handles sensitive credit card data. When deploying:

### ⚠️ NEVER in Production:
- Use self-signed certificates
- Store encryption keys in code or environment files
- Log credit card numbers
- Disable HTTPS
- Use default passwords

### ✅ ALWAYS in Production:
- Use proper SSL/TLS certificates from trusted CAs
- Implement proper key management (AWS KMS, HashiCorp Vault, etc.)
- Enable comprehensive audit logging
- Follow PCI DSS requirements
- Regular security updates and patches
- Network segmentation and firewalls
- Regular security audits
- Implement rate limiting and DDoS protection

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Security Best Practices

1. **Encryption Keys**: Never commit encryption keys. Use proper key management systems.
2. **Database**: Always use encrypted connections to MySQL
3. **Network**: Implement proper network segmentation
4. **Updates**: Keep all dependencies up to date
5. **Monitoring**: Implement comprehensive logging and monitoring
6. **Access Control**: Use strong authentication and authorization

## Compliance

TokenShield is designed to help with PCI DSS compliance, but proper deployment and configuration is essential. Always consult with a QSA (Qualified Security Assessor) for your specific compliance needs.
