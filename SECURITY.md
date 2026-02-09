# Security Policy

## 🔒 Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.x-APEX   | :white_check_mark: | Active maintenance |
| 0.9.x-OMEGA  | :white_check_mark: | Security fixes only |
| < 0.9   | :x:                | No longer supported |

---

## 🚨 Reporting a Vulnerability

**We take security seriously.** If you discover a security vulnerability, please follow responsible disclosure:

### Where to Report

**Primary**: Email 4fqr5@atomicmail.io  
**Alternate Discord**: https://dsc.gg/nullsec (DM admins)  
**PGP Key**: Available on request

### What to Include

Please provide:
1. **Description**: Clear explanation of the vulnerability
2. **Impact**: What an attacker could achieve
3. **Steps to Reproduce**: Detailed reproduction steps
4. **Proof of Concept**: Code/screenshots (if applicable)
5. **Suggested Fix**: If you have one (optional)
6. **Your Contact**: How we can reach you for updates

### Example Report

```
Subject: [SECURITY] SQL Injection in Event Search

Description:
The event search functionality in the Dashboard tab is vulnerable to SQL 
injection through the search_term parameter.

Impact:
An attacker could:
- Extract sensitive data from the nosp_events.db database
- Modify or delete event records
- Potentially execute arbitrary SQL commands

Steps to Reproduce:
1. Navigate to Dashboard tab
2. In search box, enter: ' OR '1'='1
3. Observe that all events are returned, bypassing search logic

Proof of Concept:
[Attached: screenshot.png]

Suggested Fix:
Use parameterized queries instead of string concatenation in 
database.py line 48.

Contact: researcher@example.com
```

---

## ⏱️ Response Timeline

We aim for the following timelines:

| Action | Timeline |
|--------|----------|
| **Initial Response** | Within 48 hours |
| **Triage & Validation** | Within 7 days |
| **Fix Development** | Depends on severity (see below) |
| **Patch Release** | After testing |
| **Public Disclosure** | 90 days after patch release |

### Severity-Based Response

| Severity | CVSS Score | Fix Timeline | Example |
|----------|------------|--------------|---------|
| **Critical** | 9.0-10.0 | 7 days | Remote code execution |
| **High** | 7.0-8.9 | 14 days | Privilege escalation |
| **Medium** | 4.0-6.9 | 30 days | Information disclosure |
| **Low** | 0.1-3.9 | 90 days | Minor information leak |

---

## 🛡️ Security Features

NOSP includes multiple security layers:

### 1. Local Processing
- **Zero Cloud Dependencies**: All data stays on your machine
- **No Telemetry**: We don't collect any usage data
- **Offline Capable**: Works without internet connection
- **Air-Gap Friendly**: Suitable for isolated networks

### 2. Encryption
- **AES-256**: Quarantined files encrypted with industry standard
- **SHA-256**: File integrity verification
- **Secure Key Derivation**: PBKDF2 with 100,000 iterations

### 3. Input Validation
- **Command Sanitization**: Prevents command injection in terminal
- **SQL Parameterization**: All database queries use prepared statements
- **Path Traversal Protection**: File operations restricted to working directory
- **Regex Validation**: Pattern matching for all user inputs

### 4. Process Isolation
- **Least Privilege**: Only requests necessary permissions
- **Safe Subprocess**: Timeout protection (30s default)
- **Command Blacklist**: Dangerous commands blocked (format, del, rm -rf)
- **Injection Detection**: Patterns like `;`, `|`, `&` are filtered

### 5. Code Security
- **No eval/exec**: Zero dynamic code execution
- **Dependency Scanning**: Trivy security scans in CI/CD
- **Type Safety**: MyPy type checking enforced
- **Linting**: Flake8 and Clippy catch common vulnerabilities

---

## 🔐 Security Best Practices

### For Users

1. **Run as Administrator Only When Needed**
   - ✅ DO: Launch with admin for monitoring
   - ❌ DON'T: Run with admin for viewing old events

2. **Keep Dependencies Updated**
   ```bash
   pip install --upgrade -r requirements.txt
   rustup update
   ```

3. **Verify Downloads**
   ```bash
   # Check SHA-256 hash
   sha256sum nosp-1.0.0.zip
   # Compare with https://github.com/4fqr/nosp/releases
   ```

4. **Review Custom Rules**
   - Avoid rules that execute arbitrary commands
   - Test rules in isolated environment first

5. **Secure Database**
   ```bash
   chmod 600 nosp_events.db  # Restrict permissions
   ```

### For Developers

1. **Never Commit Secrets**
   ```bash
   # Use .gitignore
   *.db
   *.env
   session.json
   ```

2. **Sanitize All Inputs**
   ```python
   # Use our sanitizer
   from nosp.terminal import sanitize_command
   safe_cmd = sanitize_command(user_input)
   ```

3. **Parameterize SQL Queries**
   ```python
   # Good ✅
   cursor.execute("SELECT * FROM events WHERE id=?", (event_id,))
   
   # Bad ❌
   cursor.execute(f"SELECT * FROM events WHERE id={event_id}")
   ```

4. **Handle Errors Safely**
   ```python
   # Don't expose internals
   try:
       risky_operation()
   except Exception as e:
       log.error(f"Operation failed: {type(e).__name__}")  # Generic message
       # DON'T: return str(e) to user
   ```

5. **Run Security Tests**
   ```bash
   pytest tests/test_security.py
   bandit -r python/
   cargo clippy -- -D warnings
   ```

---

## 🐛 Known Vulnerabilities

We maintain transparency about known issues:

### Fixed Vulnerabilities

| ID | Severity | Description | Fixed In | CVE |
|----|----------|-------------|----------|-----|
| NOSP-2025-001 | Medium | Command injection via terminal history | 1.0.0-APEX | N/A |
| NOSP-2025-002 | Low | Session file permission too broad | 1.0.0-APEX | N/A |

### Active Vulnerabilities

**None currently.** Last reviewed: February 8, 2026

---

## 🏆 Security Hall of Fame

We recognize security researchers who help improve NOSP:

| Researcher | Vulnerability | Severity | Date |
|------------|---------------|----------|------|
| *Be the first!* | - | - | - |

### Recognition Rewards

- 🎖️ Name in Security Hall of Fame (with permission)
- 💌 Thank you email from the team
- 🎁 NOSP swag (stickers, shirts)
- 💰 No bug bounty program (yet) - we're open source!

---

## 🔍 Security Audits

### Internal Audits
- **Frequency**: Monthly automated scans (Trivy, Bandit)
- **Last Audit**: February 8, 2026
- **Findings**: 0 critical, 0 high, 2 medium (addressed)

### External Audits
- **Status**: Seeking security research partnerships
- **Goal**: Professional penetration testing by Q3 2026

### Third-Party Dependencies
We monitor all dependencies for vulnerabilities:

```bash
# Python
pip-audit

# Rust
cargo audit

# GitHub
Dependabot automated updates
```

---

## 📋 Compliance

### Standards
NOSP aims to comply with:
- ✅ OWASP Top 10 (Web Application Security)
- ✅ CWE Top 25 (Common Weakness Enumeration)
- 🚧 SOC 2 Type II (in progress for enterprise version)

### Privacy
- ✅ GDPR Compliant (no data collection)
- ✅ CCPA Compliant (no data selling)
- ✅ HIPAA Compatible (local processing, but not certified)

### Data Handling
- **Collection**: None (everything is local)
- **Storage**: SQLite database on your machine
- **Transmission**: None (no network calls except localhost Ollama)
- **Retention**: You control (delete `nosp_events.db` anytime)
- **Deletion**: Immediate (just delete files)

---

## 🤝 Responsible Disclosure

We follow the CERT Guide to Coordinated Vulnerability Disclosure:

### Timeline
1. **Day 0**: Vulnerability reported to 4fqr5@atomicmail.io
2. **Day 1-2**: Team acknowledges receipt
3. **Day 3-7**: Team validates and triages
4. **Day 7-30**: Fix developed and tested
5. **Day 30**: Patch released
6. **Day 120**: Public disclosure (90 days after patch)

### Public Disclosure
After the fix is released, we:
1. Publish advisory in GitHub Security Advisories
2. Update [CHANGELOG.md](CHANGELOG.md)
3. Credit researcher (with permission)
4. Notify users via GitHub release notes

### Special Cases
- **Exploited in the Wild**: Immediate patch and disclosure
- **Critical Vulnerabilities**: Accelerated timeline (7 days)
- **Low Severity**: May be bundled with next release

---

## 📞 Contact

- **Security Team**: 4fqr5@atomicmail.io
- **Discord Community**: https://dsc.gg/nullsec
- **GitHub Security**: Use [Private Vulnerability Reporting](https://github.com/4fqr/nosp/security/advisories/new)

### PGP Public Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

[Key will be added before public release]

-----END PGP PUBLIC KEY BLOCK-----
```

---

## 📄 Legal

### Safe Harbor
We will not pursue legal action against security researchers who:
- Act in good faith
- Report vulnerabilities responsibly
- Don't access or modify user data beyond what's necessary to demonstrate the vulnerability
- Don't publicly disclose the vulnerability before we release a fix

### Out of Scope
The following are **not** considered security vulnerabilities:
- ❌ Denial of Service (DoS) attacks
- ❌ Social engineering attacks
- ❌ Physical access attacks
- ❌ Reports from automated tools without validation
- ❌ Issues in dependencies (report to upstream)
- ❌ Theoretical vulnerabilities without proof of concept

### Acknowledgments
We appreciate:
- Detailed reports with clear reproduction steps
- Patience during the disclosure process
- Adherence to responsible disclosure guidelines

---

**Last Updated**: February 8, 2026  
**Version**: 1.0.0-APEX  
**Next Review**: March 8, 2026

[⬆ Back to Top](#security-policy)
