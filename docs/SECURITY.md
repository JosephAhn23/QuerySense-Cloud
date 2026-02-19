# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.3.x   | :white_check_mark: (security fixes only) |
| 1.0.x–1.2.x | :x: (upgrade recommended) |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send details to the maintainer via GitHub's private vulnerability reporting
2. **GitHub Security Advisories**: Use the "Report a vulnerability" button in the Security tab

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if available)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Initial acknowledgment | Within 48 hours |
| Severity assessment | Within 1 week |
| Fix timeline communicated | Within 2 weeks |
| Patch release | Depends on severity |

### Severity Levels

- **Critical**: Remote code execution, data exfiltration → Patch within 48 hours
- **High**: Denial of service, significant data exposure → Patch within 1 week
- **Medium**: Limited impact vulnerabilities → Patch in next minor release
- **Low**: Theoretical/unlikely vulnerabilities → Tracked for future fix

### Disclosure Policy

1. Reporter notified of fix before public release
2. CVE assigned if applicable (CVSS >= 4.0)
3. Security advisory published with patch release
4. Credit given to reporter (unless they prefer anonymity)

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations and disruptions
- Provide us reasonable time to fix issues before disclosure
- Do not exploit vulnerabilities beyond what's necessary to demonstrate them

## Security Best Practices for Users

### Thread Safety (Pre-0.4.0)

QuerySense versions prior to 0.4.0 are **NOT thread-safe**. If you're using an older version:

```python
# DON'T: Share analyzer across threads
analyzer = Analyzer()  # Single instance
executor.map(analyzer.analyze, queries)  # Race condition!

# DO: Create analyzer per thread
def analyze_query(query):
    analyzer = Analyzer()  # Thread-local instance
    return analyzer.analyze(query)
```

### Input Validation

QuerySense has built-in resource limits, but you should still:

- Validate input size before parsing
- Set appropriate timeouts for analysis
- Don't analyze untrusted EXPLAIN output from unknown sources

### Dependency Security

Keep dependencies updated:

```bash
pip install --upgrade querysense
pip audit  # Check for known vulnerabilities
```

## Known Security Considerations

### SQL Injection

QuerySense **does not execute SQL**. It only analyzes EXPLAIN output (JSON). However:

- The suggestions it generates are SQL strings
- **Never execute suggestions without review** in production
- Treat suggestions as recommendations, not commands

### Resource Exhaustion

QuerySense has default resource limits:

- Max file size: 100MB
- Max nodes: 50,000
- Max depth: 100

These can be overridden. Use strict limits for untrusted input:

```python
from querysense.parser.config import ParserConfig

config = ParserConfig.strict()  # 10MB, 5K nodes, depth 50
```
