# Roger SSRF 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Server-Side Request Forgery (SSRF) vulnerability scanner for bug bounty hunting.**

Tests 25+ SSRF payloads including internal IP bypasses, cloud metadata endpoints (AWS, GCP, Azure), and vulnerable parameter detection.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why SSRF?

SSRF is a critical vulnerability:
- Read internal services (databases, Redis)
- Access cloud metadata (AWS, GCP, Azure)
- Port scanning internal networks
- Attack internal systems

## Features

- Tests 25+ SSRF payloads
- Internal IP testing (127.0.0.1, localhost, etc.)
- Cloud metadata endpoint detection (AWS, GCP, Azure)
- Parameter injection testing
- Common vulnerable parameter detection

## Installation

```bash
git clone https://github.com/jrabbit00/roger-ssrf.git
cd roger-ssrf
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 ssrf.py https://target.com

# With output
python3 ssrf.py target.com -o findings.txt

# Custom timeout
python3 ssrf.py target.com --timeout 20
```

## What It Tests

**Internal IPs:**
- 127.0.0.1, localhost, ::1, 0.0.0.0, 127.1

**Cloud Metadata:**
- AWS: 169.254.169.254
- GCP: metadata.google.internal
- Azure: 169.254.169.254

**Internal Services:**
- Port scanning (22, 80, 443, 8080)

**Parameter Injection:**
- Tests url, dest, redirect, callback, src, etc.

## Important Notes

- SSRF often requires manual verification
- Always have authorization before testing
- Check bug bounty program's scope

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger SSRF helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)