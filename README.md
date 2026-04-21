# Roger SSRF 🐰

Server-Side Request Forgery scanner for bug bounty hunting. Tests for SSRF vulnerabilities in web applications.

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

## License

MIT License