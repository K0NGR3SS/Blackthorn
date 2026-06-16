"""
Full Pentest Chain: Bypass -> Enum -> Scan -> Recon -> Report
WAF/CDN assessment workflow with comprehensive error handling
"""
import os
import json
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional

from .pierce import CloudFrontBypasser
from .exceptions import (
    WAFPierceError,
    OutputDirectoryError,
)
from .error_handler import (
    safe_request,
    GracefulErrorHandler,
    setup_logging,
)

def supports_unicode() -> bool:
    """Check if the terminal supports Unicode"""
    try:
        if hasattr(sys.stdout, 'encoding'):
            encoding = sys.stdout.encoding or 'ascii'
            '📁'.encode(encoding)
            return True
    except (UnicodeEncodeError, LookupError, AttributeError):
        return False
    return False

# Set at module level
USE_EMOJIS = supports_unicode()

def get_icon(icon_type: str) -> str:
    """Get icon based on terminal capabilities"""
    if USE_EMOJIS:
        icons = {
            'info': '📁',
            'progress': '🔍',
            'success': '✓',
            'warning': '⚠',
            'error': '✗',
            'found': '✓',
            'scanning': '⚡',
            'folder': '📁',
            'file': '📄',
            'lock': '🔒',
        }
    else:
        icons = {
            'info': '[*]',
            'progress': '[~]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[!]',
            'found': '[+]',
            'scanning': '[~]',
            'folder': '[*]',
            'file': '[*]',
            'lock': '[!]',
        }
    return icons.get(icon_type, '[*]' if not USE_EMOJIS else '📁')

def safe_print(text: str):
    """Print with automatic encoding fallback"""
    try:
        print(text)
    except UnicodeEncodeError:
        # Strip emojis and retry
        emoji_map = {
            '📁': '[*]', '📄': '[*]', '⚠': '[!]', '🔒': '[!]',
            '✓': '[+]', '✗': '[!]', '🔍': '[~]', '⚡': '[~]',
            '═': '=', '─': '-',
        }
        for emoji, ascii_char in emoji_map.items():
            text = text.replace(emoji, ascii_char)
        print(text)

logger = logging.getLogger(__name__)

DISCLAIMER_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗    ██╗ █████╗ ███████╗██████╗ ██╗███████╗██████╗  ██████╗███████╗      ║
║   ██║    ██║██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔══██╗██╔════╝██╔════╝      ║
║   ██║ █╗ ██║███████║█████╗  ██████╔╝██║█████╗  ██████╔╝██║     █████╗        ║
║   ██║███╗██║██╔══██║██╔══╝  ██╔═══╝ ██║██╔══╝  ██╔══██╗██║     ██╔══╝        ║
║   ╚███╔███╔╝██║  ██║██║     ██║     ██║███████╗██║  ██║╚██████╗███████╗      ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝      ║
║                                                                              ║
║                     WAF/CDN Bypass & Reconnaissance Scanner                  ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ⚠️  LEGAL DISCLAIMER - READ BEFORE PROCEEDING ⚠️                              ║
║                                                                              ║
║  This tool is designed for AUTHORIZED security testing ONLY.                 ║
║                                                                              ║
║  By using WAFPierce, you acknowledge and agree that:                         ║
║                                                                              ║
║  1. You have EXPLICIT WRITTEN AUTHORIZATION to test the target system        ║
║  2. You will use this tool RESPONSIBLY and ETHICALLY                         ║
║  3. You understand that unauthorized access to systems is ILLEGAL            ║
║  4. You accept FULL RESPONSIBILITY for any actions taken with this tool      ║
║  5. The developers are NOT LIABLE for any misuse or damage caused            ║
║                                                                              ║
║  Unauthorized use of this tool may violate:                                  ║
║  • Computer Fraud and Abuse Act (CFAA) - USA                                 ║
║  • Computer Misuse Act - UK                                                  ║
║  • Similar laws in your jurisdiction                                         ║
║                                                                              ║
║  🔒 USE RESPONSIBLY • TEST ETHICALLY • REPORT VULNERABILITIES 🔒              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def print_banner():
    """Display the WAFPierce banner and disclaimer"""
    print(DISCLAIMER_BANNER)


def print_phase_header(phase_num: int, phase_name: str, description: str = ""):
    """Print a formatted phase header"""
    border = '═' if USE_EMOJIS else '='
    safe_print(f"\n{border*60}")
    safe_print(f"  PHASE {phase_num}: {phase_name.upper()}")
    if description:
        safe_print(f"  {description}")
    safe_print(f"{border*60}")

def print_status(message: str, status_type: str = "info"):
    """Print a formatted status message"""
    icon = get_icon(status_type)
    safe_print(f"  {icon} {message}")

class FullPentestChain:
    def __init__(self, target: str, output_dir: str = "pentest_results", threads: int = 10):
        """
        Initialize full penetration test chain
        
        Args:
            target: Target URL
            output_dir: Output directory for results
            threads: Number of concurrent threads
        
        Raises:
            OutputDirectoryError: If output directory cannot be created
        """
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.threads = threads
        self.bypasses = []
        self.results = {}
        self.errors = []
        
        # Create output directory with error handling
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.info(f"Output directory: {self.output_dir}")
        except PermissionError:
            raise OutputDirectoryError(
                f"Permission denied: Cannot create directory {self.output_dir}",
                details={'directory': self.output_dir}
            )
        except Exception as e:
            raise OutputDirectoryError(
                f"Failed to create output directory: {str(e)}",
                details={'directory': self.output_dir, 'error': str(e)}
            )

    def phase1_bypass(self) -> bool:
        """
        Phase 1: WAF Bypass
        
        Returns:
            True if at least one bypass found, False otherwise
        
        Raises:
            WAFPierceError: If bypass scanning fails critically
        """
        print_phase_header(1, "WAF Bypass", "Testing bypass techniques against WAF protection")
        print_status(f"Target: {self.target}", "info")
        print_status("Initializing bypass scanner...", "progress")
        logger.info("Starting Phase 1: WAF Bypass")
        
        try:
            print_status("Establishing baseline response...", "scanning")
            bypasser = CloudFrontBypasser(self.target, self.threads, 0.2)
            
            print_status("Testing 13 bypass techniques...", "scanning")
            print_status("Techniques: Host Header, X-Forwarded-For, X-Forwarded-Host,", "info")
            print_status("           X-Original-URL, Cache-Control, Encoding, Methods,", "info")
            print_status("           Content-Type, Transfer-Encoding, HTTP/2, WebSocket,", "info")
            print_status("           Range Header, Double Encoding", "info")
            print()
            
            all_results = bypasser.scan()
            self.bypasses = [r for r in all_results if r.get('bypass')]
            
            # Save bypass results
            output_file = f"{self.output_dir}/bypasses.json"
            with open(output_file, 'w') as f:
                json.dump(self.bypasses, f, indent=2)
            
            logger.info(f"Found {len(self.bypasses)} bypasses")
            print()
            if self.bypasses:
                print_status(f"Found {len(self.bypasses)} bypass techniques!", "success")
                for bypass in self.bypasses[:5]:  # Show first 5
                    print_status(f"  → {bypass.get('technique', 'Unknown')} [{bypass.get('severity', 'N/A')}]", "found")
                if len(self.bypasses) > 5:
                    print_status(f"  ... and {len(self.bypasses) - 5} more", "info")
            else:
                print_status("No bypasses found - target may be well protected", "warning")
            
            print_status(f"Results saved to {output_file}", "info")
            
            if not self.bypasses:
                logger.warning("No bypasses found - subsequent phases may fail")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Phase 1 failed: {e}")
            self.errors.append({'phase': 'bypass', 'error': str(e)})
            raise

    def phase2_enum(self) -> bool:
        """
        Phase 2: Directory Enumeration
        
        Returns:
            True if enumeration succeeded, False otherwise
        """
        print_phase_header(2, "Directory Enumeration", "Discovering accessible paths and directories")
        logger.info("Starting Phase 2: Directory Enumeration")
        
        # Try to load wordlist
        print_status("Loading wordlist...", "progress")
        wordlist_paths = [
            "wordlists/dirs.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        
        wordlist = None
        for path in wordlist_paths:
            try:
                with open(path) as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print_status(f"Loaded wordlist: {path}", "success")
                print_status(f"Entries to test: {len(wordlist)}", "info")
                logger.info(f"Loaded wordlist from {path} ({len(wordlist)} entries)")
                break
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.warning(f"Error loading wordlist {path}: {e}")
                continue
        
        if not wordlist:
            logger.error("No wordlist found")
            print_status("No wordlist found - skipping enumeration", "error")
            self.errors.append({'phase': 'enum', 'error': 'Wordlist not found'})
            return False
        
        print_status(f"Starting enumeration with {self.threads} threads...", "scanning")
        if self.bypasses:
            print_status(f"Using {min(5, len(self.bypasses))} bypass technique(s) for requests", "info")
        
        def test_path(path: str) -> Optional[Dict[str, Any]]:
            """Test a single path with available bypasses"""
            # Use bypasses if available, otherwise try baseline request
            test_configs = self.bypasses[:5] if self.bypasses else [{}]
            
            for bypass in test_configs:
                headers = bypass.get('headers', {})
                try:
                    resp = safe_request(
                        urljoin(self.target, path),
                        headers=headers,
                        timeout=5
                    )
                    if resp and resp.status_code == 200:
                        return {
                            'path': path,
                            'headers': headers,
                            'size': len(resp.content),
                            'status': resp.status_code
                        }
                except Exception as e:
                    logger.debug(f"Path test failed for {path}: {e}")
                    continue
            return None
        
        live_paths = []
        tested_count = 0
        with GracefulErrorHandler("directory_enumeration", continue_on_error=True):
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(test_path, path): path for path in wordlist}
                total = len(futures)
                
                for future in as_completed(futures):
                    tested_count += 1
                    try:
                        result = future.result()
                        if result:
                            live_paths.append(result)
                            print_status(f"FOUND: {result['path']} (HTTP {result['status']})", "found")
                            logger.info(f"Found live path: {result['path']}")
                        # Progress update every 50 paths
                        if tested_count % 50 == 0:
                            print_status(f"Progress: {tested_count}/{total} paths tested...", "progress")
                    except Exception as e:
                        logger.debug(f"Path enumeration error: {e}")
        
        self.results['live_paths'] = live_paths
        
        # Save results
        try:
            output_file = f"{self.output_dir}/live_paths.json"
            with open(output_file, 'w') as f:
                json.dump(live_paths, f, indent=2)
            logger.info(f"Saved {len(live_paths)} live paths")
        except Exception as e:
            logger.error(f"Failed to save live paths: {e}")
            self.errors.append({'phase': 'enum', 'error': f'Save failed: {str(e)}'})
        
        print()
        print_status(f"Enumeration complete: {tested_count} paths tested", "success")
        print_status(f"Live paths discovered: {len(live_paths)}", "success" if live_paths else "info")
        print_status(f"Results saved to {output_file}", "info")
        return len(live_paths) > 0

    def phase3_scan(self) -> bool:
        """
        Phase 3: Vulnerability Scan
        
        Returns:
            True if scan succeeded, False otherwise
        """
        print_phase_header(3, "Vulnerability Scanning", "Testing for common web vulnerabilities")
        logger.info("Starting Phase 3: Vulnerability Scanning")
        
        xss_payloads = [
            "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>"
        ]
        vuln_findings = []
        
        # Test paths or fall back to bypasses
        targets = self.results.get('live_paths', self.bypasses[:10] if self.bypasses else [{'path': '/'}])
        
        with GracefulErrorHandler("vulnerability_scan", continue_on_error=True):
            for path_data in targets:
                path = path_data.get('path', '/')
                headers = path_data.get('headers', {})
                
                for payload in xss_payloads:
                    test_url = f"{self.target}{path}?test={payload}"
                    try:
                        resp = safe_request(test_url, headers=headers, timeout=5)
                        if resp and payload in resp.text:
                            vuln_findings.append({
                                'type': 'XSS',
                                'url': test_url,
                                'payload': payload,
                                'severity': 'HIGH'
                            })
                            logger.warning(f"Potential XSS found: {test_url}")
                    except Exception as e:
                        logger.debug(f"Vuln scan error for {test_url}: {e}")
        
        self.results['vulns'] = vuln_findings
        
        # Save results
        try:
            output_file = f"{self.output_dir}/vulns.json"
            with open(output_file, 'w') as f:
                json.dump(vuln_findings, f, indent=2)
            logger.info(f"Found {len(vuln_findings)} potential vulnerabilities")
        except Exception as e:
            logger.error(f"Failed to save vulnerabilities: {e}")
            self.errors.append({'phase': 'scan', 'error': f'Save failed: {str(e)}'})
        
        print()
        if vuln_findings:
            print_status(f"Found {len(vuln_findings)} potential vulnerabilities!", "warning")
            for vuln in vuln_findings[:5]:
                print_status(f"  \u2192 {vuln['type']} [{vuln['severity']}]: {vuln.get('url', 'N/A')[:50]}...", "found")
        else:
            print_status("No vulnerabilities detected", "success")
        print_status(f"Results saved to {output_file}", "info")
        return True

    def phase4_recon(self) -> bool:
        """
        Phase 4: AWS Recon - Detect backend origins
        
        Detects:
            - Amazon S3 buckets
            - Elastic Load Balancing (ALB/NLB)
            - Amazon EC2 instances
            - AWS Elemental MediaPackage/MediaStore
            - Custom HTTP servers
        
        Returns:
            True if recon succeeded, False otherwise
        """
        print_phase_header(4, "AWS Backend Reconnaissance", "Identifying CDN/backend origin exposure and AWS services")
        logger.info("Starting Phase 4: AWS Reconnaissance - Backend Detection")
        
        print_status("Backend detection targets:", "info")
        print_status("  \u2022 Amazon S3 buckets", "info")
        print_status("  \u2022 Elastic Load Balancers (ALB/NLB)", "info")
        print_status("  \u2022 Amazon EC2 instances", "info")
        print_status("  \u2022 AWS Elemental MediaPackage/MediaStore", "info")
        print_status("  \u2022 Custom HTTP servers", "info")
        print()
        
        domain = urlparse(self.target).netloc.replace('.cloudfront.net', '')
        
        # Initialize results containers
        s3_buckets = []
        load_balancers = []
        ec2_instances = []
        media_services = []
        custom_servers = []
        backend_indicators = {}
        
        # ========== 1. S3 Bucket Detection ==========
        print_status("Checking for S3 bucket origins...", "scanning")
        bucket_guesses = [
            f"{domain}-{suffix}" 
            for suffix in ['prod', 'staging', 'backup', 'assets', 'static', 'dev', 'media', 'cdn', 'content', 'files']
        ]
        print_status(f"Testing {len(bucket_guesses)} bucket name variations...", "progress")
        
        with GracefulErrorHandler("s3_recon", continue_on_error=True):
            for bucket in bucket_guesses:
                try:
                    resp = safe_request(
                        f"https://s3.amazonaws.com/{bucket}/",
                        method='HEAD',
                        timeout=5
                    )
                    if resp and resp.status_code in [403, 200]:
                        s3_buckets.append({
                            'name': bucket,
                            'status': resp.status_code,
                            'accessible': resp.status_code == 200,
                            'type': 'S3'
                        })
                        status_text = "ACCESSIBLE" if resp.status_code == 200 else "exists (private)"
                        print_status(f"S3 bucket found: {bucket} - {status_text}", "found")
                        logger.info(f"Found S3 bucket: {bucket} ({resp.status_code})")
                except Exception as e:
                    logger.debug(f"S3 check failed for {bucket}: {e}")
        
        # ========== 2. Backend Header Analysis ==========
        print_status("Analyzing response headers for backend fingerprinting...", "scanning")
        with GracefulErrorHandler("header_analysis", continue_on_error=True):
            try:
                resp = safe_request(self.target, method='GET', timeout=10)
                if resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    backend_indicators = self._analyze_backend_headers(headers, resp.text)
            except Exception as e:
                logger.debug(f"Header analysis failed: {e}")
        
        # ========== 3. Elastic Load Balancer (ALB/NLB) Detection ==========
        print_status("Checking for ELB/ALB/NLB origins...", "scanning")
        elb_patterns = [
            f"{domain}.elb.amazonaws.com",
            f"{domain}.us-east-1.elb.amazonaws.com",
            f"{domain}.us-west-2.elb.amazonaws.com",
            f"{domain}.eu-west-1.elb.amazonaws.com",
            f"{domain}-alb.us-east-1.elb.amazonaws.com",
            f"{domain}-nlb.us-east-1.elb.amazonaws.com",
        ]
        
        # Check for ELB indicators in headers
        if backend_indicators.get('elb_detected'):
            load_balancers.append({
                'type': 'ELB/ALB/NLB',
                'indicator': backend_indicators.get('elb_indicator', 'Header detection'),
                'confidence': 'high'
            })
        
        with GracefulErrorHandler("elb_recon", continue_on_error=True):
            for elb_host in elb_patterns:
                try:
                    resp = safe_request(
                        f"https://{elb_host}/",
                        method='HEAD',
                        timeout=5,
                        verify=False
                    )
                    if resp and resp.status_code < 500:
                        load_balancers.append({
                            'hostname': elb_host,
                            'status': resp.status_code,
                            'type': 'ELB',
                            'confidence': 'medium'
                        })
                        logger.info(f"Found potential ELB: {elb_host}")
                except Exception as e:
                    logger.debug(f"ELB check failed for {elb_host}: {e}")
        
        # ========== 4. EC2 Instance Detection ==========
        print_status("Checking for EC2 instance origins...", "scanning")
        ec2_regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1']
        
        # Check for EC2 indicators in headers
        if backend_indicators.get('ec2_detected'):
            ec2_instances.append({
                'type': 'EC2',
                'indicator': backend_indicators.get('ec2_indicator', 'Header detection'),
                'confidence': 'high'
            })
        
        # EC2 public DNS patterns
        ec2_patterns = [
            f"ec2-{domain.replace('.', '-')}.compute-1.amazonaws.com",
        ]
        for region in ec2_regions:
            ec2_patterns.append(f"ec2-{domain.replace('.', '-')}.{region}.compute.amazonaws.com")
        
        with GracefulErrorHandler("ec2_recon", continue_on_error=True):
            for ec2_host in ec2_patterns[:5]:  # Limit checks
                try:
                    resp = safe_request(
                        f"http://{ec2_host}/",
                        method='HEAD',
                        timeout=3,
                        verify=False
                    )
                    if resp and resp.status_code < 500:
                        ec2_instances.append({
                            'hostname': ec2_host,
                            'status': resp.status_code,
                            'type': 'EC2',
                            'confidence': 'medium'
                        })
                        logger.info(f"Found potential EC2: {ec2_host}")
                except Exception as e:
                    logger.debug(f"EC2 check failed for {ec2_host}: {e}")
        
        # ========== 5. AWS Elemental MediaPackage/MediaStore Detection ==========
        print_status("Checking for MediaPackage/MediaStore origins...", "scanning")
        media_patterns = [
            f"{domain}.mediapackage.us-east-1.amazonaws.com",
            f"{domain}.mediastore.us-east-1.amazonaws.com",
            f"{domain}.data.mediastore.us-east-1.amazonaws.com",
        ]
        
        # Check for Media Services indicators in headers
        if backend_indicators.get('media_detected'):
            media_services.append({
                'type': backend_indicators.get('media_type', 'MediaServices'),
                'indicator': backend_indicators.get('media_indicator', 'Header detection'),
                'confidence': 'high'
            })
        
        with GracefulErrorHandler("media_recon", continue_on_error=True):
            for media_host in media_patterns:
                try:
                    resp = safe_request(
                        f"https://{media_host}/",
                        method='HEAD',
                        timeout=5
                    )
                    if resp and resp.status_code in [200, 403, 401]:
                        service_type = 'MediaPackage' if 'mediapackage' in media_host else 'MediaStore'
                        media_services.append({
                            'hostname': media_host,
                            'status': resp.status_code,
                            'type': service_type,
                            'confidence': 'medium'
                        })
                        logger.info(f"Found potential {service_type}: {media_host}")
                except Exception as e:
                    logger.debug(f"Media service check failed for {media_host}: {e}")
        
        # ========== 6. Custom HTTP Server Detection ==========
        print_status("Detecting custom HTTP server origins...", "scanning")
        if backend_indicators.get('server_software'):
            custom_servers.append({
                'type': 'Custom HTTP Server',
                'server': backend_indicators.get('server_software'),
                'powered_by': backend_indicators.get('powered_by', 'Unknown'),
                'confidence': 'high'
            })
            print_status(f"Server detected: {backend_indicators.get('server_software')}", "found")
        
        # ========== Compile Results ==========
        self.results['aws'] = {
            's3_buckets': s3_buckets,
            'load_balancers': load_balancers,
            'ec2_instances': ec2_instances,
            'media_services': media_services,
            'custom_servers': custom_servers,
            'backend_indicators': backend_indicators
        }
        
        # Save results
        try:
            output_file = f"{self.output_dir}/backend_recon.json"
            with open(output_file, 'w') as f:
                json.dump(self.results['aws'], f, indent=2)
            logger.info(f"Backend recon results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save recon results: {e}")
            self.errors.append({'phase': 'recon', 'error': f'Save failed: {str(e)}'})
        
        # Print summary
        total_findings = len(s3_buckets) + len(load_balancers) + len(ec2_instances) + len(media_services) + len(custom_servers)
        print()
        print_status("Backend Detection Summary:", "success")
        print_status(f"  \u2022 S3 Buckets: {len(s3_buckets)}", "info")
        print_status(f"  \u2022 Load Balancers (ALB/NLB): {len(load_balancers)}", "info")
        print_status(f"  \u2022 EC2 Instances: {len(ec2_instances)}", "info")
        print_status(f"  \u2022 MediaPackage/MediaStore: {len(media_services)}", "info")
        print_status(f"  \u2022 Custom HTTP Servers: {len(custom_servers)}", "info")
        print_status(f"Total backend origins detected: {total_findings}", "success" if total_findings > 0 else "info")
        print_status(f"Results saved to {output_file}", "info")
        
        return True

    def _analyze_backend_headers(self, headers: Dict[str, str], body: str = "") -> Dict[str, Any]:
        """
        Analyze HTTP response headers to identify backend origin type
        
        Args:
            headers: Response headers (lowercase keys)
            body: Response body text
        
        Returns:
            Dictionary with detected backend indicators
        """
        indicators = {}
        
        # S3 Detection
        s3_headers = ['x-amz-request-id', 'x-amz-id-2', 'x-amz-bucket-region']
        for h in s3_headers:
            if h in headers:
                indicators['s3_detected'] = True
                indicators['s3_indicator'] = f"Header: {h}"
                break
        
        if 'server' in headers and 'AmazonS3' in headers['server']:
            indicators['s3_detected'] = True
            indicators['s3_indicator'] = "Server: AmazonS3"
        
        # ELB/ALB/NLB Detection
        elb_indicators = [
            ('x-amzn-requestid', 'ALB/NLB'),
            ('x-amzn-trace-id', 'ALB'),
            ('x-amz-apigw-id', 'API Gateway + ALB'),
        ]
        for header, lb_type in elb_indicators:
            if header in headers:
                indicators['elb_detected'] = True
                indicators['elb_indicator'] = f"Header: {header}"
                indicators['elb_type'] = lb_type
                break
        
        # Check for ELB in Via header
        if 'via' in headers and 'elb' in headers['via'].lower():
            indicators['elb_detected'] = True
            indicators['elb_indicator'] = f"Via header: {headers['via']}"
        
        # EC2 Detection
        ec2_headers = ['x-amz-meta-', 'x-amz-version-id']
        for h in ec2_headers:
            matching = [k for k in headers if h in k]
            if matching:
                indicators['ec2_detected'] = True
                indicators['ec2_indicator'] = f"Header pattern: {h}"
                break
        
        # Check Server header for common EC2 web servers
        if 'server' in headers:
            server = headers['server'].lower()
            ec2_servers = ['apache', 'nginx', 'tomcat', 'iis', 'gunicorn', 'uvicorn', 'node']
            for srv in ec2_servers:
                if srv in server:
                    indicators['ec2_detected'] = True
                    indicators['ec2_indicator'] = f"Server: {headers['server']}"
                    break
        
        # MediaPackage/MediaStore Detection
        media_headers = ['x-mediapackage-request-id', 'x-mediastore-']
        for h in media_headers:
            matching = [k for k in headers if h in k]
            if matching:
                indicators['media_detected'] = True
                indicators['media_indicator'] = f"Header: {matching[0]}"
                indicators['media_type'] = 'MediaPackage' if 'mediapackage' in h else 'MediaStore'
                break
        
        # Check Content-Type for streaming media
        if 'content-type' in headers:
            ct = headers['content-type'].lower()
            media_types = ['application/x-mpegurl', 'video/mp4', 'application/dash+xml', 'video/mp2t']
            for mt in media_types:
                if mt in ct:
                    indicators['media_content_detected'] = True
                    indicators['media_content_type'] = ct
                    break
        
        # Custom HTTP Server Detection
        if 'server' in headers:
            indicators['server_software'] = headers['server']
        
        if 'x-powered-by' in headers:
            indicators['powered_by'] = headers['x-powered-by']
        
        # API Gateway Detection
        if 'x-amz-apigw-id' in headers or 'x-amzn-requestid' in headers:
            indicators['api_gateway_detected'] = True
            indicators['api_gateway_indicator'] = 'API Gateway headers present'
        
        # Lambda@Edge / Lambda Detection
        if 'x-amz-cf-id' in headers or 'x-cache' in headers:
            indicators['cloudfront_confirmed'] = True
        
        if 'x-amz-function-error' in headers or 'x-amz-executed-version' in headers:
            indicators['lambda_detected'] = True
            indicators['lambda_indicator'] = 'Lambda execution headers'
        
        return indicators

    def phase5_report(self) -> bool:
        """
        Phase 5: Generate Report
        
        Returns:
            True if report generated successfully, False otherwise
        """
        print_phase_header(5, "Report Generation", "Compiling findings into comprehensive security report")
        logger.info("Starting Phase 5: Report Generation")
        
        print_status("Gathering scan results...", "progress")
        
        try:
            vulns = self.results.get('vulns', [])
            aws_data = self.results.get('aws', {})
            s3 = aws_data.get('s3_buckets', [])
            load_balancers = aws_data.get('load_balancers', [])
            ec2_instances = aws_data.get('ec2_instances', [])
            media_services = aws_data.get('media_services', [])
            custom_servers = aws_data.get('custom_servers', [])
            backend_indicators = aws_data.get('backend_indicators', {})
            live_paths = self.results.get('live_paths', [])
            
            # Calculate risk score (updated to include all backend types)
            risk_score = (
                len(self.bypasses) * 2 + 
                len(vulns) * 5 + 
                len([b for b in s3 if b.get('accessible')]) * 3 +
                len(load_balancers) * 1 +
                len(ec2_instances) * 2
            )
            risk_level = 'CRITICAL' if risk_score > 20 else 'HIGH' if risk_score > 10 else 'MEDIUM' if risk_score > 5 else 'LOW'
            
            # Total backend origins detected
            total_backends = len(s3) + len(load_balancers) + len(ec2_instances) + len(media_services) + len(custom_servers)
            
            report = f"""# WAFPierce Penetration Test Report
**Target:** {self.target}  
**Date:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Risk Level:** {risk_level} (Score: {risk_score})

## Executive Summary
| Metric | Count |
|--------|-------|
| WAF Bypasses | {len(self.bypasses)} |
| Live Paths | {len(live_paths)} |
| Vulnerabilities | {len(vulns)} |
| **Backend Origins Detected** | **{total_backends}** |
| S3 Buckets | {len(s3)} |
| Load Balancers (ALB/NLB) | {len(load_balancers)} |
| EC2 Instances | {len(ec2_instances)} |
| MediaPackage/MediaStore | {len(media_services)} |
| Custom HTTP Servers | {len(custom_servers)} |

## 1. WAF Bypass Findings

### Critical Bypasses
"""
            
            # Add top 3 critical bypasses
            critical_bypasses = [b for b in self.bypasses if b.get('severity') == 'CRITICAL'][:3]
            if critical_bypasses:
                report += "```json\n" + json.dumps(critical_bypasses, indent=2) + "\n```\n\n"
            else:
                report += "No critical bypasses found.\n\n"
            
            # Add vulnerabilities
            report += "## 2. Vulnerabilities\n\n"
            if vulns:
                for v in vulns[:5]:  # Top 5
                    report += f"- **{v['type']}** ({v['severity']}): `{v['url']}`\n"
            else:
                report += "No vulnerabilities detected.\n"
            
            # Add Backend Origin Findings (expanded section)
            report += "\n## 3. Backend Origin Detection\n\n"
            
            # S3 Buckets
            report += "### 3.1 Amazon S3 Buckets\n\n"
            if s3:
                for bucket in s3:
                    status = "✅ ACCESSIBLE" if bucket.get('accessible') else "🔒 Private"
                    report += f"- `{bucket['name']}` - {status}\n"
            else:
                report += "No S3 buckets detected.\n"
            
            # Load Balancers
            report += "\n### 3.2 Elastic Load Balancers (ALB/NLB)\n\n"
            if load_balancers:
                for lb in load_balancers:
                    confidence = lb.get('confidence', 'unknown')
                    hostname = lb.get('hostname', lb.get('indicator', 'N/A'))
                    lb_type = lb.get('type', 'ELB')
                    report += f"- `{hostname}` - Type: {lb_type} (Confidence: {confidence})\n"
            else:
                report += "No load balancers detected.\n"
            
            # EC2 Instances
            report += "\n### 3.3 Amazon EC2 Instances\n\n"
            if ec2_instances:
                for ec2 in ec2_instances:
                    confidence = ec2.get('confidence', 'unknown')
                    hostname = ec2.get('hostname', ec2.get('indicator', 'N/A'))
                    report += f"- `{hostname}` (Confidence: {confidence})\n"
            else:
                report += "No EC2 instances detected.\n"
            
            # MediaPackage/MediaStore
            report += "\n### 3.4 AWS Elemental MediaPackage/MediaStore\n\n"
            if media_services:
                for media in media_services:
                    media_type = media.get('type', 'MediaServices')
                    hostname = media.get('hostname', media.get('indicator', 'N/A'))
                    confidence = media.get('confidence', 'unknown')
                    report += f"- `{hostname}` - Type: {media_type} (Confidence: {confidence})\n"
            else:
                report += "No MediaPackage/MediaStore services detected.\n"
            
            # Custom HTTP Servers
            report += "\n### 3.5 Custom HTTP Servers\n\n"
            if custom_servers:
                for srv in custom_servers:
                    server_name = srv.get('server', 'Unknown')
                    powered_by = srv.get('powered_by', 'Unknown')
                    report += f"- Server: `{server_name}`"
                    if powered_by != 'Unknown':
                        report += f" | Powered by: `{powered_by}`"
                    report += "\n"
            else:
                report += "No custom HTTP servers detected.\n"
            
            # Backend Indicators Summary
            if backend_indicators:
                report += "\n### 3.6 Backend Indicators (Header Analysis)\n\n"
                report += "```json\n" + json.dumps(backend_indicators, indent=2) + "\n```\n\n"
            
            # Prepare S3 remediation message
            accessible_s3 = [b['name'] for b in s3 if b.get('accessible')]
            s3_remediation = (
                f"- Restrict public access to: {', '.join(accessible_s3)}"
                if accessible_s3
                else "- All buckets are properly secured"
            )
            
            # Add remediation
            report += f"""
## 4. Remediation Recommendations

### High Priority
1. **WAF Configuration**: Review and strengthen WAF rules
   - Block suspicious header combinations (X-Forwarded-For: 127.0.0.1, etc.)
   - Implement strict Host header validation
   - Add rate limiting per IP

2. **Input Validation**: Sanitize all user inputs
   - Escape special characters in parameters
   - Implement Content Security Policy (CSP)

3. **S3 Security**: Review S3 bucket permissions
   {s3_remediation}

4. **Backend Origin Security**:
    - Ensure all backend origins (ELB, EC2, etc.) are only accessible via your approved CDN/edge layer
   - Implement origin access controls
   - Use security groups to restrict direct access to EC2/ELB origins
   - Enable WAF on ALB if detected

### Medium Priority
- Implement request signing
- Add additional authentication layers
- Review CDN/edge distribution settings
- Enable CDN/edge access logs
- Use AWS WAF on all detected load balancers

## 5. Testing Methodology
This assessment used the following techniques:
- WAF/CDN bypass testing (12 techniques)
- Directory enumeration ({len(live_paths)} paths found)
- Vulnerability scanning (XSS, injection)
- AWS resource enumeration:
  - S3 bucket discovery
  - ELB/ALB/NLB detection
  - EC2 instance fingerprinting
  - MediaPackage/MediaStore detection
  - HTTP server header analysis

## 6. Errors Encountered
"""
            if self.errors:
                for error in self.errors:
                    report += f"- Phase {error['phase']}: {error['error']}\n"
            else:
                report += "No errors encountered during testing.\n"
            
            report += """
---
**Disclaimer:** This report is for authorized security testing only. 
Handle findings responsibly and patch vulnerabilities promptly.
"""
            
            # Save report
            report_file = f"{self.output_dir}/REPORT.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            logger.info(f"Report generated: {report_file}")
            print()
            print_status("Report generated successfully!", "success")
            print_status(f"Risk Level: {risk_level} (Score: {risk_score})", "info")
            print_status(f"Report saved to: {report_file}", "info")
            return True
        
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print_status(f"Error generating report: {e}", "error")
            self.errors.append({'phase': 'report', 'error': str(e)})
            return False
    def run(self) -> int:
        """
        Execute full penetration test chain
        
        Returns:
            Exit code: 0 = success, 1 = failures occurred
        """
        # Display banner and disclaimer
        print_banner()
        
        border = '═' if USE_EMOJIS else '='
        safe_print(f"{border*78}")
        safe_print(f"  TARGET: {self.target}")
        safe_print(f"  OUTPUT: {self.output_dir}/")
        safe_print(f"  THREADS: {self.threads}")
        safe_print(f"{border*78}")
        
        logger.info(f"Starting full pentest chain for {self.target}")
        
        phases = [
            ('Bypass', self.phase1_bypass),
            ('Enumeration', self.phase2_enum),
            ('Vulnerability Scan', self.phase3_scan),
            ('AWS Recon', self.phase4_recon),
            ('Report', self.phase5_report),
        ]
        
        completed_phases = 0
        failed_phases = []
        
        for phase_name, phase_func in phases:
            try:
                success = phase_func()
                if success:
                    completed_phases += 1
                else:
                    logger.warning(f"Phase {phase_name} completed with limited results")
            except KeyboardInterrupt:
                logger.warning(f"Pentest interrupted during {phase_name}")
                safe_print(f"\n[!] Interrupted during {phase_name} phase")
                break
            except Exception as e:
                logger.error(f"Phase {phase_name} failed: {e}")
                safe_print(f"    [!] Error in {phase_name}: {e}")
                failed_phases.append(phase_name)
                # Continue with next phase
        
        # Final summary
        safe_print(f"\n{border*78}")
        safe_print(f"{border}  SCAN COMPLETE")
        safe_print(f"{border*78}")
        safe_print(f"  {get_icon('success')} Phases completed: {completed_phases}/{len(phases)}")
        if failed_phases:
            safe_print(f"  {get_icon('error')} Phases failed: {', '.join(failed_phases)}")
        if self.errors:
            safe_print(f"  {get_icon('warning')} Errors encountered: {len(self.errors)}")
        safe_print(f"  {get_icon('folder')} Output directory: {self.output_dir}/")
        safe_print(f"  {get_icon('file')} Files generated:")
        safe_print(f"       - bypasses.json")
        safe_print(f"       - live_paths.json")
        safe_print(f"       - vulns.json")
        safe_print(f"       - backend_recon.json")
        safe_print(f"       - REPORT.md")
        safe_print(f"{border*78}\n")
        safe_print(f"{get_icon('lock')} Remember: Use findings responsibly and report vulnerabilities ethically!\n")
        
        logger.info(f"Pentest complete: {completed_phases}/{len(phases)} phases successful")
        
        return 0 if completed_phases == len(phases) else 1

def main():
    """Main entry point with comprehensive error handling"""
    from argparse import ArgumentParser
    
    parser = ArgumentParser(description='WAFPierce Full WAF/CDN Penetration Test Chain')
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", default="pentest_results", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--log-file", help="Log file path")
    parser.add_argument("--log-level", default="INFO",
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help="Logging level")
    args = parser.parse_args()
    
    # Validate threads parameter
    if args.threads < 1 or args.threads > 100:
        print("[!] Thread count must be between 1 and 100")
        sys.exit(1)
    
    # Setup logging
    setup_logging(args.log_file, args.log_level)
    
    try:
        chain = FullPentestChain(args.target, args.output, args.threads)
        exit_code = chain.run()
        sys.exit(exit_code)
    
    except KeyboardInterrupt:
        print("\n[!] Pentest interrupted by user")
        logger.warning("Pentest interrupted by user (Ctrl+C)")
        sys.exit(130)
    
    except WAFPierceError as e:
        print(f"[!] WAFPierce Error: {e}")
        logger.error(f"WAFPierce error: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        logger.exception("Unexpected error during pentest chain")
        sys.exit(1)


if __name__ == "__main__":
    main()