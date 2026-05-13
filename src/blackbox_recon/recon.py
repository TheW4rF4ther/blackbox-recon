"""Core reconnaissance engine."""

import asyncio
import json
import socket
import subprocess
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


@dataclass
class SubdomainResult:
    """Subdomain enumeration result."""
    subdomain: str
    ip_addresses: List[str]
    status_code: Optional[int] = None
    server: Optional[str] = None
    technologies: List[str] = None


@dataclass
class PortScanResult:
    """Port scan result."""
    host: str
    port: int
    state: str  # open, closed, filtered
    service: Optional[str] = None
    version: Optional[str] = None


@dataclass
class TechnologyResult:
    """Technology detection result."""
    url: str
    technologies: List[Dict[str, str]]
    headers: Dict[str, str]
    interesting_headers: List[str] = None


class SubdomainEnumerator:
    """Subdomain enumeration module."""
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap",
        "test", "ns", "blog", "pop3", "dev", "www2", "portal", "admin", "wiki",
        "api", "staging", "login", "signin", "register", "signup", "support",
        "help", "docs", "documentation", "forum", "shop", "store", "app", "mobile",
        "api-v1", "api-v2", "graphql", "rest", "cdn", "static", "assets", "media",
        "files", "download", "uploads", "img", "images", "video", "videos",
        "git", "svn", "cvs", "jenkins", "ci", "build", "deploy", "docker",
        "kubernetes", "k8s", "grafana", "prometheus", "zabbix", "nagios",
        "elastic", "elasticsearch", "kibana", "logstash", "splunk",
        "db", "database", "mysql", "postgres", "mongodb", "redis", "memcached",
        "vpn", "remote", "rdp", "ssh", "sftp", "ftp", "smb", "nfs",
        "backup", "archive", "snapshots", "old", "legacy", "v1", "v2", "v3",
        "internal", "intranet", "corp", "corporate", "hr", "finance", "accounting",
        "sales", "marketing", "it", "helpdesk", "support", "security", "soc"
    ]
    
    def __init__(self, threads: int = 50, wordlist: Optional[str] = None):
        self.threads = threads
        self.wordlist = wordlist
        
    async def enumerate(self, domain: str) -> List[SubdomainResult]:
        """Enumerate subdomains for a target domain."""
        print(f"[+] Enumerating subdomains for {domain}...")
        
        subdomains = set()
        
        # DNS brute force with common subdomains
        tasks = []
        for sub in self.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            tasks.append(self._check_subdomain(subdomain))
        
        # Run with semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.threads)
        
        async def bounded_check(sub):
            async with semaphore:
                return await sub
        
        results = await asyncio.gather(*[bounded_check(t) for t in tasks])
        
        valid_results = [r for r in results if r is not None]
        print(f"[+] Found {len(valid_results)} valid subdomains")
        
        return valid_results
    
    async def _check_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Check if a subdomain exists."""
        try:
            # DNS resolution
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                socket.gethostbyname_ex, 
                subdomain
            )
            
            hostname, aliaslist, ipaddrlist = result
            
            # Try HTTP request to get more info
            try:
                url = f"http://{subdomain}"
                response = requests.get(url, timeout=5, allow_redirects=True)
                server = response.headers.get('Server', 'Unknown')
                return SubdomainResult(
                    subdomain=subdomain,
                    ip_addresses=ipaddrlist,
                    status_code=response.status_code,
                    server=server,
                    technologies=[]
                )
            except:
                return SubdomainResult(
                    subdomain=subdomain,
                    ip_addresses=ipaddrlist,
                    status_code=None,
                    server=None,
                    technologies=[]
                )
        except:
            return None


class PortScanner:
    """Port scanning module."""
    
    TOP_PORTS = [
        80, 443, 21, 22, 25, 53, 110, 143, 3306, 3389, 445, 139, 8080, 8443,
        23, 81, 88, 111, 135, 161, 389, 443, 445, 500, 514, 593, 636, 993,
        995, 1080, 1433, 1521, 2049, 3128, 3306, 3389, 5432, 5900, 5901, 5985,
        6379, 7001, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 10000
    ]
    
    SERVICE_NAMES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
        993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
        3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
        5901: "vnc-1", 6379: "redis", 8080: "http-proxy", 8443: "https-alt"
    }
    
    def __init__(self, ports: str = "top1000", timeout: int = 3):
        self.timeout = timeout
        
        if ports == "top100":
            self.ports = self.TOP_PORTS[:100]
        elif ports == "top1000":
            self.ports = self.TOP_PORTS
        elif ports == "all":
            self.ports = list(range(1, 65536))
        else:
            # Custom ports
            self.ports = [int(p.strip()) for p in ports.split(",")]
    
    async def scan(self, host: str) -> List[PortScanResult]:
        """Scan ports on a host."""
        print(f"[+] Scanning {len(self.ports)} ports on {host}...")
        
        open_ports = []
        
        semaphore = asyncio.Semaphore(100)
        
        async def bounded_scan(port):
            async with semaphore:
                return await self._check_port(host, port)
        
        tasks = [bounded_scan(port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None and r.state == "open"]
        print(f"[+] Found {len(open_ports)} open ports on {host}")
        
        return open_ports
    
    async def _check_port(self, host: str, port: int) -> Optional[PortScanResult]:
        """Check if a port is open."""
        try:
            loop = asyncio.get_event_loop()
            
            # Create connection
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            service = self.SERVICE_NAMES.get(port, "unknown")
            
            return PortScanResult(
                host=host,
                port=port,
                state="open",
                service=service,
                version=None
            )
        except asyncio.TimeoutError:
            return PortScanResult(host=host, port=port, state="filtered", service=None, version=None)
        except:
            return None


class TechnologyDetector:
    """Technology detection module."""
    
    TECH_SIGNATURES = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla": ["/administrator/", "/components/"],
        "Drupal": ["/sites/default/", "/misc/drupal.js"],
        "Apache": ["Apache", "apache"],
        "Nginx": ["nginx", "Nginx"],
        "IIS": ["Microsoft-IIS", "IIS"],
        "PHP": ["PHP", ".php"],
        "ASP.NET": ["ASP.NET", "__VIEWSTATE"],
        "Jenkins": ["Jenkins", "/jenkins/", "/job/"],
        "Tomcat": ["Apache Tomcat", "/manager/html"],
        "GitLab": ["GitLab", "/explore"],
        "phpMyAdmin": ["phpMyAdmin", "pma"],
        "React": ["react", "reactjs"],
        "Angular": ["angular", "ng-app"],
        "Vue.js": ["vue", "vuejs"],
        "jQuery": ["jquery", "jQuery"],
        "Bootstrap": ["bootstrap", "bootstrap.css"],
    }
    
    INTERESTING_HEADERS = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-Frame-Options",
        "Content-Security-Policy", "X-Content-Type-Options", "X-XSS-Protection",
        "Set-Cookie", "Authorization", "WWW-Authenticate"
    ]
    
    async def detect(self, url: str) -> Optional[TechnologyResult]:
        """Detect technologies on a URL."""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            
            technologies = []
            content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            # Detect from content and headers
            for tech, signatures in self.TECH_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in content or sig.lower() in headers_str:
                        technologies.append({"name": tech, "confidence": "medium"})
                        break
            
            # Extract interesting headers
            interesting = []
            for header in self.INTERESTING_HEADERS:
                if header in response.headers:
                    interesting.append(f"{header}: {response.headers[header]}")
            
            return TechnologyResult(
                url=url,
                technologies=technologies,
                headers=dict(response.headers),
                interesting_headers=interesting
            )
        except Exception as e:
            return None


class ReconEngine:
    """Main reconnaissance engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.subdomain_enumerator = SubdomainEnumerator(
            threads=config.get("threads", 50),
            wordlist=config.get("wordlist")
        )
        self.port_scanner = PortScanner(
            ports=config.get("ports", "top1000"),
            timeout=config.get("timeout", 3)
        )
        self.tech_detector = TechnologyDetector()
        self.results = {
            "target": None,
            "timestamp": None,
            "subdomains": [],
            "ports": [],
            "technologies": [],
            "summary": {}
        }
    
    async def run(self, target: str, modules: List[str]) -> Dict[str, Any]:
        """Run reconnaissance with specified modules."""
        from datetime import datetime
        
        self.results["target"] = target
        self.results["timestamp"] = datetime.now().isoformat()
        
        print(f"\n[+] Starting reconnaissance on {target}")
        print("=" * 50)
        
        tasks = []
        
        if "subdomain" in modules:
            subdomains = await self.subdomain_enumerator.enumerate(target)
            self.results["subdomains"] = [asdict(s) for s in subdomains]
        
        if "portscan" in modules:
            # Get unique IPs from subdomains or use target
            ips = set()
            for sub in self.results["subdomains"]:
                ips.update(sub.get("ip_addresses", []))
            
            if not ips:
                try:
                    ip = socket.gethostbyname(target)
                    ips.add(ip)
                except:
                    pass
            
            all_ports = []
            for ip in ips:
                ports = await self.port_scanner.scan(ip)
                all_ports.extend(ports)
            
            self.results["ports"] = [asdict(p) for p in all_ports]
        
        if "technology" in modules:
            urls_to_check = [f"http://{target}", f"https://{target}"]
            for sub in self.results["subdomains"][:10]:  # Limit to first 10
                urls_to_check.append(f"http://{sub['subdomain']}")
            
            tech_results = []
            for url in urls_to_check:
                result = await self.tech_detector.detect(url)
                if result:
                    tech_results.append(asdict(result))
            
            self.results["technologies"] = tech_results
        
        # Generate summary
        self.results["summary"] = {
            "total_subdomains": len(self.results["subdomains"]),
            "total_open_ports": len(self.results["ports"]),
            "total_tech_detected": len(self.results["technologies"]),
            "web_services": len([s for s in self.results["subdomains"] if s.get("status_code")])
        }
        
        print("\n[+] Reconnaissance complete")
        print(f"    Subdomains: {self.results['summary']['total_subdomains']}")
        print(f"    Open Ports: {self.results['summary']['total_open_ports']}")
        print(f"    Web Services: {self.results['summary']['web_services']}")
        
        return self.results
    
    def save_results(self, output_file: str, format: str = "json"):
        """Save results to file."""
        if format == "json":
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
        # Add other formats as needed
        
        print(f"[+] Results saved to: {output_file}")
