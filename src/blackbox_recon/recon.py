"""Core reconnaissance engine."""

import asyncio
import ipaddress
import socket
from datetime import datetime
from functools import partial
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict

import requests
import urllib3
from bs4 import BeautifulSoup

# Technology probes intentionally skip TLS verification (self-signed / lab targets).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich import print as rprint
from rich.markup import escape

from .nmap_top1000_tcp import NMAP_TOP1000_TCP
from .service_detection import (
    find_nmap_executable,
    probe_tcp_service,
    run_nmap_service_scan,
    run_nmap_aggressive_scan,
    parse_nmap_xml_open_tcp_ports,
)
from .dns_intel import run_nslookup
from .dir_scan import run_directory_scan, resolve_directory_wordlist
from .reporting import dumps_pretty, build_executive_snapshot, utc_now_iso
from .evidence import build_evidence_package, _http_like_port_row
from .engagement import EngagementRuntime, scope_allows_host
from .kali_platform import ensure_kali_toolchain
from .methodology import build_methodology_block
from .execution_trace import PhaseTracer, print_execution_recap


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
    banner: Optional[str] = None  # truncated raw probe or script excerpt
    scripts: Optional[List[str]] = None  # nmap script output lines (aggressive scan)


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
        rprint(f"[bold green]{escape('[+]')}[/bold green] Enumerating subdomains for [cyan]{escape(domain)}[/cyan]…")
        
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
        rprint(
            f"[bold green]{escape('[+]')}[/bold green] Found [yellow]{len(valid_results)}[/yellow] valid subdomains"
        )
        
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
    """TCP connect port scan (Python asyncio). ``top1000`` uses Nmap's nmap-services frequency ordering."""

    SERVICE_NAMES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
        993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
        3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
        5901: "vnc-1", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    }

    def __init__(
        self,
        ports: str = "top1000",
        timeout: int = 6,
        service_detection: str = "auto",
        nmap_executable: Optional[str] = None,
        nmap_timeout_sec: int = 300,
        service_probe_timeout: float = 4.0,
    ):
        self.timeout = timeout
        self.service_detection = (service_detection or "auto").strip().lower()
        if self.service_detection not in ("none", "banner", "nmap", "auto"):
            self.service_detection = "auto"
        self.nmap_executable = nmap_executable
        self.nmap_timeout_sec = int(nmap_timeout_sec)
        self.service_probe_timeout = float(service_probe_timeout)
        nmap_full = list(NMAP_TOP1000_TCP)

        if ports == "top100":
            self.ports = nmap_full[:100]
        elif ports == "top1000":
            self.ports = nmap_full
        elif ports == "all":
            self.ports = list(range(1, 65536))
        else:
            self.ports = sorted({int(p.strip()) for p in ports.split(",") if p.strip()})

    def _service_name(self, port: int) -> str:
        if port in self.SERVICE_NAMES:
            return self.SERVICE_NAMES[port]
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    async def scan(self, host: str) -> List[PortScanResult]:
        """Scan ports on a host."""
        rprint(
            f"[bold green]{escape('[+]')}[/bold green] Scanning [yellow]{len(self.ports)}[/yellow] ports on "
            f"[cyan]{escape(host)}[/cyan]…"
        )

        # Limit parallel handshakes so cloud/WAF rate limits are less likely to drop valid opens.
        workers = 64 if len(self.ports) > 64 else max(8, min(len(self.ports), 32))
        semaphore = asyncio.Semaphore(workers)

        async def bounded_scan(port: int) -> Optional[PortScanResult]:
            async with semaphore:
                return await self._check_port(host, port)

        tasks = [bounded_scan(port) for port in self.ports]
        results = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r is not None and r.state == "open"]
        rprint(
            f"[bold green]{escape('[+]')}[/bold green] Found [yellow]{len(open_ports)}[/yellow] open ports on "
            f"[cyan]{escape(host)}[/cyan]"
        )
        await self._enrich_port_services(host, open_ports)

        return open_ports

    async def _enrich_port_services(self, host: str, open_ports: List[PortScanResult]) -> None:
        """Populate service names / versions via banner probe and optional ``nmap -sV``."""
        if self.service_detection == "none" or not open_ports:
            return

        if self.service_detection in ("banner", "auto"):
            rprint(
                f"[bold green]{escape('[+]')}[/bold green] Probing services (banner / HTTP) on "
                f"[yellow]{len(open_ports)}[/yellow] open port(s) for [cyan]{escape(host)}[/cyan]…"
            )
            sem = asyncio.Semaphore(16)

            async def _probe_one(p: PortScanResult) -> None:
                async with sem:
                    svc, ver, ban = await probe_tcp_service(
                        host, p.port, float(self.timeout), self.service_probe_timeout
                    )
                    if svc:
                        p.service = svc
                    if ver:
                        p.version = ver
                    if ban:
                        p.banner = ban

            await asyncio.gather(*[_probe_one(p) for p in open_ports])

        if self.service_detection in ("nmap", "auto"):
            exe = find_nmap_executable(self.nmap_executable)
            if exe:
                rprint(
                    f"[bold green]{escape('[+]')}[/bold green] Running nmap -sV on [cyan]{escape(host)}[/cyan] "
                    "(open ports only; may take several minutes)…"
                )
                loop = asyncio.get_running_loop()

                def _nmap() -> bool:
                    return run_nmap_service_scan(host, open_ports, exe, self.nmap_timeout_sec)

                ok = await loop.run_in_executor(None, _nmap)
                if not ok and self.service_detection == "nmap":
                    rprint(
                        f"[bold red]{escape('[!]')}[/bold red] nmap service scan failed or returned no parseable "
                        f"XML for [cyan]{escape(host)}[/cyan]"
                    )
                elif not ok:
                    rprint(
                        f"[bold red]{escape('[!]')}[/bold red] nmap service scan skipped or failed for "
                        f"[cyan]{escape(host)}[/cyan]; using banner data if any"
                    )
            elif self.service_detection == "nmap":
                rprint(
                    f"[bold red]{escape('[!]')}[/bold red] nmap not found. Install Nmap or set "
                    f"[yellow]recon.nmap_executable[/yellow] in config; falling back to banner-only for this run."
                )

    async def _check_port(self, host: str, port: int) -> Optional[PortScanResult]:
        """TCP connect probe; treats successful handshake as open."""
        writer: Optional[asyncio.StreamWriter] = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            return PortScanResult(
                host=host, port=port, state="filtered", service=None, version=None
            )
        except (ConnectionRefusedError, ConnectionResetError, OSError):
            return None
        except Exception:
            return None

        service = self._service_name(port)
        result = PortScanResult(
            host=host,
            port=port,
            state="open",
            service=service,
            version=None,
        )

        if writer is not None:
            try:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
            except Exception:
                pass

        return result


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
        except Exception:
            return None


_WEBISH_PORTS = frozenset(
    {
        80,
        81,
        443,
        591,
        800,
        8008,
        8080,
        8081,
        8088,
        8180,
        8888,
        8443,
        9443,
        8000,
        3000,
        5000,
        8880,
    }
)


def web_urls_from_port_rows(ports: List[Dict[str, Any]]) -> List[str]:
    """Derive http(s) base URLs from open ports suitable for directory bruteforce."""
    seen: Set[str] = set()
    out: List[str] = []
    for row in ports:
        if not isinstance(row, dict) or row.get("state") != "open":
            continue
        host = row.get("host")
        port = row.get("port")
        if not host or not port:
            continue
        svc = (row.get("service") or "").lower()
        if port not in _WEBISH_PORTS and "http" not in svc:
            continue
        use_tls = port in (443, 8443, 9443, 8883) or "https" in svc or "ssl/http" in svc
        scheme = "https" if use_tls else "http"
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            netloc = str(host)
        else:
            netloc = f"{host}:{port}"
        u = f"{scheme}://{netloc}/"
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


class ReconEngine:
    """Main reconnaissance engine."""

    def __init__(
        self,
        config: Dict[str, Any],
        engagement_runtime: Optional[EngagementRuntime] = None,
    ):
        self.config = config
        self._rt = engagement_runtime
        self.subdomain_enumerator = SubdomainEnumerator(
            threads=config.get("threads", 50),
            wordlist=config.get("wordlist"),
        )
        self.port_scanner = PortScanner(
            ports=config.get("ports", "top1000"),
            timeout=int(config.get("port_scan_timeout", config.get("timeout", 6))),
            service_detection=str(config.get("service_detection", "auto")),
            nmap_executable=config.get("nmap_executable"),
            nmap_timeout_sec=int(config.get("nmap_scan_timeout", 300)),
            service_probe_timeout=float(config.get("service_probe_timeout", 4.0)),
        )
        self.tech_detector = TechnologyDetector()
        self.results: Dict[str, Any] = {}

    def _gather_ipv4s(self, target: str) -> Set[str]:
        """Collect IPv4 addresses for the apex, enumerated subdomains, and direct resolution."""
        ips: Set[str] = set()
        for sub in self.results.get("subdomains", []):
            ips.update(sub.get("ip_addresses", []))

        def _add_ipv4_for_host(hostname: str) -> None:
            try:
                infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            except OSError:
                return
            for inf in infos:
                ip = inf[4][0]
                if ip:
                    ips.add(ip)

        _add_ipv4_for_host(target)
        for sub in self.results.get("subdomains", []):
            fqdn = sub.get("subdomain")
            if fqdn:
                _add_ipv4_for_host(fqdn)

        if not ips:
            try:
                ips.add(socket.gethostbyname(target))
            except OSError:
                pass
        if self._rt is not None:
            ips = {ip for ip in ips if self._host_allowed_for_active_scan(ip)}
        return ips

    def _host_allowed_for_active_scan(self, host: str) -> bool:
        """Enforce engagement allowed_targets for any host or IP we would actively touch."""
        if self._rt is None:
            return True
        h = host.strip().lower()
        if h in self._rt.scope_expanded_ips:
            return True
        ok, _ = scope_allows_host(h, self._rt.spec)
        return ok

    @staticmethod
    def _host_from_http_url(url: str) -> str:
        u = url.replace("http://", "").replace("https://", "")
        return u.split("/")[0].split(":")[0].strip().lower()

    async def run(self, target: str, modules: List[str]) -> Dict[str, Any]:
        """Run reconnaissance with specified modules."""
        started = utc_now_iso()
        self.results = {
            "schema_version": "2.2",
            "report_title": "Blackbox Recon — structured engagement findings",
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "recon_started_utc": started,
            "recon_completed_utc": None,
            "engagement": {
                "target": target,
                "modules_requested": list(modules),
                "recon_started_utc": started,
                "port_scan_mode": str(self.config.get("port_scan_mode", "nmap_aggressive")).lower(),
            },
            "executive_snapshot": {},
            "dns_intelligence": {"nslookups": []},
            "nmap_scan": {"mode": None, "per_host": []},
            "subdomains": [],
            "ports": [],
            "technologies": [],
            "web_content_discovery": {"directory_scans": [], "urls_targeted": []},
            "recon_phase_trace": [],
            "summary": {},
        }

        if self._rt is not None:
            self.results["engagement"]["record"] = self._rt.spec.model_dump()
            self.results["engagement"]["workspace_root"] = str(self._rt.paths["root"])
            self.results["engagement"]["methodology"] = {
                "execution_gates": "authorization, in_scope_asset, allowed_technique, action_reason",
                "enforced_at": "cli_before_subprocess",
            }
            self.results["engagement"]["scope_note"] = (
                "Subdomain enumeration may list assets beyond explicit allowed_targets; "
                "active scans (nmap, nslookup, gobuster, HTTP probes) are filtered to in-scope hosts only."
            )
            self._rt.audit("recon_engine_start", target=target, modules=list(modules))

        snap, install_err = ensure_kali_toolchain(
            self.config,
            auto_install=bool(self.config.get("kali_auto_install_missing", False)),
            apt_update_first=bool(self.config.get("kali_apt_update_before_install", False)),
        )
        self.results["platform_toolchain"] = snap
        self.results["recon_methodology"] = build_methodology_block(modules, self.config, snap)
        if install_err:
            rprint(f"[bold red]{escape('[!]')}[/bold red] Kali toolchain auto-install: [white]{escape(str(install_err))}[/white]")
        if (
            snap.get("is_kali")
            and (snap.get("missing_apt_packages") or [])
            and bool(self.config.get("kali_report_missing_tools", True))
            and not bool(self.config.get("kali_auto_install_missing", False))
        ):
            pkgs = " ".join(snap["missing_apt_packages"])
            rprint(
                f"[bold red]{escape('[!]')}[/bold red] Kali tool gaps for current config — install:\n"
                f"    [dim]sudo apt-get install -y[/dim] [cyan]{escape(pkgs)}[/cyan]\n"
                f"    Or: [yellow]blackbox-recon kali-setup --install[/yellow] (passwordless sudo required)"
            )

        rprint()
        rprint(
            f"[bold green]{escape('[+]')}[/bold green] Starting reconnaissance on [bold cyan]{escape(target)}[/bold cyan]"
        )
        rprint(f"[dim]{escape('=' * 50)}[/dim]")
        echo_phases = bool(self.config.get("recon_verbose_phases", True))
        tr = PhaseTracer(self.results, echo=echo_phases)

        if "subdomain" in modules:
            m1_lines = [
                "Stack: Python 3 — asyncio + socket.gethostbyname_ex + requests (HTTP probe where DNS resolves)",
                f"Wordlist: built-in {len(SubdomainEnumerator.COMMON_SUBDOMAINS)} common sub-labels against `{target}`",
            ]
            try:
                ipaddress.ip_address(target.strip())
                m1_lines.append(
                    "Note: target is a bare IP — DNS brute uses labels like `www.<target>`; expect few or no hits. "
                    "Use a hostname apex for meaningful subdomain discovery."
                )
            except ValueError:
                pass
            tr.start("M1", m1_lines)
            tr.note_command(
                "method",
                f"DNS brute: enumerate `{len(SubdomainEnumerator.COMMON_SUBDOMAINS)}` labels → gethostbyname_ex; "
                f"optional GET http://<fqdn>/ (timeout=5)",
            )
            subdomains = await self.subdomain_enumerator.enumerate(target)
            self.results["subdomains"] = [asdict(s) for s in subdomains]
            tr.note_command(
                "python_http_probe",
                "requests.get(http://<subdomain>/) for resolved hosts (same phase as DNS checks)",
                hosts_with_http_status=sum(1 for s in subdomains if s.status_code is not None),
            )
            tr.finish(
                "completed",
                f"{len(subdomains)} subdomain(s) with A records; "
                f"{sum(1 for s in subdomains if s.status_code is not None)} returned HTTP status",
            )
        else:
            tr.skip("M1", "subdomain module not in --modules")

        ips = self._gather_ipv4s(target)

        if bool(self.config.get("run_nslookup", True)):
            tr.start(
                "M2",
                [
                    "Stack: host `nslookup` binary (subprocess) — PTR / forward DNS intelligence",
                    f"Targets: {len(ips)} IPv4 address(es) plus apex string `{target}`",
                ],
            )
            loop = asyncio.get_running_loop()
            lookups: List[Dict[str, Any]] = []
            queried: Set[str] = set()
            for ip in sorted(ips):
                key = str(ip).strip()
                if key in queried:
                    continue
                queried.add(key)
                ns = await loop.run_in_executor(
                    None,
                    partial(
                        run_nslookup,
                        ip,
                        int(self.config.get("nslookup_timeout_sec", 120)),
                    ),
                )
                lookups.append(ns)
                cmd = ns.get("command") or f"nslookup {ip}"
                tr.note_command("nslookup", cmd, target=ip, exit_code=ns.get("exit_code"))
            apex = target.strip()
            if apex not in queried:
                ns_target = await loop.run_in_executor(
                    None,
                    partial(
                        run_nslookup,
                        target,
                        int(self.config.get("nslookup_timeout_sec", 120)),
                    ),
                )
                lookups.append(ns_target)
                cmdt = ns_target.get("command") or f"nslookup {target}"
                tr.note_command("nslookup", cmdt, target=target, exit_code=ns_target.get("exit_code"))
            else:
                tr.note_command(
                    "nslookup_skipped_duplicate",
                    f"Apex `{apex}` already covered by IP nslookup above; not run twice",
                )
            rprint(
                f"[bold green]{escape('[+]')}[/bold green] Running nslookup (PTR / forward hints): "
                f"[yellow]{len(lookups)}[/yellow] run(s) for [yellow]{len(queried)}[/yellow] unique IP(s) "
                "plus apex when needed"
            )
            self.results["dns_intelligence"]["nslookups"] = lookups
            tr.finish("completed", f"{len(lookups)} nslookup run(s) recorded")
        else:
            tr.skip("M2", "recon.run_nslookup is false in config")

        if "portscan" not in modules:
            tr.skip("M3", "portscan module not in --modules")
            tr.skip("M4", "web content discovery runs after port scan (portscan not selected)")

        if "portscan" in modules:
            mode = str(self.config.get("port_scan_mode", "nmap_aggressive")).strip().lower()
            self.results["nmap_scan"]["mode"] = mode
            exe = find_nmap_executable(self.config.get("nmap_executable"))
            scan_hosts = sorted(ips) if ips else ([target] if target else [])

            tr.start(
                "M3",
                [
                    f"Configured port_scan_mode: `{mode}`",
                    f"Targets: {len(scan_hosts)} host(s) — {', '.join(scan_hosts[:12])}{' …' if len(scan_hosts) > 12 else ''}",
                    f"Service enrichment: service_detection={self.config.get('service_detection', 'auto')} "
                    f"(may invoke nmap -sV from PortScanner on tcp_connect path)",
                ],
            )

            if mode == "nmap_aggressive" and exe:
                budget = int(self.config.get("nmap_aggressive_timeout_sec", self.config.get("nmap_scan_timeout", 7200)))
                tr.note_command("nmap_binary", exe)
                tr.note_command(
                    "nmap_profile",
                    f"Per host: nmap -v -p- -A --open -T4 (full TCP + scripts/OS/service); budget {budget}s",
                )
                rprint(
                    f"[bold green]{escape('[+]')}[/bold green] Default port scan: "
                    f"[cyan]nmap -v -p- -A --open[/cyan] (per host; budget [yellow]{budget}s[/yellow] each). "
                    "[dim]This is thorough and may take a long time.[/dim]"
                )
                loop = asyncio.get_running_loop()
                all_ports: List[PortScanResult] = []
                for ip in scan_hosts:
                    rprint(
                        f"[bold green]{escape('[+]')}[/bold green] nmap aggressive scan [dim]→[/dim] "
                        f"[cyan]{escape(str(ip))}[/cyan]"
                    )
                    if self._rt is not None:
                        self._rt.audit("nmap_aggressive_start", host=ip)
                    ok, xml_out, err, cmd = await loop.run_in_executor(
                        None, partial(run_nmap_aggressive_scan, ip, exe, budget)
                    )
                    tr.note_command("nmap_aggressive", cmd, host=ip, xml_parseable=bool(ok and ("<nmaprun" in (xml_out or "")[:8000])))
                    rows = parse_nmap_xml_open_tcp_ports(xml_out)
                    if not rows and ok:
                        rprint(
                            f"[bold red]{escape('[!]')}[/bold red] nmap returned no open TCP ports in XML for "
                            f"[cyan]{escape(str(ip))}[/cyan]"
                        )
                    for r in rows:
                        all_ports.append(
                            PortScanResult(
                                host=r["host"],
                                port=r["port"],
                                state=r["state"],
                                service=r.get("service"),
                                version=r.get("version"),
                                banner=r.get("banner"),
                                scripts=r.get("scripts"),
                            )
                        )
                    self.results["nmap_scan"]["per_host"].append(
                        {
                            "host": ip,
                            "command": cmd,
                            "xml_parseable": ok and ("<nmaprun" in (xml_out or "")[:8000]),
                            "open_ports_in_xml": len(rows),
                            "stderr_tail": (err or "")[-8000:],
                        }
                    )
                self.results["ports"] = [asdict(p) for p in all_ports]
            else:
                if mode == "nmap_aggressive" and not exe:
                    rprint(
                        f"[bold red]{escape('[!]')}[/bold red] [yellow]port_scan_mode=nmap_aggressive[/yellow] but "
                        "nmap not found; falling back to async TCP connect scan. Install Nmap or set "
                        "[cyan]nmap_executable[/cyan]."
                    )
                    self.results["nmap_scan"]["mode"] = "tcp_connect_fallback"
                else:
                    self.results["nmap_scan"]["mode"] = "tcp_connect"
                n_ports = len(self.port_scanner.ports)
                tr.note_command(
                    "tcp_connect_engine",
                    f"Python asyncio.open_connection per port — {n_ports} TCP ports × {len(scan_hosts)} host(s)",
                )
                all_ports: List[PortScanResult] = []
                for ip in scan_hosts:
                    tr.note_command("tcp_connect_batch", f"asyncio full handshake scan → {ip} (ports={n_ports})")
                    ports = await self.port_scanner.scan(ip)
                    all_ports.extend(ports)
                self.results["ports"] = [asdict(p) for p in all_ports]

            open_ct = sum(1 for p in self.results["ports"] if p.get("state") == "open")
            tr.finish(
                "completed",
                f"{len(self.results['ports'])} port row(s) stored ({open_ct} open) across {len(scan_hosts)} host(s)",
            )

            wl_path = self.config.get("directory_wordlist")
            wordlist = str(resolve_directory_wordlist(str(wl_path) if wl_path else None))

            dir_enabled = bool(self.config.get("directory_scan_enabled", True))
            d_tool = str(self.config.get("directory_tool", "auto")).lower()
            if dir_enabled and d_tool != "none":
                tr.start(
                    "M4",
                    [
                        "Stack: gobuster or dirb (external subprocess) + on-disk wordlist",
                        f"Wordlist path: {wordlist}",
                        f"Tool preference: directory_tool={d_tool}",
                    ],
                )
                urls = web_urls_from_port_rows(self.results["ports"])
                if self._rt is not None:
                    urls = [u for u in urls if self._host_allowed_for_active_scan(self._host_from_http_url(u))]
                max_urls = int(self.config.get("directory_max_urls", 6))
                urls = urls[:max_urls]
                self.results["web_content_discovery"]["urls_targeted"] = urls
                if not urls:
                    tr.finish(
                        "completed",
                        "No HTTP(S) base URLs derived from open ports (or none in-scope); directory tools not launched",
                    )
                else:
                    rprint(
                        f"[bold green]{escape('[+]')}[/bold green] Web content discovery on "
                        f"[yellow]{len(urls)}[/yellow] URL(s) [dim](gobuster/dirb)…[/dim]"
                    )
                    loop = asyncio.get_running_loop()
                    d_timeout = int(self.config.get("directory_timeout_sec", 900))
                    d_threads = int(self.config.get("directory_threads", 10))
                    scans: List[Dict[str, Any]] = []
                    for url in urls:
                        if self._rt is not None:
                            self._rt.audit(
                                "directory_bruteforce_start",
                                url=url,
                                tool=str(self.config.get("directory_tool", "auto")),
                            )
                        rep = await loop.run_in_executor(
                            None,
                            partial(
                                run_directory_scan,
                                url,
                                wordlist,
                                tool=d_tool,
                                threads=d_threads,
                                timeout_sec=d_timeout,
                            ),
                        )
                        scans.append(rep)
                        tlab = rep.get("tool") or "directory_scan"
                        cmd = rep.get("command") or rep.get("reason") or "(no subprocess — see status/reason in JSON)"
                        tr.note_command(tlab, cmd, base_url=rep.get("base_url"), status=rep.get("status"))
                    self.results["web_content_discovery"]["directory_scans"] = scans
                    hits = sum(len(s.get("findings_interesting") or []) for s in scans)
                    tr.finish(
                        "completed",
                        f"{len(scans)} bruteforce run(s); {hits} interesting path(s) (see web_content_discovery)",
                    )
            elif not dir_enabled:
                tr.skip("M4", "directory_scan_enabled is false")
            else:
                tr.skip("M4", "directory_tool is none")

        if "technology" in modules:
            tr.start(
                "M5",
                [
                    "Stack: Python requests + BeautifulSoup heuristics (header/HTML tech fingerprinting)",
                    "TLS verify disabled for opportunistic fingerprinting (lab / authorized testing only)",
                ],
            )
            urls_to_check = [f"http://{target}", f"https://{target}"]
            for sub in self.results["subdomains"][:10]:
                urls_to_check.append(f"http://{sub['subdomain']}")

            tech_results = []
            for url in urls_to_check:
                host = self._host_from_http_url(url + "/")
                if self._rt is not None and not self._host_allowed_for_active_scan(host):
                    continue
                tr.note_command(
                    "requests_fingerprint",
                    f"GET {url} timeout=10 verify=False allow_redirects=True",
                )
                result = await self.tech_detector.detect(url)
                if result:
                    tech_results.append(asdict(result))

            self.results["technologies"] = tech_results
            tr.finish(
                "completed",
                f"{len(tech_results)} technology profile(s) stored (see technologies[] in JSON)",
            )
        else:
            tr.skip("M5", "technology module not in --modules")

        dir_scans = (self.results.get("web_content_discovery") or {}).get("directory_scans") or []
        interesting_hits = sum(len(s.get("findings_interesting") or []) for s in dir_scans)

        ports_list = self.results["ports"]
        http_services_detected = sum(
            1 for p in ports_list if isinstance(p, dict) and _http_like_port_row(p)
        )
        tech_list = self.results["technologies"]
        subdomain_http = len([s for s in self.results["subdomains"] if s.get("status_code")])

        self.results["summary"] = {
            "total_subdomains": len(self.results["subdomains"]),
            "total_open_ports": len(ports_list),
            "open_tcp_ports": len(ports_list),
            "total_tech_detected": len(tech_list),
            "technology_profiles_stored": len(tech_list),
            "web_services": subdomain_http,
            "subdomain_http_probes_with_status": subdomain_http,
            "http_services_detected": http_services_detected,
            "nslookup_runs": len((self.results.get("dns_intelligence") or {}).get("nslookups") or []),
            "web_urls_targeted": len((self.results.get("web_content_discovery") or {}).get("urls_targeted") or []),
            "http_urls_targeted": len((self.results.get("web_content_discovery") or {}).get("urls_targeted") or []),
            "directory_scan_runs": len(dir_scans),
            "directory_interesting_hits": interesting_hits,
        }

        self.results["evidence_package"] = build_evidence_package(
            self.results, list(modules), lab_mode=self._rt is None
        )
        self.results["deterministic_findings"] = self.results["evidence_package"]["deterministic_findings"]
        self.results["deterministic_attack_paths"] = self.results["evidence_package"]["deterministic_attack_paths"]

        self.results["recon_completed_utc"] = utc_now_iso()
        self.results["executive_snapshot"] = build_executive_snapshot(self.results)

        if self._rt is not None:
            self._rt.audit(
                "recon_engine_complete",
                target=target,
                open_ports=len(self.results.get("ports") or []),
            )
        rprint()
        rprint(f"[bold green]{escape('[+]')}[/bold green] [bold]Reconnaissance complete[/bold]")
        rprint(
            f"    [yellow]Subdomains:[/yellow] [white]{self.results['summary']['total_subdomains']}[/white]  "
            f"[yellow]Open TCP ports:[/yellow] [white]{self.results['summary']['total_open_ports']}[/white]  "
            f"[yellow]HTTP(S) on ports:[/yellow] [white]{self.results['summary']['http_services_detected']}[/white]"
        )
        rprint(
            f"    [yellow]Subdomain HTTP probes w/ status:[/yellow] "
            f"[white]{self.results['summary']['subdomain_http_probes_with_status']}[/white]  "
            f"[yellow]DNS lookups:[/yellow] [white]{self.results['summary']['nslookup_runs']}[/white]  "
            f"[yellow]Directory scans:[/yellow] [white]{self.results['summary']['directory_scan_runs']}[/white]"
        )
        print_execution_recap(self.results, echo=echo_phases)

        return self.results

    def save_results(self, output_file: str, format: str = "json"):
        """Save results to file."""
        if format == "json":
            with open(output_file, "w", encoding="utf-8") as handle:
                handle.write(dumps_pretty(self.results))
        rprint(f"[bold green]{escape('[+]')}[/bold green] Results saved to: [cyan]{escape(output_file)}[/cyan]")
