"""High-performance config verification module with optimized DNS caching and async support."""

import os
import socket
import time
import threading
import ssl
import json
import itertools
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse, parse_qs, unquote
import base64
import concurrent.futures
import multiprocessing
from collections import defaultdict
from utils.logger import log

# Try to import aiodns for faster async DNS resolution (optional)
try:
    import aiodns
    import asyncio
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

# Try to import requests for HTTP proxy testing
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class DNSCache:
    """Lock-free DNS cache using GIL for thread safety."""
    
    def __init__(self, ttl: int = 60):
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._ttl = ttl
    
    def get(self, hostname: str) -> Optional[str]:
        """Get cached IP if valid - lock-free, GIL protects dict operations."""
        if hostname in self._cache:
            ip, expiry = self._cache[hostname]
            if time.time() < expiry:
                return ip
            self._cache.pop(hostname, None)
        return None
    
    def set(self, hostname: str, ip: str):
        """Cache IP with TTL - lock-free, GIL protects dict operations."""
        self._cache[hostname] = (ip, time.time() + self._ttl)
    
    def clear_expired(self):
        """Remove expired entries."""
        now = time.time()
        self._cache = {
            k: v for k, v in self._cache.items() 
            if now < v[1]
        }


class SharedDNSResolver:
    """Shared aiodns resolver instance to avoid event loop creation overhead."""
    
    _instance = None
    _init_lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._resolver = None
        self._loop = None
        self._loop_thread = None
        self._initialized = True
        
        if HAS_AIODNS:
            self._start_dns_loop()
    
    def _start_dns_loop(self):
        """Start dedicated DNS resolver loop in background thread."""
        def run_loop():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            
            # Set exception handler to suppress DNS errors
            def exception_handler(loop, context):
                # Suppress DNS errors - they're expected and handled
                pass
            
            self._loop.set_exception_handler(exception_handler)
            self._resolver = aiodns.DNSResolver(loop=self._loop)
            self._loop.run_forever()
        
        self._loop_thread = threading.Thread(target=run_loop, daemon=True)
        self._loop_thread.start()
        
        # Wait for loop to be ready
        time.sleep(0.1)
    
    def resolve(self, hostname: str, timeout: float = 2.0) -> Optional[str]:
        """Resolve hostname using shared resolver."""
        if not self._resolver or not self._loop:
            return None
        
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._resolver.query(hostname, 'A'),
                self._loop
            )
            result = future.result(timeout=timeout)
            if result and len(result) > 0:
                return result[0].host
        except Exception:
            # Silently ignore DNS errors - will fall back to socket DNS
            pass
        return None
    
    def close(self):
        """Shutdown DNS resolver loop."""
        if self._loop:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass


class ConfigVerifier:
    """High-performance verifier with optimized DNS caching and HTTP proxy testing."""
    
    # Shared DNS resolver across all instances
    _shared_dns = None
    _dns_init_lock = threading.Lock()
    
    # Test URLs (same as v2rayN)
    SPEED_PING_TEST_URLS = [
        "https://www.google.com/generate_204",
        "https://www.gstatic.com/generate_204", 
        "https://www.apple.com/library/test/success.html",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]
    
    def __init__(
        self, 
        timeout: float = 5.0, 
        ping_count: int = 1, 
        max_workers: Optional[int] = None,
        dns_ttl: int = 60,
        test_mode: str = "tcp",  # "tcp", "http", or "smart" - smart does TCP first, then HTTP
        fast_timeout: float = 0.5,  # Fast timeout for initial TCP filter
        http_timeout: float = 3.0,  # Timeout for HTTP proxy test (matches VALIDATION_HTTP_TIMEOUT)
        batch_size: int = 500  # Number of configs to process before progress update
    ):
        self.timeout = timeout
        self.ping_count = ping_count
        self.test_mode = test_mode
        self.fast_timeout = fast_timeout  # For TCP pre-check
        self.http_timeout = http_timeout  # For HTTP test
        self.batch_size = batch_size
        
        # v2rayN-style optimization: Higher concurrency for faster testing
        # Based on v2rayN's SpeedTestPageSize = 1000
        if max_workers is None:
            cpu_count = multiprocessing.cpu_count()
            self.max_workers = min(200, max(50, cpu_count * 8))  # Higher concurrency
        else:
            self.max_workers = min(max_workers, 200)  # Cap at 200
        
        self.dns_cache = DNSCache(ttl=dns_ttl)
        self._stats = {'checked': 0, 'working': 0, 'failed': 0}
        
        # Host extraction cache to avoid redundant parsing
        self._host_cache: Dict[int, Tuple[str, int]] = {}
        self._host_cache_lock = threading.Lock()
        
        # Initialize shared DNS resolver with proper locking
        if ConfigVerifier._shared_dns is None and HAS_AIODNS:
            with ConfigVerifier._dns_init_lock:
                if ConfigVerifier._shared_dns is None:
                    ConfigVerifier._shared_dns = SharedDNSResolver()
    
    def _extract_host_port(self, config: str) -> Optional[Tuple[str, int]]:
        """Extract host and port from config URL."""
        config = config.strip()
        
        try:
            # VMess
            if config.startswith('vmess://'):
                try:
                    payload = config[8:]
                    padding = 4 - len(payload) % 4
                    if padding != 4:
                        payload += '=' * padding
                    decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                    if decoded.startswith('{'):
                        data = json.loads(decoded)
                        host = data.get('add') or data.get('host')
                        port = int(data.get('port', 443))
                        if host:
                            return host, port
                except Exception:
                    pass
            
            # VLESS, Trojan, Hysteria, TUIC, etc.
            if '://' in config:
                parsed = urlparse(config)
                host = parsed.hostname
                port = parsed.port
                
                if not host:
                    if '@' in config:
                        host_port = config.split('@')[-1].split('?')[0].split('/')[0]
                        if ':' in host_port:
                            host, port_str = host_port.rsplit(':', 1)
                            port = int(port_str)
                
                if not port:
                    security = parse_qs(parsed.query).get('security', ['tls'])[0]
                    port = 443 if security in ['tls', 'reality'] else 80
                
                if host:
                    return host, int(port)
            
            # Shadowsocks
            if config.startswith('ss://'):
                try:
                    ss_part = config[5:]
                    if '@' in ss_part:
                        userinfo, server = ss_part.rsplit('@', 1)
                        if ':' in server:
                            host, port_str = server.rsplit(':', 1)
                            return host, int(port_str)
                except Exception:
                    pass
            
        except Exception:
            pass
        
        return None
    
    def _extract_host_port_cached(self, config: str) -> Optional[Tuple[str, int]]:
        """Extract host/port with caching to avoid redundant parsing."""
        config_hash = hash(config)
        
        # Quick cache lookup
        with self._host_cache_lock:
            if config_hash in self._host_cache:
                return self._host_cache[config_hash]
        
        # Extract normally
        host_port = self._extract_host_port(config)
        
        # Cache result
        if host_port:
            with self._host_cache_lock:
                self._host_cache[config_hash] = host_port
        
        return host_port
    
    def _resolve_host(self, hostname: str) -> Optional[str]:
        """Resolve hostname with multi-level caching and shared resolver."""
        # Check cache first (fastest)
        cached_ip = self.dns_cache.get(hostname)
        if cached_ip:
            return cached_ip
        
        # Try shared aiodns resolver (fast)
        if ConfigVerifier._shared_dns:
            ip = ConfigVerifier._shared_dns.resolve(hostname, timeout=self.timeout)
            if ip:
                self.dns_cache.set(hostname, ip)
                return ip
        
        # Fallback to standard socket DNS (slower but reliable)
        try:
            ip = socket.gethostbyname(hostname)
            self.dns_cache.set(hostname, ip)
            return ip
        except socket.gaierror:
            return None
    
    def _tcp_ping(self, host: str, port: int) -> Tuple[bool, float]:
        """Test TCP connectivity with v2rayN-style fast timeout."""
        # Resolve hostname with caching
        resolved_ip = self._resolve_host(host)
        if not resolved_ip:
            return False, 0.0
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # v2rayN-style: Very fast timeout (500ms) for initial filter
            sock.settimeout(self.fast_timeout)
            
            start_time = time.perf_counter()
            sock.connect((resolved_ip, port))
            latency = (time.perf_counter() - start_time) * 1000
            return True, latency
        except (socket.timeout, socket.error, OSError, ConnectionRefusedError):
            return False, 0.0
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _http_proxy_ping(self, config: str, host: str, port: int) -> Tuple[bool, float]:
        """Test proxy by making HTTP request THROUGH the proxy (like v2rayN realping)."""
        if not HAS_REQUESTS:
            return self._tcp_ping(host, port)
        
        # Build proxy URL based on config type
        config_lower = config.lower()
        proxy_url = None
        
        if config_lower.startswith('socks://') or config_lower.startswith('socks5://'):
            proxy_url = f"socks5://{host}:{port}"
        elif config_lower.startswith('socks4://'):
            proxy_url = f"socks4://{host}:{port}"
        elif config_lower.startswith('http://'):
            proxy_url = f"http://{host}:{port}"
        elif any(config_lower.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://', 'tuic://']):
            proxy_url = f"socks5://{host}:{port}"
        
        if not proxy_url:
            return self._tcp_ping(host, port)
        
        # v2rayN-style: Test with multiple URLs, return fastest
        proxies = {"http": proxy_url, "https": proxy_url}
        
        # Use a single session with connection pooling
        session = requests.Session()
        retry = Retry(total=0, backoff_factor=0)  # No retries for speed
        adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Try URLs in order, return first success (like v2rayN)
        for test_url in self.SPEED_PING_TEST_URLS[:2]:  # Only test 2 URLs for speed
            try:
                start_time = time.perf_counter()
                response = session.get(test_url, proxies=proxies, timeout=self.http_timeout, allow_redirects=False)
                latency = (time.perf_counter() - start_time) * 1000
                
                if response.status_code < 500:
                    session.close()
                    return True, latency
            except Exception:
                continue
        
        session.close()
        return False, 0.0
    
    def _multi_ping(self, host: str, port: int, config: str = "") -> Tuple[bool, float]:
        """Perform ping tests with smart mode support.
        
        Smart mode: First check TCP connectivity, then test HTTP proxy functionality.
        This avoids wasting time on HTTP tests for unreachable servers.
        """
        latencies = []
        success_count = 0
        
        for _ in range(self.ping_count):
            # SMART MODE: TCP check first, then HTTP test only if TCP succeeds
            if self.test_mode == "smart" and config:
                # Step 1: Quick TCP check (is server reachable?)
                tcp_success, tcp_latency = self._tcp_ping(host, port)
                
                if not tcp_success:
                    # Server unreachable, skip HTTP test
                    success, latency = False, 0.0
                else:
                    # Step 2: HTTP proxy test (does proxy actually work?)
                    success, http_latency = self._http_proxy_ping(config, host, port)
                    # Use HTTP latency if successful, otherwise TCP latency
                    latency = http_latency if success else tcp_latency
            elif self.test_mode == "http" and config:
                # HTTP mode only (no TCP pre-check)
                success, latency = self._http_proxy_ping(config, host, port)
            else:
                # TCP mode only
                success, latency = self._tcp_ping(host, port)
            
            if success:
                success_count += 1
                latencies.append(latency)
            time.sleep(0.05)
        
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        return success_count > 0, avg_latency
    
    def verify_config(self, config: str) -> Tuple[bool, float]:
        """Verify a single config with cached host extraction."""
        config = config.strip()
        if not config:
            return False, 0.0
        
        # Use cached host extraction
        host_port = self._extract_host_port_cached(config)
        if not host_port:
            self._stats['failed'] += 1
            return False, 0.0
        
        host, port = host_port
        
        # Use HTTP proxy ping for actual functionality test, or TCP ping for quick check
        is_working, latency = self._multi_ping(host, port, config)
        
        self._stats['checked'] += 1
        if is_working:
            self._stats['working'] += 1
        else:
            self._stats['failed'] += 1
        
        return is_working, latency
    
    def _group_configs_by_host(self, configs: List[str]) -> Dict[str, List[str]]:
        """Group configs by host for DNS cache efficiency."""
        groups: Dict[str, List[str]] = defaultdict(list)
        for config in configs:
            host_port = self._extract_host_port_cached(config.strip())
            if host_port:
                host = host_port[0]
                groups[host].append(config)
        return dict(groups)
    
    def verify_configs(
        self, 
        configs: List[str], 
        show_progress: bool = True,
        group_by_host: bool = True
    ) -> List[Tuple[str, bool, float]]:
        """Verify multiple configs with optimized concurrency and DNS caching."""
        if not configs:
            return []
        
        log(f"Verifying {len(configs)} configs with {self.max_workers} workers (optimized)...")
        
        results = []
        start_time = time.time()
        
        # Use itertools.count for lock-free progress tracking
        counter = itertools.count()
        
        def verify_single(config):
            is_working, latency = self.verify_config(config)
            count = next(counter)  # Lock-free atomic increment
            
            if show_progress and count % 500 == 0:
                elapsed = time.time() - start_time
                rate = count / elapsed if elapsed > 0 else 0
                remaining = len(configs) - count
                eta = remaining / rate if rate > 0 else 0
                log(f"Progress: {count}/{len(configs)} ({rate:.0f} configs/sec, ETA: {eta:.0f}s)")
            
            return config, is_working, latency
        
        # Group configs by host for better DNS cache utilization
        if group_by_host:
            host_groups = self._group_configs_by_host(configs)
            sorted_hosts = sorted(host_groups.keys(), key=lambda h: len(host_groups[h]), reverse=True)
            
            ordered_configs = []
            for host in sorted_hosts:
                ordered_configs.extend(host_groups[host])
            
            configs = ordered_configs
            log(f"Configs grouped by {len(host_groups)} unique hosts for DNS cache efficiency")
        
        # Execute with optimized worker count
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(verify_single, configs))
        
        # Filter working configs
        working = [(cfg, working, latency) for cfg, working, latency in results if working]
        working.sort(key=lambda x: x[2])
        
        elapsed = time.time() - start_time
        success_rate = len(working) / len(configs) * 100 if configs else 0
        log(f"Verification complete: {len(working)}/{len(configs)} working ({success_rate:.1f}%) in {elapsed:.1f}s")
        
        return working
    
    def create_working_file(self, configs: List[str], output_path: str):
        """Verify configs and create file with working ones (sorted by ping)."""
        if not configs:
            log(f"No configs to verify for {output_path}")
            return
        
        log(f"Creating working config file: {output_path}")
        working_configs = self.verify_configs(configs)
        
        if not working_configs:
            log(f"No working configs found for {output_path}")
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('')
            return
        
        sorted_configs = [cfg for cfg, _, _ in working_configs]
        
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_configs))
        
        log(f"Created {output_path} with {len(sorted_configs)} working configs (sorted by ping)")
        
        if working_configs:
            log(f"Top 5 fastest configs:")
            for i, (cfg, _, latency) in enumerate(working_configs[:5], 1):
                remark = ''
                if '#' in cfg:
                    remark = cfg.split('#')[-1][:30]
                log(f"  {i}. {latency:.0f}ms - {cfg[:60]}... {remark}")
    
    def verify_configs_two_pass(
        self, 
        configs: List[str], 
        show_progress: bool = True,
        fast_timeout: float = 0.5,
        full_timeout: float = 2.0
    ) -> List[Tuple[str, bool, float]]:
        """Two-pass verification: quick filter then full verification."""
        if not configs:
            return []
        
        log(f"Two-pass verification: {len(configs)} configs (fast: {fast_timeout}s, full: {full_timeout}s)")
        
        # Pass 1: Quick filter with short timeout
        quick_verifier = ConfigVerifier(
            timeout=fast_timeout,
            ping_count=1,
            max_workers=self.max_workers
        )
        quick_results = quick_verifier.verify_configs(configs, show_progress=show_progress, group_by_host=False)
        
        candidates = [cfg for cfg, working, _ in quick_results if working]
        
        if not candidates:
            log(f"No configs survived quick filter")
            return []
        
        log(f"Quick filter: {len(candidates)}/{len(configs)} survived ({len(candidates)/len(configs)*100:.1f}%)")
        
        # Pass 2: Full verification on survivors
        full_verifier = ConfigVerifier(
            timeout=full_timeout,
            ping_count=self.ping_count,
            max_workers=self.max_workers
        )
        final_results = full_verifier.verify_configs(candidates, show_progress=show_progress, group_by_host=True)
        
        log(f"Two-pass complete: {len(final_results)}/{len(configs)} final working configs")
        
        return final_results
    
    def get_stats(self) -> Dict[str, int]:
        """Get verification statistics."""
        return self._stats.copy()
    
    def reset_stats(self):
        """Reset verification statistics."""
        self._stats = {'checked': 0, 'working': 0, 'failed': 0}
    
    def __del__(self):
        """Cleanup on destruction."""
        if hasattr(self, '_shared_dns') and self._shared_dns:
            try:
                self._shared_dns.close()
            except:
                pass
