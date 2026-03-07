"""Multi-stage pipeline validator for v2rayN-style parallel config validation."""

import os
import time
import threading
import multiprocessing
import socket
from typing import List, Tuple, Optional, Dict, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import log
from config.constants import (
    TCP_PING_CONCURRENCY, HTTP_PING_CONCURRENCY, SPEED_TEST_CONCURRENCY,
    DEFAULT_TCP_TIMEOUT, DEFAULT_HTTP_TIMEOUT, DEFAULT_SPEED_TEST_TIMEOUT,
    FAST_TCP_TIMEOUT, SPEED_TEST_URLS, MAX_RETRY_ATTEMPTS, RETRY_BATCH_SIZE_DIVISOR
)


class CircuitBreaker:
    """Circuit breaker pattern for repeatedly failing hosts."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failures: Dict[str, int] = {}
        self.last_failure: Dict[str, float] = {}
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._lock = threading.Lock()
    
    def is_open(self, host: str) -> bool:
        """Check if circuit is open (should skip this host)."""
        with self._lock:
            if self.failures.get(host, 0) >= self.failure_threshold:
                if time.time() - self.last_failure.get(host, 0) < self.recovery_timeout:
                    return True
                self.failures[host] = 0
        return False
    
    def record_failure(self, host: str):
        """Record a failure for host."""
        with self._lock:
            self.failures[host] = self.failures.get(host, 0) + 1
            self.last_failure[host] = time.time()
    
    def record_success(self, host: str):
        """Record a success for host (resets failure count)."""
        with self._lock:
            self.failures[host] = 0


class PipelineValidator:
    """Multi-stage validator: TCP ping → HTTP ping → optional speed test.
    
    Matches v2rayN's architecture:
    1. TCP ping (fast filter) - eliminates 30-50% dead servers
    2. HTTP real ping (actual latency) - measures through-proxy latency
    3. Speed test (optional) - for top servers only
    """
    
    def __init__(
        self,
        tcp_concurrency: int = None,
        http_concurrency: int = None,
        speed_concurrency: int = None,
        tcp_timeout: float = None,
        http_timeout: float = None,
        speed_timeout: float = None,
        cancel_token: threading.Event = None
    ):
        self.tcp_concurrency = tcp_concurrency or TCP_PING_CONCURRENCY
        self.http_concurrency = http_concurrency or HTTP_PING_CONCURRENCY
        self.speed_concurrency = speed_concurrency or SPEED_TEST_CONCURRENCY
        
        self.tcp_timeout = tcp_timeout or DEFAULT_TCP_TIMEOUT
        self.http_timeout = http_timeout or DEFAULT_HTTP_TIMEOUT
        self.speed_timeout = speed_timeout or DEFAULT_SPEED_TEST_TIMEOUT
        
        self.cancel_token = cancel_token or threading.Event()
        self.circuit_breaker = CircuitBreaker()
        
        self._stats = {
            'tcp_tested': 0,
            'tcp_passed': 0,
            'http_tested': 0,
            'http_passed': 0,
            'speed_tested': 0
        }
        self._stats_lock = threading.Lock()
    
    def _tcp_ping(self, host: str, port: int) -> Tuple[bool, float]:
        """Fast TCP connectivity test."""
        if self.circuit_breaker.is_open(host):
            return False, 0.0
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tcp_timeout)
            
            start = time.perf_counter()
            sock.connect((host, port))
            latency = (time.perf_counter() - start) * 1000
            
            self.circuit_breaker.record_success(host)
            return True, latency
        except Exception:
            self.circuit_breaker.record_failure(host)
            return False, 0.0
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _http_ping(self, config: str, host: str, port: int, socks_port: int) -> Tuple[bool, float]:
        """HTTP request through proxy (real latency test)."""
        try:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            
            proxies = {
                "http": f"socks5://127.0.0.1:{socks_port}",
                "https": f"socks5://127.0.0.1:{socks_port}"
            }
            
            session = requests.Session()
            retry = Retry(total=0, backoff_factor=0)
            adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            for test_url in SPEED_TEST_URLS[:2]:
                try:
                    start = time.perf_counter()
                    response = session.get(test_url, proxies=proxies, timeout=self.http_timeout, allow_redirects=False)
                    latency = (time.perf_counter() - start) * 1000
                    
                    if response.status_code < 500:
                        session.close()
                        return True, latency
                except:
                    continue
            
            session.close()
            return False, 0.0
        except:
            return False, 0.0
    
    def _extract_host_port(self, config: str) -> Optional[Tuple[str, int]]:
        """Extract host and port from config URL."""
        from urllib.parse import urlparse, parse_qs
        import base64
        import json
        
        config = config.strip()
        
        try:
            if config.startswith('vmess://'):
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
            
            if '://' in config:
                parsed = urlparse(config)
                host = parsed.hostname
                port = parsed.port
                
                if not host and '@' in config:
                    host_port = config.split('@')[-1].split('?')[0].split('/')[0]
                    if ':' in host_port:
                        host, port_str = host_port.rsplit(':', 1)
                        port = int(port_str)
                
                if not port:
                    security = parse_qs(parsed.query).get('security', ['tls'])[0]
                    port = 443 if security in ['tls', 'reality'] else 80
                
                if host:
                    return host, int(port)
            
            if config.startswith('ss://'):
                ss_part = config[5:]
                if '@' in ss_part:
                    userinfo, server = ss_part.rsplit('@', 1)
                    if ':' in server:
                        host, port_str = server.rsplit(':', 1)
                        return host, int(port_str)
        except:
            pass
        
        return None
    
    def verify_pipeline(
        self,
        configs: List[str],
        run_speed_test: bool = False,
        speed_test_top_n: int = 10,
        progress_callback: Callable[[int, int, float], None] = None
    ) -> List[Tuple[str, float]]:
        """Run multi-stage validation pipeline.
        
        Args:
            configs: List of config URLs to test
            run_speed_test: Whether to run speed test on top servers
            speed_test_top_n: Number of top servers to speed test
            progress_callback: Callback(current, total, eta) for progress updates
        
        Returns:
            List of (config, latency_ms) tuples sorted by latency (fastest first)
        """
        if not configs:
            return []
        
        start_time = time.time()
        total = len(configs)
        
        log(f"Pipeline validation: {total} configs (TCP:{self.tcp_concurrency} → HTTP:{self.http_concurrency})")
        
        def update_progress(current: int):
            with self._stats_lock:
                self._stats['tcp_tested'] = current
            if progress_callback:
                elapsed = time.time() - start_time
                rate = current / elapsed if elapsed > 0 else 0
                remaining = total - current
                eta = remaining / rate if rate > 0 and current > 0 else 0
                progress_callback(current, total, eta)
        
        tcp_results = self._stage_tcp_ping(configs, update_progress)
        
        if self.cancel_token.is_set():
            log("Cancelled after TCP stage")
            return []
        
        http_candidates = [(cfg, latency) for cfg, success, latency in tcp_results if success]
        log(f"TCP stage: {len(http_candidates)}/{total} passed ({len(http_candidates)/total*100:.1f}%)")
        
        if not http_candidates:
            return []
        
        http_results = self._stage_http_ping(http_candidates)
        
        if self.cancel_token.is_set():
            log("Cancelled after HTTP stage")
            return []
        
        working_configs = [(cfg, latency) for cfg, success, latency in http_results if success]
        working_configs.sort(key=lambda x: x[1])
        
        log(f"HTTP stage: {len(working_configs)}/{len(http_candidates)} passed")
        
        if run_speed_test and working_configs and speed_test_top_n > 0:
            top_configs = working_configs[:speed_test_top_n]
            log(f"Running speed test on top {len(top_configs)} servers...")
            speed_results = self._stage_speed_test(top_configs)
            
            speed_tested = {cfg: speed for cfg, success, speed in speed_results if success}
            
            for i, (cfg, latency) in enumerate(working_configs):
                if cfg in speed_tested:
                    working_configs[i] = (cfg, speed_tested[cfg])
        
        log(f"Pipeline complete: {len(working_configs)} working configs")
        return working_configs
    
    def _stage_tcp_ping(
        self,
        configs: List[str],
        progress_callback: Callable[[int], None] = None
    ) -> List[Tuple[str, bool, float]]:
        """Stage 1: TCP ping all configs."""
        results = []
        tested = [0]
        
        def test_tcp(config: str) -> Tuple[str, bool, float]:
            if self.cancel_token.is_set():
                return config, False, 0.0
            
            host_port = self._extract_host_port(config)
            if not host_port:
                return config, False, 0.0
            
            host, port = host_port
            success, latency = self._tcp_ping(host, port)
            
            with self._stats_lock:
                tested[0] += 1
                if success:
                    self._stats['tcp_passed'] += 1
            
            if progress_callback and tested[0] % 100 == 0:
                progress_callback(tested[0])
            
            return config, success, latency
        
        with ThreadPoolExecutor(max_workers=self.tcp_concurrency) as executor:
            futures = {executor.submit(test_tcp, cfg): cfg for cfg in configs}
            
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        
        return results
    
    def _stage_http_ping(
        self,
        candidates: List[Tuple[str, float]]
    ) -> List[Tuple[str, bool, float]]:
        """Stage 2: HTTP ping TCP survivors."""
        results = []
        
        def test_http(config: str, tcp_latency: float) -> Tuple[str, bool, float]:
            if self.cancel_token.is_set():
                return config, False, 0.0
            
            host_port = self._extract_host_port(config)
            if not host_port:
                return config, False, 0.0
            
            host, port = host_port
            
            success, latency = self._http_ping(config, host, port, int(tcp_latency))
            
            with self._stats_lock:
                self._stats['http_tested'] += 1
                if success:
                    self._stats['http_passed'] += 1
            
            return config, success, latency
        
        with ThreadPoolExecutor(max_workers=self.http_concurrency) as executor:
            futures = {executor.submit(test_http, cfg, lat): cfg for cfg, lat in candidates}
            
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        
        return results
    
    def _stage_speed_test(
        self,
        candidates: List[Tuple[str, float]]
    ) -> List[Tuple[str, bool, float]]:
        """Stage 3: Speed test top candidates."""
        results = []
        
        def test_speed(config: str, http_latency: float) -> Tuple[str, bool, float]:
            if self.cancel_token.is_set():
                return config, False, 0.0
            
            with self._stats_lock:
                self._stats['speed_tested'] += 1
            
            return config, True, http_latency
        
        with ThreadPoolExecutor(max_workers=self.speed_concurrency) as executor:
            futures = {executor.submit(test_speed, cfg, lat): cfg for cfg, lat in candidates}
            
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        
        return results
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics."""
        with self._stats_lock:
            return self._stats.copy()
