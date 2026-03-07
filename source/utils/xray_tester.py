"""Xray-core based VPN config tester - like v2rayN realping."""

import os
import sys
import json
import subprocess
import tempfile
import time
import socket
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse, parse_qs, unquote
import base64
import threading
import multiprocessing
from utils.logger import log


class XrayTester:
    """Test VPN configs using Xray-core binary (like v2rayN)."""
    
    TEST_URLS = [
        "https://www.google.com/generate_204",
        "https://www.gstatic.com/generate_204",
    ]
    
    def __init__(self, xray_path: str = None):
        if xray_path is None:
            # Try common locations
            script_dir = os.path.dirname(os.path.abspath(__file__))
            source_dir = os.path.dirname(script_dir)
            possible_paths = [
                os.path.join(source_dir, "xray.exe"),  # source/ folder
                os.path.join(source_dir, "xray"),  # source/ folder (Unix)
                "xray.exe",  # Current directory (Windows)
                "xray",  # Current directory (Unix)
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    xray_path = path
                    break
            
            if xray_path is None:
                xray_path = "xray"  # Will check PATH
        
        self.xray_path = xray_path
        self._check_xray_binary()
    
    def _check_xray_binary(self):
        """Check if Xray binary exists, download if needed."""
        if os.path.exists(self.xray_path):
            return
        
        # Try to find in PATH
        xray_exe = "xray.exe" if sys.platform == "win32" else "xray"
        for path in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(path, xray_exe)
            if os.path.exists(candidate):
                self.xray_path = candidate
                return
        
        log(f"Warning: Xray binary not found at '{self.xray_path}'. TCP testing will be used instead.")
        self.xray_path = None
    
    def _parse_vless(self, url: str) -> Optional[Dict]:
        """Parse VLESS URL to Xray outbound config."""
        try:
            parsed = urlparse(url.replace('vless://', ''))
            uuid = parsed.username
            host = parsed.hostname
            port = parsed.port
            
            params = parse_qs(parsed.query)
            security = params.get('security', ['none'])[0]
            
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": params.get('encryption', ['none'])[0],
                            "flow": params.get('flow', [''])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": params.get('type', ['tcp'])[0],
                    "security": security
                }
            }
            
            # TLS settings
            if security == 'tls':
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get('sni', [host])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0]
                }
            # Reality settings
            elif security == 'reality':
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get('sni', [''])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0],
                    "publicKey": params.get('pbk', [''])[0],
                    "shortId": params.get('sid', [''])[0]
                }
            
            # Transport
            transport = params.get('type', ['tcp'])[0]
            if transport == 'ws':
                outbound["streamSettings"]["wsSettings"] = {
                    "path": unquote(params.get('path', ['/'])[0]),
                    "headers": {"Host": unquote(params.get('host', [host])[0])}
                }
            elif transport == 'grpc':
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": unquote(params.get('serviceName', [''])[0])
                }
            
            return outbound
        except Exception as e:
            log(f"Error parsing VLESS: {e}")
            return None
    
    def _parse_vmess(self, url: str) -> Optional[Dict]:
        """Parse VMess URL (base64 JSON)."""
        try:
            encoded = url.replace('vmess://', '')
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            decoded = base64.b64decode(encoded).decode('utf-8')
            data = json.loads(decoded)
            
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": data.get('add', ''),
                        "port": int(data.get('port', 443)),
                        "users": [{
                            "id": data.get('id', ''),
                            "alterId": int(data.get('aid', 0)),
                            "security": data.get('scy', 'auto')
                        }]
                    }]
                },
                "streamSettings": {
                    "network": data.get('net', 'tcp'),
                    "security": 'tls' if data.get('tls') == 'tls' else 'none'
                }
            }
        except Exception as e:
            log(f"Error parsing VMess: {e}")
            return None
    
    def _parse_trojan(self, url: str) -> Optional[Dict]:
        """Parse Trojan URL."""
        try:
            parsed = urlparse(url.replace('trojan://', ''))
            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": parsed.hostname,
                        "port": parsed.port,
                        "password": parsed.username
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": parsed.hostname
                    }
                }
            }
        except Exception as e:
            log(f"Error parsing Trojan: {e}")
            return None
    
    def _url_to_xray_config(self, url: str, socks_port: int) -> Optional[Dict]:
        """Convert share URL to Xray config with SOCKS inbound."""
        if url.startswith('vless://'):
            outbound = self._parse_vless(url)
        elif url.startswith('vmess://'):
            outbound = self._parse_vmess(url)
        elif url.startswith('trojan://'):
            outbound = self._parse_trojan(url)
        else:
            return None
        
        if not outbound:
            return None
        
        return {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": [{
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "mixed",  # FIX: Match v2rayN (supports HTTP+SOCKS)
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            }],
            "outbounds": [outbound],
            "routing": {"domainStrategy": "AsIs", "rules": []}
        }
    
    def _test_through_proxy(self, socks_port: int, timeout: float) -> Tuple[bool, float]:
        """Test connection through SOCKS proxy - FIXED: Use requests library."""
        try:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            
            proxies = {
                "http": f"socks5://127.0.0.1:{socks_port}",
                "https": f"socks5://127.0.0.1:{socks_port}"
            }
            
            # Create session with no retries (match v2rayN)
            session = requests.Session()
            retry = Retry(total=0, backoff_factor=0)
            adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Try first 2 URLs (match v2rayN's 2 attempts)
            for test_url in self.TEST_URLS[:2]:
                try:
                    start = time.perf_counter()
                    response = session.get(
                        test_url,
                        proxies=proxies,
                        timeout=timeout,
                        allow_redirects=True  # Match v2rayN
                    )
                    latency = (time.perf_counter() - start) * 1000
                    
                    # Match v2rayN: successful request = working (no status check)
                    session.close()
                    return True, latency
                except Exception as e:
                    # Try next URL
                    continue
            
            session.close()
            return False, 0.0
            
        except Exception:
            return False, 0.0
    
    def test_config(self, url: str, timeout: float = 3.0) -> Tuple[bool, float]:
        """
        Test single config using Xray-core.
        
        Returns: (success, latency_ms)
        """
        if not self.xray_path:
            # CRITICAL FIX: No TCP fallback - match v2rayN behavior
            log(f"ERROR: Xray binary not found at {self.xray_path}")
            return False, 0.0
        
        # Generate config
        socks_port = 10000 + (hash(url) % 1000)  # Unique port per config
        config = self._url_to_xray_config(url, socks_port)
        
        if not config:
            return False, 0.0
        
        # Create temp config file
        config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(config, config_file)
        config_file.close()
        
        try:
            # Start Xray
            cmd = [self.xray_path, "run", "-config", config_file.name]
            
            # FIX: Capture stderr to detect config errors
            if sys.platform == "win32":
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            # FIX: Match v2rayN's 1.0s wait
            time.sleep(1.0)
            
            # Check if running (match v2rayN's immediate check)
            if process.poll() is not None:
                # Xray exited immediately - config error
                try:
                    stderr = process.stderr.read(timeout=1).decode('utf-8', errors='ignore')
                    log(f"Xray failed: {stderr[:200]}")
                except:
                    pass
                return False, 0.0
            
            # Test through proxy
            success, latency = self._test_through_proxy(socks_port, timeout)
            
            # Stop Xray
            process.terminate()
            try:
                process.wait(timeout=2)
            except:
                process.kill()
                process.wait()
            
            return success, latency
            
        except Exception as e:
            log(f"Xray test error: {e}")
            return False, 0.0
        finally:
            # Cleanup
            try:
                os.unlink(config_file.name)
            except:
                pass
    
    def _tcp_fallback(self, url: str, timeout: float) -> Tuple[bool, float]:
        """REMOVED: No longer used - v2rayN has no TCP fallback."""
        return False, 0.0
    
    def test_batch(self, urls: List[str], max_workers: int = 10, timeout: float = 3.0) -> List[Tuple[str, bool, float]]:
        """Test multiple configs in parallel."""
        if not self.xray_path:
            log("Xray binary not found, using TCP fallback for all tests")
        
        log(f"Testing {len(urls)} configs with Xray-core (workers={max_workers})...")
        
        results = []
        start_time = time.time()
        counter = [0]
        lock = threading.Lock()
        
        def test_single(url):
            success, latency = self.test_config(url, timeout)
            
            with lock:
                counter[0] += 1
                count = counter[0]
            
            if count % 100 == 0:
                elapsed = time.time() - start_time
                rate = count / elapsed if elapsed > 0 else 0
                log(f"Progress: {count}/{len(urls)} ({rate:.1f} configs/sec)")
            
            return url, success, latency
        
        # Use ThreadPoolExecutor for parallel testing
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(test_single, urls))
        
        # Filter working and sort by latency
        working = [(url, success, latency) for url, success, latency in results if success]
        working.sort(key=lambda x: x[2])
        
        elapsed = time.time() - start_time
        log(f"Xray testing complete: {len(working)}/{len(urls)} working in {elapsed:.1f}s")
        
        return working
