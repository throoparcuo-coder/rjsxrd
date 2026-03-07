"""v2rayN-style VPN config tester: v2rayN architecture - ONE Xray instance for MULTIPLE configs."""

import os
import sys
import json
import subprocess
import tempfile
import time
import socket
import ssl
import threading
import atexit
import signal
import re
import random
import asyncio
import requests
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse, parse_qs, unquote
from urllib3.util.retry import Retry
import base64
import multiprocessing
from utils.logger import log

try:
    from curl_cffi.requests import Session as CurlSession, AsyncSession
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    CurlSession = None
    AsyncSession = None


# Global registry for cleanup on exit
_active_testers: List['XrayBatchTester'] = []
_cleanup_lock = threading.Lock()


def _cleanup_all():
    """Cleanup all active Xray processes on exit."""
    with _cleanup_lock:
        for tester in _active_testers[:]:
            try:
                tester.cleanup()
            except:
                pass


# Register cleanup handlers
atexit.register(_cleanup_all)

# Handle Ctrl+C and termination signals
def _signal_handler(signum, frame):
    _cleanup_all()
    sys.exit(1)

try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
except:
    pass  # Signal handling not available in all contexts


class XrayBatchTester:
    """Test VPN configs using Xray-core with v2rayN's architecture.
    
    OPTIMIZED: Uses v2rayN's approach - ONE Xray process with multiple inbounds/outbounds
    instead of one Xray process per config. This reduces process overhead by 1000x.
    """
    
    TEST_URLS = [
        "https://www.google.com/generate_204"
    ]
    DEFAULT_TIMEOUT = 5.0  # Default 5s (matches VALIDATION_HTTP_TIMEOUT)
    BASE_PORT = 20000
    BATCH_SIZE = 100  # Conservative: Less waste if batch fails, faster startup
    MAX_BATCH_SIZE = 150  # Absolute maximum
    MIN_BATCH_SIZE = 50   # Minimum for efficiency
    
    def __init__(self, xray_path: str = None, pool_size: int = 0):
        """Initialize Xray batch tester with optional process pool."""
        self.xray_path = xray_path or self._find_xray()
        self._running_processes: List[subprocess.Popen] = []
        self._process_lock = threading.Lock()
        self._port_counter = [self.BASE_PORT]
        self._port_lock = threading.Lock()
        
        # Process pool for reusing Xray instances
        self.pool_size = pool_size
        self._pool_processes: List[subprocess.Popen] = []
        self._pool_ports: List[int] = []
        self._pool_lock = threading.Lock()
        self._pool_initialized = False
        
        # Error tracking for debugging
        self._error_stats = {}
        self._error_samples = {}
        self._error_stats_lock = threading.Lock()
        
        # Register this tester for cleanup
        with _cleanup_lock:
            _active_testers.append(self)
    
    def _find_xray(self) -> str:
        """Find Xray binary with cross-platform support."""
        xray_exe = "xray.exe" if sys.platform == "win32" else "xray"
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "..", "xray", xray_exe),
            os.path.join(os.path.dirname(__file__), "..", xray_exe),
            xray_exe,
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return os.path.abspath(path)
        return "xray"
    
    def _get_next_port(self) -> int:
        """Get next port atomically - OS handles conflicts (removed socket bind check)."""
        with self._port_lock:
            port = self._port_counter[0]
            self._port_counter[0] += 1
            if self._port_counter[0] > self.BASE_PORT + 5000:
                self._port_counter[0] = self.BASE_PORT
            return port
    
    def _initialize_pool(self, pool_size: int = None):
        """Initialize persistent Xray process pool for faster testing.
        
        Creates pool_size Xray instances that stay alive and are reused.
        Each instance listens on a unique port.
        
        Args:
            pool_size: Number of processes (default: self.pool_size)
        """
        if pool_size is None:
            pool_size = self.pool_size
        
        if pool_size <= 0:
            return
        
        # Cleanup any existing pool first
        if self._pool_initialized:
            self._cleanup_pool()
        
        log(f"Initializing Xray process pool with {pool_size} instances...")
        
        with self._pool_lock:
            # Use incrementing base port to avoid conflicts with previous pools
            base_port = self.BASE_PORT + 10000 + (hash(time.time()) % 10000)
            
            failed_count = 0
            for i in range(pool_size):
                port = base_port + i
                self._pool_ports.append(port)
                
                # Create minimal config for this pool instance
                config = {
                    "log": {"loglevel": "error", "access": "", "error": ""},
                    "inbounds": [{
                        "tag": f"pool_in_{i}",
                        "listen": "127.0.0.1",
                        "port": port,
                        "protocol": "mixed",
                        "settings": {"auth": "noauth", "udp": True}
                    }],
                    "outbounds": [
                        {"tag": "direct", "protocol": "freedom"},
                        {"tag": "block", "protocol": "blackhole"}
                    ],
                    "routing": {"domainStrategy": "AsIs", "rules": []}
                }
                
                # Write config to temp file
                config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                json.dump(config, config_file, separators=(',', ':'))
                config_file.close()
                
                with self._temp_files_lock:
                    self._temp_files.append(config_file.name)
                
                # Start Xray process
                cmd = [self.xray_path, "run", "-config", config_file.name]
                
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
                
                self._pool_processes.append(process)
                
                # Wait for port to be ready (reduced from 0.2s for faster init)
                time.sleep(0.1)
                
                # Check if process started successfully
                if process.poll() is not None:
                    failed_count += 1
            
            # Verify all processes started
            if failed_count > 0:
                log(f"WARNING: {failed_count}/{pool_size} pool processes failed to start")
            
            self._pool_initialized = True
            if pool_size - failed_count > 0:
                log(f"Xray pool initialized: {pool_size - failed_count} instances ready on ports {base_port}-{base_port + pool_size - 1}")
    
    def _test_through_pool(self, url: str, pool_index: int, timeout: float, max_retries: int = 2) -> Tuple[bool, float]:
        """Test config through pooled Xray with TCP → Xray → TLS fallback flow."""
        if pool_index >= len(self._pool_processes):
            return False, 0.0
        
        process = self._pool_processes[pool_index]
        port = self._pool_ports[pool_index]
        host_port = self._extract_host_port(url)
        
        for attempt in range(max_retries):
            if process.poll() is not None:
                self._track_error("pool_process_dead")
                if attempt < max_retries - 1:
                    self._restart_pool_instance(pool_index)
                    process = self._pool_processes[pool_index]
                    continue
                else:
                    return False, 0.0
            
            outbound = self._url_to_outbound(url, "pool_outbound")
            if not outbound:
                self._track_error("invalid_config")
                return False, 0.0
            
            config = {
                "log": {"loglevel": "error", "access": "", "error": ""},
                "inbounds": [{
                    "tag": "pool_in",
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "mixed",
                    "settings": {"auth": "noauth", "udp": True}
                }],
                "outbounds": [
                    outbound,
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "block", "protocol": "blackhole"}
                ],
                "routing": {
                    "domainStrategy": "AsIs",
                    "rules": [{
                        "type": "field",
                        "inboundTag": ["pool_in"],
                        "outboundTag": "pool_outbound"
                    }]
                }
            }
            
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(config, config_file, separators=(',', ':'))
            config_file.close()
            
            try:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
                    process.wait()
                
                cmd = [self.xray_path, "run", "-config", config_file.name]
                
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
                
                self._pool_processes[pool_index] = process
                
                # Wait for Xray to fully initialize (0.5s is sufficient)
                time.sleep(0.5)
                
                if not self._wait_for_port(port, timeout=2.0):
                    self._track_error("pool_port_timeout")
                    if attempt < max_retries - 1:
                        time.sleep(1.0)
                        continue
                    else:
                        return False, 0.0
                
                tested, latency = self.test_through_socks(port, timeout, verbose=False)
                
                if tested:
                    return tested, latency
                
                # Xray failed - try TLS handshake fallback
                if host_port:
                    host, remote_port = host_port
                    is_tls = ('security=tls' in url.lower() or 'security=reality' in url.lower() or 'security=xtls' in url.lower())
                    if is_tls:
                        sni = None
                        try:
                            parsed = urlparse(url)
                            params = parse_qs(parsed.query)
                            sni = params.get('sni', [None])[0] or params.get('peer', [None])[0] or params.get('host', [None])[0]
                        except:
                            pass
                        tls_ok, tls_version = self._tls_handshake(host, remote_port, sni or host, timeout=5.0)
                        if tls_ok:
                            self._track_error(f"xray_fail_tls_ok_{tls_version.lower().replace(' ', '_')}")
                            return True, latency
                
                if attempt < max_retries - 1:
                    time.sleep(0.2)
                    continue
                else:
                    return False, 0.0
                    
            except Exception as e:
                self._track_error(f"pool_exception_{type(e).__name__}")
                if attempt < max_retries - 1:
                    time.sleep(0.2)
                    continue
                else:
                    return False, 0.0
            finally:
                try:
                    os.unlink(config_file.name)
                except:
                    pass
        
        return False, 0.0
    
    def _cleanup_pool(self):
        """Cleanup all pool processes."""
        with self._pool_lock:
            for process in self._pool_processes:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    try:
                        process.kill()
                    except:
                        pass
            
            self._pool_processes.clear()
            self._pool_ports.clear()
            self._pool_initialized = False
    
    def _wait_for_port(self, port: int, timeout: float = 1.5) -> bool:
        """Wait for SOCKS port to be listening (reduced from 5.0s for faster failure)."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
            time.sleep(0.05)
        return False
    
    def _parse_vless_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        """Parse VLESS URL to Xray outbound with tag."""
        try:
            # Remove protocol prefix
            url_part = url.replace('vless://', '', 1)
            
            # Split at # to separate fragment
            if '#' in url_part:
                url_part, fragment = url_part.split('#', 1)
            
            # Split at ? to separate query params
            if '?' in url_part:
                base_part, query_part = url_part.split('?', 1)
            else:
                base_part = url_part
                query_part = ''
            
            # Parse base part: uuid@host:port
            if '@' not in base_part:
                return None
            
            uuid, host_port = base_part.rsplit('@', 1)
            
            if ':' not in host_port:
                return None
            
            hostname, port_str = host_port.rsplit(':', 1)
            
            # Clean port string
            port_str = port_str.strip().rstrip('/')
            
            try:
                port = int(port_str)
            except:
                return None
            
            # Parse query params
            params = parse_qs(query_part)
            
            if not hostname or not port or not uuid:
                return None
            
            security = params.get('security', ['none'])[0] if params.get('security') else 'none'
            
            outbound = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": hostname,
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
            
            if security == 'tls':
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get('sni', [hostname])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0]
                }
            elif security == 'reality':
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get('sni', [''])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0],
                    "publicKey": params.get('pbk', [''])[0],
                    "shortId": params.get('sid', [''])[0]
                }
            
            transport = params.get('type', ['tcp'])[0]
            if transport == 'ws':
                outbound["streamSettings"]["wsSettings"] = {
                    "path": unquote(params.get('path', ['/'])[0]),
                    "headers": {"Host": unquote(params.get('host', [hostname])[0])}
                }
            elif transport == 'grpc':
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": unquote(params.get('serviceName', [''])[0])
                }
            
            return outbound
        except Exception as e:
            return None
    
    def _parse_vmess_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        """Parse VMess URL to Xray outbound."""
        try:
            encoded = url.replace('vmess://', '').strip()
            
            # Add padding if needed
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            
            # Decode base64 with error handling
            try:
                decoded_bytes = base64.b64decode(encoded)
            except Exception:
                return None
            
            # Decode UTF-8 with error handling
            try:
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
            except Exception:
                return None
            
            # Parse JSON with error handling
            try:
                data = json.loads(decoded)
            except json.JSONDecodeError:
                return None
            
            # Validate required fields
            if not data.get('add') or not data.get('port') or not data.get('id'):
                return None
            
            return {
                "tag": tag,
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": str(data.get('add', '')),
                        "port": int(data.get('port', 443)),
                        "users": [{
                            "id": str(data.get('id', '')),
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
        except Exception:
            return None
    
    def _parse_trojan_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        """Parse Trojan URL to Xray outbound."""
        try:
            # Remove protocol prefix
            url_part = url.replace('trojan://', '', 1)
            
            # Split at # to separate fragment
            if '#' in url_part:
                url_part, fragment = url_part.split('#', 1)
            
            # Split at ? to separate query params
            if '?' in url_part:
                url_part, query_part = url_part.split('?', 1)
            
            # Parse: password@host:port
            if '@' not in url_part:
                return None
            
            password, host_port = url_part.rsplit('@', 1)
            
            if ':' not in host_port:
                return None
            
            hostname, port_str = host_port.rsplit(':', 1)
            
            # Clean port string
            port_str = port_str.strip().rstrip('/')
            
            try:
                port = int(port_str)
            except:
                return None
            
            if not hostname or not port or not password:
                return None
            
            return {
                "tag": tag,
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": hostname,
                        "port": port,
                        "password": password
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": hostname}
                }
            }
        except Exception as e:
            return None
    
    def _parse_shadowsocks_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        """Parse Shadowsocks URL to Xray outbound."""
        try:
            # Remove protocol prefix
            url_part = url.replace('ss://', '', 1)
            
            # Split at # to separate fragment
            if '#' in url_part:
                url_part, fragment = url_part.split('#', 1)
            
            # Split at ? to separate query params FIRST
            if '?' in url_part:
                url_part, query_part = url_part.split('?', 1)
            else:
                query_part = ''
            
            # Handle both formats: base64 and plain
            method = 'chacha20-poly1305'
            password = ''
            hostname = None
            port = None
            
            # Try base64 decode first
            decoded_success = False
            try:
                # Add padding if needed
                padding = 4 - len(url_part) % 4
                if padding != 4:
                    url_part += '=' * padding
                
                decoded = base64.urlsafe_b64decode(url_part).decode('utf-8', errors='ignore')
                
                # Decoded format: method:password@host:port
                if '@' in decoded:
                    userinfo, server = decoded.rsplit('@', 1)
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                    else:
                        method = userinfo
                        password = ''
                    
                    if ':' in server:
                        hostname, port_str = server.rsplit(':', 1)
                        port = int(port_str)
                    else:
                        hostname = server
                        port = 443
                    decoded_success = True
                        
            except Exception:
                pass  # Will try legacy format
            
            # Try legacy format: method:password@host:port (not base64)
            if not decoded_success:
                # Reset url_part (remove any padding we added)
                url_part = url.replace('ss://', '', 1)
                if '#' in url_part:
                    url_part, fragment = url_part.split('#', 1)
                if '?' in url_part:
                    url_part, query_part = url_part.split('?', 1)
                
                if '@' in url_part:
                    userinfo, server = url_part.rsplit('@', 1)
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                    else:
                        method = userinfo
                        password = ''
                    
                    if ':' in server:
                        hostname, port_str = server.rsplit(':', 1)
                        port = int(port_str)
                    else:
                        hostname = server
                        port = 443
                    decoded_success = True
            
            # Last resort: try to extract what we can
            if not decoded_success:
                url_part = url.replace('ss://', '', 1)
                if '#' in url_part:
                    url_part, fragment = url_part.split('#', 1)
                if '?' in url_part:
                    url_part, query_part = url_part.split('?', 1)
                
                if ':' in url_part:
                    parts = url_part.split(':')
                    if len(parts) >= 2:
                        port_str = parts[-1].strip()
                        hostname = ':'.join(parts[:-1]).split('@')[-1]
                        try:
                            port = int(port_str)
                            decoded_success = True
                        except:
                            pass
            
            # Final validation
            if not hostname:
                return None
            
            if not port:
                port = 443
            
            if not password:
                password = 'password'
            
            return {
                "tag": tag,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": str(hostname),
                        "port": int(port),
                        "password": str(password),
                        "method": str(method)
                    }]
                }
            }
        except Exception:
            return None
    
    def _parse_hysteria2_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        """Parse Hysteria2/Hy2 URL to Xray outbound."""
        try:
            parsed = urlparse(url.replace('hysteria2://', '').replace('hy2://', ''))
            params = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.port:
                return None
            
            return {
                "tag": tag,
                "protocol": "hysteria2",
                "settings": {
                    "servers": [{
                        "address": parsed.hostname,
                        "port": parsed.port,
                        "password": unquote(parsed.username) if parsed.username else ""
                    }]
                },
                "streamSettings": {
                    "network": "udp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": params.get('sni', [parsed.hostname])[0]
                    }
                }
            }
        except Exception:
            return None
    
    def _url_to_outbound(self, url: str, tag: str) -> Optional[Dict]:
        """Convert URL to outbound based on protocol."""
        protocol_parsers = {
            'vless://': self._parse_vless_to_outbound,
            'vmess://': self._parse_vmess_to_outbound,
            'trojan://': self._parse_trojan_to_outbound,
            'ss://': self._parse_shadowsocks_to_outbound,
            'hysteria2://': self._parse_hysteria2_to_outbound,
            'hy2://': self._parse_hysteria2_to_outbound,
        }
        
        for prefix, parser in protocol_parsers.items():
            if url.startswith(prefix):
                return parser(url, tag)
        
        return None
    
    def create_single_outbound_config(self, url: str, socks_port: int) -> Optional[Dict]:
        """Create Xray config with single inbound + single outbound."""
        outbound = self._url_to_outbound(url, "proxy")
        if not outbound:
            return None
        
        return {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": [{
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "mixed",  # Match v2rayN - supports both HTTP and SOCKS
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [{
                    "type": "field",
                    "inboundTag": ["socks"],
                    "outboundTag": "proxy"
                }]
            }
        }
    
    def create_multi_config(self, urls: List[str], base_port: int) -> Tuple[Optional[Dict], Dict[int, str]]:
        """Create SINGLE Xray config with multiple inbounds/outbounds (SMART batching).
        
        OPTIMAL BATCH SIZE: 100 configs per Xray instance.
        This creates ONE Xray process with 100 inbounds instead of 100 processes.
        
        Returns: (config_dict, port_to_url_mapping) or (None, {}) if failed
        """
        # SMART: Validate batch size
        if len(urls) > self.MAX_BATCH_SIZE:
            log(f"WARNING: Batch size {len(urls)} exceeds maximum {self.MAX_BATCH_SIZE}. Split into smaller batches.")
        
        config = {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": [],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}  # FIX: Required for proper routing
            ],
            "routing": {"domainStrategy": "AsIs", "rules": []}
        }
        port_map = {}
        used_ports = set()
        skipped_urls = []
        
        for idx, url in enumerate(urls):
            port = base_port + idx
            if port in used_ports:
                # Skip to next available port
                while port in used_ports:
                    port += 1
            
            # PRE-VALIDATE: Skip obviously broken configs BEFORE parsing
            # Skip configs that commonly cause Xray to crash entire batch
            if not url or not url.strip():
                skipped_urls.append((url, "Empty config"))
                continue
            
            # Skip malformed URLs
            if '://' not in url:
                skipped_urls.append((url, "Missing protocol prefix"))
                continue
            
            outbound = self._url_to_outbound(url, f"proxy{port}")
            if not outbound:
                skipped_urls.append((url, "Failed to parse outbound"))
                continue
            
            # VALIDATE: Check for common config errors BEFORE adding to batch
            try:
                protocol = outbound.get("protocol", "")
                settings = outbound.get("settings", {})
                
                # Check VLESS/REALITY configs
                if protocol == "vless":
                    vnext = settings.get("vnext", [])
                    if vnext and len(vnext) > 0:
                        users = vnext[0].get("users", [])
                        if users and len(users) > 0:
                            user = users[0]
                            # Empty UUID/password
                            if not user.get("id"):
                                skipped_urls.append((url, "VLESS/REALITY with empty UUID"))
                                continue
                
                # Check Shadowsocks configs
                if protocol == "shadowsocks":
                    servers = settings.get("servers", [])
                    if servers and len(servers) > 0:
                        method = servers[0].get("method", "")
                        password = servers[0].get("password", "")
                        
                        # Empty password
                        if not password:
                            skipped_urls.append((url, "Shadowsocks with empty password"))
                            continue
                
                # Check Trojan configs
                if protocol == "trojan":
                    servers = settings.get("servers", [])
                    if servers and len(servers) > 0:
                        password = servers[0].get("password", "")
                        if not password:
                            skipped_urls.append((url, "Trojan with empty password"))
                            continue
                
            except Exception as e:
                skipped_urls.append((url, f"Validation error: {str(e)[:60]}"))
                continue
            
            inbound = {
                "tag": f"mixed{port}",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True}
            }
            config["inbounds"].append(inbound)
            config["outbounds"].append(outbound)
            
            rule = {
                "type": "field",
                "inboundTag": [f"mixed{port}"],
                "outboundTag": f"proxy{port}"
            }
            config["routing"]["rules"].append(rule)
            
            port_map[port] = url
            used_ports.add(port)
        
        if skipped_urls:
            # Log first few skipped configs for debugging
            sample = skipped_urls[:5]
            reasons = {}
            for _, reason in sample:
                reasons[reason] = reasons.get(reason, 0) + 1
            log(f"Skipped {len(skipped_urls)} invalid configs: {', '.join([f'{k}({v})' for k,v in list(reasons.items())[:3]])}...")
        
        if not port_map:
            return None, {}
        
        log(f"Created multi-config with {len(port_map)} valid inbounds (ports {min(port_map.keys())}-{max(port_map.keys())})")
        return config, port_map
    
    def _wait_for_ports(self, ports: List[int], timeout: float = None) -> bool:
        """Wait for multiple ports to be listening with SMART timeout.
        
        DYNAMIC TIMEOUT: 50ms per port, min 3s, max 30s
        For 100 ports: 5 seconds
        For 200 ports: 10 seconds
        """
        if timeout is None:
            timeout = min(30.0, max(3.0, 0.05 * len(ports)))
        
        start = time.time()
        pending_ports = set(ports)
        
        while time.time() - start < timeout and pending_ports:
            for port in list(pending_ports):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.05)
                    result = sock.connect_ex(('127.0.0.1', port))
                    sock.close()
                    if result == 0:
                        pending_ports.discard(port)
                except:
                    pass
            if pending_ports:
                time.sleep(0.05)
        
        if pending_ports:
            log(f"WARNING: {len(pending_ports)}/{len(ports)} ports never opened after {timeout:.1f}s")
        
        return len(pending_ports) == 0
    
    def start_xray_multi_config(self, config: Dict, port_map: Dict[int, str], verbose: bool = False) -> Tuple[bool, Optional[subprocess.Popen], str]:
        """Start Xray with multi-config and wait for ALL ports to be ready."""
        ports = list(port_map.keys())
        if not ports:
            return False, None, "No ports in port_map"
        
        # Validate config JSON first
        try:
            config_json = json.dumps(config, separators=(',', ':'))
            json.loads(config_json)
        except json.JSONDecodeError as e:
            if verbose:
                log(f"Invalid config JSON: {e}")
            return False, None, "Invalid JSON config"
        
        temp_name = f"xray_cfg_{random.randint(10000, 99999)}.json"
        config_file = os.path.join(tempfile.gettempdir(), temp_name)
        
        try:
            with open(config_file, 'w') as f:
                f.write(config_json)
        except Exception as e:
            if verbose:
                log(f"Failed to write config: {e}")
            return False, None, str(e)
        
        try:
            cmd = [self.xray_path, "run", "-config", config_file]
            
            # Suppress all Xray output (no banners, no logs)
            if sys.platform == "win32":
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            time.sleep(0.05)  # Trust OS, don't wait
            
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=2)
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
                stdout_text = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
                
                if verbose:
                    log(f"Xray exited immediately: {stderr_text[:300] if stderr_text else stdout_text[:300]}")
                
                try:
                    os.unlink(config_file)
                except:
                    pass
                return False, None, stderr_text or stdout_text or "Xray exited immediately"
            
            # Wait for ALL ports to be listening with DYNAMIC timeout
            port_timeout = min(10.0, max(2.0, 0.02 * len(ports)))  # Fast timeout
            if not self._wait_for_ports(ports, timeout=port_timeout):
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except:
                    process.kill()
                    stdout, stderr = b"", b""
                
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
                stdout_text = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
                
                if verbose:
                    log(f"Xray ports not listening: {stderr_text[:300] if stderr_text else stdout_text[:300]}")
                
                try:
                    os.unlink(config_file)
                except:
                    pass
                return False, None, stderr_text or stdout_text or "Ports not listening"
            
            with self._process_lock:
                self._running_processes.append(process)
            
            return True, process, ""
            
        except Exception as e:
            # Suppress spammy "Failed to start" messages for common config errors
            error_str = str(e)
            is_config_error = any([
                "empty \"password\"" in error_str,
                "unsupported \"encryption\"" in error_str,
                "failed to build outbound" in error_str.lower(),
            ])
            if verbose and not is_config_error:
                log(f"Failed to start Xray: {e}")
            try:
                os.unlink(config_file)
            except:
                pass
            return False, None, str(e)
    
    def start_xray_instance(self, config: Dict, socks_port: int, verbose: bool = False) -> Tuple[bool, Optional[subprocess.Popen], str]:
        """Start Xray with single config and wait for port readiness."""
        # Validate config JSON first
        try:
            config_json = json.dumps(config, separators=(',', ':'))  # Minified JSON
            json.loads(config_json)  # Validate it parses back
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON config: {e}"
            if verbose:
                log(error_msg)
            return False, None, error_msg
        
        # Validate config structure
        if not config.get('inbounds') or not config.get('outbounds'):
            error_msg = "Invalid config structure: missing inbounds or outbounds"
            if verbose:
                log(f"{error_msg}: {config_json[:500]}")
            return False, None, error_msg
        
        # Use temp file with random name (reduce collision risk)
        temp_name = f"xray_cfg_{random.randint(10000, 99999)}.json"
        config_file = os.path.join(tempfile.gettempdir(), temp_name)
        
        try:
            with open(config_file, 'w') as f:
                f.write(config_json)
        except Exception as e:
            if verbose:
                log(f"Failed to write config: {e}")
            return False, None, str(e)
        
        try:
            cmd = [self.xray_path, "run", "-config", config_file]
            
            # Suppress all Xray output (no banners, no logs) - capture only on error
            if sys.platform == "win32":
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    bufsize=1024*1024
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1024*1024
                )
            
            # Wait for Xray to fully initialize (0.3s - fast startup)
            time.sleep(0.3)
            
            # Check if process exited immediately
            if process.poll() is not None:
                # Process died, get stderr
                stdout, stderr = process.communicate(timeout=2)
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
                stdout_text = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
                
                # Get FULL error message (up to 2000 chars) - filter spam
                error_detail = stderr_text[:2000] if stderr_text else (stdout_text[:2000] if stdout_text else "Xray exited immediately")
                
                # Filter out ALL spam (banners, runtime errors, goroutine traces, info logs)
                is_spam = any([
                    "Xray 26.2.6" in error_detail,
                    "Xray," in error_detail and "Penetrates Everything" in error_detail,
                    "A unified platform" in error_detail,
                    "[Warning]" in error_detail,
                    "[Info]" in error_detail,
                    "infra/conf" in error_detail,
                    "deprecated" in error_detail.lower(),
                    "goroutine" in error_detail.lower(),
                    "runtime." in error_detail,
                    "fp=0x" in error_detail,
                    "sp=0x" in error_detail,
                    "pc=0x" in error_detail,
                    "runtime stack:" in error_detail.lower(),
                    "fatal error:" in error_detail.lower(),
                    "errno=" in error_detail,
                    "ulimit" in error_detail.lower(),
                    "Reading config:" in error_detail,
                ])
                
                # Always filter spam (even if not verbose) - track error category
                if is_spam:
                    # Track as Xray error but return clean message
                    self._track_error("XRAY_RESOURCE")
                    error_detail = "Xray resource error (filtered)"
                elif verbose:
                    log(f"Xray error: {error_detail}")
                
                try:
                    os.unlink(config_file)
                except:
                    pass
                return False, None, error_detail
            
            # Wait for port to be listening (2s timeout - fast failure)
            if not self._wait_for_port(socks_port, timeout=2.0):
                # Xray didn't bind to port, get stderr
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except:
                    process.kill()
                    stdout, stderr = b"", b""
                
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
                stdout_text = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
                
                # Get FULL error message (up to 2000 chars) - suppress spam
                error_detail = stderr_text[:2000] if stderr_text else (stdout_text[:2000] if stdout_text else "")
                # Already filtered above, no need to log again
                
                try:
                    os.unlink(config_file)
                except:
                    pass
                return False, None, error_detail or "Port not listening"
            
            with self._process_lock:
                self._running_processes.append(process)
            
            return True, process, ""
            
        except Exception as e:
            # Suppress spammy "Failed to start" messages for common config errors
            error_str = str(e)
            is_config_error = any([
                "empty \"password\"" in error_str,
                "unsupported \"encryption\"" in error_str,
                "failed to build outbound" in error_str.lower(),
            ])
            if verbose and not is_config_error:
                log(f"Failed to start Xray: {e}")
            try:
                os.unlink(config_file)
            except:
                pass
            return False, None, str(e)
    
    def stop_xray_process(self, process: subprocess.Popen):
        """Stop a single Xray process."""
        try:
            if process.poll() is None:  # Still running
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
                    process.wait(timeout=1)
        except:
            try:
                process.kill()
            except:
                pass
        
        with self._process_lock:
            if process in self._running_processes:
                self._running_processes.remove(process)
    
    def _get_session(self):
        """Get thread-local session (no lock contention)."""
        if not hasattr(self, '_thread_local') or self._thread_local is None:
            self._thread_local = threading.local()
        
        if not hasattr(self._thread_local, 'session'):
            session = requests.Session()
            retry = Retry(total=0, backoff_factor=0)
            adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._thread_local.session = session
        
        return self._thread_local.session
    
    def _quick_validate_url(self, url: str) -> Tuple[bool, str]:
        """Minimal validation - let Xray decide if config is valid."""
        if not url or not isinstance(url, str):
            return False, "Empty URL"
        if '://' not in url:
            return False, "No protocol"
        # Let Xray validate the rest
        return True, ""
    
    def test_through_socks(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """Test connection through SOCKS proxy - HTTP only (port already verified)."""
        # Port already verified by _wait_for_port(), skip redundant TCP ping
        return self._http_ping_through_proxy(socks_port, timeout, verbose)
    
    async def test_through_socks_async(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """Async test connection through SOCKS proxy using curl_cffi."""
        # Port already verified, skip redundant TCP ping
        return await self._http_ping_through_proxy_async(socks_port, timeout, verbose)
    
    def _tcp_ping(self, host: str, port: int, timeout: float = 5.0) -> Tuple[bool, float]:
        """Fast TCP connectivity check to proxy server (increased to 5s for slow handshakes)."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.perf_counter()
            sock.connect((host, port))
            latency = (time.perf_counter() - start) * 1000
            return True, latency
        except Exception:
            return False, 0.0
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _tls_handshake(self, host: str, port: int, sni: str = None, timeout: float = 5.0) -> Tuple[bool, Optional[str]]:
        """Check if TLS handshake succeeds (fallback test for TLS/Reality configs) - 5s timeout."""
        sock = None
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=sni or host)
            ssl_sock.do_handshake()
            
            version = ssl_sock.version()
            ssl_sock.close()
            sock.close()
            
            return True, version
        except Exception:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            return False, None
    
    def _check_alternative_methods(self, url: str, host_port: Optional[Tuple[str, int]]) -> Optional[Dict]:
        """TCP + TLS handshake fallback when Xray fails (matches working project).
        
        Returns: {'ping': latency_ms, 'method': 'tcp_tls_ok'} or None
        """
        if not host_port:
            return None
        
        host, port = host_port
        
        # Test 1: TCP connectivity (2s timeout)
        tcp_ok = self._tcp_ping(host, port, timeout=2.0)[0]
        if not tcp_ok:
            return None
        
        # Test 2: TLS handshake for secure configs (2s timeout)
        is_tls = ('security=tls' in url.lower() or 'security=reality' in url.lower() or 'security=xtls' in url.lower())
        if is_tls:
            sni = None
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                sni = params.get('sni', [None])[0] or params.get('peer', [None])[0] or params.get('host', [None])[0]
            except:
                pass
            
            tls_ok, tls_version = self._tls_handshake(host, port, sni or host, timeout=2.0)
            if tls_ok:
                return {'ping': 100, 'method': f'tls_ok_{tls_version.lower().replace(" ", "_")}'}
        
        return None
    
    def _track_error(self, error_msg: str, category: str = None):
        """Track error for summary statistics with deduplication."""
        # Auto-categorize if not provided
        if not category:
            error_lower = error_msg.lower() if error_msg else "unknown"
            
            if "timeout" in error_lower or "timed out" in error_lower:
                category = "timeout"
            elif "connection refused" in error_lower:
                category = "connection_refused"
            elif "connection reset" in error_lower or "connection aborted" in error_lower:
                category = "connection_reset"
            elif "proxy" in error_lower or "socks" in error_lower:
                category = "proxy_error"
            elif "xray" in error_lower or "process" in error_lower:
                category = "xray_error"
            elif "parse" in error_lower or "invalid" in error_lower or "malformed" in error_lower:
                category = "parse_error"
            elif "certificate" in error_lower or "ssl" in error_lower or "tls" in error_lower:
                category = "ssl_error"
            elif "http" in error_lower and ("failed" in error_lower or "error" in error_lower):
                category = "http_error"
            else:
                category = "other"
        
        # Normalize error message for deduplication (remove specific values)
        normalized = self._normalize_error(error_msg)
        
        with self._error_stats_lock:
            self._error_stats[category] = self._error_stats.get(category, 0) + 1
            
            # Store up to 3 sample errors per category
            if category not in self._error_samples:
                self._error_samples[category] = []
            if len(self._error_samples[category]) < 3 and normalized not in self._error_samples[category]:
                self._error_samples[category].append(error_msg[:200])
    
    def _normalize_error(self, error_msg: str) -> str:
        """Normalize error message by removing variable parts for deduplication."""
        if not error_msg:
            return "unknown"
        
        # Remove ports, IPs, UUIDs, timestamps
        normalized = error_msg
        # Remove port numbers
        normalized = re.sub(r':\d+', ':PORT', normalized)
        # Remove UUIDs
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', normalized, flags=re.I)
        # Remove IP addresses
        normalized = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', normalized)
        # Remove file paths
        normalized = re.sub(r'C:\\[^\\s]+|/[^\\s]+\\.json', 'FILE', normalized)
        
        return normalized[:150]  # Truncate for comparison
    
    def _print_error_summary(self):
        """Print detailed summary of errors with samples (called once at end of batch)."""
        with self._error_stats_lock:
            if not self._error_stats:
                return
            
            log(f"\n{'='*70}")
            log(f"DETAILED ERROR SUMMARY:")
            total = sum(self._error_stats.values())
            
            for category, count in sorted(self._error_stats.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                log(f"\n  {category.upper()}: {count} ({pct:.1f}%)")
                
                # Show sample errors for this category
                if category in self._error_samples:
                    for i, sample in enumerate(self._error_samples[category], 1):
                        log(f"    [{i}] {sample}")
            
            log(f"\n  {'='*60}")
            log(f"  TOTAL ERRORS: {total}")
            log(f"{'='*70}\n")
            
            # Reset for next batch
            self._error_stats.clear()
            self._error_samples.clear()
    
    def _http_ping_through_proxy(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """HTTP request through proxy using curl_cffi - better SOCKS support."""
        if CURL_CFFI_AVAILABLE:
            return self._http_ping_through_proxy_curl(socks_port, timeout, verbose)
        else:
            return self._http_ping_through_proxy_requests(socks_port, timeout, verbose)
    
    def _http_ping_through_proxy_curl(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """HTTP request through proxy using curl_cffi (sync Session)."""
        proxy_url = f"socks://127.0.0.1:{socks_port}"  # curl_cffi string format uses socks://
        
        # Try each test URL until one works
        for test_url in self.TEST_URLS:
            latencies = []
            
            # v2rayN makes 2 requests, takes minimum latency
            for attempt in range(2):
                try:
                    start = time.perf_counter()
                    with CurlSession() as session:
                        response = session.get(
                            test_url,
                            proxy=proxy_url,
                            timeout=timeout,
                            allow_redirects=True
                        )
                        latency = (time.perf_counter() - start) * 1000
                        latencies.append(latency)
                        break  # Success
                except Exception as e:
                    # Track specific error type
                    if verbose:
                        log(f"HTTP attempt failed: {type(e).__name__}: {str(e)[:80]}")
                    continue
            
            if latencies:
                min_latency = min(latencies)
                if verbose:
                    log(f"Port {socks_port}: OK via {test_url[:40]} in {min_latency:.0f}ms")
                return True, min_latency
        
        if verbose:
            log(f"Port {socks_port}: All test URLs failed")
        return False, 0.0
    
    def _http_ping_through_proxy_requests(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """HTTP request through proxy using requests with socks5h:// (remote DNS)."""
        session = self._get_session()
        
        # Use socks5:// for local DNS resolution (matches v2rayN behavior)
        proxies = {
            "http": f"socks5://127.0.0.1:{socks_port}",
            "https": f"socks5://127.0.0.1:{socks_port}"
        }
        
        # Try each test URL until one works
        for test_url in self.TEST_URLS:
            latencies = []
            
            # v2rayN makes 2 requests, takes minimum latency
            for attempt in range(2):
                try:
                    start = time.perf_counter()
                    response = session.get(
                        test_url,
                        proxies=proxies,
                        timeout=(min(10.0, timeout), timeout),
                        allow_redirects=True
                    )
                    latency = (time.perf_counter() - start) * 1000
                    latencies.append(latency)
                    break  # Success
                except Exception as e:
                    if verbose:
                        log(f"Port {socks_port}: {test_url[:40]} failed - {type(e).__name__}: {str(e)[:80]}")
                    continue
            
            if latencies:
                min_latency = min(latencies)
                if verbose:
                    log(f"Port {socks_port}: OK via {test_url[:40]} in {min_latency:.0f}ms")
                return True, min_latency
        
        if verbose:
            log(f"Port {socks_port}: All test URLs failed")
        return False, 0.0
    
    async def _http_ping_through_proxy_async(self, socks_port: int, timeout: float, verbose: bool = False) -> Tuple[bool, float]:
        """Native curl_cffi async HTTP test through SOCKS5 proxy with 10s+3s retry."""
        if not CURL_CFFI_AVAILABLE:
            return self._http_ping_through_proxy(socks_port, timeout, verbose)
        
        # Use socks:// for curl_cffi (matches sync version)
        proxy_url = f"socks://127.0.0.1:{socks_port}"
        
        # Try each test URL until one works (matches v2rayN behavior)
        for test_url in self.TEST_URLS:
            # Main attempt with full timeout (5s)
            try:
                async with AsyncSession(
                    impersonate="chrome124",  # Browser fingerprint for compatibility
                    trust_env=False
                ) as session:
                    start = time.perf_counter()
                    response = await session.get(
                        test_url,
                        proxy=proxy_url,  # Single proxy URL (curl_cffi format)
                        timeout=timeout,  # Main timeout (10s)
                        allow_redirects=True
                    )
                    latency = (time.perf_counter() - start) * 1000
                    
                    if verbose:
                        log(f"Port {socks_port}: OK via {test_url[:40]} in {latency:.0f}ms")
                    return True, latency
                    
            except asyncio.TimeoutError:
                # Main attempt timed out, try retry with 3s
                if verbose:
                    log(f"Port {socks_port}: Main timeout via {test_url[:40]}, retrying with 3s...")
                
                try:
                    async with AsyncSession(
                        impersonate="chrome124",  # Browser fingerprint for compatibility
                        trust_env=False
                    ) as session:
                        start = time.perf_counter()
                        response = await session.get(
                            test_url,
                            proxy=proxy_url,
                            timeout=2.0,  # Retry timeout (2s)
                            allow_redirects=True
                        )
                        latency = (time.perf_counter() - start) * 1000
                        
                        if verbose:
                            log(f"Port {socks_port}: OK on retry via {test_url[:40]} in {latency:.0f}ms")
                        return True, latency
                        
                except asyncio.TimeoutError:
                    if verbose:
                        log(f"Port {socks_port}: Retry timeout via {test_url[:40]}")
                    self._track_error("HTTP_Timeout")
                    continue  # Try next URL
                except Exception as e2:
                    error_type = type(e2).__name__
                    if verbose:
                        log(f"Port {socks_port}: Retry failed - {error_type} via {test_url[:40]}")
                    self._track_error(f"HTTP_{error_type}")
                    continue  # Try next URL
                    
            except Exception as e:
                error_type = type(e).__name__
                if verbose:
                    log(f"Port {socks_port}: Main failed - {error_type} via {test_url[:40]}")
                self._track_error(f"HTTP_{error_type}")
                continue  # Try next URL
        
        # All URLs failed
        if verbose:
            log(f"Port {socks_port}: All test URLs failed")
        return False, 0.0
    
    def _extract_host_port(self, url: str) -> Optional[Tuple[str, int]]:
        """Extract host and port from config URL for TCP ping."""
        try:
            # Remove protocol prefix first
            url_no_proto = url
            for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://']:
                if url.startswith(proto):
                    url_no_proto = url[len(proto):]
                    break
            
            # Remove fragment (#comment)
            if '#' in url_no_proto:
                url_no_proto = url_no_proto.split('#')[0]
            
            # Remove query params for initial parsing
            url_base = url_no_proto.split('?')[0]
            
            # Special handling for VMess (base64 encoded)
            if url.startswith('vmess://'):
                try:
                    import base64
                    # Try to decode VMess config
                    decoded = base64.b64decode(url_base).decode('utf-8', errors='ignore')
                    # Try to parse as JSON
                    import json
                    vmess_config = json.loads(decoded)
                    if 'add' in vmess_config and 'port' in vmess_config:
                        return vmess_config['add'], int(vmess_config['port'])
                except:
                    pass
                # Fall through to normal parsing if decode fails
            
            # Extract host:port from various formats
            if '@' in url_base:
                # Format: userinfo@host:port (VLESS, Trojan, SS)
                host_port = url_base.split('@')[-1]
            else:
                # Format: host:port (some SS variants)
                host_port = url_base
            
            # Parse host and port
            if ':' in host_port:
                # Handle IPv6 addresses [::1]:port
                if host_port.startswith('['):
                    bracket_end = host_port.find(']')
                    if bracket_end > 0 and host_port[bracket_end+1:bracket_end+2] == ':':
                        host = host_port[1:bracket_end]
                        port_str = host_port[bracket_end+2:]
                    else:
                        return None
                else:
                    # Regular host:port
                    host, port_str = host_port.rsplit(':', 1)
                
                port = int(port_str)
                if host and port:
                    return host, port
            
            # Fallback: try urlparse for edge cases
            parsed = urlparse(url)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
            
            # Default ports based on security
            if 'security=tls' in url.lower() or 'security=reality' in url.lower():
                if parsed.hostname:
                    return parsed.hostname, 443
            
            return None
            
        except Exception:
            return None
    
    def test_single_config(self, url: str, timeout: float, verbose: bool = False, max_retries: int = 2, skip_tcp_ping: bool = False) -> Tuple[str, bool, float, str]:
        """Test config through Xray HTTP test only.
        
        Args:
            url: Config URL to test
            timeout: HTTP test timeout (default 10s)
            verbose: Enable verbose logging
            max_retries: Number of retry attempts (default 2)
            skip_tcp_ping: Ignored (kept for compatibility)
        
        Returns:
            (url, is_working, latency_ms, error_message)
        """
        last_error = "Unknown error"
        
        for attempt in range(max_retries):
            valid, error = self._quick_validate_url(url)
            if not valid:
                self._track_error(error)
                return (url, False, 0.0, error)
            
            # STAGE 1: XRAY HTTP TEST
            socks_port = self._get_next_port()
            
            config = self.create_single_outbound_config(url, socks_port)
            if not config:
                last_error = "Failed to parse config"
                self._track_error(last_error)
                return (url, False, 0.0, last_error)
            
            success, process, error_msg = self.start_xray_instance(config, socks_port, verbose=verbose)
            if not success:
                # error_msg already logged in start_xray_instance
                self._track_error(error_msg or "Xray failed to start")
                if attempt < max_retries - 1:
                    time.sleep(0.1)
                    continue
                else:
                    return (url, False, 0.0, error_msg or "Xray failed to start")
            
            try:
                tested, latency = self.test_through_socks(socks_port, timeout)
                if tested:
                    return (url, tested, latency, "")
                
                # HTTP failed = config doesn't work
                last_error = "HTTP test failed (no response)"
                self._track_error(last_error)
                
                if attempt < max_retries - 1:
                    time.sleep(0.1)
                    continue
                else:
                    return (url, False, 0.0, last_error)
            finally:
                self.stop_xray_process(process)
        
        return (url, False, 0.0, last_error)
    
    def _test_batch_concurrent(self, port_map: Dict[int, str], timeout: float, concurrency: int, verbose: bool = False) -> List[Tuple[str, bool, float]]:
        """Test all configs in batch concurrently through different ports with VERBOSE error logging."""
        import concurrent.futures
        
        results = []
        results_lock = threading.Lock()
        failed_ports = []
        
        def test_port(port: int) -> Tuple[str, bool, float]:
            url = port_map[port]
            try:
                tested, latency = self.test_through_socks(port, timeout, verbose=False)
                if not tested:
                    failed_ports.append(port)
                return (url, tested, latency)
            except Exception as e:
                if verbose:
                    log(f"Port {port} ({url[:60]}...) exception: {type(e).__name__}: {str(e)[:100]}")
                failed_ports.append(port)
                return (url, False, 0.0)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(test_port, port): port for port in port_map.keys()}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=timeout + 5)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    port = futures[future]
                    if verbose:
                        log(f"Port {port} test timed out after {timeout + 5}s")
                    results.append((port_map[port], False, 0.0))
                except Exception as e:
                    port = futures[future]
                    if verbose:
                        log(f"Port {port} future exception: {type(e).__name__}: {str(e)[:100]}")
                    results.append((port_map[port], False, 0.0))
        
        if verbose and failed_ports:
            log(f"Batch testing complete: {len(results) - len(failed_ports)}/{len(results)} passed, {len(failed_ports)} failed")
        
        return results
    
    async def _test_single_config_pipelined_async(self, url: str, timeout: float, verbose: bool = False) -> Tuple[str, bool, float]:
        """Pipelined test: Xray in thread, curl_cffi async HTTP with socks5h://."""
        loop = asyncio.get_running_loop()
        
        # STAGE 1: Start Xray in thread pool (doesn't block event loop)
        socks_port = self._get_next_port()
        config = self.create_single_outbound_config(url, socks_port)
        
        if not config:
            self._track_error("parse_error")
            return (url, False, 0.0)
        
        def start_xray_sync():
            success, process, error = self.start_xray_instance(config, socks_port, verbose=False)
            return (process, success, error)
        
        # Start Xray (other configs can proceed while this runs)
        process, success, error = await loop.run_in_executor(None, start_xray_sync)
        
        if not success:
            self._track_error(error or "Xray_failed")
            return (url, False, 0.0)
        
        try:
            # STAGE 2: HTTP test via curl_cffi async (native async, socks5h:// for remote DNS)
            tested, latency = await self._http_ping_through_proxy_async(socks_port, timeout, verbose=verbose)
            
            if tested:
                return (url, True, latency)
            
            self._track_error("HTTP_test_failed")
            return (url, False, 0.0)
        
        finally:
            # STAGE 3: Cleanup Xray in background (fire-and-forget)
            loop.run_in_executor(None, self.stop_xray_process, process)
    
    async def _test_batch_async(self, urls: List[str], concurrency: int, timeout: float, verbose: bool) -> List[Tuple[str, bool, float]]:
        """Test configs with PIPELINED ASYNC (Xray startup overlaps with HTTP testing)."""
        semaphore = asyncio.Semaphore(concurrency)
        results = []
        results_lock = asyncio.Lock()
        completed = [0]
        failed_count = [0]
        start_time = time.time()
        
        async def test_with_semaphore(url: str) -> Tuple[str, bool, float]:
            async with semaphore:
                try:
                    # Use PIPELINED async (Xray startup overlaps with other HTTP tests)
                    result = await self._test_single_config_pipelined_async(url, timeout, verbose=False)
                    async with results_lock:
                        completed[0] += 1
                        count = completed[0]
                        if not result[1]:
                            failed_count[0] += 1
                    if count % 50 == 0 or count == len(urls):
                        elapsed = time.time() - start_time
                        rate = count / elapsed if elapsed > 0 else 0
                        remaining = len(urls) - count
                        eta = remaining / rate if rate > 0 else 0
                        working_count = count - failed_count[0]
                        log(f"Progress: {count}/{len(urls)} ({rate:.1f}/s, ETA: {eta:.0f}s) - Working: {working_count}")
                    return result
                except Exception as e:
                    if verbose:
                        log(f"Async test failed for {url[:60]}: {type(e).__name__}: {str(e)[:100]}")
                    async with results_lock:
                        completed[0] += 1
                        failed_count[0] += 1
                    return (url, False, 0.0)
        
        tasks = [test_with_semaphore(url) for url in urls]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(task_results):
            if isinstance(result, Exception):
                results.append((urls[i], False, 0.0))
            else:
                results.append(result)
        
        return results
    
    def _test_batch_async_wrapper(self, urls: List[str], concurrency: int, timeout: float, verbose: bool) -> List[Tuple[str, bool, float]]:
        """Simple async wrapper: Xray in threads, HTTP via requests (hybrid approach)."""
        from concurrent.futures import ThreadPoolExecutor
        import asyncio
        
        # Increased concurrency for WSL2/Linux (300 workers - optimal balance)
        max_workers = min(concurrency, 300)
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="xray_worker")
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.set_default_executor(executor)
            
            results = loop.run_until_complete(self._test_batch_async(urls, concurrency, timeout, verbose))
            
            # Brief pause for cleanup
            time.sleep(0.5)
            
            # Sort by latency (fastest first)
            working = [(url, s, l) for url, s, l in results if s]
            working.sort(key=lambda x: x[2])
            
            success_rate = len(working) / len(urls) * 100 if urls else 0
            log(f"Async testing complete: {len(working)}/{len(urls)} working ({success_rate:.1f}%)")
            
            self._print_error_summary()
            
            return working
        finally:
            executor.shutdown(wait=False)
            loop.close()
    
    def test_batch(self, urls: List[str], concurrency: int = None, timeout: float = None, verbose: bool = False, tcp_only: bool = False, use_pool: bool = False, batch_size: int = 100, use_batch_mode: bool = False) -> List[Tuple[str, bool, float]]:
        """Test configs through Xray with TCP+TLS fallback (no pre-filtering)."""
        if not urls:
            return []
        
        # Import VALIDATION_HTTP_TIMEOUT from settings (default 10s)
        try:
            from config.settings import VALIDATION_HTTP_TIMEOUT
            default_timeout = VALIDATION_HTTP_TIMEOUT
        except:
            default_timeout = 10.0
        
        timeout = timeout or default_timeout  # Default 10s (main attempt, retry is 3s)
        if concurrency is None:
            cpu_count = multiprocessing.cpu_count()
            concurrency = max(400, cpu_count * 50)
        
        # Reduce concurrency on Linux to avoid resource exhaustion (Errno 11)
        if sys.platform == "linux":
            concurrency = min(concurrency, 300)  # Cap at 300 - optimal for WSL2
            log(f"Testing {len(urls)} configs (CPU cores={cpu_count}, concurrency={concurrency} (capped for Linux), timeout={timeout}s)")
        else:
            log(f"Testing {len(urls)} configs (CPU cores={cpu_count}, concurrency={concurrency}, timeout={timeout}s)")
        
        # Auto-detect platform and use async on Linux/WSL
        if sys.platform == "linux":
            return self._test_batch_async_wrapper(urls, concurrency, timeout, verbose)
        else:
            return self._test_batch_single(urls, concurrency, timeout, verbose)
    
    def _make_test_callable(self, url: str, timeout: float):
        """Create callable for executor without lambda closure issues."""
        def test_callable():
            return self.test_single_config(url, timeout, verbose=False, max_retries=2, skip_tcp_ping=False)
        return test_callable
    
    def _test_batch_true(self, urls: List[str], batch_size: int, concurrency: int, timeout: float, verbose: bool) -> List[Tuple[str, bool, float]]:
        """True batch mode: ONE Xray process with multiple inbounds/outbounds."""
        batches = [urls[i:i+batch_size] for i in range(0, len(urls), batch_size)]
        
        all_results = []
        total_start = time.time()
        failed_batches = []
        
        for batch_idx, batch in enumerate(batches, 1):
            log(f"Batch {batch_idx}/{len(batches)}: Testing {len(batch)} configs...")
            
            # Create batch config with multiple inbounds/outbounds
            base_port = self.BASE_PORT + (batch_idx * 1000)
            config, port_map = self.create_multi_config(batch, base_port)
            
            if not config or not port_map:
                log(f"Failed to create batch config, skipping {len(batch)} configs")
                all_results.extend([(url, False, 0.0) for url in batch])
                continue
            
            # Start ONE Xray process for entire batch
            success, process, error = self.start_xray_multi_config(config, port_map, verbose=False)
            
            if not success or not process:
                log(f"Xray failed to start: {error}, will retry batch individually")
                failed_batches.append((batch_idx, batch))
                all_results.extend([(url, False, 0.0) for url in batch])
                continue
            
            try:
                # Test all ports in parallel (NO restart per config!)
                results = self._test_batch_concurrent(port_map, timeout, concurrency, verbose=False)
                all_results.extend(results)
                
                working = sum(1 for _, ok, _ in results if ok)
                pass_rate = working / len(results) * 100 if results else 0
                
                # If pass rate is abnormally low (<30%), mark for retry
                if pass_rate < 30:
                    log(f"WARNING: Low pass rate ({pass_rate:.1f}%), marking for retry")
                    failed_batches.append((batch_idx, batch))
                else:
                    log(f"Batch {batch_idx} complete: {working}/{len(results)} working ({pass_rate:.1f}%)")
                
            finally:
                self.stop_xray_process(process)
        
        # RETRY FAILED BATCHES INDIVIDUALLY
        if failed_batches:
            log(f"\nRetrying {len(failed_batches)} failed batches individually...")
            retry_results = []
            
            for batch_idx, batch in failed_batches:
                log(f"Retrying batch {batch_idx}: {len(batch)} configs...")
                
                # Test each config individually with fallback
                for url in batch:
                    result = self.test_single_config(url, timeout, verbose=False, max_retries=2)
                    retry_results.append((result[0], result[1], result[2]))
                
                working = sum(1 for _, ok, _ in retry_results[-len(batch):] if ok)
                log(f"Retry batch {batch_idx} complete: {working}/{len(batch)} working")
            
            # Replace failed batch results with retry results
            retry_idx = 0
            final_results = []
            for url, ok, latency in all_results:
                # Check if this was from a failed batch
                is_failed = False
                for batch_idx, batch in failed_batches:
                    if url in batch:
                        is_failed = True
                        break
                
                if is_failed and retry_idx < len(retry_results):
                    final_results.append(retry_results[retry_idx])
                    retry_idx += 1
                else:
                    final_results.append((url, ok, latency))
            
            all_results = final_results
        
        # Sort and return
        working = [(url, s, l) for url, s, l in all_results if s]
        working.sort(key=lambda x: x[2])
        
        elapsed = time.time() - total_start
        success_rate = len(working) / len(urls) * 100 if urls else 0
        log(f"True batch complete: {len(working)}/{len(urls)} working ({success_rate:.1f}%) in {elapsed:.1f}s")
        
        self._print_error_summary()
        
        return working
    
    def _test_batch_single(self, urls: List[str], concurrency: int, timeout: float, verbose: bool) -> List[Tuple[str, bool, float]]:
        """Single-config mode: Test each config individually with fallback."""
        import concurrent.futures
        
        results = []
        results_lock = threading.Lock()
        completed = [0]
        failed_count = [0]
        start_time = time.time()
        max_future_timeout = timeout * 3 + 10  # 40s for 10s timeout with retries
        
        log(f"Starting single-config test with {concurrency} workers...")
        
        def test_with_progress(url: str) -> Tuple[str, bool, float]:
            try:
                result = self.test_single_config(url, timeout, verbose=False, max_retries=2, skip_tcp_ping=False)
                
                with results_lock:
                    completed[0] += 1
                    count = completed[0]
                    if not result[1]:
                        failed_count[0] += 1
                if count % 50 == 0 or count == len(urls):
                    elapsed = time.time() - start_time
                    rate = count / elapsed if elapsed > 0 else 0
                    remaining = len(urls) - count
                    eta = remaining / rate if rate > 0 else 0
                    working_count = count - failed_count[0]
                    log(f"Progress: {count}/{len(urls)} ({rate:.1f}/s, ETA: {eta:.0f}s) - Working: {working_count}")
                return (result[0], result[1], result[2])
            except Exception as e:
                with results_lock:
                    completed[0] += 1
                    failed_count[0] += 1
                return (url, False, 0.0)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(test_with_progress, url): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=max_future_timeout)
                    with results_lock:
                        results.append(result)
                except concurrent.futures.TimeoutError:
                    url = futures[future]
                    with results_lock:
                        results.append((url, False, 0.0))
                        completed[0] += 1
                        failed_count[0] += 1
                except:
                    url = futures[future]
                    with results_lock:
                        results.append((url, False, 0.0))
        
        self.cleanup()
        
        working = [(url, s, l) for url, s, l in results if s]
        working.sort(key=lambda x: x[2])
        
        elapsed = time.time() - start_time
        success_rate = len(working) / len(urls) * 100 if urls else 0
        log(f"Single-config complete: {len(working)}/{len(urls)} working ({success_rate:.1f}%) in {elapsed:.1f}s")
        
        self._print_error_summary()
        
        return working
    
    def cleanup(self):
        """Stop all running Xray instances and cleanup."""
        with self._process_lock:
            for process in self._running_processes[:]:
                try:
                    if process.poll() is None:
                        process.kill()
                        try:
                            process.wait(timeout=2)
                        except:
                            pass
                except:
                    pass
            self._running_processes.clear()
        
        # Also cleanup prefire pool
        self._cleanup_prefire_pool()
