"""Fetcher module for downloading VPN configs using curl_cffi for speed."""

from curl_cffi import requests
from typing import Optional
from config.settings import CHROME_UA


def build_session(max_pool_size: int = 4):
    """Builds a curl_cffi session with proper headers."""
    session = requests.Session(
        impersonate="chrome120",  # Browser-like TLS fingerprint
    )
    session.headers.update({"User-Agent": CHROME_UA})
    # Note: curl_cffi handles connection pooling internally
    return session


def fetch_data(url: str, timeout: int = 10, max_attempts: int = 3, session=None) -> str:
    """Fetches data from URL with retry logic and fallbacks using curl_cffi.
    
    curl_cffi is 2-3x faster than requests and bypasses anti-bot protection.
    """
    sess = session or build_session(max_pool_size=4)
    
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True
            
            if attempt == 2:
                verify = False  # Skip SSL verification on retry
            elif attempt == 3:
                # Fallback to HTTP on final attempt
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.scheme == "https":
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False
            
            # curl_cffi API matches requests
            response = sess.get(
                modified_url,
                timeout=timeout,
                verify=verify,
                allow_redirects=True
            )
            response.raise_for_status()
            return response.text
            
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts:
                continue
            raise last_exc