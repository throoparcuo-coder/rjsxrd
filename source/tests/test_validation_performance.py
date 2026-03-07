"""Comprehensive test suite for config validation performance."""

import os
import sys
import time
import threading
from typing import List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config.settings import URLS, EXTRA_URLS_FOR_BYPASS
from fetchers.fetcher import fetch_data
from utils.file_utils import prepare_config_content
from utils.logger import log
from utils.config_verifier import ConfigVerifier
from utils.xray_batch_tester import XrayBatchTester
from utils.pipeline_validator import PipelineValidator
from utils.merged_config_generator import MergedConfigGenerator


def fetch_test_configs(max_configs: int = 1000) -> List[str]:
    """Fetch real configs from URL sources for testing."""
    all_configs = []
    
    log(f"Fetching configs from {len(URLS[:5])} sources for testing...")
    
    for url in URLS[:5]:
        try:
            content = fetch_data(url)
            configs = prepare_config_content(content)
            all_configs.extend(configs)
            log(f"Fetched {len(configs)} configs from {url[:50]}")
            
            if len(all_configs) >= max_configs:
                break
        except Exception as e:
            log(f"Error fetching {url}: {e}")
    
    if len(all_configs) > max_configs:
        all_configs = all_configs[:max_configs]
    
    log(f"Total configs fetched for testing: {len(all_configs)}")
    return all_configs


def test_config_verifier(configs: List[str]):
    """Test ConfigVerifier with TCP and HTTP modes."""
    log("=" * 60)
    log("TEST: ConfigVerifier (TCP mode)")
    log("=" * 60)
    
    verifier = ConfigVerifier(
        timeout=2.0,
        max_workers=100,
        test_mode="tcp",
        fast_timeout=0.5
    )
    
    start = time.time()
    results = verifier.verify_configs(configs[:200], show_progress=True)
    elapsed = time.time() - start
    
    log(f"ConfigVerifier TCP: {len(results)} working in {elapsed:.1f}s ({len(results)/elapsed:.1f}/s)")
    
    if results:
        log(f"Top 5 fastest:")
        for cfg, working, latency in results[:5]:
            log(f"  {latency:.0f}ms - {cfg[:60]}")
    
    log("")
    log("=" * 60)
    log("TEST: ConfigVerifier (Smart mode - TCP + HTTP)")
    log("=" * 60)
    
    verifier_smart = ConfigVerifier(
        timeout=5.0,
        max_workers=50,
        test_mode="smart",
        fast_timeout=0.5,
        http_timeout=3.0
    )
    
    start = time.time()
    results_smart = verifier_smart.verify_configs(configs[:100], show_progress=True)
    elapsed = time.time() - start
    
    log(f"ConfigVerifier Smart: {len(results_smart)} working in {elapsed:.1f}s ({len(results_smart)/elapsed:.1f}/s)")


def test_xray_batch_tester(configs: List[str]):
    """Test XrayBatchTester with increased concurrency."""
    log("")
    log("=" * 60)
    log("TEST: XrayBatchTester (v2rayN-style)")
    log("=" * 60)
    
    tester = XrayBatchTester()
    
    if not tester.xray_path or not os.path.exists(tester.xray_path):
        log(f"Xray binary not found at {tester.xray_path}, skipping Xray test")
        return
    
    test_configs = configs[:50]
    
    start = time.time()
    results = tester.test_batch(test_configs, concurrency=20, timeout=5.0)
    elapsed = time.time() - start
    
    log(f"XrayBatchTester: {len(results)} working in {elapsed:.1f}s ({len(results)/elapsed:.1f}/s)")
    
    tester.cleanup()


def test_pipeline_validator(configs: List[str]):
    """Test PipelineValidator with multi-stage testing."""
    log("")
    log("=" * 60)
    log("TEST: PipelineValidator (Multi-stage)")
    log("=" * 60)
    
    cancel_token = threading.Event()
    
    validator = PipelineValidator(
        tcp_concurrency=100,
        http_concurrency=20,
        cancel_token=cancel_token
    )
    
    def progress_cb(current, total, eta):
        log(f"Progress: {current}/{total} (ETA: {eta:.0f}s)")
    
    start = time.time()
    results = validator.verify_pipeline(
        configs[:200],
        run_speed_test=False,
        progress_callback=progress_cb
    )
    elapsed = time.time() - start
    
    log(f"PipelineValidator: {len(results)} working in {elapsed:.1f}s ({len(results)/elapsed:.1f}/s)")
    
    stats = validator.get_stats()
    log(f"Stats: TCP tested={stats['tcp_tested']}, TCP passed={stats['tcp_passed']}, "
        f"HTTP tested={stats['http_tested']}, HTTP passed={stats['http_passed']}")


def test_merged_config_generator(configs: List[str]):
    """Test MergedConfigGenerator."""
    log("")
    log("=" * 60)
    log("TEST: MergedConfigGenerator")
    log("=" * 60)
    
    generator = MergedConfigGenerator()
    
    test_configs = configs[:50]
    result = generator.generate_merged_config(test_configs)
    
    if result:
        config, ports = result
        log(f"Generated merged config with {len(config['inbounds'])} inbounds")
        log(f"Ports: {ports[:10]}... (showing first 10)")
        log(f"Config size: {len(str(config))} bytes")
    else:
        log("Failed to generate merged config")


def run_performance_comparison(configs: List[str]):
    """Run performance comparison of all validators."""
    log("")
    log("=" * 60)
    log("PERFORMANCE COMPARISON")
    log("=" * 60)
    
    test_sizes = [50, 100, 200]
    
    for size in test_sizes:
        if size > len(configs):
            continue
        
        test_configs = configs[:size]
        log(f"\n--- Testing with {size} configs ---")
        
        testers = [
            ("ConfigVerifier (TCP)", lambda: ConfigVerifier(test_mode="tcp", max_workers=100).verify_configs(test_configs, show_progress=False)),
            ("ConfigVerifier (Smart)", lambda: ConfigVerifier(test_mode="smart", max_workers=50).verify_configs(test_configs, show_progress=False)),
            ("PipelineValidator", lambda: PipelineValidator().verify_pipeline(test_configs)),
        ]
        
        for name, test_func in testers:
            try:
                start = time.time()
                results = test_func()
                elapsed = time.time() - start
                rate = len(results) / elapsed if elapsed > 0 else 0
                log(f"{name:25s}: {len(results):3d} working in {elapsed:6.1f}s ({rate:6.1f}/s)")
            except Exception as e:
                log(f"{name:25s}: ERROR - {e}")


def main():
    """Main test runner."""
    log("=" * 60)
    log("CONFIG VALIDATION PERFORMANCE TEST SUITE")
    log("=" * 60)
    log("")
    
    configs = fetch_test_configs(max_configs=500)
    
    if not configs:
        log("ERROR: No configs fetched for testing")
        return
    
    log(f"\nStarting tests with {len(configs)} configs...")
    log("")
    
    try:
        test_config_verifier(configs)
        test_xray_batch_tester(configs)
        test_pipeline_validator(configs)
        test_merged_config_generator(configs)
        run_performance_comparison(configs)
    except Exception as e:
        log(f"Test suite error: {e}")
        import traceback
        log(traceback.format_exc())
    
    log("")
    log("=" * 60)
    log("TEST SUITE COMPLETE")
    log("=" * 60)


if __name__ == "__main__":
    main()
