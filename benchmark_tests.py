#!/usr/bin/env python3
"""
Benchmark Tests for NetSec AI Scanner
Measures performance of core components
"""

import time
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner.nmap_engine import NmapScanner
from src.utils.data_sanitizer import sanitize_scan_data
from src.utils.token_optimizer import prune_scan_data

def benchmark_nmap_fast():
    """Benchmark Nmap fast scan on localhost"""
    print("\n[TEST 1] Nmap Fast Scan Performance")
    print("=" * 60)

    try:
        scanner = NmapScanner()
        target = "127.0.0.1"

        start = time.time()
        result = scanner.run_scan(target, mode="fast")
        elapsed = time.time() - start

        print(f"✓ Target: {target}")
        print(f"✓ Mode: Fast")
        print(f"✓ Duration: {elapsed:.2f}s")

        if "error" not in result:
            host_count = len(result.get("hosts", []))
            port_count = sum(len(h.get("open_ports", [])) for h in result.get("hosts", []))
            print(f"✓ Hosts Scanned: {host_count}")
            print(f"✓ Open Ports Found: {port_count}")
            print(f"✓ Throughput: {port_count/elapsed:.2f} ports/second")
            return {"success": True, "duration": elapsed, "ports": port_count}
        else:
            print(f"✗ Error: {result['error']}")
            return {"success": False, "error": result['error']}
    except Exception as e:
        print(f"✗ Test Failed: {e}")
        return {"success": False, "error": str(e)}

def benchmark_data_sanitization():
    """Benchmark data sanitization performance"""
    print("\n[TEST 2] Data Sanitization Performance")
    print("=" * 60)

    # Create mock scan data with sensitive information
    mock_data = {
        "target": "192.168.1.100",
        "hosts": [
            {
                "ip": "192.168.1.100",
                "mac": "AA:BB:CC:DD:EE:FF",
                "open_ports": [
                    {
                        "port": 80,
                        "service": "http",
                        "banner": "Apache/2.4.41 (Ubuntu) user@example.com",
                        "credentials": "username: admin password: secret123"
                    },
                    {
                        "port": 443,
                        "service": "https",
                        "description": "Internal server at 10.0.0.5"
                    }
                ] * 10  # Multiply to simulate larger dataset
            }
        ] * 5  # Simulate multiple hosts
    }

    try:
        start = time.time()
        sanitized = sanitize_scan_data(mock_data, target="192.168.1.100")
        elapsed = time.time() - start

        # Verify sanitization
        sanitized_str = json.dumps(sanitized)

        checks = {
            "MAC addresses removed": "AA:BB:CC:DD:EE:FF" not in sanitized_str,
            "Email addresses removed": "user@example.com" not in sanitized_str,
            "Passwords removed": "secret123" not in sanitized_str,
            "Private IPs masked": "10.0.0.5" not in sanitized_str
        }

        print(f"✓ Duration: {elapsed*1000:.2f}ms")
        print(f"✓ Data Size: {len(json.dumps(mock_data))} bytes")
        print(f"✓ Sanitization Checks:")
        for check, passed in checks.items():
            status = "✓" if passed else "✗"
            print(f"  {status} {check}")

        all_passed = all(checks.values())
        return {
            "success": all_passed,
            "duration": elapsed,
            "checks_passed": sum(checks.values()),
            "checks_total": len(checks)
        }
    except Exception as e:
        print(f"✗ Test Failed: {e}")
        return {"success": False, "error": str(e)}

def benchmark_token_optimization():
    """Benchmark token optimization performance"""
    print("\n[TEST 3] Token Optimization Performance")
    print("=" * 60)

    # Create large mock dataset
    large_data = {
        "target": "example.com",
        "scan_stats": {"elapsed": "120.5", "totalhosts": "1"},
        "hosts": [
            {
                "ip": "192.168.1.100",
                "open_ports": [
                    {
                        "port": i,
                        "service": f"service-{i}",
                        "product": f"Product {i}",
                        "version": f"1.{i}.0",
                        "state": "open",
                        "vulnerabilities_found": f"Long vulnerability description for port {i} " * 20
                    }
                    for i in range(50)  # 50 ports with verbose data
                ]
            }
        ]
    }

    try:
        original_size = len(json.dumps(large_data))

        start = time.time()
        optimized = prune_scan_data(large_data)
        elapsed = time.time() - start

        optimized_size = len(json.dumps(optimized))
        reduction = ((original_size - optimized_size) / original_size) * 100

        print(f"✓ Duration: {elapsed*1000:.2f}ms")
        print(f"✓ Original Size: {original_size:,} bytes")
        print(f"✓ Optimized Size: {optimized_size:,} bytes")
        print(f"✓ Size Reduction: {reduction:.1f}%")
        print(f"✓ Compression Ratio: {original_size/optimized_size:.2f}x")

        return {
            "success": True,
            "duration": elapsed,
            "original_size": original_size,
            "optimized_size": optimized_size,
            "reduction_percent": reduction
        }
    except Exception as e:
        print(f"✗ Test Failed: {e}")
        return {"success": False, "error": str(e)}

def run_all_benchmarks():
    """Run all benchmark tests and generate report"""
    print("\n" + "=" * 60)
    print("NetSec AI Scanner - Benchmark Suite")
    print("=" * 60)

    results = {
        "nmap_fast": benchmark_nmap_fast(),
        "sanitization": benchmark_data_sanitization(),
        "token_optimization": benchmark_token_optimization()
    }

    # Summary
    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)

    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if r.get("success", False))

    print(f"\nTests Passed: {passed_tests}/{total_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%\n")

    # Save results
    output_file = "/tmp/benchmark_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"✓ Results saved to: {output_file}\n")

    return results

if __name__ == "__main__":
    results = run_all_benchmarks()
    sys.exit(0 if all(r.get("success", False) for r in results.values()) else 1)
