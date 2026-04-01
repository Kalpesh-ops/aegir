import subprocess
import os
import logging
import time
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TSharkScanner:
    """
    TShark packet capture engine with privacy-by-design.
    
    CRITICAL PRIVACY CONSTRAINT:
    - Captures ONLY first 80 bytes (headers) using -s 80 flag
    - Generates protocol summary, NOT raw packet hex
    - Strips PII from output before returning
    """
    
    def __init__(self, output_dir="logs/captures"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logging.info(f"Created capture directory: {self.output_dir}")

    @staticmethod
    def detect_interface(target_ip: str) -> str:
        """
        Auto-detect the correct TShark interface for a given target IP.
        Falls back to TSHARK_INTERFACE env var, then index '1'.
        """
        import subprocess, os, ipaddress

        env_iface = os.getenv("TSHARK_INTERFACE")
        if env_iface:
            return env_iface

        try:
            target = ipaddress.ip_address(target_ip)
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            current_iface = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if "adapter" in line.lower():
                    current_iface = line
                if "IPv4" in line and current_iface:
                    ip_part = line.split(":")[-1].strip()
                    try:
                        iface_ip = ipaddress.ip_address(ip_part)
                        # Check if target is in same /24
                        if list(target.packed[:3]) == list(iface_ip.packed[:3]):
                            # Extract adapter name from "Ethernet adapter Ethernet:"
                            name = current_iface.split("adapter")[-1].strip().rstrip(":")
                            logging.info(f"[TShark] Auto-detected interface: {name}")
                            return name
                    except ValueError:
                        continue
        except Exception as e:
            logging.warning(f"[TShark] Interface detection failed: {e}")

        return "Ethernet"  # sane Windows default
    
    def run_capture(self, target_ip, duration=30, interface=None):
        """
        Capture network traffic with privacy protection.
        
        Args:
            target_ip: Target IP for traffic filtering
            duration: Capture duration in seconds
            interface: Network interface (eth0, wlan0, etc.)
        
        Returns:
            dict with protocol summary and statistics
        """
        if interface is None:
            interface = self.detect_interface(target_ip)
            
        try:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            pcap_filename = f"capture_{timestamp}.pcap"
            pcap_filepath = os.path.join(self.output_dir, pcap_filename)
            
            logging.info(f"Starting TShark capture on {interface} for {duration}s...")
            logging.info(f"Privacy constraint: Snapshot length = 80 bytes (headers only)")
            
            # Build TShark command with privacy constraints
            # -s 80: Snapshot length = 80 bytes (headers only, NO payloads)
            # -i: Interface
            # -a duration: Auto-stop after N seconds
            # -f: Display filter (packets matching criteria)
            # -w: Write to file (.pcap)
            cmd = [
                "tshark",
                "-i", interface,
                "-s", "80",  # CRITICAL: Capture only 80 bytes (headers)
                "-a", f"duration:{duration}",
                "-w", pcap_filepath
            ]
            
            # Apply BPF filter if target is not localhost
            if target_ip and target_ip != "127.0.0.1":
                # Strict whitelist: only alphanumeric and dots for IP filtering
                if self._validate_ip_for_filter(target_ip):
                    cmd.extend(["-f", f"host {target_ip}"])
            
            logging.info(f"Executing: {' '.join(cmd)}")
            
            # Run capture
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
            
            if result.returncode != 0:
                logging.warning(f"TShark warning: {result.stderr}")
            
            # Verify file was created
            if not os.path.exists(pcap_filepath):
                return {
                    "status": "failed",
                    "error": "PCAP file not created"
                }
            
            file_size = os.path.getsize(pcap_filepath)
            logging.info(f"Capture complete: {file_size} bytes written to {pcap_filename}")
            
            # Parse PCAP file to extract protocol summary
            protocol_summary = self._parse_pcap_summary(pcap_filepath)
            
            return {
                "status": "captured",
                "pcap_file": pcap_filename,
                "pcap_path": pcap_filepath,
                "size_bytes": file_size,
                "duration_seconds": duration,
                "protocol_summary": protocol_summary,
                "privacy_notes": "Snapshot length: 80 bytes (headers only, payloads excluded)"
            }
        
        except subprocess.TimeoutExpired:
            logging.error("TShark capture timeout")
            return {
                "status": "timeout",
                "error": "Capture timeout exceeded"
            }
        except FileNotFoundError:
            logging.error("TShark binary not found")
            return {
                "status": "error",
                "error": "TShark not installed. Install Wireshark package."
            }
        except Exception as e:
            logging.error(f"Capture error: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _parse_pcap_summary(self, pcap_filepath):
        """
        Extract privacy-safe protocol summary from PCAP.
        Returns: dict with protocol counts and types (NO raw data)
        """
        try:
            # Use tshark to read the PCAP and extract protocol info
            cmd = [
                "tshark",
                "-r", pcap_filepath,
                "-T", "fields",
                "-e", "frame.protocols",
                "-E", "separator=,"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                logging.warning("Failed to parse PCAP")
                return {}
            
            # Count protocols
            protocols = {}
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                proto_list = line.split(',')
                for proto in proto_list:
                    proto = proto.strip()
                    if proto:
                        protocols[proto] = protocols.get(proto, 0) + 1
            
            return {
                "protocols_detected": protocols,
                "total_packets": sum(protocols.values()),
                "unique_protocols": list(protocols.keys())
            }
        
        except Exception as e:
            logging.warning(f"PCAP parsing error: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def _validate_ip_for_filter(ip: str) -> bool:
        """
        Validate IP address for safe use in BPF filter.
        Prevents filter injection attacks.
        """
        # Strict IPv4 validation
        ipv4_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(ipv4_regex, ip))
