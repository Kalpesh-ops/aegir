import nmap
import logging
import socket
import shutil
import os
import subprocess
import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class NmapScanner:
    def __init__(self):
        possible_paths = ["/usr/bin/nmap", "/usr/local/bin/nmap", "nmap"]

        found_path = None
        for path in possible_paths:
            if shutil.which(path):
                found_path = path
                break

        if not found_path:
            found_path = "nmap"

        self.nmap_path = found_path

        try:
            self.scanner = nmap.PortScanner(nmap_search_path=[found_path])
            logging.info(f"Nmap Scanner initialized at: {found_path}")
        except nmap.PortScannerError:
            raise Exception("Nmap binary not found.")
        except Exception as e:
            logging.error(f"Error initializing scanner: {e}")
            raise

    def _build_args(self, mode: str) -> str:
        """Return Nmap arguments string for a given scan mode."""
        if mode == "fast":
            # FIX: Added -sV --version-intensity 5 so product/version are detected
            return "-Pn -sT -F -sV --version-intensity 0"
        elif mode == "deep":
            return "-Pn -sT -sV --version-intensity 5 --script=default"
        elif mode == "pen_test":
            return "-Pn -sT -sV --version-intensity 9 -p-"
        else:
            return "-Pn -sT -F -sV --version-intensity 0"

    def parse_ports_from_xml(self, xml_output: str) -> list:
        """
        Parse Nmap XML output and return a list of port dicts.

        Each dict has the exact keys:
            port, protocol, service, product, version, state

        All fields default to "unknown" when not detected.
        Filtered ports are included with state "filtered".

        This function never raises an exception. On any error it returns [].

        Args:
            xml_output: Raw XML string from Nmap (-oX output)

        Returns:
            list of dicts, one per port
        """
        try:
            root = ET.fromstring(xml_output)
        except Exception:
            logging.error("parse_ports_from_xml: failed to parse XML")
            return []

        ports = []

        try:
            for port_elem in root.findall(".//port"):
                port_id = port_elem.get("portid", "unknown")
                protocol = port_elem.get("protocol", "unknown")

                state = "unknown"
                state_elem = port_elem.find("state")
                if state_elem is not None:
                    state = state_elem.get("state", "unknown")

                service = "unknown"
                product = "unknown"
                version = "unknown"
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service = service_elem.get("name", "unknown")
                    product = service_elem.get("product", "unknown")
                    version = service_elem.get("version", "unknown")

                ports.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "service": service,
                        "product": product,
                        "version": version,
                        "state": state,
                    }
                )
        except Exception:
            logging.error("parse_ports_from_xml: error iterating ports")
            return []

        return ports

    def run_scan(self, target, mode="fast", fast_mode=None):
        """
        Execute Nmap scan and return both raw XML and structured data.

        Args:
            target: IP address or hostname
            mode: "fast" | "deep" | "pen_test"
            fast_mode: (deprecated) kept for backwards compatibility

        Returns:
            {"xml": str, "data": dict} on success.
            {"error": str} dict on failure.
        """
        try:
            socket.gethostbyname(target)

            if fast_mode is not None:
                mode = "fast" if fast_mode else "deep"

            logging.info(f"Starting {mode} scan on target: {target}...")

            scan_args = self._build_args(mode)

            with NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
                tmp_path = tmp.name

            try:
                cmd = [self.nmap_path] + scan_args.split() + ["-oX", tmp_path, target]
                logging.info(f"Executing: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )

                if result.returncode not in [0, 1]:
                    logging.error(
                        f"Nmap exit code {result.returncode}: {result.stderr}"
                    )

                with open(tmp_path, "r", encoding="utf-8") as f:
                    xml_output = f.read()
                structured = self._structure_from_xml(xml_output, target, mode)
                return {"xml": xml_output, "data": structured}

            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        except subprocess.TimeoutExpired:
            logging.error("Nmap scan timed out after 300 seconds")
            return {"error": "Nmap scan timed out after 300 seconds"}
        except socket.gaierror:
            logging.error(f"DNS resolution failed for target: {target}")
            return {"error": "DNS resolution failed for the specified target."}
        except Exception:
            logging.exception(f"Scan failed for target: {target}")
            return {"error": "Scan failed. See server logs for details."}

    def run_scan_xml(self, target, mode="fast"):
        """
        Execute Nmap scan with XML output and return structured data.
        Alias for run_scan() — kept for backwards compatibility.

        Args:
            target: IP address or hostname
            mode: "fast" | "deep" | "pen_test"

        Returns:
            Structured dict with scan results.
            Returns {"error": str} on failure.
        """
        return self.run_scan(target, mode)

    def _structure_from_xml(
        self, xml_output: str, target: str, mode: str = "fast"
    ) -> dict:
        """
        Parse XML output and structure it into the expected scan result dict.

        Args:
            xml_output: Raw XML string from Nmap
            target: Target IP/hostname
            mode: Scan mode

        Returns:
            Structured dict matching the expected output format
        """
        scan_stats = {}
        hosts = []

        try:
            root = ET.fromstring(xml_output)
        except Exception as e:
            logging.error(f"XML parsing error: {e}")
            return {"error": f"XML parsing error: {e}"}

        try:
            runstats = root.find(".//runstats/finished")
            if runstats is not None:
                scan_stats = {
                    "timestr": runstats.get("timestr", "unknown"),
                    "summary": runstats.get("summary", ""),
                    "exit": runstats.get("exit", "unknown"),
                }
        except Exception as e:
            logging.warning(f"Could not extract scan stats: {e}")

        try:
            for host in root.findall(".//host"):
                host_info = {
                    "ip": "unknown",
                    "status": "unknown",
                    "hostnames": [],
                    "open_ports": [],
                }

                address = host.find('.//address[@addrtype="ipv4"]')
                if address is not None:
                    host_info["ip"] = address.get("addr", "unknown")
                else:
                    address = host.find('.//address[@addrtype="ipv6"]')
                    if address is not None:
                        host_info["ip"] = address.get("addr", "unknown")

                status = host.find("status")
                if status is not None:
                    host_info["status"] = status.get("state", "unknown")

                hostnames = host.find("hostnames")
                if hostnames is not None:
                    host_info["hostnames"] = [
                        hn.get("name", "") for hn in hostnames.findall("hostname")
                    ]

                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        port_dict = {
                            "port": port_elem.get("portid", "unknown"),
                            "protocol": port_elem.get("protocol", "unknown"),
                            "state": "unknown",
                            "service": "unknown",
                            "product": "unknown",
                            "version": "unknown",
                            "vulnerabilities_found": "",
                        }

                        state_elem = port_elem.find("state")
                        if state_elem is not None:
                            port_dict["state"] = state_elem.get("state", "unknown")

                        service_elem = port_elem.find("service")
                        if service_elem is not None:
                            port_dict["service"] = service_elem.get("name", "unknown")
                            port_dict["product"] = service_elem.get(
                                "product", "unknown"
                            )
                            port_dict["version"] = service_elem.get(
                                "version", "unknown"
                            )

                        script_elem = port_elem.find("script")
                        if script_elem is not None:
                            port_dict["vulnerabilities_found"] = script_elem.get(
                                "output", ""
                            )

                        host_info["open_ports"].append(port_dict)

                hosts.append(host_info)

        except Exception as e:
            logging.error(f"Error structuring XML data: {e}")
            return {"error": f"Error structuring XML data: {e}"}

        return {
            "target": target,
            "scan_mode": mode,
            "scan_stats": scan_stats,
            "hosts": hosts,
        }

    def _structure_data_for_ai(self, target, mode="fast"):
        """
        Cleans the raw Nmap output into a clean JSON format.
        """
        clean_data = {
            "target": target,
            "scan_mode": mode,
            "scan_stats": self.scanner.scanstats(),
            "hosts": [],
        }

        for host in self.scanner.all_hosts():
            host_info = {
                "ip": host,
                "status": self.scanner[host].state(),
                "hostnames": self.scanner[host].hostname(),
                "open_ports": [],
            }

            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in sorted(ports):
                    port_data = self.scanner[host][proto][port]

                    vuln_output = ""
                    if "script" in port_data:
                        vuln_output = port_data["script"]

                    host_info["open_ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_data["state"],
                            "service": port_data["name"],
                            "product": port_data.get("product", "unknown"),
                            "version": port_data.get("version", "unknown"),
                            "vulnerabilities_found": vuln_output,
                        }
                    )

            clean_data["hosts"].append(host_info)

        return clean_data
