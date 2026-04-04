# Logic for Scapy Packet Manipulation
import logging
from scapy.all import IP, TCP, ICMP, sr1, conf

# Suppress Scapy verbose output
conf.verb = 0

class ScapyEngine:
    def __init__(self):
        logging.info("Scapy Engine initialized.")

    def firewall_detect(self, target_ip, port=80):
        """
        Sends an ACK packet to a port. 
        - If we get an RST (Reset) response, the firewall is likely 'Stateless' or non-existent (Unfiltered).
        - If we get NO response (Timeout), the firewall is 'Stateful' (Filtered/Dropping packets).
        """
        logging.info(f"Probing firewall on {target_ip}:{port}...")
        
        try:
            # Craft a raw TCP ACK packet (simulating an established connection)
            # A stateful firewall should DROP this because it didn't see a SYN first.
            pkt = IP(dst=target_ip)/TCP(dport=port, flags="A")
            
            # Send and wait 2 seconds for response
            response = sr1(pkt, timeout=2, verbose=False)

            result = {
                "target": target_ip,
                "port": port,
                "response_type": "None",
                "firewall_status": "Unknown",
                "explanation": ""
            }

            if response is None:
                result["response_type"] = "Timeout"
                result["firewall_status"] = "Stateful / Filtered (Secure)"
                result["explanation"] = "The target dropped our unsolicited ACK packet. This indicates a Stateful Firewall is active."
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x04: # RST flag
                    result["response_type"] = "RST Packet"
                    result["firewall_status"] = "Stateless / Unfiltered (Less Secure)"
                    result["explanation"] = "The target replied with a Reset (RST). It does not track connection states, allowing us to map its rules."
                else:
                    result["response_type"] = f"Flags: {response[TCP].flags}"
                    result["firewall_status"] = "Unknown Behavior"
            elif response.haslayer(ICMP):
                result["response_type"] = "ICMP Error"
                result["firewall_status"] = "Blocked by Admin"
            
            return result

        except Exception as e:
            logging.error(f"Scapy scan failed: {e}")
            return {"error": str(e)}

# --- TEST BLOCK ---
if __name__ == "__main__":
    # Windows Users: You might need to install Npcap for Scapy to work!
    scanner = ScapyEngine()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logging.info(scanner.firewall_detect("8.8.8.8", 53))  # Test against Google DNS