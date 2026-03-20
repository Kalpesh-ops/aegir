# Logic for Google Gemini API
# src/ai_agent/gemini_client.py

import os
import json
import logging
import google.generativeai as genai
from dotenv import load_dotenv
from google.generativeai.types import helper_types

# Try relative import, fallback to absolute for testing
try:
    from .prompts import SYSTEM_PROMPT
except ImportError:
    from prompts import SYSTEM_PROMPT

load_dotenv()
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class GeminiAgent:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            logging.error("GOOGLE_API_KEY not found in .env file.")
            raise ValueError("Missing API Key")

        genai.configure(api_key=self.api_key)

        # UPDATED MODEL LIST based on your check_models.py output
        # We prioritize 2.5 Flash for speed/quality, then fall back to 2.0
        self.preferred_models = [
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-flash-latest",
            "gemini-pro-latest",
        ]

        self.model = None
        self._initialize_model()

    def _initialize_model(self):
        """
        Iterates through preferred models and initializes the first one that works.
        """
        for model_name in self.preferred_models:
            try:
                logging.info(f"Attempting to initialize model: {model_name}")
                self.model = genai.GenerativeModel(
                    model_name=model_name, system_instruction=SYSTEM_PROMPT
                )
                self.current_model_name = model_name
                logging.info(f"Selected Model: {model_name}")
                return
            except Exception as e:
                logging.warning(f"Failed to init {model_name}: {e}")
                continue

        # If all precise names fail, try a generic fallback
        try:
            self.model = genai.GenerativeModel("gemini-pro")
            self.current_model_name = "gemini-pro (fallback)"
        except Exception as init_err:
            raise RuntimeError(
                f"Could not initialize any Gemini models. Check API Key."
            ) from init_err

    def analyze_scan(self, ports: list, cve_findings: list) -> str:
        """
        Send scan data to Gemini for plain-English analysis.

        Args:
            ports: List of detected services (from parse_ports_from_xml).
            cve_findings: List of CVE dicts from CIRCL enrichment.

        Returns:
            AI-generated report text, or error string on failure.
        """
        try:
            payload = {"ports": ports, "cve_findings": cve_findings}
            scan_json_str = json.dumps(payload, indent=2)

            logging.info(f"Sending data to {self.current_model_name}...")

            response = self.model.generate_content(
                f"Here is the scan data: \n\n{scan_json_str}",
                request_options=helper_types.RequestOptions(timeout=60),
            )
            return response.text

        except Exception as e:
            logging.error(f"AI Analysis Failed: {e}")
            return f"Error during analysis: {str(e)}"


if __name__ == "__main__":
    # Test Block
    mock_scan_file = "logs/temp_scans/latest_scan.json"
    if os.path.exists(mock_scan_file):
        with open(mock_scan_file, "r") as f:
            scan_data = json.load(f)

        agent = GeminiAgent()
        print(agent.analyze_scan(scan_data))
    else:
        print("Run nmap_engine.py first to generate data.")
